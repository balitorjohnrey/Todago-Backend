/**
 * Operator Auth Routes
 *
 * FIX SUMMARY:
 * - Register now requires the main account JWT (Authorization: Bearer <token>)
 *   instead of looking up by email in a separate "commuters" table.
 *   The backend reads the user's data (name, phone, email, password_hash, salt)
 *   directly from the `users` table using req.userId set by requireAuth.
 *   This eliminates the "No account found" error and auto-fills all personal info.
 *
 * - Login uses the same password as the main account (password_hash + salt
 *   copied from users at registration time).
 *
 * - LOGIN FIX: The WHERE clause now also matches against association_name
 *   (case-insensitive), so users can enter either the short association code
 *   OR the full association name (e.g. "Panabo City TODA") in the login field.
 */
const express = require('express');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { dbRun, dbGet, dbAll } = require('../db/database');
const { verifyPassword } = require('../utils/password');

// ── FIX: requireAuth is now properly exported from auth.js ────────────────────
const { requireAuth } = require('./auth');

const router = express.Router();

function generateOperatorToken(operatorId) {
  return jwt.sign({ sub: operatorId, role: 'operator' }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
    issuer: 'todago-api',
    audience: 'todago-app',
  });
}

function sanitizeOperator(op) {
  const { password_hash, salt, ...safe } = op;
  return safe;
}

function clientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]
    || req.socket?.remoteAddress || 'unknown';
}

// ── POST /api/operator/register ───────────────────────────────────────────────
// Requires main account JWT in Authorization header.
// Contact info (name, phone, email) is pulled from the users table automatically.
router.post('/register',
  requireAuth, // ← verifies main account token, sets req.userId
  [
    body('associationName').trim().isLength({ min: 2 })
      .withMessage('Association name is required'),
    body('associationCode').trim().notEmpty()
      .withMessage('Association code is required'),
    body('ltfrbNumber').trim().notEmpty()
      .withMessage('LTFRB franchise number is required'),
    body('region').trim().notEmpty()
      .withMessage('Region/city is required'),
    body('serviceArea').optional().trim(),
    body('totalTricycles').optional(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ success: false, message: errors.array()[0].msg });
    }

    const {
      associationName, associationCode, ltfrbNumber,
      region, serviceArea, totalTricycles,
    } = req.body;

    try {
      // ── FIX: Look up the main account from `users` table using req.userId ──
      // No more commuters table, no more email/phone mismatches.
      const mainUser = await dbGet(
        `SELECT * FROM users WHERE id = $1 AND is_active IS NOT FALSE`,
        [req.userId]
      );

      if (!mainUser) {
        return res.status(404).json({
          success: false,
          message: 'Main account not found. Please sign in to your TodaGo account first.',
        });
      }

      // Check if this user already has an operator account
      const existingOperator = await dbGet(
        'SELECT operator_id FROM operators WHERE user_id = $1',
        [mainUser.id]
      );
      if (existingOperator) {
        return res.status(409).json({
          success: false,
          message: 'This account already has an operator profile.',
        });
      }

      // Duplicate checks for association details
      const checks = [
        ['SELECT toda_id FROM toda_associations WHERE ltfrb_number = $1',
         [ltfrbNumber], 'LTFRB number already registered'],
        ['SELECT toda_id FROM toda_associations WHERE association_code = $1',
         [associationCode], 'Association code already exists'],
      ];
      for (const [sql, params, msg] of checks) {
        if (await dbGet(sql, params)) {
          return res.status(409).json({ success: false, message: msg });
        }
      }

      // Create TODA association
      const todaId = uuidv4();
      await dbRun(
        `INSERT INTO toda_associations
          (toda_id, association_name, association_code,
           ltfrb_number, region, service_area, total_tricycles)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [
          todaId,
          associationName.trim(),
          associationCode.trim(),
          ltfrbNumber.trim(),
          region.trim(),
          serviceArea || null,
          parseInt(totalTricycles || 0),
        ]
      );

      // Create operator — personal info and password come from the main users record
      const operatorId = uuidv4();
      await dbRun(
        `INSERT INTO operators
          (operator_id, user_id, toda_id, contact_name, email, phone,
           password_hash, salt, toda_body_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [
          operatorId,
          mainUser.id,
          todaId,
          mainUser.full_name,
          mainUser.email,
          mainUser.phone,
          mainUser.password_hash,
          mainUser.salt,
          associationCode.trim(),
        ]
      );

      const operator = await dbGet(
        `SELECT o.*, ta.association_name, ta.association_code,
                ta.ltfrb_number, ta.region, ta.service_area,
                ta.total_tricycles
         FROM operators o
         JOIN toda_associations ta ON ta.toda_id = o.toda_id
         WHERE o.operator_id = $1`,
        [operatorId]
      );

      const token = generateOperatorToken(operatorId);
      console.log(`[Operator] Registered: ${associationName} — ${mainUser.email}`);

      return res.status(201).json({
        success: true,
        message: 'Operator account created! Pending LTFRB verification.',
        token,
        operator: sanitizeOperator(operator),
      });

    } catch (error) {
      console.error('[Operator] Register error:', error.message);
      return res.status(500).json({ success: false, message: 'Registration failed. Try again.' });
    }
  }
);

// ── POST /api/operator/login ──────────────────────────────────────────────────
// Login: TODA Association ID (full name OR code) + email + main account password
//
// FIX: The WHERE clause now matches on association_name OR association_code
// (both case-insensitive), so users can type either value in the login field.
// Previously only association_code was matched, causing "Invalid credentials"
// when the user typed the full association name (e.g. "Panabo City TODA").
router.post('/login', [
  body('todaAssociationId').trim().notEmpty()
    .withMessage('TODA Association ID is required'),
  body('email').trim().isEmail().normalizeEmail()
    .withMessage('Enter a valid email'),
  body('password').notEmpty().withMessage('Password is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  const { todaAssociationId, email, password } = req.body;
  const ip = clientIp(req);

  try {
    // ── FIX: Match by association_code OR association_name (both case-insensitive)
    // Previously only association_code was checked, so entering the full name
    // like "Panabo City TODA" always returned 401 even with correct credentials.
    const operator = await dbGet(
      `SELECT o.*, ta.association_name, ta.association_code,
              ta.ltfrb_number, ta.is_verified AS toda_verified
       FROM operators o
       JOIN toda_associations ta ON ta.toda_id = o.toda_id
       WHERE o.email = $1
         AND o.is_active IS NOT FALSE
         AND (
           ta.association_code = $2
           OR ta.toda_id::text = $2
           OR LOWER(ta.association_code) = LOWER($2)
           OR LOWER(ta.association_name) = LOWER($2)
         )`,
      [email.toLowerCase(), todaAssociationId.trim()]
    );

    const dummyHash = '$2b$12$dummyhashfortimingattackXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
    const dummySalt = 'a1b2c3d4e5f6a7b8c9d0e1f2';

    const passwordMatch = await verifyPassword(
      password,
      operator ? operator.password_hash : dummyHash,
      operator ? operator.salt          : dummySalt
    );

    if (!operator || !passwordMatch) {
      await dbRun(
        `INSERT INTO login_attempts (user_type, email, ip_address, success)
         VALUES ('operator',$1,$2,false)`,
        [email, ip]
      ).catch(() => {});

      return res.status(401).json({
        success: false,
        message: 'Invalid TODA Association ID, email, or password',
      });
    }

    await dbRun(
      `UPDATE operators SET last_login = NOW() WHERE operator_id = $1`,
      [operator.operator_id]
    );
    await dbRun(
      `INSERT INTO login_attempts (user_type, email, ip_address, success)
       VALUES ('operator',$1,$2,true)`,
      [email, ip]
    ).catch(() => {});

    const token = generateOperatorToken(operator.operator_id);
    console.log(`[Operator] Login: ${email} from ${ip}`);

    return res.status(200).json({
      success: true,
      message: 'Login successful! Welcome back 👋',
      token,
      operator: sanitizeOperator(operator),
    });

  } catch (error) {
    console.error('[Operator] Login error:', error.message);
    return res.status(500).json({ success: false, message: 'Login failed. Try again.' });
  }
});

// ── GET /api/operator/me ──────────────────────────────────────────────────────
router.get('/me', requireOperatorAuth, async (req, res) => {
  try {
    const operator = await dbGet(
      `SELECT o.*, ta.association_name, ta.association_code, ta.ltfrb_number,
              ta.region, ta.service_area, ta.total_tricycles,
              ta.is_verified AS toda_verified
       FROM operators o
       JOIN toda_associations ta ON ta.toda_id = o.toda_id
       WHERE o.operator_id = $1 AND o.is_active IS NOT FALSE`,
      [req.operatorId]
    );
    if (!operator) return res.status(404).json({ success: false, message: 'Not found' });
    return res.json({ success: true, operator: sanitizeOperator(operator) });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── GET /api/operator/drivers ─────────────────────────────────────────────────
router.get('/drivers', requireOperatorAuth, async (req, res) => {
  try {
    const op = await dbGet(
      `SELECT toda_id FROM operators WHERE operator_id = $1`,
      [req.operatorId]
    );
    if (!op) return res.status(404).json({ success: false, message: 'Operator not found' });

    const drivers = await dbAll(
      `SELECT d.driver_id, d.driver_name, d.phone, d.license_no,
              d.toda_body_number, d.status, d.avg_rating,
              d.total_trips, d.is_verified, d.created_at,
              t.plate_no, t.vehicle_color
       FROM drivers d
       LEFT JOIN tricycles t ON t.driver_id = d.driver_id
       WHERE d.toda_id = $1 AND d.is_active IS NOT FALSE
       ORDER BY d.driver_name`,
      [op.toda_id]
    );
    return res.json({ success: true, total: drivers.length, drivers });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── GET /api/operator/stats ───────────────────────────────────────────────────
router.get('/stats', requireOperatorAuth, async (req, res) => {
  try {
    const op = await dbGet(
      `SELECT toda_id FROM operators WHERE operator_id = $1`,
      [req.operatorId]
    );
    if (!op) return res.status(404).json({ success: false, message: 'Operator not found' });

    const todaId = op.toda_id;
    const [active, total, trips, rev] = await Promise.all([
      dbGet(
        `SELECT COUNT(*) FROM drivers
         WHERE toda_id = $1 AND status = 'online' AND is_active IS NOT FALSE`,
        [todaId]
      ),
      dbGet(
        `SELECT COUNT(*) FROM drivers
         WHERE toda_id = $1 AND is_active IS NOT FALSE`,
        [todaId]
      ),
      dbGet(
        `SELECT COUNT(*) FROM trips tr
         JOIN drivers d ON d.driver_id = tr.driver_id
         WHERE d.toda_id = $1
           AND tr.request_timestamp::date = CURRENT_DATE
           AND tr.status = 'completed'`,
        [todaId]
      ),
      dbGet(
        `SELECT COALESCE(SUM(fare), 0) AS total FROM trips tr
         JOIN drivers d ON d.driver_id = tr.driver_id
         WHERE d.toda_id = $1
           AND tr.request_timestamp::date = CURRENT_DATE
           AND tr.status = 'completed'`,
        [todaId]
      ),
    ]);

    return res.json({
      success: true,
      stats: {
        active_drivers  : parseInt(active.count),
        total_drivers   : parseInt(total.count),
        trips_today     : parseInt(trips.count),
        gross_revenue   : parseFloat(rev.total),
        commission_due  : parseFloat(rev.total) * 0.10,
        net_payout      : parseFloat(rev.total) * 0.90,
      },
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── POST /api/operator/logout ─────────────────────────────────────────────────
router.post('/logout', requireOperatorAuth, (req, res) => {
  return res.json({ success: true, message: 'Logged out' });
});

// ── Operator Auth Middleware ───────────────────────────────────────────────────
function requireOperatorAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Authorization required' });
  }
  try {
    const payload = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET, {
      issuer: 'todago-api', audience: 'todago-app',
    });
    if (payload.role !== 'operator') {
      return res.status(403).json({ success: false, message: 'Operator access only' });
    }
    req.operatorId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
}

module.exports = router;