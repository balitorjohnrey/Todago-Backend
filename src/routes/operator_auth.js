/**
 * Operator Auth Routes
 * Registration: no password — uses linked commuter account password
 * Login: TODA Association ID + email + commuter account password
 */
const express = require('express');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { dbRun, dbGet, dbAll } = require('../db/database');
const { verifyPassword } = require('../utils/password');

const router = express.Router();

function generateToken(operatorId) {
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
// No password — links to commuter account by email
router.post('/register', [
  body('associationName').trim().isLength({ min: 2 })
    .withMessage('Association name is required'),
  body('associationCode').trim().notEmpty()
    .withMessage('Association code is required'),
  body('ltfrbNumber').trim().notEmpty()
    .withMessage('LTFRB franchise number is required'),
  body('region').trim().notEmpty()
    .withMessage('Region/city is required'),
  body('contactName').trim().isLength({ min: 2 })
    .withMessage('Contact person name is required'),
  body('email').trim().isEmail().normalizeEmail()
    .withMessage('Enter a valid email'),
  body('phone').trim().matches(/^[+\d\s\-()]{7,20}$/)
    .withMessage('Enter a valid phone number'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  const { associationName, associationCode, ltfrbNumber, region,
          serviceArea, totalTricycles, contactName, email, phone } = req.body;

  try {
    // Find commuter account by email — password lives there
    const commuter = await dbGet(
      `SELECT * FROM commuters WHERE email = $1 AND is_active = true`,
      [email.toLowerCase()]
    );
    if (!commuter) {
      return res.status(404).json({
        success: false,
        message: 'No main account found with this email. '
          + 'Please sign up your main TodaGo account first.',
      });
    }

    // Duplicate checks
    const checks = [
      ['SELECT toda_id FROM toda_associations WHERE ltfrb_number = $1',
       [ltfrbNumber], 'LTFRB number already registered'],
      ['SELECT toda_id FROM toda_associations WHERE association_code = $1',
       [associationCode], 'Association code already exists'],
      ['SELECT operator_id FROM operators WHERE email = $1',
       [email], 'Email already registered as operator'],
      ['SELECT operator_id FROM operators WHERE phone = $1',
       [phone], 'Phone already registered as operator'],
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
      [todaId, associationName.trim(), associationCode.trim(),
       ltfrbNumber.trim(), region.trim(),
       serviceArea || null, parseInt(totalTricycles || 0)]
    );

    // Create operator — copy password_hash + salt from commuter
    const operatorId = uuidv4();
    await dbRun(
      `INSERT INTO operators
        (operator_id, toda_id, contact_name, email, phone,
         password_hash, salt, toda_body_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [operatorId, todaId, contactName.trim(), email,
       phone.trim(), commuter.password_hash, commuter.salt,
       associationCode.trim()]
    );

    const operator = await dbGet(
      `SELECT o.*, ta.association_name, ta.association_code, ta.ltfrb_number
       FROM operators o
       JOIN toda_associations ta ON ta.toda_id = o.toda_id
       WHERE o.operator_id = $1`,
      [operatorId]
    );
    const token = generateToken(operatorId);
    console.log(`[Operator] Registered: ${associationName} — ${email}`);

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
});

// ── POST /api/operator/login ──────────────────────────────────────────────────
// Uses same password as commuter main account
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
    // Find operator by email + validate TODA association ID
    const operator = await dbGet(
      `SELECT o.*, ta.association_name, ta.association_code,
              ta.ltfrb_number, ta.is_verified AS toda_verified
       FROM operators o
       JOIN toda_associations ta ON ta.toda_id = o.toda_id
       WHERE o.email = $1
         AND o.is_active = true
         AND (ta.association_code = $2
              OR ta.toda_id = $2
              OR LOWER(ta.association_code) = LOWER($2))`,
      [email.toLowerCase(), todaAssociationId.trim()]
    );

    const dummyHash = '$2b$12$invalidhashfortimingattackprevention000000000000000000000';
    const dummySalt = 'dummy_salt_timing_prevention';
    const passwordMatch = await verifyPassword(
      password,
      operator ? operator.password_hash : dummyHash,
      operator ? operator.salt : dummySalt
    );

    if (!operator || !passwordMatch) {
      await dbRun(
        `INSERT INTO login_attempts (user_type, email, ip_address, success)
         VALUES ('operator',$1,$2,false)`,
        [email, ip]
      );
      return res.status(401).json({
        success: false,
        message: 'Invalid TODA Association ID, email, or password',
      });
    }

    await dbRun(
      `UPDATE operators SET last_login=NOW() WHERE operator_id=$1`,
      [operator.operator_id]
    );
    await dbRun(
      `INSERT INTO login_attempts (user_type, email, ip_address, success)
       VALUES ('operator',$1,$2,true)`,
      [email, ip]
    );

    const token = generateToken(operator.operator_id);
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

// ── GET /api/operator/me ───────────────────────────────────────────────────────
router.get('/me', requireOperatorAuth, async (req, res) => {
  try {
    const operator = await dbGet(
      `SELECT o.*, ta.association_name, ta.association_code, ta.ltfrb_number,
              ta.region, ta.service_area, ta.total_tricycles,
              ta.is_verified AS toda_verified
       FROM operators o
       JOIN toda_associations ta ON ta.toda_id = o.toda_id
       WHERE o.operator_id = $1 AND o.is_active = true`,
      [req.operatorId]
    );
    if (!operator) return res.status(404).json({ success: false, message: 'Not found' });
    return res.json({ success: true, operator: sanitizeOperator(operator) });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── GET /api/operator/drivers ──────────────────────────────────────────────────
router.get('/drivers', requireOperatorAuth, async (req, res) => {
  try {
    const op = await dbGet(
      `SELECT toda_id FROM operators WHERE operator_id=$1`, [req.operatorId]
    );
    const drivers = await dbAll(
      `SELECT d.driver_id, d.driver_name, d.phone, d.license_no,
              d.toda_body_number, d.status, d.avg_rating,
              d.total_trips, d.is_verified, d.created_at,
              t.plate_no, t.vehicle_color
       FROM drivers d
       LEFT JOIN tricycles t ON t.driver_id = d.driver_id
       WHERE d.toda_id = $1 AND d.is_active = true
       ORDER BY d.driver_name`,
      [op.toda_id]
    );
    return res.json({ success: true, total: drivers.length, drivers });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── GET /api/operator/stats ────────────────────────────────────────────────────
router.get('/stats', requireOperatorAuth, async (req, res) => {
  try {
    const op = await dbGet(
      `SELECT toda_id FROM operators WHERE operator_id=$1`, [req.operatorId]
    );
    const todaId = op.toda_id;
    const [active, total, trips, rev] = await Promise.all([
      dbGet(`SELECT COUNT(*) FROM drivers WHERE toda_id=$1 AND status='online' AND is_active=true`, [todaId]),
      dbGet(`SELECT COUNT(*) FROM drivers WHERE toda_id=$1 AND is_active=true`, [todaId]),
      dbGet(`SELECT COUNT(*) FROM trips tr JOIN drivers d ON d.driver_id=tr.driver_id
             WHERE d.toda_id=$1 AND tr.request_timestamp::date=CURRENT_DATE AND tr.status='completed'`, [todaId]),
      dbGet(`SELECT COALESCE(SUM(fare),0) AS total FROM trips tr
             JOIN drivers d ON d.driver_id=tr.driver_id
             WHERE d.toda_id=$1 AND tr.request_timestamp::date=CURRENT_DATE AND tr.status='completed'`, [todaId]),
    ]);
    return res.json({
      success: true,
      stats: {
        active_drivers: parseInt(active.count),
        total_drivers: parseInt(total.count),
        trips_today: parseInt(trips.count),
        gross_revenue: parseFloat(rev.total),
        commission_due: parseFloat(rev.total) * 0.10,
        net_payout: parseFloat(rev.total) * 0.90,
      },
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── POST /api/operator/logout ──────────────────────────────────────────────────
router.post('/logout', requireOperatorAuth, (req, res) => {
  return res.json({ success: true, message: 'Logged out' });
});

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