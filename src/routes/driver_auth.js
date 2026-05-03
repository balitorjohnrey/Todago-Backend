/**
 * Driver Auth Routes
 *
 * FIX SUMMARY:
 * - Register now requires the main account JWT (Authorization: Bearer <token>)
 *   instead of looking up by phone in a separate "commuters" table.
 *   The backend reads the user's data (name, phone, email, password_hash, salt)
 *   directly from the `users` table using req.userId set by requireAuth.
 *   This eliminates the "No account found" error and auto-fills all personal info.
 *
 * - Login uses the same password as the main account (password_hash + salt
 *   copied from users at registration time).
 */
const express = require('express');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { dbRun, dbGet } = require('../db/database');
const { verifyPassword } = require('../utils/password');

// ── FIX: Import requireAuth from auth.js instead of duplicating it ────────────
const { requireAuth } = require('./auth');

const router = express.Router();

function generateDriverToken(driverId) {
  return jwt.sign({ sub: driverId, role: 'driver' }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
    issuer: 'todago-api',
    audience: 'todago-app',
  });
}

function sanitizeDriver(d) {
  const { password_hash, salt, ...safe } = d;
  return safe;
}

function clientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]
    || req.socket?.remoteAddress || 'unknown';
}

// ── POST /api/driver/register ─────────────────────────────────────────────────
// Requires main account JWT in Authorization header.
// Personal info (name, phone, email) is pulled from the users table automatically
// — the Flutter app does NOT need to send them; they're auto-filled from the token.
router.post('/register',
  requireAuth, // ← verifies main account token, sets req.userId
  [
    body('licenseNo').trim().notEmpty().withMessage('License number is required'),
    body('todaBodyNumber').trim().notEmpty().withMessage('TODA body number is required'),
    body('plateNo').trim().notEmpty().withMessage('Plate number is required'),
    body('vehicleColor').optional().trim(),
    body('todaId').optional().trim(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ success: false, message: errors.array()[0].msg });
    }

    const { licenseNo, todaBodyNumber, plateNo, vehicleColor, todaId } = req.body;

    try {
      // ── FIX: Look up the main account from `users` table using req.userId ──
      // No more commuters table, no more phone number mismatches.
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

      // Check if this user already has a driver account
      const existingDriver = await dbGet(
        'SELECT driver_id FROM drivers WHERE user_id = $1',
        [mainUser.id]
      );
      if (existingDriver) {
        return res.status(409).json({
          success: false,
          message: 'This account already has a driver profile.',
        });
      }

      // Duplicate checks for vehicle details
      const checks = [
        ['SELECT driver_id FROM drivers WHERE license_no = $1',
         [licenseNo], 'License number already registered'],
        ['SELECT driver_id FROM drivers WHERE toda_body_number = $1',
         [todaBodyNumber], 'TODA body number already registered'],
        ['SELECT tricycle_id FROM tricycles WHERE plate_no = $1',
         [plateNo.trim().toLowerCase().replace(/\s/g, '')],
         'Plate number already registered'],
      ];
      for (const [sql, params, msg] of checks) {
        if (await dbGet(sql, params)) {
          return res.status(409).json({ success: false, message: msg });
        }
      }

      const driverId = uuidv4();

      // Insert driver — personal info and password come from the main users record
      // toda_id is NULL here — the free-text branch name is stored in toda_branch_name
      // toda_id FK link happens later when an operator claims/verifies the driver
      await dbRun(
        `INSERT INTO drivers
          (driver_id, user_id, toda_id, toda_branch_name, driver_name, email, phone,
           license_no, toda_body_number, password_hash, salt, status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'offline')`,
        [
          driverId,
          mainUser.id,           // ← linked to main account
          null,                  // ← toda_id NULL (no FK violation)
          todaId || null,        // ← free-text branch name stored here instead
          mainUser.full_name,    // ← auto-filled from main account
          mainUser.email,        // ← auto-filled from main account
          mainUser.phone,        // ← auto-filled from main account (no mismatch!)
          licenseNo.trim(),
          todaBodyNumber.trim(),
          mainUser.password_hash, // ← shared password hash
          mainUser.salt,          // ← shared salt
        ]
      );

      // Create tricycle record
      const tricycleId = uuidv4();
      await dbRun(
        `INSERT INTO tricycles
          (tricycle_id, driver_id, toda_id, plate_no, body_number, vehicle_color, status)
         VALUES ($1,$2,$3,$4,$5,$6,'inactive')`,
        [
          tricycleId,
          driverId,
          todaId || null,
          plateNo.trim().toLowerCase().replace(/\s/g, ''),
          todaBodyNumber.trim(),
          vehicleColor || null,
        ]
      ).catch((err) => {
        console.error('[Driver] Tricycle insert error:', err.message);
      });

      const driver = await dbGet(
        `SELECT d.*, t.plate_no, t.vehicle_color
         FROM drivers d
         LEFT JOIN tricycles t ON t.driver_id = d.driver_id
         WHERE d.driver_id = $1`,
        [driverId]
      );

      const token = generateDriverToken(driverId);
      console.log(`[Driver] Registered: ${mainUser.full_name} (${driverId})`);

      return res.status(201).json({
        success: true,
        message: 'Driver account created! Pending TODA verification.',
        token,
        driver: sanitizeDriver(driver),
      });

    } catch (error) {
      console.error('[Driver] Register error:', error.message);
      return res.status(500).json({ success: false, message: 'Registration failed. Try again.' });
    }
  }
);

// ── POST /api/driver/login ────────────────────────────────────────────────────
// Login: TODA body number + plate number + main account password
router.post('/login', [
  body('todaBodyNumber').trim().notEmpty().withMessage('TODA body number is required'),
  body('plateNo').trim().notEmpty().withMessage('Plate number is required'),
  body('password').notEmpty().withMessage('Password is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  const { todaBodyNumber, plateNo, password } = req.body;
  const ip = clientIp(req);

  // Normalize plate for comparison (strip spaces, lowercase)
  const normalizedPlate = plateNo.trim().toLowerCase().replace(/\s/g, '');

  try {
    // Find driver by TODA body number
    const driver = await dbGet(
      `SELECT d.*, t.plate_no AS tricycle_plate
       FROM drivers d
       LEFT JOIN tricycles t ON t.driver_id = d.driver_id
       WHERE d.toda_body_number = $1
         AND d.is_active IS NOT FALSE`,
      [todaBodyNumber.trim()]
    );

    // Validate plate matches (normalized comparison)
    const plateMatch = driver
      ? (driver.tricycle_plate || '').toLowerCase().replace(/\s/g, '') === normalizedPlate
      : false;

    // Always run bcrypt to prevent timing attacks
    const dummyHash = '$2b$12$dummyhashfortimingattackXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
    const dummySalt = 'a1b2c3d4e5f6a7b8c9d0e1f2';

    const passwordMatch = await verifyPassword(
      password,
      (driver && plateMatch) ? driver.password_hash : dummyHash,
      (driver && plateMatch) ? driver.salt          : dummySalt
    );

    if (!driver || !plateMatch || !passwordMatch) {
      await dbRun(
        `INSERT INTO login_attempts (user_type, email, ip_address, success)
         VALUES ('driver',$1,$2,false)`,
        [todaBodyNumber, ip]
      ).catch(() => {});

      return res.status(401).json({
        success: false,
        message: 'Invalid TODA body number, plate number, or password',
      });
    }

    await dbRun(
      `UPDATE drivers SET last_login = NOW() WHERE driver_id = $1`,
      [driver.driver_id]
    );
    await dbRun(
      `INSERT INTO login_attempts (user_type, email, ip_address, success)
       VALUES ('driver',$1,$2,true)`,
      [todaBodyNumber, ip]
    ).catch(() => {});

    const token = generateDriverToken(driver.driver_id);
    console.log(`[Driver] Login: ${driver.driver_name} from ${ip}`);

    return res.status(200).json({
      success: true,
      message: "Login successful! Welcome back, partner 👋",
      token,
      driver: sanitizeDriver(driver),
    });

  } catch (error) {
    console.error('[Driver] Login error:', error.message);
    return res.status(500).json({ success: false, message: 'Login failed. Try again.' });
  }
});

// ── GET /api/driver/me ────────────────────────────────────────────────────────
router.get('/me', requireDriverAuth, async (req, res) => {
  try {
    const driver = await dbGet(
      `SELECT d.*, t.plate_no, t.vehicle_color,
              ta.association_name, ta.association_code
       FROM drivers d
       LEFT JOIN tricycles t ON t.driver_id = d.driver_id
       LEFT JOIN toda_associations ta ON ta.toda_id = d.toda_id
       WHERE d.driver_id = $1 AND d.is_active IS NOT FALSE`,
      [req.driverId]
    );
    if (!driver) return res.status(404).json({ success: false, message: 'Driver not found' });
    return res.json({ success: true, driver: sanitizeDriver(driver) });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── PUT /api/driver/status ────────────────────────────────────────────────────
router.put('/status', requireDriverAuth, [
  body('status').isIn(['online', 'offline', 'on_trip']).withMessage('Invalid status'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    await dbRun(
      `UPDATE drivers SET status = $1, updated_at = NOW() WHERE driver_id = $2`,
      [req.body.status, req.driverId]
    );
    await dbRun(
      `UPDATE tricycles SET status = $1 WHERE driver_id = $2`,
      [req.body.status !== 'offline' ? 'active' : 'inactive', req.driverId]
    );
    return res.json({ success: true, message: `Status: ${req.body.status}` });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Failed to update status' });
  }
});

// ── POST /api/driver/logout ───────────────────────────────────────────────────
router.post('/logout', requireDriverAuth, async (req, res) => {
  await dbRun(
    `UPDATE drivers SET status = 'offline', updated_at = NOW() WHERE driver_id = $1`,
    [req.driverId]
  ).catch(() => {});
  return res.json({ success: true, message: 'Logged out successfully' });
});

// ── Driver Auth Middleware ─────────────────────────────────────────────────────
function requireDriverAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Authorization required' });
  }
  try {
    const payload = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET, {
      issuer: 'todago-api', audience: 'todago-app',
    });
    if (payload.role !== 'driver') {
      return res.status(403).json({ success: false, message: 'Driver access only' });
    }
    req.driverId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
}

module.exports = router;