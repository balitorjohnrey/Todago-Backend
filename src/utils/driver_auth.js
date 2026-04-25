/**
 * Driver Authentication Routes
 * POST /api/driver/register  — Driver sign up
 * POST /api/driver/login     — Driver sign in (TODA body # + plate + password)
 * GET  /api/driver/me        — Get driver profile
 * PUT  /api/driver/status    — Update online/offline status
 */

const express = require('express');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { dbRun, dbGet } = require('../db/database');
const { generateSalt, hashPassword, verifyPassword, validatePasswordStrength } = require('../utils/password');

const router = express.Router();

// ─── Helpers ──────────────────────────────────────────────────────────────────
function generateToken(driverId) {
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
  return req.headers['x-forwarded-for']?.split(',')[0] || req.socket?.remoteAddress || 'unknown';
}

// ─── POST /api/driver/register ────────────────────────────────────────────────
router.post('/register', [
  body('driverName').trim().isLength({ min: 2, max: 100 }).withMessage('Full name must be 2–100 characters'),
  body('phone').trim().matches(/^[+\d\s\-()]{7,20}$/).withMessage('Enter a valid phone number'),
  body('licenseNo').trim().notEmpty().withMessage('License number is required'),
  body('todaBodyNumber').trim().notEmpty().withMessage('TODA body number is required'),
  body('password').isLength({ min: 8, max: 128 }).withMessage('Password must be 8–128 characters'),
  body('email').optional().trim().isEmail().normalizeEmail(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  const { driverName, phone, email, licenseNo, todaBodyNumber, vehicleColor,
          plateNo, todaId, password } = req.body;

  try {
    // Validate password strength
    const strengthErrors = validatePasswordStrength(password);
    if (strengthErrors.length > 0) {
      return res.status(400).json({ success: false, message: strengthErrors[0] });
    }

    // Check duplicates
    const checks = [
      { sql: 'SELECT driver_id FROM drivers WHERE phone = $1', val: [phone], msg: 'Phone number already registered' },
      { sql: 'SELECT driver_id FROM drivers WHERE license_no = $1', val: [licenseNo], msg: 'License number already registered' },
      { sql: 'SELECT driver_id FROM drivers WHERE toda_body_number = $1', val: [todaBodyNumber], msg: 'TODA body number already registered' },
    ];
    if (email) checks.push({
      sql: 'SELECT driver_id FROM drivers WHERE email = $1', val: [email], msg: 'Email already registered',
    });

    for (const check of checks) {
      const existing = await dbGet(check.sql, check.val);
      if (existing) return res.status(409).json({ success: false, message: check.msg });
    }

    // Hash password
    const salt = generateSalt();
    const passwordHash = await hashPassword(password, salt);
    const driverId = uuidv4();

    await dbRun(
      `INSERT INTO drivers
        (driver_id, toda_id, driver_name, email, phone, license_no,
         toda_body_number, password_hash, salt, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'offline')`,
      [driverId, todaId || null, driverName.trim(), email || null,
       phone.trim(), licenseNo.trim(), todaBodyNumber.trim(), passwordHash, salt]
    );

    // Create tricycle record if plate number provided
    if (plateNo) {
      await dbRun(
        `INSERT INTO tricycles (tricycle_id, driver_id, toda_id, plate_no, body_number, vehicle_color, status)
         VALUES ($1,$2,$3,$4,$5,$6,'inactive')
         ON CONFLICT (plate_no) DO NOTHING`,
        [uuidv4(), driverId, todaId || null, plateNo.trim(),
         todaBodyNumber.trim(), vehicleColor || null]
      ).catch(() => {}); // ignore if tricycle already exists
    }

    const driver = await dbGet('SELECT * FROM drivers WHERE driver_id = $1', [driverId]);
    const token = generateToken(driverId);

    console.log(`[Driver] Registered: ${driverName} (${driverId})`);

    return res.status(201).json({
      success: true,
      message: 'Driver account created successfully! Pending TODA verification.',
      token,
      driver: sanitizeDriver(driver),
    });

  } catch (error) {
    console.error('[Driver] Register error:', error.message);
    return res.status(500).json({ success: false, message: 'Registration failed. Please try again.' });
  }
});

// ─── POST /api/driver/login ───────────────────────────────────────────────────
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

  try {
    // Find driver by TODA body number
    const driver = await dbGet(
      `SELECT d.* FROM drivers d
       LEFT JOIN tricycles t ON t.driver_id = d.driver_id
       WHERE d.toda_body_number = $1 AND d.is_active = true`,
      [todaBodyNumber.trim()]
    );

    // Constant-time — always run bcrypt even if driver not found
    const dummyHash = '$2b$12$invalidhashfortimingattackprevention000000000000000000000';
    const dummySalt = 'dummy_salt_for_timing_attack_prevention_todago';
    const passwordMatch = await verifyPassword(
      password,
      driver ? driver.password_hash : dummyHash,
      driver ? driver.salt : dummySalt
    );

    if (!driver || !passwordMatch) {
      await dbRun(
        `INSERT INTO login_attempts (user_type, email, ip_address, success)
         VALUES ('driver', $1, $2, false)`,
        [todaBodyNumber, ip]
      );
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Update last login
    await dbRun(`UPDATE drivers SET last_login = NOW() WHERE driver_id = $1`, [driver.driver_id]);
    await dbRun(
      `INSERT INTO login_attempts (user_type, email, ip_address, success)
       VALUES ('driver', $1, $2, true)`,
      [todaBodyNumber, ip]
    );

    const token = generateToken(driver.driver_id);
    console.log(`[Driver] Login: ${driver.driver_name} from ${ip}`);

    return res.status(200).json({
      success: true,
      message: 'Login successful',
      token,
      driver: sanitizeDriver(driver),
    });

  } catch (error) {
    console.error('[Driver] Login error:', error.message);
    return res.status(500).json({ success: false, message: 'Login failed. Please try again.' });
  }
});

// ─── GET /api/driver/me ────────────────────────────────────────────────────────
router.get('/me', requireDriverAuth, async (req, res) => {
  try {
    const driver = await dbGet(
      `SELECT d.*, t.plate_no, t.vehicle_color, t.status AS tricycle_status,
              ta.association_name, ta.association_code
       FROM drivers d
       LEFT JOIN tricycles t ON t.driver_id = d.driver_id
       LEFT JOIN toda_associations ta ON ta.toda_id = d.toda_id
       WHERE d.driver_id = $1 AND d.is_active = true`,
      [req.driverId]
    );
    if (!driver) return res.status(404).json({ success: false, message: 'Driver not found' });
    return res.json({ success: true, driver: sanitizeDriver(driver) });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─── PUT /api/driver/status ────────────────────────────────────────────────────
router.put('/status', requireDriverAuth, [
  body('status').isIn(['online', 'offline', 'on_trip']).withMessage('Invalid status'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(422).json({ success: false, message: errors.array()[0].msg });
  try {
    await dbRun(
      `UPDATE drivers SET status = $1, updated_at = NOW() WHERE driver_id = $2`,
      [req.body.status, req.driverId]
    );
    // Also update tricycle status
    await dbRun(
      `UPDATE tricycles SET status = $1 WHERE driver_id = $2`,
      [req.body.status === 'online' || req.body.status === 'on_trip' ? 'active' : 'inactive', req.driverId]
    );
    return res.json({ success: true, message: `Status updated to ${req.body.status}` });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Failed to update status' });
  }
});

// ─── POST /api/driver/logout ───────────────────────────────────────────────────
router.post('/logout', requireDriverAuth, async (req, res) => {
  await dbRun(`UPDATE drivers SET status = 'offline', updated_at = NOW() WHERE driver_id = $1`, [req.driverId]);
  return res.json({ success: true, message: 'Logged out successfully' });
});

// ─── Middleware ────────────────────────────────────────────────────────────────
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