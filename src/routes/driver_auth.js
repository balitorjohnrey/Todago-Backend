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
const { dbRun, dbGet, dbAll } = require('../db/database');
const { verifyPassword } = require('../utils/password');

// ── FIX: requireAuth is now properly exported from auth.js ────────────────────
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

function normalizeLicense(licenseNo) {
  return String(licenseNo || '').trim().toUpperCase().replace(/\s+/g, '');
}

function normalizePlate(plateNo) {
  return String(plateNo || '').trim().toLowerCase().replace(/\s/g, '');
}

function isValidLicenseNo(licenseNo) {
  const normalized = normalizeLicense(licenseNo);
  return normalized.length >= 5
    && normalized.length <= 32
    && /^[A-Z0-9-]+$/.test(normalized);
}

async function findTodaAssociation(identifier) {
  const value = String(identifier || '').trim();
  if (!value) return null;

  return dbGet(
    `SELECT toda_id, association_name, association_code, is_verified
     FROM toda_associations
     WHERE is_active IS NOT FALSE
       AND (
         toda_id = $1
         OR association_code = $1
         OR LOWER(association_code) = LOWER($1)
         OR LOWER(association_name) = LOWER($1)
       )
     LIMIT 1`,
    [value]
  );
}

function normalizeDriverType(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (['associated', 'with_association', 'with-association', 'with association'].includes(raw)) {
    return 'associated';
  }
  return 'independent';
}

function driverApprovalContext(driver) {
  const isAssociated = !!driver?.toda_id;
  return {
    requiredBy: isAssociated ? 'operator' : 'admin',
    message: isAssociated
      ? `Your account is pending operator approval${driver.association_name ? ` for ${driver.association_name}` : ''}. Please wait until your TODA association verifies your application.`
      : 'Your account is pending admin approval. Please wait until TodaGo verifies your license and independent driver application.',
  };
}

function clientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]
    || req.socket?.remoteAddress || 'unknown';
}

async function updateDriverAvailability(driverId, status) {
  await dbRun(
    `UPDATE drivers
     SET online_seconds_today = CASE
           WHEN online_seconds_date IS DISTINCT FROM CURRENT_DATE THEN 0
           ELSE COALESCE(online_seconds_today, 0)
         END,
         online_seconds_date = CURRENT_DATE,
         online_since = CASE
           WHEN online_since IS NOT NULL AND online_since::date < CURRENT_DATE
             THEN date_trunc('day', NOW())
           ELSE online_since
         END
     WHERE driver_id = $1`,
    [driverId]
  );

  await dbRun(
    `UPDATE drivers
     SET status = $1,
         updated_at = NOW(),
         online_seconds_today = CASE
           WHEN $1 = 'offline' AND online_since IS NOT NULL
             THEN online_seconds_today
                  + GREATEST(0, FLOOR(EXTRACT(EPOCH FROM NOW() - online_since)))::int
           ELSE online_seconds_today
         END,
         online_since = CASE
           WHEN $1 = 'offline' THEN NULL
           WHEN online_since IS NULL THEN NOW()
           ELSE online_since
         END
     WHERE driver_id = $2`,
    [status, driverId]
  );
}

// GET /api/driver/toda-associations
// Public list used by driver registration so applicants can choose a real
// operator-created TODA association instead of entering loose free text.
router.get('/toda-associations', async (req, res) => {
  try {
    const search = String(req.query.search || '').trim();
    const params = [];
    let where = 'WHERE is_active IS NOT FALSE';
    if (search) {
      params.push(`%${search}%`);
      where += ` AND (
        association_name ILIKE $1
        OR association_code ILIKE $1
        OR region ILIKE $1
      )`;
    }

    const associations = await dbAll(
      `SELECT toda_id, association_name, association_code, region,
              service_area, is_verified
       FROM toda_associations
       ${where}
       ORDER BY association_name ASC
       LIMIT 100`,
      params
    );
    return res.json({ success: true, total: associations.length, associations });
  } catch (error) {
    console.error('[Driver] TODA association list error:', error.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── POST /api/driver/register ─────────────────────────────────────────────────
// Requires main account JWT in Authorization header.
// Personal info (name, phone, email) is pulled from the users table automatically
// — the Flutter app does NOT need to send them; they're auto-filled from the token.
router.post('/register',
  requireAuth, // ← verifies main account token, sets req.userId
  [
    body('licenseNo')
      .trim()
      .notEmpty().withMessage('License number is required')
      .custom((value) => isValidLicenseNo(value))
      .withMessage('Enter a valid driver license number'),
    body('todaBodyNumber').trim().notEmpty().withMessage('Vehicle body number is required'),
    body('plateNo').trim().notEmpty().withMessage('Plate number is required'),
    body('vehicleColor').optional().trim(),
    body('driverType').optional().trim(),
    body('todaId').optional().trim(),
    body('todaAssociation').optional().trim(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ success: false, message: errors.array()[0].msg });
    }

    const {
      licenseNo,
      todaBodyNumber,
      plateNo,
      vehicleColor,
      driverType,
      todaId,
      todaAssociation,
    } = req.body;
    const normalizedLicenseNo = normalizeLicense(licenseNo);
    const normalizedPlateNo = normalizePlate(plateNo);
    const normalizedDriverType = normalizeDriverType(driverType);
    const associationIdentifier = String(todaId || todaAssociation || '').trim();

    try {
      if (normalizedDriverType === 'associated' && !associationIdentifier) {
        return res.status(422).json({
          success: false,
          message: 'TODA Association Name or Code is required for associated drivers.',
        });
      }

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

      let association = null;
      if (normalizedDriverType === 'associated') {
        association = await findTodaAssociation(associationIdentifier);
        if (!association) {
          return res.status(404).json({
            success: false,
            message: 'TODA association not found. Enter a registered association name or code.',
          });
        }
      }

      // Duplicate checks for vehicle details
      const checks = [
        ['SELECT driver_id FROM drivers WHERE license_no = $1',
         [normalizedLicenseNo], 'License number already registered'],
        ['SELECT driver_id FROM drivers WHERE toda_body_number = $1',
         [todaBodyNumber], 'TODA body number already registered'],
        ['SELECT tricycle_id FROM tricycles WHERE plate_no = $1',
         [normalizedPlateNo],
         'Plate number already registered'],
      ];
      for (const [sql, params, msg] of checks) {
        if (await dbGet(sql, params)) {
          return res.status(409).json({ success: false, message: msg });
        }
      }

      const driverId = uuidv4();

      // Insert driver — personal info and password come from the main users record
      await dbRun(
        `INSERT INTO drivers
          (driver_id, user_id, toda_id, toda_branch_name, driver_name, email, phone,
           license_no, toda_body_number, password_hash, salt, status, is_verified)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'offline',$12)`,
        [
          driverId,
          mainUser.id,
          association?.toda_id || null,
          association?.association_name || null,
          mainUser.full_name,
          mainUser.email,
          mainUser.phone,
          normalizedLicenseNo,
          todaBodyNumber.trim(),
          mainUser.password_hash,
          mainUser.salt,
          false,
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
          association?.toda_id || null,
          normalizedPlateNo,
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

      console.log(`[Driver] Registered: ${mainUser.full_name} (${driverId})`);

      return res.status(201).json({
        success: true,
        message: association
          ? `Driver registration submitted to ${association.association_name}. Operator approval is required before you can log in.`
          : 'Independent driver registration submitted. Admin approval is required before you can log in.',
        token: null,
        approval_status: 'pending',
        requires_admin_approval: !association,
        requires_operator_approval: !!association,
        driver: sanitizeDriver(driver),
      });

    } catch (error) {
      console.error('[Driver] Register error:', error.message);
      return res.status(500).json({ success: false, message: 'Registration failed. Try again.' });
    }
  }
);

// ── POST /api/driver/login ────────────────────────────────────────────────────
// Login:
// - Independent drivers use license number + password.
// - Associated drivers use TODA Association Name/Code + license number + password.
// Legacy body-number + plate-number login remains accepted for older app builds.
router.post('/login', [
  body('driverType').optional().trim(),
  body('licenseNo').optional().trim(),
  body('todaAssociation').optional().trim(),
  body('todaBodyNumber').optional().trim(),
  body('plateNo').optional().trim(),
  body('password').notEmpty().withMessage('Password is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  const {
    driverType,
    licenseNo,
    todaAssociation,
    todaBodyNumber,
    plateNo,
    password,
  } = req.body;
  const ip = clientIp(req);
  const normalizedDriverType = normalizeDriverType(driverType);
  const normalizedLicenseNo = normalizeLicense(licenseNo);
  const associationIdentifier = String(todaAssociation || '').trim();
  const usingLicenseLogin = normalizedLicenseNo.isNotEmpty;
  const normalizedPlate = normalizePlate(plateNo);

  if (!usingLicenseLogin && (!todaBodyNumber || !plateNo)) {
    return res.status(422).json({
      success: false,
      message: 'License number is required. Older logins may use body number and plate number.',
    });
  }
  if (usingLicenseLogin && normalizedDriverType === 'associated' && !associationIdentifier) {
    return res.status(422).json({
      success: false,
      message: 'TODA Association Name or Code is required for associated driver login.',
    });
  }

  try {
    let association = null;
    if (usingLicenseLogin && normalizedDriverType === 'associated') {
      association = await findTodaAssociation(associationIdentifier);
      if (!association) {
        await dbRun(
          `INSERT INTO login_attempts (user_type, email, ip_address, success)
           VALUES ('driver',$1,$2,false)`,
          [associationIdentifier, ip]
        ).catch(() => {});

        return res.status(401).json({
          success: false,
          message: 'Invalid TODA Association Name or Code, license number, or password',
        });
      }
    }

    const driver = usingLicenseLogin
      ? await dbGet(
        `SELECT d.*, t.plate_no AS tricycle_plate,
                ta.association_name, ta.association_code
         FROM drivers d
         LEFT JOIN tricycles t ON t.driver_id = d.driver_id
         LEFT JOIN toda_associations ta ON ta.toda_id = d.toda_id
         WHERE d.license_no = $1
           AND d.is_active IS NOT FALSE
           AND (
             ($2::text = 'independent' AND d.toda_id IS NULL)
             OR ($2::text = 'associated' AND d.toda_id = $3)
           )
         LIMIT 1`,
        [
          normalizedLicenseNo,
          normalizedDriverType,
          association?.toda_id || null,
        ]
      )
      : await dbGet(
        `SELECT d.*, t.plate_no AS tricycle_plate,
                ta.association_name, ta.association_code
         FROM drivers d
         LEFT JOIN tricycles t ON t.driver_id = d.driver_id
         LEFT JOIN toda_associations ta ON ta.toda_id = d.toda_id
         WHERE d.toda_body_number = $1
           AND d.is_active IS NOT FALSE`,
        [todaBodyNumber.trim()]
      );

    const plateMatch = usingLicenseLogin || (driver
      ? (driver.tricycle_plate || '').toLowerCase().replace(/\s/g, '') === normalizedPlate
      : false);

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
        [usingLicenseLogin ? normalizedLicenseNo : todaBodyNumber, ip]
      ).catch(() => {});

      return res.status(401).json({
        success: false,
        message: usingLicenseLogin
          ? 'Invalid driver login details or password'
          : 'Invalid TODA body number, plate number, or password',
      });
    }

    if (driver.is_verified !== true) {
      const approval = driverApprovalContext(driver);
      await dbRun(
        `INSERT INTO login_attempts (user_type, email, ip_address, success)
         VALUES ('driver',$1,$2,false)`,
        [usingLicenseLogin ? normalizedLicenseNo : todaBodyNumber, ip]
      ).catch(() => {});

      return res.status(403).json({
        success: false,
        code: 'DRIVER_NOT_VERIFIED',
        verification_required: true,
        approval_required_by: approval.requiredBy,
        message: approval.message,
      });
    }

    await dbRun(
      `UPDATE drivers SET last_login = NOW() WHERE driver_id = $1`,
      [driver.driver_id]
    );
    await dbRun(
      `INSERT INTO login_attempts (user_type, email, ip_address, success)
       VALUES ('driver',$1,$2,true)`,
      [usingLicenseLogin ? normalizedLicenseNo : todaBodyNumber, ip]
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

// ── GET /api/driver/stats/today ───────────────────────────────────────────────
router.get('/stats/today', requireDriverAuth, async (req, res) => {
  try {
    const stats = await dbGet(
      `SELECT d.status,
              d.avg_rating,
              d.total_trips,
              (
                CASE
                  WHEN d.online_seconds_date = CURRENT_DATE
                    THEN COALESCE(d.online_seconds_today, 0)
                  ELSE 0
                END
                + CASE
                    WHEN d.status IN ('online','on_trip') AND d.online_since IS NOT NULL
                      THEN GREATEST(
                        0,
                        FLOOR(EXTRACT(EPOCH FROM NOW() - GREATEST(d.online_since, date_trunc('day', NOW()))))::int
                      )
                    ELSE 0
                  END
              ) AS online_seconds_today,
              COALESCE(today.trips_today, 0)::int AS trips_today,
              COALESCE(today.earnings_today, 0)::float AS earnings_today
       FROM drivers d
       LEFT JOIN (
         SELECT tr.driver_id,
                COUNT(*) FILTER (
                  WHERE tr.status = 'completed'
                    AND tr.end_timestamp::date = CURRENT_DATE
                ) AS trips_today,
                SUM(
                  CASE
                    WHEN tr.status = 'completed'
                     AND tr.end_timestamp::date = CURRENT_DATE
                      THEN COALESCE(tr.fare, 0)
                    ELSE 0
                  END
                ) AS earnings_today
         FROM trips tr
         WHERE tr.driver_id = $1
         GROUP BY tr.driver_id
       ) today ON today.driver_id = d.driver_id
       WHERE d.driver_id = $1 AND d.is_active IS NOT FALSE`,
      [req.driverId]
    );
    if (!stats) return res.status(404).json({ success: false, message: 'Driver not found' });
    return res.json({ success: true, stats });
  } catch (error) {
    console.error('[Driver] Today stats error:', error.message);
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
    if (req.body.status !== 'offline') {
      const driver = await dbGet(
        `SELECT d.toda_id, d.is_verified, ta.association_name
         FROM drivers d
         LEFT JOIN toda_associations ta ON ta.toda_id = d.toda_id
         WHERE d.driver_id = $1 AND d.is_active IS NOT FALSE`,
        [req.driverId]
      );
      if (!driver) {
        return res.status(404).json({ success: false, message: 'Driver not found' });
      }
      if (driver.is_verified !== true) {
        const approval = driverApprovalContext(driver);
        return res.status(403).json({
          success: false,
          code: 'DRIVER_NOT_VERIFIED',
          approval_required_by: approval.requiredBy,
          message: approval.message,
        });
      }
    }

    await updateDriverAvailability(req.driverId, req.body.status);
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
  await updateDriverAvailability(req.driverId, 'offline').catch(() => {});
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
