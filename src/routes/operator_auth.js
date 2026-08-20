/**
 * Operator Auth Routes
 *
 * Operator registration is separate from passenger accounts. An operator signs
 * up with association details, contact details, password, valid ID proof, and
 * a face verification image.
 *
 * LOGIN: The WHERE clause matches against association_name
 *   (case-insensitive), so users can enter either the short association code
 *   OR the full association name (e.g. "Panabo City TODA") in the login field.
 */
const express = require('express');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { dbRun, dbGet, dbAll } = require('../db/database');
const { clampInt, getRoutePerformance } = require('../utils/routeAnalytics');
const {
  clampInt: clampPeakInt,
  getPeakHourAnalysis,
} = require('../utils/peakHourAnalytics');
const {
  generateSalt,
  hashPassword,
  verifyPasswordDetailed,
  validatePasswordStrength,
} = require('../utils/password');
const {
  pickIdentityPayload,
  validateIdentityPayload,
} = require('../utils/identityVerification');

const router = express.Router();

function generateOperatorToken(operatorId) {
  return jwt.sign({ sub: operatorId, role: 'operator' }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
    issuer: 'todago-api',
    audience: 'todago-app',
  });
}

function sanitizeOperator(op) {
  const {
    password_hash,
    salt,
    valid_id_number,
    valid_id_image_url,
    face_verification_image_url,
    ...safe
  } = op;
  return safe;
}

function clientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]
    || req.socket?.remoteAddress || 'unknown';
}

// ── POST /api/operator/register ───────────────────────────────────────────────
// Separate operator signup. Requires association details, contact details,
// password, valid ID proof, and a face verification image.
router.post('/register',
  [
    body('associationName').trim().isLength({ min: 2 })
      .withMessage('Association name is required'),
    body('associationCode').trim().notEmpty()
      .withMessage('Association code is required'),
    body('ltfrbNumber').trim().notEmpty()
      .withMessage('LTFRB franchise number is required'),
    body('region').trim().notEmpty()
      .withMessage('Region/city is required'),
    body('contactName').trim().isLength({ min: 2, max: 100 })
      .withMessage('Contact person name must be 2–100 characters'),
    body('email').trim().isEmail().normalizeEmail()
      .withMessage('Enter a valid email address'),
    body('phone').trim().matches(/^[+\d\s\-()]{7,20}$/)
      .withMessage('Enter a valid phone number'),
    body('password').isLength({ min: 8, max: 128 })
      .withMessage('Password must be 8–128 characters'),
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
      region, contactName, email, phone, password,
      serviceArea, totalTricycles,
    } = req.body;
    const identityError = validateIdentityPayload(req.body);
    if (identityError) {
      return res.status(422).json({ success: false, message: identityError });
    }
    const identity = pickIdentityPayload(req.body);

    try {
      const strengthErrors = validatePasswordStrength(password);
      if (strengthErrors.length > 0) {
        return res.status(400).json({ success: false, message: strengthErrors[0] });
      }

      // Duplicate checks for association details
      const checks = [
        ['SELECT operator_id FROM operators WHERE email = $1',
         [email.toLowerCase()], 'An operator account with this email already exists'],
        ['SELECT operator_id FROM operators WHERE phone = $1',
         [phone.trim()], 'An operator account with this phone number already exists'],
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

      const salt = generateSalt();
      const passwordHash = await hashPassword(password, salt);

      const operatorId = uuidv4();
      await dbRun(
        `INSERT INTO operators
          (operator_id, user_id, toda_id, contact_name, email, phone,
           password_hash, salt, toda_body_id, valid_id_type, valid_id_number,
           valid_id_image_url, face_verification_image_url,
           identity_verification_status, identity_submitted_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'submitted',NOW())`,
        [
          operatorId,
          null,
          todaId,
          contactName.trim(),
          email.toLowerCase(),
          phone.trim(),
          passwordHash,
          salt,
          associationCode.trim(),
          identity.validIdType,
          identity.validIdNumber,
          identity.validIdImageUrl,
          identity.faceImageUrl,
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

      console.log(`[Operator] Registered: ${associationName} — ${email}`);

      return res.status(201).json({
        success: true,
        message: 'Operator account created! Pending LTFRB verification.',
        token: null,
        operator: sanitizeOperator(operator),
      });

    } catch (error) {
      console.error('[Operator] Register error:', error.message);
      return res.status(500).json({ success: false, message: 'Registration failed. Try again.' });
    }
  }
);

// ── POST /api/operator/login ──────────────────────────────────────────────────
// Login: TODA Association ID (full name OR code) + email + operator password
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

    const dummyHash = '$2b$12$rv45F04fsLv5.gOAt41RRevnVbwwjYIGP28gnv4G7tRNQz5TjQ7pC';
    const dummySalt = 'a1b2c3d4e5f6a7b8c9d0e1f2';

    let passwordMatch = false;
    let passwordResetRequired = false;

    if (operator) {
      const passwordResult = await verifyPasswordDetailed(password, operator.password_hash, operator.salt);
      passwordMatch = passwordResult.match;
      passwordResetRequired = passwordResult.resetRequired;

      if (passwordResult.legacy && passwordResult.match) {
        const newSalt = generateSalt();
        const newHash = await hashPassword(password, newSalt);

        await dbRun(
          'UPDATE operators SET password_hash = $1, salt = $2, updated_at = NOW() WHERE operator_id = $3',
          [newHash, newSalt, operator.operator_id]
        );

        operator.password_hash = newHash;
        operator.salt = newSalt;
        console.log(`[Operator] Migrated legacy password hash for ${operator.operator_id}`);
      } else if (passwordResult.resetRequired) {
        console.log(`[Operator] Password reset required for legacy hash: ${operator.operator_id}`);
      }
    } else {
      await verifyPasswordDetailed(password, `v2:${dummyHash}`, dummySalt);
    }

    if (!operator || !passwordMatch) {
      await dbRun(
        `INSERT INTO login_attempts (user_type, email, ip_address, success)
         VALUES ('operator',$1,$2,false)`,
        [email, ip]
      ).catch(() => {});

      if (passwordResetRequired) {
        return res.status(409).json({
          success: false,
          code: 'PASSWORD_RESET_REQUIRED',
          message: 'This older operator account needs a password reset before login.',
        });
      }

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
              CASE WHEN d.is_verified THEN 'approved' ELSE 'pending' END AS approval_status,
              t.plate_no, t.vehicle_color
       FROM drivers d
       LEFT JOIN tricycles t ON t.driver_id = d.driver_id
       WHERE d.toda_id = $1 AND d.is_active IS NOT FALSE
       ORDER BY d.is_verified ASC, d.created_at DESC, d.driver_name`,
      [op.toda_id]
    );
    return res.json({ success: true, total: drivers.length, drivers });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// GET /api/operator/fleet
// Real fleet data for the operator map. Coordinates come from the latest GPS
// record or the latest active trip location reported by the driver app.
router.get('/fleet', requireOperatorAuth, async (req, res) => {
  try {
    const op = await dbGet(
      `SELECT toda_id FROM operators WHERE operator_id = $1`,
      [req.operatorId]
    );
    if (!op) return res.status(404).json({ success: false, message: 'Operator not found' });

    const drivers = await dbAll(
      `SELECT d.driver_id, d.driver_name, d.toda_body_number,
              d.status, d.is_verified, d.avg_rating, d.total_trips,
              t.plate_no, t.vehicle_color,
              COALESCE(gps.latitude, last_trip.driver_lat) AS driver_lat,
              COALESCE(gps.longitude, last_trip.driver_lng) AS driver_lng,
              COALESCE(gps.timestamp, last_trip.driver_location_updated_at) AS location_updated_at
       FROM drivers d
       LEFT JOIN tricycles t ON t.driver_id = d.driver_id
       LEFT JOIN LATERAL (
         SELECT latitude, longitude, timestamp
         FROM gps_locations
         WHERE tricycle_id = t.tricycle_id
         ORDER BY timestamp DESC
         LIMIT 1
       ) gps ON true
       LEFT JOIN LATERAL (
         SELECT driver_lat, driver_lng, driver_location_updated_at
         FROM trips
         WHERE driver_id = d.driver_id
           AND driver_lat IS NOT NULL
           AND driver_lng IS NOT NULL
         ORDER BY driver_location_updated_at DESC NULLS LAST,
                  request_timestamp DESC
         LIMIT 1
       ) last_trip ON true
       WHERE d.toda_id = $1
         AND d.is_active IS NOT FALSE
       ORDER BY d.status = 'online' DESC,
                d.status = 'on_trip' DESC,
                d.driver_name ASC`,
      [op.toda_id]
    );

    return res.json({ success: true, total: drivers.length, drivers });
  } catch (error) {
    console.error('[Operator] Fleet error:', error.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// PATCH /api/operator/drivers/:driverId/verification
// Accept or revoke a driver's membership in this operator's TODA association.
router.patch('/drivers/:driverId/verification', requireOperatorAuth, [
  body('isVerified').isBoolean().withMessage('isVerified must be true or false'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  try {
    const op = await dbGet(
      `SELECT toda_id FROM operators WHERE operator_id = $1`,
      [req.operatorId]
    );
    if (!op) return res.status(404).json({ success: false, message: 'Operator not found' });

    const driver = await dbGet(
      `SELECT driver_id, driver_name
       FROM drivers
       WHERE driver_id = $1
         AND toda_id = $2
         AND is_active IS NOT FALSE`,
      [req.params.driverId, op.toda_id]
    );
    if (!driver) {
      return res.status(404).json({
        success: false,
        message: 'Driver not found in your TODA association',
      });
    }

    const isVerified = req.body.isVerified === true || req.body.isVerified === 'true';
    await dbRun(
      `UPDATE drivers
       SET is_verified = $1,
           status = CASE
             WHEN $1 = false AND status <> 'offline' THEN 'offline'
             ELSE status
           END,
           updated_at = NOW()
       WHERE driver_id = $2`,
      [isVerified, req.params.driverId]
    );

    if (!isVerified) {
      await dbRun(
        `UPDATE tricycles SET status = 'inactive' WHERE driver_id = $1`,
        [req.params.driverId]
      ).catch(() => {});
    }

    const updated = await dbGet(
      `SELECT d.driver_id, d.driver_name, d.email, d.phone, d.license_no,
              d.toda_body_number, d.status, d.avg_rating,
              d.total_trips, d.is_verified, d.created_at,
              'associated' AS application_type,
              CASE WHEN d.is_verified THEN 'approved' ELSE 'pending' END AS approval_status,
              t.plate_no, t.vehicle_color
       FROM drivers d
       LEFT JOIN tricycles t ON t.driver_id = d.driver_id
       WHERE d.driver_id = $1`,
      [req.params.driverId]
    );

    return res.json({
      success: true,
      message: isVerified
        ? `${driver.driver_name} is approved for your TODA association.`
        : `${driver.driver_name} membership approval was revoked.`,
      driver: updated,
    });
  } catch (error) {
    console.error('[Operator] Driver verification error:', error.message);
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
    const [active, offline, total, pending, trips, rev, rating] = await Promise.all([
      dbGet(
        `SELECT COUNT(*) FROM drivers
         WHERE toda_id = $1
           AND status IN ('online','on_trip')
           AND is_verified = true
           AND is_active IS NOT FALSE`,
        [todaId]
      ),
      dbGet(
        `SELECT COUNT(*) FROM drivers
         WHERE toda_id = $1
           AND status = 'offline'
           AND is_verified = true
           AND is_active IS NOT FALSE`,
        [todaId]
      ),
      dbGet(
        `SELECT COUNT(*) FROM drivers
         WHERE toda_id = $1 AND is_active IS NOT FALSE`,
        [todaId]
      ),
      dbGet(
        `SELECT COUNT(*) FROM drivers
         WHERE toda_id = $1
           AND is_verified IS NOT TRUE
           AND is_active IS NOT FALSE`,
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
      dbGet(
        `SELECT COALESCE(AVG(NULLIF(avg_rating, 0)), 0) AS avg_rating
         FROM drivers
         WHERE toda_id = $1
           AND is_verified = true
           AND is_active IS NOT FALSE`,
        [todaId]
      ),
    ]);

    return res.json({
      success: true,
      stats: {
        active_drivers: parseInt(active.count, 10),
        offline_drivers: parseInt(offline.count, 10),
        total_drivers: parseInt(total.count, 10),
        pending_drivers: parseInt(pending.count, 10),
        trips_today: parseInt(trips.count, 10),
        gross_revenue: parseFloat(rev.total),
        avg_rating: parseFloat(rating.avg_rating),
      },
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.get('/analytics/routes', requireOperatorAuth, async (req, res) => {
  try {
    const op = await dbGet(
      `SELECT toda_id FROM operators WHERE operator_id = $1`,
      [req.operatorId]
    );
    if (!op) return res.status(404).json({ success: false, message: 'Operator not found' });

    const days = clampInt(req.query.days, 30, 1, 365);
    const limit = clampInt(req.query.limit, 6, 1, 20);
    const routes = await getRoutePerformance({
      todaId: op.toda_id,
      days,
      limit,
    });

    return res.json({
      success: true,
      range_days: days,
      routes,
    });
  } catch (error) {
    console.error('[Operator] Route analytics error:', error.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.get('/analytics/peak-hours', requireOperatorAuth, async (req, res) => {
  try {
    const op = await dbGet(
      `SELECT toda_id FROM operators WHERE operator_id = $1`,
      [req.operatorId]
    );
    if (!op) return res.status(404).json({ success: false, message: 'Operator not found' });

    const days = clampPeakInt(req.query.days, 30, 1, 365);
    const limit = clampPeakInt(req.query.limit, 6, 1, 24);
    const hours = await getPeakHourAnalysis({
      todaId: op.toda_id,
      days,
      limit,
    });

    return res.json({
      success: true,
      range_days: days,
      hours,
    });
  } catch (error) {
    console.error('[Operator] Peak hour analytics error:', error.message);
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
