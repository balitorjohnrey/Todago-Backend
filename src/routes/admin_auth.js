const express = require('express');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const { dbRun, dbGet, dbAll } = require('../db/database');
const { clampInt, getRoutePerformance } = require('../utils/routeAnalytics');

const router = express.Router();

function adminSecret() {
  return process.env.ADMIN_SECRET
    || process.env.ADMIN_LOGIN_SECRET
    || 'todago-admin-2026';
}

function generateAdminToken() {
  return jwt.sign({ sub: 'todago-admin', role: 'admin' }, process.env.JWT_SECRET, {
    expiresIn: process.env.ADMIN_JWT_EXPIRES_IN || '12h',
    issuer: 'todago-api',
    audience: 'todago-app',
  });
}

function requireAdminAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Admin authorization required' });
  }

  try {
    const payload = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET, {
      issuer: 'todago-api',
      audience: 'todago-app',
    });
    if (payload.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Admin access only' });
    }
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired admin token' });
  }
}

function sanitizeDriver(row) {
  if (!row) return row;
  const { password_hash, salt, ...safe } = row;
  return safe;
}

router.post('/login', [
  body('secret').trim().notEmpty().withMessage('Admin secret is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  if (req.body.secret !== adminSecret()) {
    return res.status(401).json({
      success: false,
      message: 'Invalid admin secret',
    });
  }

  return res.json({
    success: true,
    message: 'Admin login successful',
    token: generateAdminToken(),
    admin: {
      role: 'admin',
      name: process.env.ADMIN_DISPLAY_NAME || 'TodaGo Admin',
    },
  });
});

router.get('/stats', requireAdminAuth, async (req, res) => {
  try {
    const [pendingIndependent, approvedIndependent, pendingAssociated, operators] =
      await Promise.all([
        dbGet(
          `SELECT COUNT(*) FROM drivers
           WHERE toda_id IS NULL
             AND is_verified IS NOT TRUE
             AND is_active IS NOT FALSE`
        ),
        dbGet(
          `SELECT COUNT(*) FROM drivers
           WHERE toda_id IS NULL
             AND is_verified = true
             AND is_active IS NOT FALSE`
        ),
        dbGet(
          `SELECT COUNT(*) FROM drivers
           WHERE toda_id IS NOT NULL
             AND is_verified IS NOT TRUE
             AND is_active IS NOT FALSE`
        ),
        dbGet(
          `SELECT COUNT(*) FROM operators
           WHERE is_active IS NOT FALSE`
        ),
      ]);

    return res.json({
      success: true,
      stats: {
        pending_independent_drivers: parseInt(pendingIndependent.count, 10),
        approved_independent_drivers: parseInt(approvedIndependent.count, 10),
        pending_associated_drivers: parseInt(pendingAssociated.count, 10),
        operators: parseInt(operators.count, 10),
      },
    });
  } catch (error) {
    console.error('[Admin] Stats error:', error.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.get('/analytics/routes', requireAdminAuth, async (req, res) => {
  try {
    const days = clampInt(req.query.days, 30, 1, 365);
    const limit = clampInt(req.query.limit, 6, 1, 20);
    const routes = await getRoutePerformance({ days, limit });

    return res.json({
      success: true,
      range_days: days,
      routes,
    });
  } catch (error) {
    console.error('[Admin] Route analytics error:', error.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.get('/drivers/independent', requireAdminAuth, async (req, res) => {
  try {
    const drivers = await dbAll(
      `SELECT d.driver_id, d.driver_name, d.email, d.phone, d.license_no,
              d.toda_body_number, d.status, d.avg_rating, d.total_trips,
              d.is_verified, d.created_at, d.updated_at,
              CASE WHEN d.is_verified THEN 'approved' ELSE 'pending' END AS approval_status,
              t.plate_no, t.vehicle_color
       FROM drivers d
       LEFT JOIN tricycles t ON t.driver_id = d.driver_id
       WHERE d.toda_id IS NULL
         AND d.is_active IS NOT FALSE
       ORDER BY d.is_verified ASC, d.created_at DESC, d.driver_name ASC`
    );
    return res.json({
      success: true,
      total: drivers.length,
      drivers: drivers.map(sanitizeDriver),
    });
  } catch (error) {
    console.error('[Admin] Independent drivers error:', error.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.patch('/drivers/:driverId/verification', requireAdminAuth, [
  body('isVerified').isBoolean().withMessage('isVerified must be true or false'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  try {
    const driver = await dbGet(
      `SELECT driver_id, driver_name, toda_id
       FROM drivers
       WHERE driver_id = $1
         AND is_active IS NOT FALSE`,
      [req.params.driverId]
    );
    if (!driver) {
      return res.status(404).json({ success: false, message: 'Driver not found' });
    }
    if (driver.toda_id) {
      return res.status(403).json({
        success: false,
        message: 'Associated drivers must be approved by their TODA operator.',
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
              d.toda_body_number, d.status, d.avg_rating, d.total_trips,
              d.is_verified, d.created_at, d.updated_at,
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
        ? `${driver.driver_name} is approved as an independent driver.`
        : `${driver.driver_name} approval was revoked.`,
      driver: sanitizeDriver(updated),
    });
  } catch (error) {
    console.error('[Admin] Driver verification error:', error.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

module.exports = router;
