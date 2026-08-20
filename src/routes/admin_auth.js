const express = require('express');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const { dbRun, dbGet, dbAll } = require('../db/database');
const { clampInt, getRoutePerformance } = require('../utils/routeAnalytics');
const {
  clampInt: clampPeakInt,
  getPeakHourAnalysis,
} = require('../utils/peakHourAnalytics');

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
    const [pendingIndependent, approvedIndependent, pendingAssociated, operators, pendingReports, serviceAlerts] =
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
        dbGet(
          `SELECT COUNT(*) FROM issue_reports
           WHERE status = 'pending'`
        ).catch(() => ({ count: 0 })),
        dbGet(
          `SELECT COUNT(*) FROM issue_reports
           WHERE status = 'pending'
             AND report_type = 'driver_outside_service_area'`
        ).catch(() => ({ count: 0 })),
      ]);

    return res.json({
      success: true,
      stats: {
        pending_independent_drivers: parseInt(pendingIndependent.count, 10),
        approved_independent_drivers: parseInt(approvedIndependent.count, 10),
        pending_associated_drivers: parseInt(pendingAssociated.count, 10),
        operators: parseInt(operators.count, 10),
        pending_reports: parseInt(pendingReports.count, 10),
        service_area_alerts: parseInt(serviceAlerts.count, 10),
      },
    });
  } catch (error) {
    console.error('[Admin] Stats error:', error.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.get('/reports', requireAdminAuth, async (req, res) => {
  try {
    const status = String(req.query.status || 'pending').toLowerCase();
    const allowedStatuses = ['pending', 'validated', 'rejected', 'resolved', 'all'];
    const selectedStatus = allowedStatuses.includes(status) ? status : 'pending';
    const params = [];
    let where = '';
    if (selectedStatus !== 'all') {
      params.push(selectedStatus);
      where = 'WHERE ir.status = $1';
    }

    const reports = await dbAll(
      `SELECT ir.*
       FROM issue_reports ir
       ${where}
       ORDER BY
         CASE ir.priority
           WHEN 'urgent' THEN 1
           WHEN 'high' THEN 2
           WHEN 'normal' THEN 3
           ELSE 4
         END,
         ir.created_at DESC
       LIMIT 100`,
      params
    );

    return res.json({
      success: true,
      total: reports.length,
      reports,
    });
  } catch (error) {
    console.error('[Admin] Reports list error:', error.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.patch('/reports/:issueId/status', requireAdminAuth, [
  body('status')
    .isIn(['pending','validated','rejected','resolved'])
    .withMessage('Invalid report status'),
  body('adminNotes')
    .optional({ nullable: true })
    .isString()
    .trim()
    .isLength({ max: 800 })
    .withMessage('Admin notes must be 800 characters or less'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  try {
    const report = await dbGet(
      `SELECT *
       FROM issue_reports
       WHERE issue_id = $1`,
      [req.params.issueId]
    );
    if (!report) {
      return res.status(404).json({ success: false, message: 'Report not found' });
    }

    const status = req.body.status;
    const adminNotes = req.body.adminNotes ? req.body.adminNotes.trim() : null;
    await dbRun(
      `UPDATE issue_reports
       SET status = $1,
           admin_notes = $2,
           validated_at = CASE
             WHEN $1 IN ('validated','rejected','resolved') THEN NOW()
             ELSE validated_at
           END,
           updated_at = NOW()
       WHERE issue_id = $3`,
      [status, adminNotes, report.issue_id]
    );

    if (
      status === 'validated' &&
      report.report_type === 'blacklist_passenger' &&
      report.reporter_role === 'driver' &&
      ['passenger', 'commuter'].includes(report.subject_role) &&
      report.reporter_id &&
      report.subject_id
    ) {
      await dbRun(
        `INSERT INTO passenger_blacklist
          (passenger_id, driver_id, issue_id, reason, is_active)
         VALUES ($1,$2,$3,$4,true)
         ON CONFLICT DO NOTHING`,
        [
          report.subject_id,
          report.reporter_id,
          report.issue_id,
          report.details || report.title,
        ]
      ).catch(() => {});
    }

    const updated = await dbGet(
      `SELECT * FROM issue_reports WHERE issue_id = $1`,
      [report.issue_id]
    );

    return res.json({
      success: true,
      message: 'Report status updated.',
      report: updated,
    });
  } catch (error) {
    console.error('[Admin] Report status error:', error.message);
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

router.get('/analytics/peak-hours', requireAdminAuth, async (req, res) => {
  try {
    const days = clampPeakInt(req.query.days, 30, 1, 365);
    const limit = clampPeakInt(req.query.limit, 6, 1, 24);
    const hours = await getPeakHourAnalysis({ days, limit });

    return res.json({
      success: true,
      range_days: days,
      hours,
    });
  } catch (error) {
    console.error('[Admin] Peak hour analytics error:', error.message);
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
      `SELECT driver_id, driver_name, toda_id,
              identity_provider, identity_is_verified,
              identity_verification_status
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
    if (isVerified && driver.identity_provider === 'persona' && driver.identity_is_verified !== true) {
      return res.status(409).json({
        success: false,
        code: 'IDENTITY_VERIFICATION_REQUIRED',
        identity_status: driver.identity_verification_status || 'not_submitted',
        message: 'Persona identity verification must be approved before driver approval.',
      });
    }

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
