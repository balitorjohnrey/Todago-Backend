const express = require('express');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { dbRun, dbGet, dbAll } = require('../db/database');
const { clampInt, getRoutePerformance } = require('../utils/routeAnalytics');
const {
  clampInt: clampPeakInt,
  getPeakHourAnalysis,
} = require('../utils/peakHourAnalytics');

const router = express.Router();
const { reviewCashOut } = require('../services/driverWallet');
const EXTERNAL_KYC_PROVIDERS = new Set(['didit', 'persona']);

function isExternalKycProvider(provider) {
  return EXTERNAL_KYC_PROVIDERS.has(String(provider || '').trim().toLowerCase());
}

function adminSecret() {
  return process.env.ADMIN_SECRET
    || process.env.ADMIN_LOGIN_SECRET
    || 'todago-admin-2026';
}

function payoutSecret() { return (process.env.PAYOUT_ADMIN_SECRET || '').trim(); }
function payoutVersion() { return crypto.createHash('sha256').update(payoutSecret()).digest('hex').slice(0, 24); }

function generateAdminToken(role = 'admin') {
  return jwt.sign({ sub: role === 'payout_admin' ? 'todago-payout-admin' : 'todago-admin', role,
    ...(role === 'payout_admin' ? { payoutVersion: payoutVersion() } : {}) }, process.env.JWT_SECRET, {
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
    req.adminId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired admin token' });
  }
}

function requirePayoutAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ success: false, message: 'Payout admin login required.' });
  try {
    const payload = jwt.verify(auth.slice(7), process.env.JWT_SECRET, { issuer: 'todago-api', audience: 'todago-app' });
    if (payload.role !== 'payout_admin') return res.status(403).json({ success: false, message: 'Payout admin access only.' });
    if (!payoutSecret() || payoutSecret() === adminSecret() || payload.payoutVersion !== payoutVersion()) {
      return res.status(401).json({ success: false, message: 'Payout admin access changed. Sign in again.' });
    }
    req.adminId = payload.sub;
    next();
  } catch { return res.status(401).json({ success: false, message: 'Invalid or expired payout admin token.' }); }
}

router.get('/driver-cashouts', requirePayoutAdmin, async (req, res) => {
  try {
    const history = req.query.view === 'history';
    const requests = await dbAll(`SELECT co.*, d.driver_name FROM driver_cashouts co
      JOIN drivers d ON d.driver_id = co.driver_id
      WHERE ${history ? "co.status IN ('paid','rejected','cancelled')" : "co.status IN ('pending','processing')"}
      ORDER BY CASE co.status WHEN 'processing' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END,
        co.updated_at DESC LIMIT 100`);
    return res.json({ success: true, requests, payoutMode: 'manual', driverFee: 0 });
  } catch { return res.status(500).json({ success: false, message: 'Unable to load cash-outs.' }); }
});

router.post('/driver-cashouts/:cashoutId/review', requirePayoutAdmin, async (req, res) => {
  if (!/^[0-9a-f-]{36}$/i.test(req.params.cashoutId)) return res.status(422).json({ success: false, message: 'Invalid request.' });
  try { return res.json({ success: true, request: await reviewCashOut(req.params.cashoutId,
    { ...req.body, adminId: req.adminId }) }); }
  catch (error) { return res.status(error.statusCode || 500).json({ success: false,
    message: error.statusCode ? error.message : 'Unable to update cash-out. Refresh before retrying.' }); }
});

function sanitizeDriver(row) {
  if (!row) return row;
  const { password_hash, salt, ...safe } = row;
  return safe;
}

router.post('/login', rateLimit({ windowMs: 15 * 60 * 1000, limit: 20,
  standardHeaders: 'draft-7', legacyHeaders: false,
  message: { success: false, message: 'Too many admin login attempts. Try again later.' } }), [
  body('secret').trim().notEmpty().withMessage('Admin secret is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  const isPayoutAdmin = payoutSecret() && payoutSecret() !== adminSecret() && req.body.secret === payoutSecret();
  if (!isPayoutAdmin && req.body.secret !== adminSecret()) {
    return res.status(401).json({
      success: false,
      message: 'Invalid admin secret',
    });
  }

  return res.json({
    success: true,
    message: 'Admin login successful',
    token: generateAdminToken(isPayoutAdmin ? 'payout_admin' : 'admin'),
    admin: {
      role: isPayoutAdmin ? 'payout_admin' : 'admin',
      name: isPayoutAdmin ? 'TodaGo Payout Admin' : process.env.ADMIN_DISPLAY_NAME || 'TodaGo Admin',
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
    if (isVerified && isExternalKycProvider(driver.identity_provider) && driver.identity_is_verified !== true) {
      return res.status(409).json({
        success: false,
        code: 'IDENTITY_VERIFICATION_REQUIRED',
        identity_status: driver.identity_verification_status || 'not_submitted',
        message: 'KYC identity verification must be approved before driver approval.',
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
