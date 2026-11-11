const express = require('express');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const { createIssueReport } = require('../utils/adminReports');
const { dbGet, dbAll } = require('../db/database');

const router = express.Router();

function requireAnyAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Authorization required' });
  }

  try {
    const payload = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET, {
      issuer: 'todago-api',
      audience: 'todago-app',
    });
    req.actorId = payload.sub;
    req.actorRole = payload.role === 'commuter' ? 'passenger' : payload.role;
    if (!['passenger', 'driver', 'operator'].includes(req.actorRole)) {
      return res.status(403).json({ success: false, message: 'Unsupported reporter role' });
    }
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
}

async function actorName(role, id) {
  if (role === 'driver') {
    const row = await dbGet(
      `SELECT driver_name AS name FROM drivers WHERE driver_id = $1`,
      [id]
    );
    return row?.name || 'Driver';
  }
  if (role === 'operator') {
    const row = await dbGet(
      `SELECT contact_name AS name FROM operators WHERE operator_id = $1`,
      [id]
    );
    return row?.name || 'Operator';
  }
  const row = await dbGet(
    `SELECT full_name AS name FROM users WHERE id = $1`,
    [id]
  );
  return row?.name || 'Passenger';
}

router.post('/', requireAnyAuth, [
  body('reportType').trim().notEmpty().withMessage('Report type is required')
    .custom(value => !['driver_route_deviation', 'driver_outside_service_area'].includes(value))
    .withMessage('GPS alerts are generated automatically by the system.'),
  body('title').trim().isLength({ min: 3, max: 120 }).withMessage('Title must be 3 to 120 characters'),
  body('details').optional({ nullable: true }).trim().isLength({ max: 1200 }).withMessage('Details must be 1200 characters or less'),
  body('subjectRole').optional({ nullable: true }).isIn(['passenger','commuter','driver','operator','vehicle','trip','system']).withMessage('Invalid subject role'),
  body('subjectId').optional({ nullable: true }).trim().isLength({ max: 120 }),
  body('subjectName').optional({ nullable: true }).trim().isLength({ max: 160 }),
  body('tripId').optional({ nullable: true }).trim().isLength({ max: 120 }),
  body('priority').optional({ nullable: true }).isIn(['low','normal','high','urgent']).withMessage('Invalid priority'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  try {
    const reporterName = await actorName(req.actorRole, req.actorId);
    let subjectRole = req.body.subjectRole || null;
    let subjectId = req.body.subjectId || null;
    let subjectName = req.body.subjectName || null;
    const participantReporter = ['driver', 'passenger'].includes(req.actorRole);
    const accountIncident = req.actorRole === 'driver'
      ? ['passenger_issue', 'blacklist_passenger', 'fare_or_item_issue'].includes(req.body.reportType)
      : req.actorRole === 'passenger' &&
        ['wrong_driver_vehicle', 'driver_behavior', 'fare_or_baggage_fee'].includes(req.body.reportType);
    const accountSubject = ['driver', 'passenger', 'commuter'].includes(subjectRole);
    if (participantReporter && !req.body.tripId && (accountIncident || accountSubject || subjectId)) {
      return res.status(422).json({
        success: false,
        message: 'Select the trip for this report so admin can identify the passenger or driver.',
      });
    }
    if (req.body.tripId) {
      const trip = await dbGet(
        'SELECT commuter_id, driver_id FROM trips WHERE trip_id = $1',
        [req.body.tripId]
      );
      const isDriver = req.actorRole === 'driver' && trip?.driver_id === req.actorId;
      const isPassenger = req.actorRole === 'passenger' && trip?.commuter_id === req.actorId;
      if (['driver', 'passenger'].includes(req.actorRole)) {
        if (!isDriver && !isPassenger) {
          return res.status(403).json({ success: false, message: 'You can only report an incident on your own trip.' });
        }
        subjectRole = isDriver ? 'passenger' : 'driver';
        subjectId = isDriver ? trip.commuter_id : trip.driver_id;
        if (!subjectId) {
          return res.status(422).json({ success: false, message: 'This trip has no linked passenger or driver to report.' });
        }
        subjectName = await actorName(subjectRole, subjectId);
      }
    }
    const report = await createIssueReport({
      reporterRole: req.actorRole,
      reporterId: req.actorId,
      reporterName,
      reportType: req.body.reportType.trim(),
      subjectRole,
      subjectId,
      subjectName,
      tripId: req.body.tripId || null,
      title: req.body.title.trim(),
      details: req.body.details ? req.body.details.trim() : null,
      metadata: req.body.metadata && typeof req.body.metadata === 'object'
        ? req.body.metadata
        : {},
      priority: req.body.priority || 'normal',
    });

    return res.status(201).json({
      success: true,
      message: 'Report sent to admin for validation.',
      report,
    });
  } catch (error) {
    console.error('[Reports] Submit error:', error.message);
    return res.status(500).json({ success: false, message: 'Failed to submit report' });
  }
});

router.get('/mine', requireAnyAuth, async (req, res) => {
  try {
    const reports = await dbAll(
      `SELECT *
       FROM issue_reports
       WHERE reporter_role = $1
         AND reporter_id = $2
       ORDER BY created_at DESC
       LIMIT 50`,
      [req.actorRole, req.actorId]
    );
    return res.json({ success: true, reports });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

module.exports = router;
