/**
 * Trip & Driver Discovery Routes
 * GET  /api/trips/drivers/online     — Passenger: find available online drivers
 * POST /api/trips/request            — Passenger: request a ride
 * PUT  /api/trips/:tripId/accept     — Driver: accept a trip
 * PUT  /api/trips/:tripId/decline    — Driver: decline a trip
 * PUT  /api/trips/:tripId/status     — Driver: update trip status
 * GET  /api/trips/driver/active      — Driver: get current active trip
 * GET  /api/trips/commuter/history   — Passenger: trip history
 * GET  /api/trips/driver/history     — Driver: trip history
 */
const express = require('express');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { dbRun, dbGet, dbAll } = require('../db/database');

const router = express.Router();

// ── Auth middleware (any role) ────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Authorization required' });
  }
  try {
    const payload = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET, {
      issuer: 'todago-api', audience: 'todago-app',
    });
    req.userId   = payload.sub;
    req.userRole = payload.role;
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
}

// ── GET /api/trips/drivers/online ─────────────────────────────────────────────
// Passenger sees ONLY online drivers with real names from commuter account
router.get('/drivers/online', requireAuth, async (req, res) => {
  try {
    const { serviceType } = req.query; // optional filter: solo|shared|express

    // Join drivers with commuters to get real name, and tricycles for plate info
    const drivers = await dbAll(
      `SELECT
         d.driver_id,
         COALESCE(c.full_name, d.driver_name) AS driver_name,
         d.toda_body_number,
         d.avg_rating,
         d.total_trips,
         d.status,
         d.phone,
         t.plate_no,
         t.vehicle_color,
         ta.association_name,
         ta.association_code,
         -- Simulated distance (replace with real GPS calculation in production)
         ROUND((RANDOM() * 4 + 0.5)::numeric, 1) AS distance_km,
         ROUND((RANDOM() * 8 + 1)::numeric, 0)   AS eta_minutes
       FROM drivers d
       LEFT JOIN commuters c
              ON c.phone_no = d.phone AND c.is_active = true
       LEFT JOIN tricycles t ON t.driver_id = d.driver_id
       LEFT JOIN toda_associations ta ON ta.toda_id = d.toda_id
       WHERE d.status = 'online'
         AND d.is_active = true
       ORDER BY d.avg_rating DESC`,
      []
    );

    return res.json({
      success: true,
      total: drivers.length,
      drivers,
    });
  } catch (err) {
    console.error('[Trips] Online drivers error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── POST /api/trips/request ───────────────────────────────────────────────────
// Passenger requests a ride from a specific driver
router.post('/request', requireAuth, [
  body('driverId').notEmpty().withMessage('Driver ID is required'),
  body('pickupLocation').notEmpty().withMessage('Pickup location is required'),
  body('destination').notEmpty().withMessage('Destination is required'),
  body('serviceType').isIn(['solo','shared','express']).withMessage('Invalid service type'),
  body('fare').isNumeric().withMessage('Fare must be a number'),
  body('paymentMethod').isIn(['cash','gcash','maya','wallet'])
    .withMessage('Invalid payment method'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }
  if (req.userRole !== 'commuter' && req.userRole !== 'passenger') {
    return res.status(403).json({ success: false, message: 'Passenger access only' });
  }

  const { driverId, pickupLocation, destination,
          serviceType, fare, paymentMethod } = req.body;

  try {
    // Verify driver is still online
    const driver = await dbGet(
      `SELECT d.driver_id, d.status, d.toda_body_number,
              COALESCE(c.full_name, d.driver_name) AS driver_name,
              t.plate_no, t.tricycle_id
       FROM drivers d
       LEFT JOIN commuters c ON c.phone_no = d.phone
       LEFT JOIN tricycles t ON t.driver_id = d.driver_id
       WHERE d.driver_id = $1 AND d.is_active = true`,
      [driverId]
    );

    if (!driver) {
      return res.status(404).json({ success: false, message: 'Driver not found' });
    }
    if (driver.status !== 'online') {
      return res.status(400).json({
        success: false,
        message: 'Driver is no longer available. Please choose another driver.',
      });
    }

    // Get commuter info
    const commuter = await dbGet(
      `SELECT commuter_id, full_name, phone_no FROM commuters WHERE commuter_id = $1`,
      [req.userId]
    );

    // Create trip
    const tripId = uuidv4();
    await dbRun(
      `INSERT INTO trips
        (trip_id, commuter_id, tricycle_id, driver_id,
         service_type, pickup_location, destination,
         fare, payment_method, status, request_timestamp)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'requested',NOW())`,
      [tripId, req.userId, driver.tricycle_id, driverId,
       serviceType, pickupLocation, destination,
       parseFloat(fare), paymentMethod]
    );

    // Set driver status to on_trip (pending acceptance)
    await dbRun(
      `UPDATE drivers SET status = 'on_trip', updated_at = NOW() WHERE driver_id = $1`,
      [driverId]
    );

    const trip = await dbGet(`SELECT * FROM trips WHERE trip_id = $1`, [tripId]);

    return res.status(201).json({
      success: true,
      message: 'Ride requested successfully!',
      trip: {
        ...trip,
        driver_name: driver.driver_name,
        plate_no: driver.plate_no,
        toda_body_number: driver.toda_body_number,
        commuter_name: commuter?.full_name,
      },
    });
  } catch (err) {
    console.error('[Trips] Request error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to request ride' });
  }
});

// ── GET /api/trips/driver/pending ─────────────────────────────────────────────
// Driver polls for incoming trip requests
router.get('/driver/pending', requireAuth, async (req, res) => {
  if (req.userRole !== 'driver') {
    return res.status(403).json({ success: false, message: 'Driver access only' });
  }
  try {
    const trip = await dbGet(
      `SELECT tr.*,
              COALESCE(c.full_name, 'Passenger') AS commuter_name,
              c.phone_no AS commuter_phone,
              (SELECT AVG(f.rating_score)
               FROM feedback f
               WHERE f.commuter_id = tr.commuter_id) AS commuter_rating
       FROM trips tr
       LEFT JOIN commuters c ON c.commuter_id = tr.commuter_id
       WHERE tr.driver_id = $1
         AND tr.status = 'requested'
       ORDER BY tr.request_timestamp DESC
       LIMIT 1`,
      [req.userId]
    );
    return res.json({ success: true, trip: trip || null, hasPendingTrip: !!trip });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── PUT /api/trips/:tripId/accept ─────────────────────────────────────────────
router.put('/:tripId/accept', requireAuth, async (req, res) => {
  if (req.userRole !== 'driver') {
    return res.status(403).json({ success: false, message: 'Driver access only' });
  }
  try {
    const trip = await dbGet(
      `SELECT * FROM trips WHERE trip_id = $1 AND driver_id = $2 AND status = 'requested'`,
      [req.params.tripId, req.userId]
    );
    if (!trip) {
      return res.status(404).json({ success: false, message: 'Trip not found or already handled' });
    }
    await dbRun(
      `UPDATE trips SET status = 'accepted', pickup_timestamp = NOW() WHERE trip_id = $1`,
      [req.params.tripId]
    );
    return res.json({ success: true, message: 'Trip accepted! Navigate to pickup.' });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── PUT /api/trips/:tripId/decline ────────────────────────────────────────────
router.put('/:tripId/decline', requireAuth, async (req, res) => {
  if (req.userRole !== 'driver') {
    return res.status(403).json({ success: false, message: 'Driver access only' });
  }
  try {
    await dbRun(
      `UPDATE trips SET status = 'cancelled' WHERE trip_id = $1 AND driver_id = $2`,
      [req.params.tripId, req.userId]
    );
    // Set driver back to online
    await dbRun(
      `UPDATE drivers SET status = 'online', updated_at = NOW() WHERE driver_id = $1`,
      [req.userId]
    );
    return res.json({ success: true, message: 'Trip declined. Back to searching.' });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── PUT /api/trips/:tripId/status ─────────────────────────────────────────────
router.put('/:tripId/status', requireAuth, [
  body('status').isIn(['pickup','ongoing','completed','cancelled'])
    .withMessage('Invalid status'),
], async (req, res) => {
  if (req.userRole !== 'driver') {
    return res.status(403).json({ success: false, message: 'Driver access only' });
  }
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { status } = req.body;
    const updates = { status };
    if (status === 'completed') updates.end_timestamp = 'NOW()';

    await dbRun(
      `UPDATE trips SET status = $1 ${status === 'completed' ? ', end_timestamp = NOW()' : ''}
       WHERE trip_id = $2 AND driver_id = $3`,
      [status, req.params.tripId, req.userId]
    );

    // If completed — calculate commission & set driver back to online
    if (status === 'completed') {
      const trip = await dbGet(`SELECT * FROM trips WHERE trip_id = $1`, [req.params.tripId]);
      if (trip) {
        // Get driver's commission rate
        const driver = await dbGet(
          `SELECT d.driver_id, d.toda_id,
                  COALESCE(cr.rate_percent, 10) AS commission_pct
           FROM drivers d
           LEFT JOIN subscriptions s
                  ON s.user_id = d.driver_id AND s.user_type = 'driver'
                  AND s.status = 'active' AND s.expires_at > NOW()
           LEFT JOIN subscription_plans sp ON sp.plan_id = s.plan_id
           LEFT JOIN commission_rates cr
                  ON cr.user_type = 'driver'
                  AND cr.plan_type = CASE
                    WHEN sp.plan_name ILIKE '%pro%' THEN 'pro'
                    WHEN sp.plan_name IS NOT NULL THEN 'basic'
                    ELSE 'none' END
                  AND cr.is_active = true
           WHERE d.driver_id = $1`,
          [req.userId]
        );

        const grossFare   = parseFloat(trip.fare);
        const commPct     = parseFloat(driver?.commission_pct || 10);
        const commAmt     = +(grossFare * commPct / 100).toFixed(2);
        const driverPayout = +(grossFare - commAmt).toFixed(2);

        // Record commission ledger
        await dbRun(
          `INSERT INTO commission_ledger
            (ledger_id, trip_id, driver_id, toda_id,
             gross_fare, commission_pct, commission_amt, driver_payout)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [uuidv4(), trip.trip_id, req.userId,
           driver?.toda_id || null,
           grossFare, commPct, commAmt, driverPayout]
        );

        // Update driver stats
        await dbRun(
          `UPDATE drivers
           SET total_trips = total_trips + 1,
               status = 'online',
               updated_at = NOW()
           WHERE driver_id = $1`,
          [req.userId]
        );

        return res.json({
          success: true,
          message: 'Trip completed!',
          earnings: {
            gross_fare: grossFare,
            commission_pct: commPct,
            commission_amt: commAmt,
            your_earnings: driverPayout,
          },
        });
      }
    }

    if (status === 'cancelled') {
      await dbRun(
        `UPDATE drivers SET status = 'online', updated_at = NOW() WHERE driver_id = $1`,
        [req.userId]
      );
    }

    return res.json({ success: true, message: `Trip status updated to ${status}` });
  } catch (err) {
    console.error('[Trips] Status update error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── GET /api/trips/driver/active ──────────────────────────────────────────────
router.get('/driver/active', requireAuth, async (req, res) => {
  if (req.userRole !== 'driver') {
    return res.status(403).json({ success: false, message: 'Driver access only' });
  }
  try {
    const trip = await dbGet(
      `SELECT tr.*,
              COALESCE(c.full_name, 'Passenger') AS commuter_name,
              c.phone_no AS commuter_phone
       FROM trips tr
       LEFT JOIN commuters c ON c.commuter_id = tr.commuter_id
       WHERE tr.driver_id = $1
         AND tr.status IN ('accepted','pickup','ongoing')
       ORDER BY tr.request_timestamp DESC LIMIT 1`,
      [req.userId]
    );
    return res.json({ success: true, trip: trip || null });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── GET /api/trips/commuter/active ────────────────────────────────────────────
router.get('/commuter/active', requireAuth, async (req, res) => {
  try {
    const trip = await dbGet(
      `SELECT tr.*,
              COALESCE(c2.full_name, d.driver_name) AS driver_name,
              d.phone AS driver_phone,
              d.avg_rating AS driver_rating,
              d.toda_body_number,
              t.plate_no, t.vehicle_color
       FROM trips tr
       LEFT JOIN drivers d ON d.driver_id = tr.driver_id
       LEFT JOIN commuters c2 ON c2.phone_no = d.phone
       LEFT JOIN tricycles t ON t.driver_id = d.driver_id
       WHERE tr.commuter_id = $1
         AND tr.status IN ('requested','accepted','pickup','ongoing')
       ORDER BY tr.request_timestamp DESC LIMIT 1`,
      [req.userId]
    );
    return res.json({ success: true, trip: trip || null });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── GET /api/trips/commuter/history ───────────────────────────────────────────
router.get('/commuter/history', requireAuth, async (req, res) => {
  try {
    const trips = await dbAll(
      `SELECT tr.*,
              COALESCE(c2.full_name, d.driver_name) AS driver_name,
              d.toda_body_number, t.plate_no
       FROM trips tr
       LEFT JOIN drivers d ON d.driver_id = tr.driver_id
       LEFT JOIN commuters c2 ON c2.phone_no = d.phone
       LEFT JOIN tricycles t ON t.driver_id = d.driver_id
       WHERE tr.commuter_id = $1
       ORDER BY tr.request_timestamp DESC LIMIT 50`,
      [req.userId]
    );
    return res.json({ success: true, trips });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── GET /api/trips/driver/history ─────────────────────────────────────────────
router.get('/driver/history', requireAuth, async (req, res) => {
  if (req.userRole !== 'driver') {
    return res.status(403).json({ success: false, message: 'Driver access only' });
  }
  try {
    const trips = await dbAll(
      `SELECT tr.*,
              COALESCE(c.full_name, 'Passenger') AS commuter_name,
              cl.commission_amt, cl.driver_payout, cl.commission_pct
       FROM trips tr
       LEFT JOIN commuters c ON c.commuter_id = tr.commuter_id
       LEFT JOIN commission_ledger cl ON cl.trip_id = tr.trip_id
       WHERE tr.driver_id = $1
       ORDER BY tr.request_timestamp DESC LIMIT 50`,
      [req.userId]
    );
    return res.json({ success: true, trips });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

module.exports = router;