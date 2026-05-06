/**
 * Trip Routes — uses 'users' table for passengers (matches auth.js)
 */
const express = require('express');
const { body, validationResult } = require('express-validator');
const jwt     = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { dbRun, dbGet, dbAll } = require('../db/database');

const router = express.Router();

// ── Auth middleware ───────────────────────────────────────────────────────────
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
    req.userRole = payload.role; // 'commuter' | 'driver' | 'operator'
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
}

// ── GET /api/trips/drivers/online ─────────────────────────────────────────────
router.get('/drivers/online', requireAuth, async (req, res) => {
  try {
    const drivers = await dbAll(
      `SELECT
         d.driver_id,
         d.driver_name,
         d.toda_body_number,
         d.avg_rating,
         d.total_trips,
         d.status,
         d.phone,
         t.plate_no,
         t.vehicle_color,
         ta.association_name,
         ta.association_code,
         ROUND((RANDOM() * 3 + 1)::numeric, 1)  AS distance_km,
         FLOOR(RANDOM() * 8 + 2)::int            AS eta_minutes
       FROM drivers d
       LEFT JOIN tricycles t         ON t.driver_id  = d.driver_id
       LEFT JOIN toda_associations ta ON ta.toda_id   = d.toda_id
       WHERE d.status    = 'online'
         AND d.is_active = true
       ORDER BY d.avg_rating DESC`,
      []
    );
    return res.json({ success: true, total: drivers.length, drivers });
  } catch (err) {
    console.error('[Trips] Online drivers error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── POST /api/trips/request ───────────────────────────────────────────────────
router.post('/request', requireAuth, [
  body('driverId').notEmpty().withMessage('Driver ID is required'),
  body('pickupLocation').notEmpty().withMessage('Pickup location is required'),
  body('destination').notEmpty().withMessage('Destination is required'),
  body('fare').isNumeric().withMessage('Fare must be a number'),
  body('paymentMethod')
    .isIn(['cash','gcash','maya','wallet'])
    .withMessage('Invalid payment method'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  // Only passengers / commuters can request rides
  if (req.userRole === 'driver' || req.userRole === 'operator') {
    return res.status(403).json({
      success: false,
      message: 'Only passengers can request rides',
    });
  }

  const { driverId, pickupLocation, destination, fare, paymentMethod } = req.body;

  // Normalize serviceType
  let serviceType = (req.body.serviceType || 'solo')
    .toLowerCase().replace(/[-\s]/g, '');
  if (serviceType.includes('express')) serviceType = 'express';
  else if (serviceType.includes('shared')) serviceType = 'shared';
  else serviceType = 'solo';

  try {
    // Verify driver is still online — get driver + tricycle info
    const driver = await dbGet(
      `SELECT d.driver_id, d.status, d.toda_body_number, d.driver_name,
              t.plate_no, t.tricycle_id
       FROM drivers d
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

    // Get passenger info from USERS table (auth.js stores passengers here)
    const passenger = await dbGet(
      `SELECT id, full_name, phone FROM users WHERE id = $1 AND is_active = true`,
      [req.userId]
    );

    if (!passenger) {
      return res.status(404).json({ success: false, message: 'Passenger account not found' });
    }

    // Create trip — use passenger's users.id as commuter_id
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

    // Mark driver as on_trip
    await dbRun(
      `UPDATE drivers SET status = 'on_trip', updated_at = NOW()
       WHERE driver_id = $1`,
      [driverId]
    );

    const trip = await dbGet(
      `SELECT * FROM trips WHERE trip_id = $1`, [tripId]
    );

    console.log(`[Trips] Ride requested: ${passenger.full_name} → ${driver.driver_name}`);

    return res.status(201).json({
      success: true,
      message: 'Ride requested successfully!',
      trip: {
        ...trip,
        driver_name:      driver.driver_name,
        plate_no:         driver.plate_no,
        toda_body_number: driver.toda_body_number,
        commuter_name:    passenger.full_name,
      },
    });
  } catch (err) {
    console.error('[Trips] Request error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to request ride' });
  }
});

// ── GET /api/trips/driver/pending ─────────────────────────────────────────────
router.get('/driver/pending', requireAuth, async (req, res) => {
  if (req.userRole !== 'driver') {
    return res.status(403).json({ success: false, message: 'Driver access only' });
  }
  try {
    // Join with users table to get real passenger name
    const trip = await dbGet(
      `SELECT tr.*,
              COALESCE(u.full_name, 'Passenger') AS commuter_name,
              u.phone AS commuter_phone
       FROM trips tr
       LEFT JOIN users u ON u.id = tr.commuter_id
       WHERE tr.driver_id = $1
         AND tr.status    = 'requested'
       ORDER BY tr.request_timestamp DESC
       LIMIT 1`,
      [req.userId]
    );
    return res.json({
      success: true,
      trip: trip || null,
      hasPendingTrip: !!trip,
    });
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
      `SELECT * FROM trips
       WHERE trip_id = $1 AND driver_id = $2 AND status = 'requested'`,
      [req.params.tripId, req.userId]
    );
    if (!trip) {
      return res.status(404).json({
        success: false, message: 'Trip not found or already handled',
      });
    }
    await dbRun(
      `UPDATE trips
       SET status = 'accepted', pickup_timestamp = NOW()
       WHERE trip_id = $1`,
      [req.params.tripId]
    );
    console.log(`[Trips] Trip accepted: ${req.params.tripId}`);
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
      `UPDATE trips SET status = 'cancelled'
       WHERE trip_id = $1 AND driver_id = $2`,
      [req.params.tripId, req.userId]
    );
    // Set driver back to online
    await dbRun(
      `UPDATE drivers SET status = 'online', updated_at = NOW()
       WHERE driver_id = $1`,
      [req.userId]
    );
    return res.json({ success: true, message: 'Trip declined.' });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── PUT /api/trips/:tripId/status ─────────────────────────────────────────────
router.put('/:tripId/status', requireAuth, [
  body('status')
    .isIn(['pickup','ongoing','completed','cancelled'])
    .withMessage('Invalid status'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  const { status } = req.body;

  try {
    await dbRun(
      `UPDATE trips
       SET status = $1
           ${status === 'completed' ? ', end_timestamp = NOW()' : ''}
       WHERE trip_id = $2`,
      [status, req.params.tripId]
    );

    // On completion — calculate commission, update driver stats
    if (status === 'completed') {
      const trip = await dbGet(
        `SELECT * FROM trips WHERE trip_id = $1`, [req.params.tripId]
      );

      if (trip && req.userRole === 'driver') {
        const grossFare    = parseFloat(trip.fare);
        const commPct      = 0;    // Flat fee — not percentage
        const commAmt      = 5.0;  // Flat ₱5 per ride
        const driverPayout = +(grossFare - commAmt).toFixed(2);

        // Record commission
        await dbRun(
          `INSERT INTO commission_ledger
            (ledger_id, trip_id, driver_id, toda_id,
             gross_fare, commission_pct, commission_amt, driver_payout)
           VALUES ($1,$2,$3,
             (SELECT toda_id FROM drivers WHERE driver_id=$3),
             $4,$5,$6,$7)`,
          [uuidv4(), trip.trip_id, req.userId,
           grossFare, commPct, commAmt, driverPayout]
        );

        // Driver goes back online + increment trips
        await dbRun(
          `UPDATE drivers
           SET total_trips = total_trips + 1,
               status      = 'online',
               updated_at  = NOW()
           WHERE driver_id = $1`,
          [req.userId]
        );

        console.log(`[Trips] Completed: ₱${grossFare} fare, ₱${commAmt} commission`);

        return res.json({
          success: true,
          message: 'Trip completed!',
          earnings: {
            gross_fare:    grossFare,
            commission_pct: commPct,
            commission_amt: commAmt,
            your_earnings:  driverPayout,
          },
        });
      }
    }

    if (status === 'cancelled') {
      // Driver goes back online
      if (req.userRole === 'driver') {
        await dbRun(
          `UPDATE drivers SET status = 'online', updated_at = NOW()
           WHERE driver_id = $1`,
          [req.userId]
        );
      }
    }

    return res.json({ success: true, message: `Status updated to ${status}` });
  } catch (err) {
    console.error('[Trips] Status update error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── GET /api/trips/commuter/active ────────────────────────────────────────────
router.get('/commuter/active', requireAuth, async (req, res) => {
  try {
    // Search by commuter_id matching users.id (the passenger's JWT sub)
    const trip = await dbGet(
      `SELECT tr.*,
              d.driver_name,
              d.toda_body_number,
              d.avg_rating    AS driver_rating,
              t.plate_no,
              t.vehicle_color
       FROM trips tr
       LEFT JOIN drivers    d ON d.driver_id  = tr.driver_id
       LEFT JOIN tricycles  t ON t.driver_id  = d.driver_id
       WHERE tr.commuter_id = $1
         AND tr.status IN ('requested','accepted','pickup','ongoing')
       ORDER BY tr.request_timestamp DESC
       LIMIT 1`,
      [req.userId]
    );
    console.log('[Trips] Active trip check for user:', req.userId, '→', trip ? trip.status : 'none');
    return res.json({ success: true, trip: trip || null });
  } catch (err) {
    console.error('[Trips] commuter/active error:', err.message);
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
              COALESCE(u.full_name, 'Passenger') AS commuter_name,
              u.phone AS commuter_phone
       FROM trips tr
       LEFT JOIN users u ON u.id = tr.commuter_id
       WHERE tr.driver_id = $1
         AND tr.status IN ('accepted','pickup','ongoing')
       ORDER BY tr.request_timestamp DESC
       LIMIT 1`,
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
      `SELECT tr.*, d.driver_name, d.toda_body_number, t.plate_no
       FROM trips tr
       LEFT JOIN drivers   d ON d.driver_id = tr.driver_id
       LEFT JOIN tricycles t ON t.driver_id = d.driver_id
       WHERE tr.commuter_id = $1
       ORDER BY tr.request_timestamp DESC
       LIMIT 50`,
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
              COALESCE(u.full_name, 'Passenger') AS commuter_name,
              cl.commission_amt,
              cl.driver_payout,
              cl.commission_pct
       FROM trips tr
       LEFT JOIN users             u  ON u.id        = tr.commuter_id
       LEFT JOIN commission_ledger cl ON cl.trip_id  = tr.trip_id
       WHERE tr.driver_id = $1
       ORDER BY tr.request_timestamp DESC
       LIMIT 50`,
      [req.userId]
    );
    return res.json({ success: true, trips });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

module.exports = router;