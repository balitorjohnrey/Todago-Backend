/**
 * Trip Routes — uses 'users' table for passengers (matches auth.js)
 */
const express = require('express');
const { body, validationResult } = require('express-validator');
const jwt     = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { dbRun, dbGet, dbAll } = require('../db/database');

const router = express.Router();
const TRICYCLE_AVERAGE_SPEED_KMH = 19.94;
const DRIVER_LOCATION_FRESHNESS_MINUTES = 5;

function haversineKm(aLat, aLng, bLat, bLng) {
  const toRad = (value) => value * Math.PI / 180;
  const radiusKm = 6371;
  const dLat = toRad(bLat - aLat);
  const dLng = toRad(bLng - aLng);
  const h = Math.sin(dLat / 2) ** 2
    + Math.cos(toRad(aLat)) * Math.cos(toRad(bLat))
    * Math.sin(dLng / 2) ** 2;
  return 2 * radiusKm * Math.asin(Math.sqrt(h));
}

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
    req.userRole = payload.role;
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
}

// ── GET /api/trips/drivers/online ─────────────────────────────────────────────
router.get('/drivers/online', requireAuth, async (req, res) => {
  try {
    const pickupLat = Number.parseFloat(req.query.pickupLat);
    const pickupLng = Number.parseFloat(req.query.pickupLng);
    const hasPickup = Number.isFinite(pickupLat) && Number.isFinite(pickupLng);

    const drivers = await dbAll(
      `SELECT
         d.driver_id,
         d.driver_name,
         d.toda_body_number,
         d.avg_rating,
         d.total_trips,
         d.status,
         d.phone,
         d.profile_photo_url,
         t.plate_no,
         t.vehicle_color,
         ta.association_name,
         ta.association_code,
         gps.latitude AS driver_lat,
         gps.longitude AS driver_lng,
         gps.timestamp AS driver_location_updated_at
       FROM drivers d
       LEFT JOIN tricycles t         ON t.driver_id  = d.driver_id
       LEFT JOIN toda_associations ta ON ta.toda_id   = d.toda_id
       LEFT JOIN LATERAL (
         SELECT latitude, longitude, timestamp
         FROM gps_locations
         WHERE tricycle_id = t.tricycle_id
           AND timestamp >= NOW() - INTERVAL '${DRIVER_LOCATION_FRESHNESS_MINUTES} minutes'
         ORDER BY timestamp DESC
         LIMIT 1
       ) gps ON true
       WHERE d.status    = 'online'
         AND d.is_active = true
         AND d.is_verified = true
       ORDER BY gps.timestamp IS NULL ASC, d.avg_rating DESC`,
      []
    );
    const enriched = drivers.map((driver) => {
      const driverLat = Number.parseFloat(driver.driver_lat);
      const driverLng = Number.parseFloat(driver.driver_lng);
      const hasDriverLocation =
        Number.isFinite(driverLat) && Number.isFinite(driverLng);
      const distanceKm = hasPickup && hasDriverLocation
        ? haversineKm(pickupLat, pickupLng, driverLat, driverLng)
        : null;
      const etaMinutes = distanceKm == null
        ? null
        : Math.max(1, Math.ceil((distanceKm / TRICYCLE_AVERAGE_SPEED_KMH) * 60));
      const { driver_lat, driver_lng, driver_location_updated_at, ...safeDriver } = driver;
      return {
        ...safeDriver,
        has_fresh_location: hasDriverLocation,
        distance_km: distanceKm == null
          ? null
          : Number(distanceKm.toFixed(1)),
        eta_minutes: etaMinutes,
      };
    });
    return res.json({ success: true, total: enriched.length, drivers: enriched });
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
  body('passengerCount')
    .optional({ nullable: true })
    .isInt({ min: 1, max: 6 })
    .withMessage('Passenger count must be between 1 and 6'),
  body('passengerFareType')
    .optional({ nullable: true })
    .isIn(['regular','student','senior','pwd'])
    .withMessage('Invalid passenger fare type'),
  body('scheduledPickupAt')
    .optional({ nullable: true })
    .isISO8601()
    .withMessage('Scheduled pickup time must be a valid date/time'),
  body('pickupLat')
    .optional({ nullable: true })
    .isFloat({ min: -90, max: 90 })
    .withMessage('Pickup latitude must be valid'),
  body('pickupLng')
    .optional({ nullable: true })
    .isFloat({ min: -180, max: 180 })
    .withMessage('Pickup longitude must be valid'),
  body('destinationLat')
    .optional({ nullable: true })
    .isFloat({ min: -90, max: 90 })
    .withMessage('Destination latitude must be valid'),
  body('destinationLng')
    .optional({ nullable: true })
    .isFloat({ min: -180, max: 180 })
    .withMessage('Destination longitude must be valid'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  if (req.userRole === 'driver' || req.userRole === 'operator') {
    return res.status(403).json({
      success: false,
      message: 'Only passengers can request rides',
    });
  }

  const {
    driverId,
    pickupLocation,
    destination,
    fare,
    paymentMethod,
    scheduledPickupAt,
    pickupLat,
    pickupLng,
    destinationLat,
    destinationLng,
  } = req.body;

  let serviceType = (req.body.serviceType || 'solo')
    .toLowerCase().replace(/[-\s]/g, '');
  if (serviceType.includes('express')) serviceType = 'express';
  else if (serviceType.includes('shared')) serviceType = 'shared';
  else serviceType = 'solo';

  const passengerFareType = ['student', 'senior', 'pwd'].includes(
    (req.body.passengerFareType || '').toString().toLowerCase()
  )
    ? req.body.passengerFareType.toString().toLowerCase()
    : 'regular';
  const requestedPassengerCount = Number.parseInt(req.body.passengerCount, 10);
  const passengerCount = serviceType === 'shared'
    ? Math.min(6, Math.max(2, Number.isFinite(requestedPassengerCount) ? requestedPassengerCount : 2))
    : 1;

  try {
    const scheduledDate = scheduledPickupAt ? new Date(scheduledPickupAt) : null;
    const isScheduled = !!scheduledDate;
    const parseCoord = (value) =>
      value === undefined || value === null || value === ''
        ? null
        : parseFloat(value);

    if (isScheduled && scheduledDate.getTime() <= Date.now() + 5 * 60 * 1000) {
      return res.status(422).json({
        success: false,
        message: 'Scheduled pickup must be at least 5 minutes from now',
      });
    }

    const driver = await dbGet(
      `SELECT d.driver_id, d.status, d.is_verified,
              d.toda_body_number, d.driver_name,
              d.profile_photo_url,
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
    if (driver.is_verified !== true) {
      return res.status(400).json({
        success: false,
        message: 'Driver is pending TODA approval. Please choose another driver.',
      });
    }

    const passenger = await dbGet(
      `SELECT id, full_name, phone FROM users WHERE id = $1 AND is_active = true`,
      [req.userId]
    );

    if (!passenger) {
      return res.status(404).json({ success: false, message: 'Passenger account not found' });
    }

    const tripId = uuidv4();
    await dbRun(
      `INSERT INTO trips
        (trip_id, commuter_id, tricycle_id, driver_id,
         service_type, passenger_count, passenger_fare_type,
         pickup_location, pickup_lat, pickup_lng,
         destination, destination_lat, destination_lng,
         fare, payment_method, status, trip_type, scheduled_pickup_at,
         request_timestamp)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,NOW())`,
      [tripId, req.userId, driver.tricycle_id, driverId,
       serviceType, passengerCount, passengerFareType,
       pickupLocation, parseCoord(pickupLat), parseCoord(pickupLng),
       destination, parseCoord(destinationLat), parseCoord(destinationLng),
       parseFloat(fare), paymentMethod,
       isScheduled ? 'scheduled' : 'requested',
       isScheduled ? 'scheduled' : 'instant',
       scheduledDate]
    );

    if (!isScheduled) {
      await dbRun(
        `UPDATE drivers
         SET status = 'on_trip',
             online_since = COALESCE(online_since, NOW()),
             updated_at = NOW()
         WHERE driver_id = $1`,
        [driverId]
      );
    }

    const trip = await dbGet(
      `SELECT * FROM trips WHERE trip_id = $1`, [tripId]
    );

    console.log(
      `[Trips] ${isScheduled ? 'Reservation scheduled' : 'Ride requested'}: ${passenger.full_name} → ${driver.driver_name}`
    );

    return res.status(201).json({
      success: true,
      message: isScheduled
        ? 'Scheduled reservation created successfully!'
        : 'Ride requested successfully!',
      trip: {
        ...trip,
        fare:             parseFloat(trip.fare),
        driver_name:      driver.driver_name,
        plate_no:         driver.plate_no,
        toda_body_number: driver.toda_body_number,
        driver_profile_photo_url: driver.profile_photo_url,
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
    const trip = await dbGet(
      `SELECT tr.*,
              COALESCE(u.full_name, 'Passenger') AS commuter_name,
              u.phone AS commuter_phone
       FROM trips tr
       LEFT JOIN users u ON u.id = tr.commuter_id
       WHERE tr.driver_id = $1
         AND (
           tr.status = 'requested'
           OR (
             tr.status = 'scheduled'
             AND tr.scheduled_pickup_at <= NOW() + INTERVAL '1 hour'
             AND tr.scheduled_pickup_at >= NOW() - INTERVAL '10 minutes'
           )
         )
       ORDER BY COALESCE(tr.scheduled_pickup_at, tr.request_timestamp) ASC
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
       WHERE trip_id = $1 AND driver_id = $2 AND status IN ('requested','scheduled')`,
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
    await dbRun(
      `UPDATE drivers
       SET status = 'on_trip',
           online_since = COALESCE(online_since, NOW()),
           updated_at = NOW()
       WHERE driver_id = $1`,
      [req.userId]
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
    await dbRun(
      `UPDATE drivers
       SET status = 'online',
           online_since = COALESCE(online_since, NOW()),
           updated_at = NOW()
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
    const trip = await dbGet(
      `SELECT trip_id, commuter_id, driver_id, status, fare
       FROM trips
       WHERE trip_id = $1`,
      [req.params.tripId]
    );

    if (!trip) {
      return res.status(404).json({ success: false, message: 'Trip not found' });
    }

    const isAssignedDriver =
      req.userRole === 'driver' && trip.driver_id === req.userId;
    const isTripPassenger =
      ['commuter', 'passenger'].includes(req.userRole) &&
      trip.commuter_id === req.userId;

    if (status === 'cancelled') {
      if (!isAssignedDriver && !isTripPassenger) {
        return res.status(403).json({ success: false, message: 'Not allowed to cancel this trip' });
      }
      if (trip.status === 'completed') {
        return res.status(409).json({ success: false, message: 'Completed trips cannot be cancelled' });
      }

      await dbRun(
        `UPDATE trips
         SET status = 'cancelled',
             end_timestamp = COALESCE(end_timestamp, NOW())
         WHERE trip_id = $1`,
        [trip.trip_id]
      );

      if (trip.driver_id) {
        await dbRun(
          `UPDATE drivers
           SET status = 'online',
               online_since = COALESCE(online_since, NOW()),
               updated_at = NOW()
           WHERE driver_id = $1`,
          [trip.driver_id]
        );
      }

      console.log(
        `[Trips] Cancelled by ${isTripPassenger ? 'passenger' : 'driver'}: ${trip.trip_id}`
      );

      return res.json({
        success: true,
        message: isTripPassenger
          ? 'Trip cancelled. Driver notified.'
          : 'Trip cancelled.',
        cancelled_by: isTripPassenger ? 'passenger' : 'driver',
      });
    }

    if (!isAssignedDriver) {
      return res.status(403).json({ success: false, message: 'Only the assigned driver can update this trip' });
    }

    if (trip.status === 'cancelled' || trip.status === 'completed') {
      return res.status(409).json({ success: false, message: `Trip is already ${trip.status}` });
    }

    await dbRun(
      `UPDATE trips
       SET status = $1
           ${status === 'completed' ? ', end_timestamp = NOW()' : ''}
       WHERE trip_id = $2`,
      [status, req.params.tripId]
    );

    if (status === 'completed') {
      const trip = await dbGet(
        `SELECT * FROM trips WHERE trip_id = $1`, [req.params.tripId]
      );

      if (trip && req.userRole === 'driver') {
        const grossFare = parseFloat(trip.fare);

        await dbRun(
          `UPDATE drivers
           SET total_trips = total_trips + 1,
               status      = 'online',
               online_since = COALESCE(online_since, NOW()),
               updated_at  = NOW()
           WHERE driver_id = $1`,
          [req.userId]
        );

        console.log(`[Trips] Completed: fare=${grossFare}`);

        return res.json({
          success: true,
          message: 'Trip completed!',
          earnings: {
            gross_fare: grossFare,
            your_earnings: grossFare,
          },
        });
      }
    }

    return res.json({ success: true, message: `Status updated to ${status}` });
  } catch (err) {
    console.error('[Trips] Status update error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── GET /api/trips/commuter/active ────────────────────────────────────────────
router.put('/:tripId/driver-location', requireAuth, [
  body('lat')
    .isFloat({ min: -90, max: 90 })
    .withMessage('Driver latitude must be valid'),
  body('lng')
    .isFloat({ min: -180, max: 180 })
    .withMessage('Driver longitude must be valid'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  if (req.userRole !== 'driver') {
    return res.status(403).json({ success: false, message: 'Driver access only' });
  }

  try {
    const trip = await dbGet(
      `SELECT trip_id, driver_id, status
       FROM trips
       WHERE trip_id = $1`,
      [req.params.tripId]
    );

    if (!trip || trip.driver_id !== req.userId) {
      return res.status(404).json({ success: false, message: 'Trip not found' });
    }

    if (!['accepted','pickup','ongoing'].includes(trip.status)) {
      return res.status(409).json({
        success: false,
        message: `Driver location cannot be updated while trip is ${trip.status}`,
      });
    }

    await dbRun(
      `UPDATE trips
       SET driver_lat = $1,
           driver_lng = $2,
           driver_location_updated_at = NOW()
       WHERE trip_id = $3`,
      [parseFloat(req.body.lat), parseFloat(req.body.lng), trip.trip_id]
    );

    return res.json({ success: true, message: 'Driver location updated' });
  } catch (err) {
    console.error('[Trips] Driver location update error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.get('/commuter/active', requireAuth, async (req, res) => {
  try {
    const trip = await dbGet(
      `SELECT tr.*,
              d.driver_name,
              d.phone AS driver_phone,
              d.profile_photo_url AS driver_profile_photo_url,
              d.toda_body_number,
              d.avg_rating    AS driver_rating,
              t.plate_no,
              t.vehicle_color
       FROM trips tr
       LEFT JOIN drivers    d ON d.driver_id  = tr.driver_id
       LEFT JOIN tricycles  t ON t.driver_id  = d.driver_id
       WHERE tr.commuter_id = $1
         AND (
           tr.status IN ('requested','accepted','pickup','ongoing')
           OR (tr.status = 'completed' AND tr.end_timestamp > NOW() - INTERVAL '5 minutes')
         )
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
      `SELECT tr.*, d.driver_name, d.phone AS driver_phone,
              d.profile_photo_url AS driver_profile_photo_url,
              d.toda_body_number, t.plate_no,
              f.rating_score, f.comments AS rating_comment
       FROM trips tr
       LEFT JOIN drivers   d ON d.driver_id = tr.driver_id
       LEFT JOIN tricycles t ON t.driver_id = d.driver_id
       LEFT JOIN feedback  f ON f.trip_id   = tr.trip_id
                             AND f.commuter_id = tr.commuter_id
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
              u.phone AS commuter_phone,
              f.rating_score,
              f.comments AS rating_comment
       FROM trips tr
       LEFT JOIN users             u  ON u.id        = tr.commuter_id
       LEFT JOIN feedback          f  ON f.trip_id   = tr.trip_id
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

// ── GET /api/trips/driver/scheduled ───────────────────────────────────────────
router.get('/driver/scheduled', requireAuth, async (req, res) => {
  if (req.userRole !== 'driver') {
    return res.status(403).json({ success: false, message: 'Driver access only' });
  }
  try {
    const trips = await dbAll(
      `SELECT tr.*,
              COALESCE(u.full_name, 'Passenger') AS commuter_name,
              u.phone AS commuter_phone
       FROM trips tr
       LEFT JOIN users u ON u.id = tr.commuter_id
       WHERE tr.driver_id = $1
         AND tr.trip_type = 'scheduled'
         AND tr.status IN ('scheduled','accepted')
         AND tr.scheduled_pickup_at >= NOW() - INTERVAL '10 minutes'
       ORDER BY tr.scheduled_pickup_at ASC
       LIMIT 50`,
      [req.userId]
    );
    return res.json({ success: true, trips });
  } catch (err) {
    console.error('[Trips] driver/scheduled error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── POST /api/trips/:tripId/rate ──────────────────────────────────────────────
// Passenger submits a 1–5 star rating + optional comment after a completed trip.
// Permanently updates the driver's avg_rating in the drivers table.
// Get a single trip for owner polling (driver/passenger notification flows)
router.get('/:tripId', requireAuth, async (req, res) => {
  try {
    const trip = await dbGet(
      `SELECT tr.*,
              COALESCE(u.full_name, 'Passenger') AS commuter_name,
              u.phone AS commuter_phone,
              d.driver_name,
              d.phone AS driver_phone,
              d.profile_photo_url AS driver_profile_photo_url,
              d.toda_body_number,
              d.avg_rating AS driver_rating,
              t.plate_no,
              t.vehicle_color
       FROM trips tr
       LEFT JOIN users     u ON u.id        = tr.commuter_id
       LEFT JOIN drivers   d ON d.driver_id = tr.driver_id
       LEFT JOIN tricycles t ON t.driver_id = d.driver_id
       WHERE tr.trip_id = $1`,
      [req.params.tripId]
    );

    if (!trip) {
      return res.status(404).json({ success: false, message: 'Trip not found' });
    }

    const isAssignedDriver =
      req.userRole === 'driver' && trip.driver_id === req.userId;
    const isTripPassenger =
      ['commuter', 'passenger'].includes(req.userRole) &&
      trip.commuter_id === req.userId;

    if (!isAssignedDriver && !isTripPassenger) {
      return res.status(403).json({ success: false, message: 'Not allowed to view this trip' });
    }

    return res.json({ success: true, trip });
  } catch (err) {
    console.error('[Trips] Trip lookup error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.post('/:tripId/rate', requireAuth, [
  body('rating')
    .isInt({ min: 1, max: 5 })
    .withMessage('Rating must be between 1 and 5'),
  body('comment')
    .optional({ nullable: true })
    .isString()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Comment must be 500 characters or less'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  const { rating, comment } = req.body;
  const { tripId } = req.params;

  if (req.userRole === 'driver' || req.userRole === 'operator') {
    return res.status(403).json({
      success: false,
      message: 'Only passengers can submit ratings',
    });
  }

  try {
    // 1. Verify the trip belongs to this passenger and is completed
    const trip = await dbGet(
      `SELECT trip_id, driver_id, commuter_id
       FROM trips
       WHERE trip_id    = $1
         AND commuter_id = $2
         AND status     = 'completed'`,
      [tripId, req.userId]
    );

    if (!trip) {
      return res.status(404).json({
        success: false,
        message: 'Trip not found, not yours, or not yet completed',
      });
    }

    // 2. Prevent duplicate ratings for the same trip
    const existing = await dbGet(
      `SELECT feedback_id FROM feedback WHERE trip_id = $1`,
      [tripId]
    );
    if (existing) {
      return res.status(409).json({
        success: false,
        message: 'You have already rated this trip',
      });
    }

    // 3. Insert into the feedback table
    const feedbackId = uuidv4();
    await dbRun(
      `INSERT INTO feedback
         (feedback_id, trip_id, commuter_id, driver_id, rating_score, comments)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        feedbackId,
        tripId,
        req.userId,
        trip.driver_id,
        parseInt(rating, 10),
        comment ? comment.trim() : null,
      ]
    );

    // 4. Permanently recalculate and update driver's avg_rating
    await dbRun(
      `UPDATE drivers
       SET avg_rating = (
         SELECT ROUND(AVG(rating_score)::numeric, 2)
         FROM feedback
         WHERE driver_id = $1
       ),
       updated_at = NOW()
       WHERE driver_id = $1`,
      [trip.driver_id]
    );

    // 5. Update today's performance report if it exists
    await dbRun(
      `INSERT INTO performance_reports (report_id, driver_id, report_date, avg_rating, total_trips)
       VALUES ($1, $2, CURRENT_DATE, 0, 0)
       ON CONFLICT DO NOTHING`,
      [uuidv4(), trip.driver_id]
    ).catch(() => {});

    await dbRun(
      `UPDATE performance_reports
       SET avg_rating = (
         SELECT ROUND(AVG(rating_score)::numeric, 2)
         FROM feedback WHERE driver_id = $1
       )
       WHERE driver_id = $1 AND report_date = CURRENT_DATE`,
      [trip.driver_id]
    ).catch(() => {});

    console.log(
      `[Trips] Rating submitted: trip=${tripId}, driver=${trip.driver_id}, score=${rating}`
    );

    return res.status(201).json({
      success: true,
      message: 'Thank you for your feedback!',
      feedback_id: feedbackId,
    });
  } catch (err) {
    console.error('[Trips] Rating error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to submit rating' });
  }
});

// ── GET /api/trips/:tripId/rating ─────────────────────────────────────────────
// Check whether the passenger has already rated a specific trip.
router.get('/:tripId/rating', requireAuth, async (req, res) => {
  try {
    const feedback = await dbGet(
      `SELECT feedback_id, rating_score, comments, created_at
       FROM feedback
       WHERE trip_id     = $1
         AND commuter_id = $2`,
      [req.params.tripId, req.userId]
    );
    return res.json({
      success:  true,
      hasRated: !!feedback,
      feedback: feedback || null,
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

module.exports = router;
