const { createFirebaseSender } = require('./firebaseMessaging');
const { currentRouteLeg, distanceMeters, validPoint } = require('../utils/routeMonitoring');

const PUSH_TYPES = {
  booking_requested: {
    title: 'New ride request', body: 'Open TodaGo to review the request.',
    ttl: 120, statuses: ['requested'],
  },
  reservation_created: {
    title: 'New scheduled reservation', body: 'Open TodaGo to view the reservation.',
    ttl: 600, statuses: ['scheduled'],
  },
  driver_accepted: {
    title: 'Ride accepted', body: 'Your driver accepted your booking. Open TodaGo to track your ride.',
    ttl: 180, statuses: ['accepted', 'pickup'],
  },
  driver_near_pickup: {
    title: 'Your driver is nearby', body: 'Get ready and head to your pickup point.',
    ttl: 90, statuses: ['accepted', 'pickup'],
  },
  pickup_arrived: {
    title: 'Your driver is at the pickup point', body: 'Please meet your driver to board.',
    ttl: 180, statuses: ['accepted', 'pickup'],
  },
  destination_arrived: {
    title: 'Arrived at your destination', body: 'Open TodaGo to view your trip and payment options.',
    ttl: 300, statuses: ['arrived'],
  },
  booking_cancelled: {
    title: 'Booking cancelled', body: 'Open TodaGo for an update on your booking.',
    ttl: 300,
  },
  passenger_no_show: {
    title: 'Booking cancelled', body: 'Your driver cancelled after waiting at the pickup point.',
    ttl: 300, statuses: ['cancelled'],
  },
  trip_message: {
    title: 'New trip message', body: 'Open TodaGo to read your message.',
    ttl: 600,
  },
  fleet_gps_alert: {
    title: 'New driver GPS alert', body: 'Open TodaGo to check driver activity.',
    ttl: 300,
  },
  cashout_requested: {
    title: 'New cash-out request', body: 'Open TodaGo to review the request.',
    ttl: 600,
  },
};

const enabled = () => Boolean(process.env.FCM_SERVICE_ACCOUNT_JSON?.trim());

async function initializePushTables(client) {
  await client.query(`CREATE TABLE IF NOT EXISTS push_devices (
    token TEXT PRIMARY KEY,
    user_role TEXT NOT NULL,
    user_id TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_push_devices_recipient
    ON push_devices(user_role, user_id)`);
  await client.query(`CREATE TABLE IF NOT EXISTS push_deliveries (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token TEXT NOT NULL REFERENCES push_devices(token) ON DELETE CASCADE,
    user_role TEXT NOT NULL,
    user_id TEXT NOT NULL,
    event_key TEXT NOT NULL,
    type TEXT NOT NULL,
    trip_id TEXT REFERENCES trips(trip_id) ON DELETE CASCADE,
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    UNIQUE (token, event_key)
  )`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_push_deliveries_due
    ON push_deliveries(available_at, id)`);
  await client.query(`ALTER TABLE trips ADD COLUMN IF NOT EXISTS pickup_near_queued_at TIMESTAMPTZ`);
}

async function enqueuePush(query, { type, eventId, role, userId = null, todaId = null, tripId = null }) {
  if (!enabled() || (!userId && !todaId)) return;
  await query(`
    INSERT INTO push_deliveries (token, user_role, user_id, event_key, type, trip_id, expires_at)
    SELECT token, user_role, user_id, $3, $4, $5, NOW() + $6 * INTERVAL '1 second'
    FROM push_devices WHERE user_role = $1
      AND (user_id = $2 OR ($1 = 'operator' AND user_id IN (
        SELECT operator_id FROM operators WHERE toda_id = $7 AND is_active IS NOT FALSE
      )))
    ON CONFLICT (token, event_key) DO NOTHING`,
  [role, userId, `${type}:${eventId}`, type, tripId, PUSH_TYPES[type].ttl, todaId]);
}

async function notify(query, event) {
  try {
    await enqueuePush(query, event);
  } catch (error) {
    console.error('[Push] Could not queue notification:', event.type, error.code || error.name);
  }
}

async function queuePickupProximity(database, trip, driverId, position) {
  if (!enabled() || !trip?.commuter_id || trip.pickup_near_queued_at || trip.pickup_arrived_at || trip.picked_up_at) return;
  const leg = currentRouteLeg(trip);
  if (leg?.key !== 'pickup' || !validPoint(leg.target)) return;
  const configured = Number(process.env.TODAGO_PICKUP_PUSH_RADIUS_METERS);
  const radius = Number.isFinite(configured) && configured > 0 ? configured : 300;
  if (distanceMeters(position, leg.target) > radius) return;

  const marked = await database.dbRun(`
    UPDATE trips SET pickup_near_queued_at = NOW()
    WHERE trip_id = $1 AND driver_id = $2 AND commuter_id = $3
      AND status IN ('accepted', 'pickup') AND picked_up_at IS NULL
      AND pickup_near_queued_at IS NULL AND pickup_arrived_at IS NULL
      AND EXISTS (SELECT 1 FROM push_devices
        WHERE user_role = 'passenger' AND user_id = $3)`,
  [trip.trip_id, driverId, trip.commuter_id]);
  if (marked.rowCount) {
    await enqueuePush(database.dbRun, {
      type: 'driver_near_pickup', eventId: trip.trip_id, role: 'passenger',
      userId: trip.commuter_id, tripId: trip.trip_id,
    });
  }
}

async function deliverPushBatch(pool, send) {
  await pool.query('DELETE FROM push_deliveries WHERE expires_at <= NOW()');
  const { rows } = await pool.query(`
    WITH due AS (
      SELECT id FROM push_deliveries
      WHERE available_at <= NOW() AND expires_at > NOW()
      ORDER BY available_at, id LIMIT 20 FOR UPDATE SKIP LOCKED
    )
    UPDATE push_deliveries p
    SET available_at = NOW() + INTERVAL '60 seconds', attempts = attempts + 1
    FROM due WHERE p.id = due.id
    RETURNING p.*`);

  await Promise.all(rows.map(async delivery => {
    const { id, token, user_id, user_role, type, attempts } = delivery;
    const { title, body, statuses } = PUSH_TYPES[type];
    const { rows: devices } = await pool.query(`
      SELECT 1 FROM push_devices d
      LEFT JOIN trips t ON t.trip_id = $4
      WHERE d.token = $1 AND d.user_role = $2 AND d.user_id = $3
        AND ($5::text[] IS NULL OR t.status = ANY($5))
        AND ($6 <> 'driver_near_pickup' OR (t.pickup_arrived_at IS NULL AND t.picked_up_at IS NULL))`,
    [token, user_role, user_id, delivery.trip_id, statuses || null, type]);
    if (devices.length) {
      let result;
      try {
        result = await send(delivery, { title, body });
      } catch (error) {
        console.error('[Push] Delivery failed:', type, error.message);
        const delay = Math.max(10 * 2 ** Math.min(attempts - 1, 4), error.retrySeconds || 0);
        await pool.query(`UPDATE push_deliveries
          SET available_at = NOW() + $2 * INTERVAL '1 second' WHERE id = $1`, [id, delay]);
        return;
      }
      if (result === 'unregistered') {
        await pool.query('DELETE FROM push_devices WHERE token = $1', [token]);
        return;
      }
    }
    await pool.query('DELETE FROM push_deliveries WHERE id = $1', [id]);
  }));
}

function startPushDelivery(pool) {
  if (!enabled()) {
    console.log('[Push] Set FCM_SERVICE_ACCOUNT_JSON to enable push delivery.');
    return;
  }
  let send;
  try {
    send = createFirebaseSender(process.env.FCM_SERVICE_ACCOUNT_JSON);
  } catch {
    console.error('[Push] FCM_SERVICE_ACCOUNT_JSON is invalid. Push delivery is disabled.');
    return;
  }
  async function poll() {
    try {
      await deliverPushBatch(pool, send);
    } catch (error) {
      console.error('[Push] Delivery queue error:', error.code || error.name);
    } finally {
      setTimeout(poll, 2000).unref();
    }
  }
  void poll();
}

module.exports = {
  initializePushTables, queuePickupProximity, enqueuePush, notify, deliverPushBatch, startPushDelivery,
};
