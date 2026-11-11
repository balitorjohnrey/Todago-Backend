const { pool } = require('../db/database');
const { recordDriverServiceAreaAlert, recordDriverRouteAlert } = require('../utils/adminReports');
const { classifyServiceArea } = require('../utils/serviceAreas');
const { validPoint, routeForTrip, normalizeRoutePoints, distanceToRouteMeters, routeToleranceMeters } = require('../utils/routeMonitoring');

async function recordDriverGpsLocation(driverId, lat, lng, { tripId = null, source = 'online_driver_location' } = {}) {
  if (!validPoint({ lat, lng })) throw new Error('Invalid GPS coordinates');
  const client = await pool.connect();
  const database = {
    dbRun: (sql, params) => client.query(sql, params),
    dbGet: async (sql, params) => (await client.query(sql, params)).rows[0] || null,
  };
  try {
    await client.query('BEGIN');
    // Serialize GPS samples for one driver, including alert deduplication.
    const driver = await database.dbGet('SELECT driver_id FROM drivers WHERE driver_id = $1 FOR UPDATE', [driverId]);
    if (!driver) throw new Error('Driver not found');
    const tricycle = await database.dbGet(`SELECT tricycle_id FROM tricycles
      WHERE driver_id = $1 ORDER BY created_at DESC LIMIT 1`, [driverId]);
    const trip = await database.dbGet(`SELECT * FROM trips WHERE driver_id = $1
      AND (($2::text IS NOT NULL AND trip_id = $2) OR
           ($2::text IS NULL AND status IN ('accepted', 'pickup', 'ongoing', 'arrived')))
      ORDER BY request_timestamp DESC LIMIT 1`, [driverId, tripId]);
    const { leg, route } = trip ? routeForTrip(trip) : { leg: null, route: null };
    const points = normalizeRoutePoints(route?.points);
    const routeDistance = points ? distanceToRouteMeters({ lat, lng }, points) : null;
    const tolerance = routeToleranceMeters();
    const deviation = routeDistance == null ? null : routeDistance > tolerance;
    const area = classifyServiceArea(lat, lng);

    const location = await database.dbGet(`INSERT INTO gps_locations
      (tricycle_id, driver_id, trip_id, latitude, longitude, source,
       within_service_area, route_leg, route_distance_m, route_deviation, timestamp)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,clock_timestamp())
      RETURNING location_id,
        TO_CHAR(timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS observed_at`,
    [tricycle?.tricycle_id || null, driverId, trip?.trip_id || null, lat, lng,
      source, area.within_service_area, leg?.key || null, routeDistance, deviation]);

    const context = { source, tripId: trip?.trip_id || null, locationId: location.location_id,
      observedAt: location.observed_at };
    if (!area.within_service_area) {
      await recordDriverServiceAreaAlert(driverId, lat, lng, context, area, database);
    }
    if (deviation) {
      await recordDriverRouteAlert(driverId, lat, lng, { ...context,
        routeLeg: leg.key, distanceMeters: routeDistance, toleranceMeters: tolerance }, database);
    }
    await client.query('COMMIT');
    return { ...area, observed_at: location.observed_at };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

module.exports = { recordDriverGpsLocation };
