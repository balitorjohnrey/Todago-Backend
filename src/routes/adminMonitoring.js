const { getDriverPerformance } = require('../services/driverPerformance');

function integer(value, fallback, max) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 1 ? Math.min(parsed, max) : fallback;
}

function registerAdminMonitoring(router, requireAdminAuth, { dbAll, dbGet }) {
  router.get('/monitoring/drivers', requireAdminAuth, async (req, res) => {
    try {
      const drivers = await getDriverPerformance(dbAll, { limit: integer(req.query.limit, 10, 50) });
      return res.json({ success: true, drivers });
    } catch (error) {
      console.error('[Admin] Driver performance error:', error.message);
      return res.status(500).json({ success: false, message: 'Unable to load driver performance' });
    }
  });

  router.get('/monitoring/charges', requireAdminAuth, async (req, res) => {
    const days = integer(req.query.days, 30, 365);
    const limit = integer(req.query.limit, 25, 100);
    const offset = Math.max(0, Math.min(1000000, Number.parseInt(req.query.offset, 10) || 0));
    const label = req.query.label ? String(req.query.label).slice(0, 120) : null;
    const params = [days, label];
    const where = `c.added_at >= NOW() - ($1::integer * INTERVAL '1 day')
      AND ($2::text IS NULL OR LOWER(c.label) = LOWER($2))`;
    try {
      const [rows, summary] = await Promise.all([
        dbAll(`SELECT c.*, tr.status AS trip_status, tr.payment_status,
          tr.fare AS total_fare, tr.fare - c.amount AS base_fare,
          tr.pickup_location, tr.destination, d.driver_name,
          u.full_name AS passenger_name, tr.driver_id
          FROM trip_additional_charges c JOIN trips tr ON tr.trip_id = c.trip_id
          LEFT JOIN drivers d ON d.driver_id = tr.driver_id
          LEFT JOIN users u ON u.id = c.added_by
          WHERE ${where}
          ORDER BY c.added_at DESC, c.charge_id DESC LIMIT $3 OFFSET $4`,
        [...params, limit + 1, offset]),
        dbGet(`SELECT COUNT(*)::integer AS charge_count, COALESCE(SUM(c.amount), 0) AS total_amount,
          COALESCE(SUM(c.amount) FILTER (WHERE LOWER(c.label) = 'tip'), 0) AS tip_amount
          FROM trip_additional_charges c WHERE ${where}`, params),
      ]);
      return res.json({ success: true, charges: rows.slice(0, limit), summary,
        has_more: rows.length > limit, next_offset: offset + limit, range_days: days });
    } catch (error) {
      console.error('[Admin] Trip charges error:', error.message);
      return res.status(500).json({ success: false, message: 'Unable to load trip charges' });
    }
  });

  router.get('/monitoring/gps', requireAdminAuth, async (req, res) => {
    const limit = integer(req.query.limit, 100, 500);
    const days = integer(req.query.days, 1, 365);
    const driverId = req.query.driverId ? String(req.query.driverId).slice(0, 120) : null;
    const tripId = req.query.tripId ? String(req.query.tripId).slice(0, 120) : null;
    const before = req.query.before || null;
    const beforeId = req.query.beforeId || null;
    if (!!before !== !!beforeId || (before && (!String(before).endsWith('Z')
        || !Number.isFinite(Date.parse(before))))) {
      return res.status(422).json({ success: false, message: 'Invalid GPS history cursor' });
    }
    try {
      const rows = await dbAll(`SELECT g.*, COALESCE(g.driver_id, t.driver_id) AS linked_driver_id,
        d.driver_name, d.toda_body_number, t.plate_no,
        TO_CHAR(g.timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS observed_at
        FROM gps_locations g LEFT JOIN tricycles t ON t.tricycle_id = g.tricycle_id
        LEFT JOIN drivers d ON d.driver_id = COALESCE(g.driver_id, t.driver_id)
        WHERE ($1::text IS NULL OR COALESCE(g.driver_id, t.driver_id) = $1)
          AND ($2::text IS NULL OR g.trip_id = $2)
          AND g.timestamp >= NOW() - ($3::integer * INTERVAL '1 day')
          AND ($4::timestamptz IS NULL OR (g.timestamp, g.location_id) < ($4::timestamptz, $5::text))
        ORDER BY g.timestamp DESC, g.location_id DESC LIMIT $6`,
      [driverId, tripId, days, before, beforeId, limit + 1]);
      const locations = rows.slice(0, limit);
      const last = locations[locations.length - 1];
      return res.json({ success: true, locations, has_more: rows.length > limit,
        next_cursor: rows.length > limit && last
          ? { before: last.observed_at, beforeId: last.location_id } : null });
    } catch (error) {
      console.error('[Admin] GPS activity error:', error.message);
      return res.status(500).json({ success: false, message: 'Unable to load GPS activity' });
    }
  });
}

module.exports = { registerAdminMonitoring };
