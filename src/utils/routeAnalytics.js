const { dbAll } = require('../db/database');

function clampInt(value, fallback, min, max) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function toNumber(value, fallback = 0) {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function toInt(value, fallback = 0) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

async function getRoutePerformance({ todaId = null, days = 30, limit = 6 } = {}) {
  const safeDays = clampInt(days, 30, 1, 365);
  const safeLimit = clampInt(limit, 6, 1, 20);
  const params = [safeDays, safeLimit];
  const driverJoin = todaId
    ? 'JOIN drivers d ON d.driver_id = tr.driver_id'
    : '';
  const scopeWhere = todaId
    ? 'AND d.toda_id = $3'
    : '';
  if (todaId) params.push(todaId);

  const rows = await dbAll(
    `
    WITH route_base AS (
      SELECT
        tr.trip_id,
        LOWER(TRIM(COALESCE(NULLIF(tr.pickup_location, ''), 'Unknown pickup'))) AS pickup_key,
        LOWER(TRIM(COALESCE(NULLIF(tr.destination, ''), 'Unknown destination'))) AS destination_key,
        TRIM(COALESCE(NULLIF(tr.pickup_location, ''), 'Unknown pickup')) AS pickup_name,
        TRIM(COALESCE(NULLIF(tr.destination, ''), 'Unknown destination')) AS destination_name,
        tr.status,
        COALESCE(tr.fare, 0) AS fare,
        tr.request_timestamp,
        tr.pickup_timestamp,
        tr.end_timestamp,
        CASE
          WHEN tr.status = 'completed'
           AND tr.end_timestamp IS NOT NULL
          THEN GREATEST(
            0,
            EXTRACT(EPOCH FROM (
              tr.end_timestamp - COALESCE(tr.pickup_timestamp, tr.request_timestamp)
            )) / 60.0
          )
        END AS trip_minutes,
        CASE
          WHEN tr.pickup_lat IS NOT NULL
           AND tr.pickup_lng IS NOT NULL
           AND tr.destination_lat IS NOT NULL
           AND tr.destination_lng IS NOT NULL
          THEN 2 * 6371 * ASIN(SQRT(
            POWER(SIN(RADIANS((tr.destination_lat - tr.pickup_lat) / 2)), 2)
            + COS(RADIANS(tr.pickup_lat))
              * COS(RADIANS(tr.destination_lat))
              * POWER(SIN(RADIANS((tr.destination_lng - tr.pickup_lng) / 2)), 2)
          ))
        END AS distance_km
      FROM trips tr
      ${driverJoin}
      WHERE tr.request_timestamp >= NOW() - ($1::int * INTERVAL '1 day')
        AND tr.status IN ('completed', 'cancelled')
        AND tr.pickup_location IS NOT NULL
        AND tr.destination IS NOT NULL
        ${scopeWhere}
    )
    SELECT
      MIN(pickup_name) AS route_from,
      MIN(destination_name) AS route_to,
      CONCAT(MIN(pickup_name), ' -> ', MIN(destination_name)) AS route_segment,
      COUNT(*) AS total_trips,
      COUNT(*) FILTER (WHERE status = 'completed') AS completed_trips,
      COUNT(*) FILTER (WHERE status = 'cancelled') AS cancelled_trips,
      ROUND((
        100.0 * COUNT(*) FILTER (WHERE status = 'completed') / NULLIF(COUNT(*), 0)
      )::numeric, 1) AS completion_rate,
      ROUND(AVG(trip_minutes)::numeric, 1) AS avg_trip_minutes,
      ROUND(AVG(distance_km)::numeric, 2) AS avg_distance_km,
      ROUND(AVG(
        CASE
          WHEN trip_minutes > 0 AND distance_km IS NOT NULL
          THEN distance_km / (trip_minutes / 60.0)
        END
      )::numeric, 1) AS avg_speed_kmh,
      ROUND(SUM(CASE WHEN status = 'completed' THEN fare ELSE 0 END)::numeric, 2)
        AS gross_revenue,
      MAX(request_timestamp) AS last_trip_at
    FROM route_base
    GROUP BY pickup_key, destination_key
    ORDER BY completed_trips DESC, gross_revenue DESC, total_trips DESC
    LIMIT $2
    `,
    params
  );

  return rows.map((row) => ({
    route_from: row.route_from,
    route_to: row.route_to,
    route_segment: row.route_segment,
    total_trips: toInt(row.total_trips),
    completed_trips: toInt(row.completed_trips),
    cancelled_trips: toInt(row.cancelled_trips),
    completion_rate: toNumber(row.completion_rate),
    avg_trip_minutes: toNumber(row.avg_trip_minutes),
    avg_distance_km: toNumber(row.avg_distance_km),
    avg_speed_kmh: toNumber(row.avg_speed_kmh),
    gross_revenue: toNumber(row.gross_revenue),
    last_trip_at: row.last_trip_at,
  }));
}

module.exports = {
  clampInt,
  getRoutePerformance,
};
