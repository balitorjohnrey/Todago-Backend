const { dbAll } = require('../db/database');

function clampInt(value, fallback, min, max) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function toInt(value, fallback = 0) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function toNumber(value, fallback = 0) {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function hourLabel(hour) {
  const safeHour = clampInt(hour, 0, 0, 23);
  const nextHour = (safeHour + 1) % 24;
  return `${clockLabel(safeHour)} - ${clockLabel(nextHour)}`;
}

function clockLabel(hour) {
  if (hour === 0) return '12 AM';
  if (hour < 12) return `${hour} AM`;
  if (hour === 12) return '12 PM';
  return `${hour - 12} PM`;
}

async function getPeakHourAnalysis({
  driverId = null,
  todaId = null,
  days = 30,
  limit = 6,
} = {}) {
  const safeDays = clampInt(days, 30, 1, 365);
  const safeLimit = clampInt(limit, 6, 1, 24);
  const params = [safeDays, safeLimit];
  let join = '';
  let scopeWhere = '';

  if (driverId) {
    params.push(driverId);
    scopeWhere = 'AND tr.driver_id = $3';
  } else if (todaId) {
    params.push(todaId);
    join = 'JOIN drivers d ON d.driver_id = tr.driver_id';
    scopeWhere = 'AND d.toda_id = $3';
  }

  const rows = await dbAll(
    `
    WITH hourly AS (
      SELECT
        EXTRACT(HOUR FROM tr.request_timestamp AT TIME ZONE 'Asia/Manila')::int
          AS hour_of_day,
        COUNT(*) AS total_requests,
        COUNT(*) FILTER (WHERE tr.status = 'completed') AS completed_trips,
        COUNT(*) FILTER (WHERE tr.status = 'cancelled') AS cancelled_trips,
        ROUND(
          SUM(CASE WHEN tr.status = 'completed' THEN COALESCE(tr.fare, 0) ELSE 0 END)::numeric,
          2
        ) AS gross_revenue,
        MAX(tr.request_timestamp) AS last_request_at
      FROM trips tr
      ${join}
      WHERE tr.request_timestamp >= NOW() - ($1::int * INTERVAL '1 day')
        ${scopeWhere}
      GROUP BY hour_of_day
    )
    SELECT
      hour_of_day,
      total_requests,
      completed_trips,
      cancelled_trips,
      ROUND(
        (100.0 * completed_trips / NULLIF(total_requests, 0))::numeric,
        1
      ) AS completion_rate,
      gross_revenue,
      last_request_at
    FROM hourly
    ORDER BY total_requests DESC, completed_trips DESC, gross_revenue DESC
    LIMIT $2
    `,
    params
  );

  return rows.map((row) => {
    const hour = toInt(row.hour_of_day);
    return {
      hour_of_day: hour,
      hour_label: hourLabel(hour),
      total_requests: toInt(row.total_requests),
      completed_trips: toInt(row.completed_trips),
      cancelled_trips: toInt(row.cancelled_trips),
      completion_rate: toNumber(row.completion_rate),
      gross_revenue: toNumber(row.gross_revenue),
      last_request_at: row.last_request_at,
    };
  });
}

module.exports = {
  clampInt,
  getPeakHourAnalysis,
};
