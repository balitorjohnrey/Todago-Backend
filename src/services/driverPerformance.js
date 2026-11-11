// A current Performance_Report snapshot is separate from the historical daily
// reports. Payment completion and passenger ratings refresh it in their own
// transaction, so the dashboards never depend on whether a driver was rated.
const SYNC_PERFORMANCE_SQL = `
  INSERT INTO performance_reports
    (driver_id, report_date, report_scope, avg_rating, rating_count,
     total_trips, gross_revenue, refreshed_at)
  SELECT d.driver_id, (NOW() AT TIME ZONE 'Asia/Manila')::date, 'lifetime',
         COALESCE(f.avg_rating, 0), COALESCE(f.rating_count, 0),
         COALESCE(tr.total_trips, 0), COALESCE(tr.gross_revenue, 0), NOW()
  FROM drivers d
  LEFT JOIN LATERAL (
    SELECT ROUND(AVG(rating_score)::numeric, 2) AS avg_rating,
           COUNT(*)::integer AS rating_count
    FROM feedback WHERE driver_id = d.driver_id
  ) f ON true
  LEFT JOIN LATERAL (
    SELECT COUNT(*)::integer AS total_trips, SUM(fare) AS gross_revenue
    FROM trips WHERE driver_id = d.driver_id
      AND status = 'completed' AND payment_status = 'paid'
  ) tr ON true
  WHERE ($1::text IS NULL OR d.driver_id = $1)
  ON CONFLICT (driver_id) WHERE report_scope = 'lifetime'
  DO UPDATE SET report_date = EXCLUDED.report_date,
    avg_rating = EXCLUDED.avg_rating, rating_count = EXCLUDED.rating_count,
    total_trips = EXCLUDED.total_trips, gross_revenue = EXCLUDED.gross_revenue,
    refreshed_at = EXCLUDED.refreshed_at`;

async function syncDriverPerformance(client, driverId = null) {
  return client.query(SYNC_PERFORMANCE_SQL, [driverId]);
}

const DRIVER_VEHICLE = `LEFT JOIN LATERAL (
  SELECT plate_no, vehicle_color FROM tricycles WHERE driver_id = d.driver_id
  ORDER BY created_at DESC, tricycle_id LIMIT 1
) t ON true`;

async function getDriverPerformance(dbAll, { todaId = null, limit = 10 } = {}) {
  return dbAll(`
    SELECT d.driver_id, d.driver_name, d.toda_body_number, d.status,
           ta.association_name, t.plate_no,
           pr.avg_rating, pr.rating_count, pr.total_trips,
           pr.gross_revenue, pr.refreshed_at
    FROM performance_reports pr
    JOIN drivers d ON d.driver_id = pr.driver_id
    LEFT JOIN toda_associations ta ON ta.toda_id = d.toda_id
    ${DRIVER_VEHICLE}
    WHERE pr.report_scope = 'lifetime' AND d.is_active IS NOT FALSE
      AND ($1::text IS NULL OR d.toda_id = $1)
    ORDER BY pr.avg_rating DESC, pr.rating_count DESC, pr.total_trips DESC,
             d.driver_name, d.driver_id
    LIMIT $2`, [todaId, limit]);
}

async function getDriverPerformanceProfile(dbGet, driverId, todaId = null) {
  return dbGet(`
    SELECT d.driver_id, d.driver_name, d.profile_photo_url, d.phone, d.email,
           d.toda_body_number, d.status, d.is_verified,
           ta.association_name, t.plate_no, t.vehicle_color
    FROM drivers d
    LEFT JOIN toda_associations ta ON ta.toda_id = d.toda_id
    ${DRIVER_VEHICLE}
    WHERE d.driver_id = $1 AND d.is_active IS NOT FALSE
      AND ($2::text IS NULL OR d.toda_id = $2)`, [driverId, todaId]);
}

module.exports = { syncDriverPerformance, getDriverPerformance, getDriverPerformanceProfile };
