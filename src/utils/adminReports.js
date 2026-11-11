const { v4: uuidv4 } = require('uuid');
const { dbRun, dbGet } = require('../db/database');
const defaultDatabase = { dbRun, dbGet };

const DEFAULT_SERVICE_AREAS = [
  {
    name: 'Panabo City',
    minLat: 7.16,
    maxLat: 7.42,
    minLng: 125.52,
    maxLng: 125.86,
  },
  {
    name: 'Carmen',
    minLat: 7.28,
    maxLat: 7.56,
    minLng: 125.52,
    maxLng: 125.90,
  },
];

function parseServiceAreas() {
  const raw = process.env.TODAGO_SERVICE_AREAS_JSON;
  if (!raw) return DEFAULT_SERVICE_AREAS;

  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed) || parsed.length === 0) {
      return DEFAULT_SERVICE_AREAS;
    }
    const valid = parsed
      .map((area) => ({
        name: String(area.name || 'Service Area'),
        minLat: Number.parseFloat(area.minLat),
        maxLat: Number.parseFloat(area.maxLat),
        minLng: Number.parseFloat(area.minLng),
        maxLng: Number.parseFloat(area.maxLng),
      }))
      .filter((area) =>
        Number.isFinite(area.minLat) &&
        Number.isFinite(area.maxLat) &&
        Number.isFinite(area.minLng) &&
        Number.isFinite(area.maxLng) &&
        area.minLat >= -90 && area.maxLat <= 90 && area.minLat <= area.maxLat &&
        area.minLng >= -180 && area.maxLng <= 180 && area.minLng <= area.maxLng
      );
    return valid.length ? valid : DEFAULT_SERVICE_AREAS;
  } catch {
    return DEFAULT_SERVICE_AREAS;
  }
}

function isWithinArea(lat, lng, area) {
  return lat >= area.minLat &&
    lat <= area.maxLat &&
    lng >= area.minLng &&
    lng <= area.maxLng;
}

function serviceAreaFor(lat, lng) {
  const areas = parseServiceAreas();
  return areas.find((area) => isWithinArea(lat, lng, area)) || null;
}

async function createIssueReport({
  reporterRole = 'system',
  reporterId = null,
  reporterName = null,
  reportType,
  subjectRole = null,
  subjectId = null,
  subjectName = null,
  tripId = null,
  title,
  details = null,
  metadata = {},
  priority = 'normal',
}, database = defaultDatabase) {
  const issueId = uuidv4();
  await database.dbRun(
    `INSERT INTO issue_reports
      (issue_id, reporter_role, reporter_id, reporter_name,
       report_type, subject_role, subject_id, subject_name, trip_id,
       title, details, metadata, priority)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13)`,
    [
      issueId,
      reporterRole,
      reporterId,
      reporterName,
      reportType,
      subjectRole,
      subjectId,
      subjectName,
      tripId,
      title,
      details,
      JSON.stringify(metadata || {}),
      priority,
    ]
  );

  return database.dbGet(
    `SELECT * FROM issue_reports WHERE issue_id = $1`,
    [issueId]
  );
}

async function recordLocationAlert(driverId, lat, lng, context, config, database) {
  const metadata = {
    lat, lng, source: context.source || 'driver_location',
    observed_at: new Date().toISOString(), ...config.metadata,
  };
  const recent = await database.dbGet(
    `SELECT issue_id, subject_name
     FROM issue_reports
     WHERE report_type = $3
       AND reporter_role = 'system'
       AND subject_role = 'driver'
       AND subject_id = $1
       AND trip_id IS NOT DISTINCT FROM $2::text
       AND COALESCE(metadata->>'route_leg', '') = $4
       AND status = 'pending'
       AND created_at > NOW() - INTERVAL '30 minutes'
     ORDER BY created_at DESC
     LIMIT 1`,
    [driverId, context.tripId || null, config.reportType, config.metadata.route_leg || '']
  );
  if (recent) {
    await database.dbRun(`UPDATE issue_reports
      SET metadata = metadata || $2::jsonb, details = $3, updated_at = NOW()
      WHERE issue_id = $1`, [recent.issue_id, JSON.stringify(metadata),
      `${recent.subject_name || 'Driver'} ${config.details}`]);
    return { outside: true, saved: false, issueId: recent.issue_id };
  }

  const driver = await database.dbGet(
    `SELECT d.driver_name, d.toda_body_number, t.plate_no,
            ta.association_name, ta.association_code
     FROM drivers d
     LEFT JOIN tricycles t ON t.driver_id = d.driver_id
     LEFT JOIN toda_associations ta ON ta.toda_id = d.toda_id
     WHERE d.driver_id = $1`,
    [driverId]
  );

  const driverLabel = driver?.driver_name || 'Driver';
  const vehicle = [
    driver?.toda_body_number,
    driver?.plate_no,
  ].filter(Boolean).join(' / ');
  const report = await createIssueReport({
    reporterRole: 'system',
    reportType: config.reportType,
    subjectRole: 'driver',
    subjectId: driverId,
    subjectName: vehicle ? `${driverLabel} (${vehicle})` : driverLabel,
    tripId: context.tripId || null,
    title: config.title,
    details: `${driverLabel} ${config.details}`,
    metadata: {
      ...metadata,
      first_observed_at: metadata.observed_at,
      association_name: driver?.association_name || null,
      association_code: driver?.association_code || null,
    },
    priority: 'high',
  }, database);

  return { outside: true, saved: true, issueId: report.issue_id };
}

async function recordDriverServiceAreaAlert(driverId, lat, lng, context = {}, database = defaultDatabase) {
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) return { outside: false, saved: false };
  const area = serviceAreaFor(lat, lng);
  if (area) return { outside: false, saved: false, matchedArea: area.name };
  return recordLocationAlert(driverId, lat, lng, context, {
    reportType: 'driver_outside_service_area',
    title: 'Driver outside configured service area',
    details: 'reported GPS coordinates outside the configured service areas.',
    metadata: { allowed_areas: parseServiceAreas() },
  }, database);
}

async function recordDriverRouteAlert(driverId, lat, lng, context, database = defaultDatabase) {
  return recordLocationAlert(driverId, lat, lng, context, {
    reportType: 'driver_route_deviation', title: 'Driver outside designated route',
    details: `is ${Math.round(context.distanceMeters)} meters from the designated route.`,
    metadata: { route_leg: context.routeLeg, route_distance_m: context.distanceMeters,
      tolerance_m: context.toleranceMeters },
  }, database);
}

module.exports = {
  createIssueReport,
  recordDriverServiceAreaAlert,
  recordDriverRouteAlert,
  serviceAreaFor,
};
