const { dbGet } = require('../db/database');

const penaltyDurations = {
  '1h': 60,
  '3h': 180,
  '5h': 300,
  '12h': 720,
  '24h': 1440,
  '1w': 10080,
  permanent: null,
};

function isPenaltyDuration(value) {
  return typeof value === 'string' && Object.hasOwn(penaltyDurations, value);
}

function penaltyTarget(report) {
  if (report.reporter_role === 'driver' && ['passenger', 'commuter'].includes(report.subject_role)) {
    return 'passenger';
  }
  if (['passenger', 'commuter'].includes(report.reporter_role) && report.subject_role === 'driver') {
    return 'driver';
  }
  return null;
}

function penaltyMinutes(target, severity) {
  if (target === 'passenger') return severity === 'severe' ? 60 : 30;
  if (target === 'driver') return severity === 'severe' ? 2880 : 1440;
  return null;
}

async function reviewIssueReport(issueId, { status, adminNotes, penaltyDuration, penaltySeverity = 'standard' }) {
  const report = await dbGet('SELECT * FROM issue_reports WHERE issue_id = $1', [issueId]);
  if (!report) {
    const error = new Error('Report not found');
    error.statusCode = 404;
    throw error;
  }
  const target = penaltyTarget(report);
  if (status === 'validated' && target && !report.subject_id) {
    const error = new Error('This report has no linked account. Identify the reported passenger or driver before applying a penalty.');
    error.statusCode = 422;
    throw error;
  }
  const appliesPenalty = status === 'validated' && target !== null;
  const usesLegacySeverity = appliesPenalty && penaltyDuration === undefined;
  let minutes = null;
  if (appliesPenalty) {
    minutes = usesLegacySeverity ? penaltyMinutes(target, penaltySeverity) : penaltyDurations[penaltyDuration];
  }
  const permanent = appliesPenalty && penaltyDuration === 'permanent';

  // One atomic update records the decision and penalty together. Retrying a
  // validation (even after expiry) never starts the same incident's timer again.
  return dbGet(
    `UPDATE issue_reports
     SET status = $1,
         admin_notes = $2,
         validated_at = CASE WHEN $1 IN ('validated','rejected','resolved')
           THEN COALESCE(validated_at, NOW()) ELSE validated_at END,
         penalty_severity = CASE
           WHEN restriction_until IS NULL AND ($4::integer IS NOT NULL OR $6::boolean) THEN $5
           ELSE penalty_severity END,
         penalty_minutes = CASE
           WHEN restriction_until IS NULL AND ($4::integer IS NOT NULL OR $6::boolean) THEN $4::integer
           ELSE penalty_minutes END,
         restriction_until = COALESCE(restriction_until, CASE
           WHEN $6::boolean THEN 'infinity'::timestamptz
           ELSE NOW() + $4::integer * INTERVAL '1 minute' END),
         updated_at = NOW()
     WHERE issue_id = $3
     RETURNING *, COALESCE(restriction_until = 'infinity'::timestamptz, false) AS penalty_permanent`,
    [status, adminNotes || null, issueId, minutes, usesLegacySeverity ? penaltySeverity : null, permanent]
  );
}

async function getRideRestriction(role, accountId) {
  const roles = role === 'driver' ? ['driver'] : ['passenger', 'commuter'];
  return dbGet(
    `SELECT issue_id, restriction_until, penalty_minutes,
            restriction_until = 'infinity'::timestamptz AS penalty_permanent,
            CASE WHEN isfinite(restriction_until) THEN
              CEIL(EXTRACT(EPOCH FROM (restriction_until - NOW())))::integer
            END AS remaining_seconds
     FROM issue_reports
     WHERE subject_role = ANY($1::text[]) AND subject_id = $2
       AND status IN ('validated','resolved') AND restriction_until > NOW()
     ORDER BY restriction_until DESC
     LIMIT 1`,
    [roles, accountId]
  );
}

function restrictionResponse(role, restriction) {
  const code = role === 'driver' ? 'DRIVER_RIDE_SUSPENDED' : 'PASSENGER_BOOKING_COOLDOWN';
  if (restriction.penalty_permanent) {
    return {
      success: false,
      code,
      message: role === 'driver'
        ? 'An admin-validated report has permanently suspended you from accepting new rides.'
        : 'An admin-validated report has permanently blocked you from booking new rides.',
      permanent: true,
      restrictedUntil: null,
      retryAfterSeconds: null,
    };
  }
  const seconds = Math.max(1, Number(restriction.remaining_seconds));
  const minutes = Math.ceil(seconds / 60);
  return {
    success: false,
    code,
    message: role === 'driver'
      ? `An admin-validated report has temporarily suspended you from accepting new rides. Try again in ${minutes} minute(s).`
      : `An admin-validated report has paused your ride bookings. Try again in ${minutes} minute(s).`,
    restrictedUntil: restriction.restriction_until,
    retryAfterSeconds: seconds,
  };
}

module.exports = { isPenaltyDuration, penaltyTarget, penaltyMinutes, reviewIssueReport, getRideRestriction, restrictionResponse };
