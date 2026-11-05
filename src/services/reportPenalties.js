const { dbGet } = require('../db/database');

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

async function reviewIssueReport(issueId, { status, adminNotes, penaltySeverity = 'standard' }) {
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
  const minutes = status === 'validated' ? penaltyMinutes(target, penaltySeverity) : null;

  // One atomic update records the decision and penalty together. Retrying a
  // validation (even after expiry) never starts the same incident's timer again.
  return dbGet(
    `UPDATE issue_reports
     SET status = $1,
         admin_notes = $2,
         validated_at = CASE WHEN $1 IN ('validated','rejected','resolved')
           THEN COALESCE(validated_at, NOW()) ELSE validated_at END,
         penalty_severity = CASE WHEN $4::integer IS NOT NULL
           THEN COALESCE(penalty_severity, $5) ELSE penalty_severity END,
         penalty_minutes = COALESCE(penalty_minutes, $4::integer),
         restriction_until = CASE WHEN $4::integer IS NOT NULL
           THEN COALESCE(restriction_until, NOW() + $4::integer * INTERVAL '1 minute')
           ELSE restriction_until END,
         updated_at = NOW()
     WHERE issue_id = $3
     RETURNING *`,
    [status, adminNotes || null, issueId, minutes, minutes ? penaltySeverity : null]
  );
}

async function getRideRestriction(role, accountId) {
  const roles = role === 'driver' ? ['driver'] : ['passenger', 'commuter'];
  return dbGet(
    `SELECT issue_id, restriction_until, penalty_minutes,
            CEIL(EXTRACT(EPOCH FROM (restriction_until - NOW())))::integer AS remaining_seconds
     FROM issue_reports
     WHERE subject_role = ANY($1::text[]) AND subject_id = $2
       AND status IN ('validated','resolved') AND restriction_until > NOW()
     ORDER BY restriction_until DESC
     LIMIT 1`,
    [roles, accountId]
  );
}

function restrictionResponse(role, restriction) {
  const seconds = Math.max(1, Number(restriction.remaining_seconds));
  const minutes = Math.ceil(seconds / 60);
  return {
    success: false,
    code: role === 'driver' ? 'DRIVER_RIDE_SUSPENDED' : 'PASSENGER_BOOKING_COOLDOWN',
    message: role === 'driver'
      ? `An admin-validated report has temporarily suspended you from accepting new rides. Try again in ${minutes} minute(s).`
      : `An admin-validated report has paused your ride bookings. Try again in ${minutes} minute(s).`,
    restrictedUntil: restriction.restriction_until,
    retryAfterSeconds: seconds,
  };
}

module.exports = { penaltyTarget, penaltyMinutes, reviewIssueReport, getRideRestriction, restrictionResponse };
