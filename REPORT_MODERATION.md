# Report validation and ride restrictions

Reports submitted to `POST /api/reports` start as pending and appear in the
admin dashboard's Reports for Validation queue. Trip reports identify the
reported account from the trip's participants. Only an authenticated admin can
validate reports through `PATCH /api/admin/reports/:issueId/status`.

When validating a passenger or driver incident, the admin chooses 1 hour,
3 hours, 5 hours, 12 hours, 24 hours, 1 week, or Permanent. The app sends the
choice as `penaltyDuration` (`1h`, `3h`, `5h`, `12h`, `24h`, `1w`, or `permanent`).

Older clients can still send `penaltySeverity` and default to standard when they
omit it. Admins can review system and operator reports without applying these
penalties. Passenger and driver incidents require a trip. Select
one in the dashboard report sheet or use Report Passenger/Report Driver on the
trip or completed-trip screen. The API verifies that the reporter owns the trip
and derives the other participant's ID and name, ignoring client-supplied targets.
General "Other" reports may still be submitted without a trip.

Older dashboard reports with no trip or account ID cannot be linked reliably.
The reporter must submit the incident again with the correct trip selected;
do not infer a person from names or the reporter's latest trip.

## Feedback after payment

After payment collection completes the ride, both roles can submit a 1–5 star
rating and report the other participant. Rating submission leaves Report
Passenger/Report Driver available. Passengers can also use Bookings > Past;
drivers can use Past Trips on their dashboard.

`POST /api/trips/:tripId/rate` and `GET /api/trips/:tripId/rating` use the
authenticated role to select the participant's own feedback. Passenger-to-driver
ratings remain in `feedback` and update the driver's average. Driver-to-passenger
ratings use the new `passenger_feedback` table and do not change driver averages.
Only participants in a completed, paid trip may submit ratings, once per role
per trip. Rating writes and driver averages commit together, with row locks
preventing duplicate concurrent submissions.

The restriction starts when the admin validates the report. The report decision
and restriction are saved in one atomic update. Retrying or revalidating the
same incident preserves its original duration. With multiple incidents, a
permanent restriction takes precedence, followed by the latest active expiry.
Marking a report resolved retains its penalty. Rejecting or reopening it
removes it from the active restriction checks.

Passenger cooldowns block both instant and scheduled new bookings with all
drivers. Suspended drivers are excluded from matching, cannot go online, cannot
receive pending requests, and cannot accept or start an unaccepted ride through
the trip status endpoint. Already accepted rides can still be finished or
cancelled. Time-limited restrictions expire through database time checks. API
denials include `restrictedUntil` and `retryAfterSeconds`. Permanent denials
return `permanent: true` with both timing fields set to `null`.

## Review history and undoing a penalty

Admins can open **Reports > Report History** to browse validated, rejected,
resolved, reopened, and penalty-undone reports. The list is paginated without
the pending queue's 100-report cap. Each report has a chronological review trail
with the decision, admin account identifier, timestamp, notes, and original
penalty. Rejected reports can be reopened for a new review, with the earlier
rejection preserved.

`GET /api/admin/reports/history` accepts `status` (`all`, `validated`, `rejected`,
`resolved`, `pending`, or `revoked`), `offset`, and `limit` (default 25, maximum
100). `GET /api/admin/reports/:issueId/history` returns the report and its review
events. Existing decisions are imported once as `legacy_review`; an unknown
reviewer or a review trail that was never recorded is not fabricated. The admin
identifier represents the authenticated account; shared admin credentials do
not identify an individual person.

`POST /api/admin/reports/:issueId/undo-penalty` requires a nonblank `reason` of
up to 800 characters. It revokes a timed or permanent penalty for that incident
and appends the reversal to history. The original report status, duration, and
review notes remain available. Repeated undo requests are idempotent. A revoked
penalty stays revoked even if an older client retries validation. Other active
incidents still restrict the account. Enforcement resumes normal booking and
driver availability checks on the next request; it does not automatically set
an offline driver online.

Review changes and their audit events commit in one transaction with a report
row lock. If recording history fails, the decision or reversal is rolled back.

Historical entries in `passenger_blacklist` continue to be enforced separately.

Database initialization adds the report penalty columns and lookup index on
backend startup. Deploy the backend before distributing the updated Flutter app.
Tests use isolated database adapters; they do not modify production reports or
accounts.
