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

Historical entries in `passenger_blacklist` continue to be enforced separately.

Database initialization adds the report penalty columns and lookup index on
backend startup. Deploy the backend before distributing the updated Flutter app.
Tests use isolated database adapters; they do not modify production reports or
accounts.
