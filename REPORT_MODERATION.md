# Report validation and ride restrictions

Reports submitted to `POST /api/reports` start as pending and appear in the
admin dashboard's Reports for Validation queue. Trip reports identify the
reported account from the trip's participants. Only an authenticated admin can
validate reports through `PATCH /api/admin/reports/:issueId/status`.

When validating a passenger/driver incident, the admin selects `penaltySeverity`:

| Report | Standard | Severe |
| --- | --- | --- |
| Driver reports passenger | 30-minute booking cooldown | 1-hour booking cooldown |
| Passenger reports driver | 1-day ride suspension | 2-day ride suspension |

Omitting severity defaults to standard for older clients. System and operator
reports remain available for admin review without automatically imposing these
passenger/driver penalties. Passenger/driver incidents now require a trip: select
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

The timer starts when the admin validates the report. The report decision,
severity, duration, and expiry are saved in one atomic update. Retrying or
revalidating the same incident preserves its original expiry. With multiple
incidents, the latest active expiry applies. Marking a report resolved retains
its penalty until expiry; rejecting or reopening it removes it from the active
restriction checks.

Passenger cooldowns block both instant and scheduled new bookings with all
drivers. Suspended drivers are excluded from matching, cannot go online, cannot
receive pending requests, and cannot accept or start an unaccepted ride through
the trip status endpoint. Already accepted rides can still be finished or
cancelled. All restrictions expire through database time checks, without a
scheduled job. API denials include `restrictedUntil` and `retryAfterSeconds`.

New cooldown requests replace the previous permanent blacklist approval action.
Historical entries in `passenger_blacklist` continue to be enforced separately;
this change does not delete historical admin decisions.

Database initialization adds the report penalty columns and lookup index on
backend startup. Deploy the backend before distributing the updated Flutter app.
Tests use isolated database adapters; they do not modify production reports or
accounts.
