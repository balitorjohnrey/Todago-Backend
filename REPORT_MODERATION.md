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
passenger/driver penalties. A report targeting an account without its ID cannot
receive a penalty; submit that incident from the trip screen to link the account.

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
