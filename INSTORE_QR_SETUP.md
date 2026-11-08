# Existing in-store QR: real wallet top-ups without a live API key

The new flow receives signed live `payment.paid` notifications. It does not
generate a QR, retrieve payments or call the PayMongo API. The existing white
QR page with a blue Done button remains at:

https://todago-qrph.johnmejio11.chatgpt.site/

## Activation and reset

Deploy this revision with the approved `WALLET_RESET_REQUEST_ID` to apply the
one-time wallet reset. Verify its audit summary in Railway's deployment logs.
New top-ups remain disabled until the verified merchant QR ID and the
endpoint-specific live signing secret are configured. Deployment or a wallet
reset alone does not enable real-money top-ups.

## PayMongo and Railway setup

1. Keep the existing TodaGo in-store QR. Confirm its identifier from PayMongo,
   preferably `data.attributes.data.attributes.source.provider.code_id` in a
   genuine `payment.paid` delivery. The uploaded QR image does not establish this
   field. Do not assume that a standee image name or a dashboard resource ID is
   interchangeable with the event's QR code ID.
2. In the PayMongo dashboard's live Webhooks module, prepare a separate endpoint:
   `https://todago-backend-production.up.railway.app/api/wallet/in-store-qr/webhook`.
   Subscribe to `payment.paid`. Configure it after deploying the receiver; do not
   make a real payment while the app/backend are still unconfigured.
3. Store that endpoint's signing secret privately on the Railway **Todago-Backend**
   service as `PAYMONGO_INSTORE_WEBHOOK_SECRET`. Use its signing secret, not an API
   key. Do not put it in Flutter, the static site, source control or chat.
4. Set `PAYMONGO_INSTORE_QR_ID` to the verified event QR ID and
   `PAYMONGO_WALLET_QR_MODE=merchant_webhook` on that same service.
   The existing API key and old checkout webhook settings are independent and
   need not be removed to use this new flow.
5. Deploy the tested backend and install Flutter version code **3**. Before
   accepting passenger top-ups, complete a controlled payment yourself and verify
   that the bank receipt's reference equals the event's `external_reference_number`,
   that `paid_at` is present, and that the QR ID matches the configured value.

Official references:
[dashboard webhooks](https://docs.paymongo.com/docs/developer-tools-dashboard-module-create-a-webhook),
[signature verification](https://docs.paymongo.com/docs/developer-tools-webhook-setup-management),
[QR Ph event fields](https://docs.paymongo.com/docs/developer-tools-webhooks-events).

## Passenger flow

1. Enter a custom peso amount with up to two decimal places (PHP 20–50,000).
   There are no preset amount buttons.
2. Top-Up Now creates/reuses a pending backend request, then opens the separate
   QR page inside TodaGo. Pay the exact requested amount using a bank/e-wallet.
3. Done only returns to the receipt-reference form. It never adds funds.
4. Enter the transaction reference from the payment receipt. The request stays
   pending until it matches a signed live PHP payment for the configured QR,
   exact amount and request time window. Either arrival order is supported.
5. Only that confirmed payment completes the ledger row. The wallet refreshes
   from the server. Pending requests can be reopened from transaction history.

Receipt references are treated as private proof of payment: do not expose a
merchant-wide list to passengers. One payment ID can fund only one ledger row.
Multiple matching claims/references, missing reference/timestamp fields,
inactive recipients, amount mismatches and old receipts require investigation;
the code does not choose a passenger by amount. Requests expire after 24 hours.
Reference changes are bounded, and the authenticated reference endpoint is rate limited.

The receiver verifies the exact raw JSON bytes and the live HMAC signature with
a five-minute delivery timestamp tolerance. Test events and other QR codes are
ignored. Database/configuration failures return an error rather than acknowledging
an unrecorded payment. Duplicate deliveries do not duplicate credits. The inbox
retains only payment/event IDs, QR ID, normalized reference, amount and timestamps.

## Authorized fresh start: accounts and rides retained

The user requested resetting the backend passenger wallets while keeping
accounts and rides. The prepared operator-only startup migration is activated
by a unique `WALLET_RESET_REQUEST_ID` on the backend service.

- It locks financial writes, saves an atomic database audit backup in
  `wallet_reset_runs`, cancels pending wallet requests and archives old wallet history.
- It adds balancing ledger adjustments so every passenger wallet starts at zero.
  Accounts, rides, historical payment proofs, driver earnings and payout records
  are retained; no financial rows are hard-deleted.
- A restart with the same reset ID does nothing. New money received after the
  first reset is preserved. Do not change the reset ID unless another reset is intended.
- The new app clears only retired `todago_demo_wallet_v1_` entries on each phone
  when installed/opened. Other preferences and account data remain untouched.

The connector exposes Railway variable names but withholds database credentials;
there is no direct SQL connection available in this workspace. Therefore the
reset runs inside the backend using its existing database connection.
After the approved deployment, verify the reset summary in the Railway logs and
zero passenger balances before enabling new live top-ups.

## Validation limits

Automated tests cover signature verification, both event/reference arrival orders,
ownership, duplicate/replayed payments, ambiguity, centavos, exact amounts,
expired requests, transaction rollback, authenticated HTTP routing and the
idempotent wallet reset. App tests cover custom input, Done remaining pending,
server-only confirmation, old preview cleanup, cancellation and narrow layouts.

The database tests use an isolated transactional adapter, not the production
database. Live notification delivery, reference equality for the merchant account,
physical-device payment authorization and actual settlement still need the
configuration and controlled acceptance check described above. Existing driver
payout restrictions and refund/dispute operations are outside this top-up change.
