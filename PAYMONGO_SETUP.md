# TodaGo wallet checkout

## Deploy

Deploy this backend revision to the **Todago-Backend** Railway service and rebuild/install the Flutter app. A backend deployment by itself does not update an already installed app. Database initialization adds an optional payment intent ID and a unique index. Existing Hosted Checkout top-ups continue to work.

Set these variables on the backend service:

```dotenv
PAYMONGO_SECRET_KEY=sk_test_replace_me
PAYMONGO_WEBHOOK_SECRET=replace_with_the_endpoints_signing_secret
TODAGO_PUBLIC_URL=https://todago-backend-production.up.railway.app
```

Use a separate test environment and database when simulating credits. Test wallet credits are simulated money and must not be carried into a live wallet. Never commit `.env` or put secret keys in Flutter. Dashboard test mode does not change the backend's API key.

## QR Ph top-ups

TodaGo offers **QR Ph only** for new top-ups. The minimum is PHP 20, enforced by the API and the app. Presets start at PHP 20. Both GCash and Maya can pay a QR Ph code, as can participating banks; this does not enable their separately activated direct checkout channels.

The passenger wallet no longer displays or collects saved GCash/Maya accounts. Existing saved records and old checkout history are retained for compatibility, not deleted. The QR screen and top-up selector show the GCash/Maya logos as supported scanning apps. On a single phone, customers can use a screenshot with their payment app's scan/upload feature if supported. Payment confirmation remains server-verified.

GET /api/wallet/payment-methods reads merchant capabilities and returns only QR Ph. Creating direct GCash/Maya top-ups is rejected in this version even if a modified client requests one. Past pending Hosted Checkout payments still reconcile normally.

## Merchant identity and checkout appearance

The recipient name in GCash/banking apps comes from the PayMongo merchant account and payment network. `billing.name` is the paying passenger's name; it cannot rename the merchant. In PayMongo Settings → Business information, review the public/trade business name and request TodaGo as the approved merchant display name. Use Settings → Branding for the TodaGo logo and colors where available. If the name is not editable or GCash still shows the individual's name, request a merchant-name update from PayMongo support. A local UI change does not change payment-network identity.

New app versions send `checkoutExperience: "native"` for QR Ph. These use the Payment Intent API and a TodaGo-owned checkout screen, so there is no PayMongo Hosted Checkout merchant/reference header. This does not inject CSS or modify provider authentication pages. Other payment methods and older app versions retain Hosted Checkout.

GCash/Maya redirect pages open in an in-app WebView. GCash's "Open in GCash" button hands the provider's deep link to the OS. Maya currently uses the authorization page supplied by PayMongo; if the provider sends a supported Maya deep link, the app opens it. Do not construct a generic Maya link that lacks payment authorization details or promise the same GCash UI for Maya.

## Return and confirmation

The Android/iOS app keeps a close button and a **Back to wallet** button available. Provider authentication may require opening the provider's app, particularly GCash. The WebView intercepts the configured return URL, and the `todago://wallet` link on the backend return page can reopen TodaGo. App resume also checks the authoritative payment status.

Register a webhook in the same mode as the backend key, pointing to:

```text
https://todago-backend-production.up.railway.app/api/trips/paymongo/webhook
```

Subscribe to `checkout_session.payment.paid` (older/other Hosted Checkout payments), `payment.paid` and `payment.failed` (native Payment API). The wallet-specific `/api/wallet/paymongo/webhook` endpoint is also supported; one endpoint is sufficient. Each webhook has its own signing secret, so use the secret belonging to the endpoint you register. Missing, invalid and wrong-mode signatures are rejected; processing errors return 500 so PayMongo can retry. A native payment event is looked up by its already stored intent ID and retrieved from PayMongo before any credit is created. Events for unrelated payments are ignored.

The app checks its own transaction through authenticated `GET /api/wallet/top-ups/:transactionId`. The backend retrieves the stored checkout directly from PayMongo and checks the successful payment, session, reference, amount, PHP currency and environment before completing the existing ledger row. A redirect saying `status=success` never credits a wallet. Duplicate confirmations do not create duplicate credits. Wallet refresh also retries recent pending top-ups to recover delayed/missed webhooks.

Native top-ups store their Payment Intent ID before attaching the payment method. Status checks retrieve that intent, verify its metadata, environment and successful payment, then match the exact stored intent and peso amount. Attaching a payment method timing out leaves the row pending so a later provider confirmation can still be recovered. Customer responses contain only action URLs, amount, status and QR image data; they never contain the secret API key or intent client key.

Closing a checkout does not cancel a payment that might still complete. An expired QR attempt does not cancel an active checkout. Only an expired Checkout Session marks the pending top-up cancelled. Pending transactions can be reopened from wallet history.

## Verify

1. Configure test credentials in an isolated test environment. Build/install the updated Android or iOS app.
2. Start a wallet top-up using an available method. Native checkout must show TodaGo branding and a return button. Live payments are labelled as using real money; test payments are labelled TEST PAYMENT.
3. Use PayMongo's test authorization page to simulate success/failure. Test QR images are hidden; use **Proceed to Top Up** when PayMongo returns its documented `test_url`. The button is disabled for missing/invalid test links and actions that are no longer active. This still opens PayMongo's official test authorization page; the app does not replace it or fabricate confirmation. PayMongo warns that paying a QR generated in test mode through GCash or a bank can process a real transaction. Only explicitly live responses display payable QRs and supported scanning-app logos. See [PayMongo testing](https://docs.paymongo.com/docs/payment-acceptance-testing).
4. Confirm a successful simulated payment changes the pending row to completed and credits exactly the expected amount once.
5. Close/cancel an unpaid checkout; balance must stay unchanged. Reopen pending history and retry.
6. Check webhook delivery and repeat the same event: balance must not increase again. A mismatched amount, reference, environment or unsigned payload must never credit funds.

`npm test` covers payment validation, duplicate events, capability filtering, direct wallet/QR intents, missed webhook recovery, expired-session handling and authenticated transaction ownership. Flutter tests cover test QR safety, status-based completion and provider intent/deep-link parsing. Native provider app redirects and merchant activation must also be checked on a device before accepting live payments.

References: [Hosted Checkout](https://docs.paymongo.com/docs/payment-channels-hosted-checkout), [account capabilities](https://docs.paymongo.com/docs/account-settings-account-capabilities), [mobile GCash](https://docs.paymongo.com/docs/payment-acceptance-integrating-gcash-on-mobile), [testing](https://docs.paymongo.com/docs/payment-acceptance-testing).

## Manual driver e-wallet cash-out and payout admin

This is a manually funded payout workflow, not a PayMongo disbursement API. It cannot unlock money in a restricted PayMongo merchant wallet. TodaGo staff must have independent funds available to send GCash/Maya payments while merchant verification or settlement is pending. The driver is charged PHP 0; TodaGo covers any provider transfer fees. Never describe external transfer fees as universally free.

Set **PAYOUT_ADMIN_SECRET** privately on the Railway backend. Use a unique strong value different from ADMIN_SECRET/ADMIN_LOGIN_SECRET and the legacy demo login. Do not commit it or put it in Flutter. Enter it in the existing Admin Access screen to open Payout Admin. The standard admin login remains separate. Payout tokens have role payout_admin and cannot manage the normal admin dashboard; normal admin/driver/passenger tokens cannot manage payouts. Rotating the payout secret invalidates existing payout sessions.

Driver flow:
1. Open the wallet icon in the driver dashboard. Confirmed cashless earnings are separate from total earnings (which includes cash already collected).
2. Request at least PHP 50, choose GCash or Maya, and enter the registered account name and 11-digit mobile number.
3. The request reserves the amount immediately. At most one pending/processing request per driver is allowed. Retries reuse a request key, so a timeout does not create a second request.
4. A driver can cancel only while pending. A paid/rejected/cancelled request stays in their history. Their screen refreshes automatically and on app resume.

Payout admin flow:
1. The Pending payouts tab refreshes every 15 seconds. Start processing before manually sending money, so another operator sees the request is in progress.
2. Check the driver's account name, number, amount and your e-wallet transaction history. Send the full requested amount outside TodaGo, covering any provider fee.
3. Only after verifying successful receipt, choose Record successful payment, enter the actual transfer reference and confirm. TodaGo records the payout; it does not send another transfer.
4. The request disappears from Pending payouts and appears in History (latest 100 records). The driver's reserve becomes paid; available balance is not debited twice.
5. Reject a pending request with a reason to release the reserve. For a processing request, use Payment not sent only after verifying no money was sent or a confirmed failure/reversal; never release a transfer that is pending or uncertain.

API:
- GET /api/driver/wallet
- POST /api/driver/wallet/cash-outs (amount, provider, accountName, accountNumber, requestKey)
- POST /api/driver/wallet/cash-outs/:cashoutId/cancel
- GET /api/admin/driver-cashouts?view=active or view=history (payout-admin role only)
- POST /api/admin/driver-cashouts/:cashoutId/review (payout-admin role only)

Driver earnings are inserted once per completed, paid cashless trip, requiring the matching completed passenger-wallet debit or a PayMongo payment ID. Cash trips and unconfirmed trips are excluded. Amounts are reserved using a driver-row database lock; duplicate references are rejected by a unique index. The current fare share remains 100% of the fare, matching the app's existing earnings calculation; TodaGo covers processing costs separately.

## Passenger wallet fare payment

After destination arrival, the passenger selects TodaGo Wallet on the live trip screen and pays from their confirmed wallet balance. Payment debits the exact stored fare and marks the trip paid. The driver then chooses Collect Payment to finish the ride. Completion and the driver earning are committed together, so a credit failure leaves the ride ready to retry without charging the passenger again. The driver wallet refreshes every five seconds while open and reloads on app resume; this is polling, not an instantaneous push notification.

Passenger-row locks serialize wallet spending across different trips. Trip locks and fresh reads protect the fare, payer, payment state and duplicate retries. A paid trip cannot have its payment method reset or be cancelled through the ordinary cancellation endpoint. Repeated driver completion cannot increment trip counts or credit earnings twice. Cash already collected is excluded from the digital wallet. Older confirmed cashless trips are also reconciled when the driver wallet is opened.

`npm test` includes an isolated transactional adapter covering the actual passenger checkout, driver collection, ledger and payout services together. It tests concurrency, insufficient funds, exact amounts, ownership, duplicate completion, cancellation/payment-method races, cash exclusion, shared drop-offs, payment proof and rollback on an earnings write failure. These automated tests do not connect to the production database or transfer money. Physical-device checkout and live provider settlement remain separate acceptance checks.

Registration of the new driver_earnings and driver_cashouts tables is automatic on backend startup. No balances, payments or cash-out records are fabricated for the defense. Cash-out creation is disabled while the payment backend uses test keys. Use an isolated database for any simulated top-ups and never carry test credits into production.
