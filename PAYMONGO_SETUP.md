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

## Payment methods

`GET /api/wallet/payment-methods` reads PayMongo's `GET /v1/merchants/capabilities/payment_methods` using the backend key. The app offers only configured payment methods: GCash, Maya, GrabPay, ShopeePay, QR Ph, cards and supported online banking identifiers. BNPL methods are excluded from wallet funding.

New methods must first be activated for the merchant account in **PayMongo Settings → Payment Methods → Request Activation**. Request GCash and Maya separately and wait for Active. The app reads current capabilities (cached for 60 seconds) and enables those options automatically. Until then they appear as Unavailable and cannot create payments. An account limited to QR Ph cannot accept direct GCash/Maya payments merely by changing the app. QR Ph lets customers use participating banks and wallets. Direct bank login methods require separate activation.

Saved GCash/Maya account details are optional display records, not verified authorization or a direct debit mandate. Customers authorize the actual payment with PayMongo/the provider on every checkout.

## Merchant identity and checkout appearance

The recipient name in GCash/banking apps comes from the PayMongo merchant account and payment network. `billing.name` is the paying passenger's name; it cannot rename the merchant. In PayMongo Settings → Business information, review the public/trade business name and request TodaGo as the approved merchant display name. Use Settings → Branding for the TodaGo logo and colors where available. If the name is not editable or GCash still shows the individual's name, request a merchant-name update from PayMongo support. A local UI change does not change payment-network identity.

New app versions send `checkoutExperience: "native"` for GCash, Maya and QR Ph. These use the Payment Intent API and a TodaGo-owned checkout screen, so there is no PayMongo Hosted Checkout merchant/reference header. This does not inject CSS or modify provider authentication pages. Other payment methods and older app versions retain Hosted Checkout.

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
3. Use PayMongo's test authorization page to simulate success/failure. Test QR images are hidden; use the **Open test simulator** button when PayMongo returns its documented `test_url`. If no simulator URL is returned, the button remains disabled. Never substitute a real wallet/bank payment to finish a simulated QR test.
4. Confirm a successful simulated payment changes the pending row to completed and credits exactly the expected amount once.
5. Close/cancel an unpaid checkout; balance must stay unchanged. Reopen pending history and retry.
6. Check webhook delivery and repeat the same event: balance must not increase again. A mismatched amount, reference, environment or unsigned payload must never credit funds.

`npm test` covers payment validation, duplicate events, capability filtering, direct wallet/QR intents, missed webhook recovery, expired-session handling and authenticated transaction ownership. Flutter tests cover test QR safety, status-based completion and provider intent/deep-link parsing. Native provider app redirects and merchant activation must also be checked on a device before accepting live payments.

References: [Hosted Checkout](https://docs.paymongo.com/docs/payment-channels-hosted-checkout), [account capabilities](https://docs.paymongo.com/docs/account-settings-account-capabilities), [mobile GCash](https://docs.paymongo.com/docs/payment-acceptance-integrating-gcash-on-mobile), [testing](https://docs.paymongo.com/docs/payment-acceptance-testing).
