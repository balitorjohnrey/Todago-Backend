# TodaGo wallet checkout

## Deploy

Deploy this backend revision to the **Todago-Backend** Railway service and rebuild/install the Flutter app. A backend deployment by itself does not update an already installed app. Database initialization updates the wallet provider constraint automatically; it does not credit or delete transactions.

Set these variables on the backend service:

```dotenv
PAYMONGO_SECRET_KEY=sk_test_replace_me
PAYMONGO_WEBHOOK_SECRET=replace_with_the_endpoints_signing_secret
TODAGO_PUBLIC_URL=https://todago-backend-production.up.railway.app
```

Use a separate test environment and database when simulating credits. Test wallet credits are simulated money and must not be carried into a live wallet. Never commit `.env` or put secret keys in Flutter. Dashboard test mode does not change the backend's API key.

## Payment methods

`GET /api/wallet/payment-methods` reads PayMongo's `GET /v1/merchants/capabilities/payment_methods` using the backend key. The app offers only configured payment methods: GCash, Maya, GrabPay, ShopeePay, QR Ph, cards and supported online banking identifiers. BNPL methods are excluded from wallet funding.

New methods must first be activated for the merchant account in **PayMongo Settings → Payment Methods**. An account limited to QR Ph cannot accept GCash merely by choosing GCash in TodaGo. QR Ph lets customers use participating banks and wallets. Direct bank login methods require separate activation.

Saved GCash/Maya account details are optional display records, not verified authorization or a direct debit mandate. Customers authorize the actual payment with PayMongo/the provider on every checkout.

## Return and confirmation

The Android/iOS app opens Hosted Checkout in a WebView. A close button and a **Back to wallet** button remain available. Provider authentication may require opening the provider's app, particularly GCash. The WebView intercepts the configured return URL, and the `todago://wallet` link on the backend return page can reopen TodaGo.

Register a webhook in the same mode as the backend key, pointing to:

```text
https://todago-backend-production.up.railway.app/api/trips/paymongo/webhook
```

Subscribe to `checkout_session.payment.paid`. The wallet-specific `/api/wallet/paymongo/webhook` endpoint is also supported; one endpoint is sufficient. Each webhook has its own signing secret, so use the secret belonging to the endpoint you register. Missing, invalid and wrong-mode signatures are rejected; processing errors return 500 so PayMongo can retry.

The app checks its own transaction through authenticated `GET /api/wallet/top-ups/:transactionId`. The backend retrieves the stored checkout directly from PayMongo and checks the successful payment, session, reference, amount, PHP currency and environment before completing the existing ledger row. A redirect saying `status=success` never credits a wallet. Duplicate confirmations do not create duplicate credits. Wallet refresh also retries recent pending top-ups to recover delayed/missed webhooks.

Closing a checkout does not cancel a payment that might still complete. An expired QR attempt does not cancel an active checkout. Only an expired Checkout Session marks the pending top-up cancelled. Pending transactions can be reopened from wallet history.

## Verify

1. Configure test credentials in an isolated test environment. Build/install the updated Android or iOS app.
2. Start a wallet top-up using an available method. It must open inside TodaGo with a visible return button and a test label when test keys are used.
3. Use PayMongo's test authorization page to simulate success/failure. Do not pay a test QR code using real funds; use PayMongo's documented test URL/simulation.
4. Confirm a successful simulated payment changes the pending row to completed and credits exactly the expected amount once.
5. Close/cancel an unpaid checkout; balance must stay unchanged. Reopen pending history and retry.
6. Check webhook delivery and repeat the same event: balance must not increase again. A mismatched amount, reference, environment or unsigned payload must never credit funds.

`npm test` covers payment validation, duplicate events, capability filtering, missed webhook recovery, expired-session handling and authenticated transaction ownership. Native provider app redirects and merchant activation must also be checked on a device before accepting live payments.

References: [Hosted Checkout](https://docs.paymongo.com/docs/payment-channels-hosted-checkout), [account capabilities](https://docs.paymongo.com/docs/account-settings-account-capabilities), [mobile GCash](https://docs.paymongo.com/docs/payment-acceptance-integrating-gcash-on-mobile), [testing](https://docs.paymongo.com/docs/payment-acceptance-testing).
