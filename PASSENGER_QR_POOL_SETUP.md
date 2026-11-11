# Passenger QR pool: manually issued QRs, automatic live credit

The production flow uses dashboard-created In-Store QR Ph codes and signed
`payment.paid` events. It does not generate QRs or call any PayMongo API. The
merchant's real payment sample identified the QR in
`data.attributes.data.attributes.source.provider.code_id`, with `origin` equal
to `instore_qrph`, a unique `pay_...` ID, a PHP amount in centavos and `paid_at`.
Its `external_reference_number` and metadata were null. A GCash receipt reference
therefore cannot be required for this product's automatic crediting.

## Operation

- `PAYMONGO_WALLET_QR_MODE=passenger_pool` selects this flow. Set
  `PAYMONGO_INSTORE_POOL_WEBHOOK_SECRET` on **Todago-Backend** to the current
  account's endpoint signing secret. The existing `PAYMONGO_INSTORE_WEBHOOK_SECRET`
  verifies prior-account deliveries. The receiver uses each secret for its own
  organization and applies a five-minute signature timestamp tolerance.
- Keep the live dashboard webhook subscribed to `payment.paid` at
  `https://todago-backend-production.up.railway.app/api/wallet/in-store-qr/webhook`.
  The MPM Wallet QR product's `qr.paid` event is a different contract.
- On startup `src/data/passengerQrPool.json` defines the current pool. Each
  entry binds a QR ID and internal label to the SHA-256 checksum of the hosted
  download and the issuing PayMongo organization. Payments must match the
  organization recorded for the QR, including retired codes.
- Registration assigns one unused QR under a database lock. Lack of stock does
  not block registration. Existing passengers receive a permanent assignment on
  their first authenticated `GET /api/wallet/in-store-qr/passenger-qr`.
- Each passenger can have one current QR. A retired code keeps its original
  owner for reconciliation, so a payment from a saved copy can still reach the
  right wallet. Retired codes are excluded from new assignments.
- Only a signed live, paid, unrefunded and undisputed PHP payment can credit.
  The amount comes from the payment, never from the phone or Done button. Amounts
  must be positive integer centavos within the existing PHP 50,000 server limit.
- The unique payment ID and transactional inbox/ledger linkage prevent duplicate
  credit. Each later payment to the same QR can credit again. Missing timestamps,
  disabled/inactive recipients and payments predating assignment remain in review.
  A receipt arriving while a QR is unassigned never becomes a future passenger's
  credit, even after a duplicate delivery.
- The app polls its own server every five seconds and on resume. This does not
  poll PayMongo. The page stays in-app; Download QR saves the exact hosted image
  in Android Photos after verifying its checksum. Done returns to the wallet.
- Old amount/reference creation routes are blocked in pool mode. Historical
  records and the one-time reset audit are retained. Do not change the existing
  `WALLET_RESET_REQUEST_ID` or reset wallets again.

## Replenishing stock

1. Manually create additional enabled In-Store QRs in the same PayMongo account.
   Keep the original images and record each unique ID and internal label.
2. Add the original JPGs, IDs and checksums to the separate QR site's allowlist
   and `dist/qr-pool.json`. Validate and publish that site first.
3. Add the identical entries to the backend manifest, run tests and deploy.
   Keep the current entries in the manifest when adding stock.
4. New registration/top-up requests can use the new stock. Empty stock leaves
   top-up unavailable and shows that a QR is being prepared.

## Replacing the pool

1. Verify each replacement decodes to the original payment data. Record the
   checksums of the final downloadable images in both manifests.
2. Publish a QR site version serving both sets of images during the rollout.
3. Set `WALLET_QR_ROTATION_PRIORITY_EMAIL` on the backend service to reserve the
   first available replacement for a specific active passenger. Deploy the
   backend manifest with only the replacement entries. Startup imports the new
   stock, retires the removed codes, and assigns replacements to eligible former
   holders in their original assignment order after the priority passenger.
4. Confirm the rotation and inventory in Railway startup logs. Publish the final
   QR site version with only the replacement images and verify their download
   checksums.

## Recovering the earlier shared-QR payment

The owner identified the intended passenger account for the existing PHP 20
payment. A separate, explicit startup request uses `WALLET_QR_RECOVERY_REQUEST_ID`,
`WALLET_QR_RECOVERY_PAYMENT_ID`, `WALLET_QR_RECOVERY_TRANSACTION_ID` and
`WALLET_QR_RECOVERY_EMAIL`. It requires a payment already in the verified server
inbox and checks the exact account, transaction, gross amount, shared QR and
payment/request timestamps. It cannot create credit from an uploaded receipt.
An audited `wallet_qr_recoveries` record makes repeated starts no-ops. The request
does not match any other shared-QR payment by amount or assign the shared QR.

## Verification limits

Node tests cover assignment, concurrency, idempotence, ownership, live event
validation, database rollback and recovery. Their transaction adapter is isolated;
production migrations and recovery must also be checked in deployment logs.
Flutter tests cover server-only balances, no amount/reference form, session-bound
navigation/downloads, checksum validation, empty stock and narrow layouts.
Physical-device Photos/Gallery visibility and the first new-pool PayMongo payment
still require an owner acceptance check after deployment and app installation.
