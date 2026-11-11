const crypto = require('node:crypto');
const { pool } = require('../db/database');
const { amountInCentavos, MIN_TOP_UP, MAX_AMOUNT } = require('./paymentLimits');

const QR_PAGE_URL = 'https://todago-qrph.johnmejio11.chatgpt.site/';
const REQUEST_LIFETIME_MS = 24 * 60 * 60 * 1000;

function failure(message, statusCode = 422) {
  return Object.assign(new Error(message), { statusCode });
}

function normalizeReference(value) {
  if (typeof value !== 'string' || value.length > 120) return null;
  const normalized = value.trim().replace(/[ -]/g, '').toUpperCase();
  return /^[A-Z0-9_]{6,100}$/.test(normalized) ? normalized : null;
}

function configuration() {
  const qrId = process.env.PAYMONGO_INSTORE_QR_ID?.trim();
  const secret = process.env.PAYMONGO_INSTORE_WEBHOOK_SECRET?.trim();
  const enabled = ['merchant_webhook', 'passenger_pool'].includes(process.env.PAYMONGO_WALLET_QR_MODE);
  return { qrId, secret, ready: enabled && /^(?:qr|code)_[A-Za-z0-9_-]+$/.test(qrId || '') && Boolean(secret) };
}

function requireConfiguration() {
  const config = configuration();
  if (!config.ready) throw failure('QR Ph top-ups are not available yet. Please try again later.', 503);
  return config;
}

// This endpoint has its own signing secret and live-mode check. It neither
// reads a PayMongo API key nor changes the authentication of older checkouts.
function verifyLiveSignature(rawBody, signature, now = Date.now(), secret = configuration().secret) {
  if (!secret || !Buffer.isBuffer(rawBody) || typeof signature !== 'string') return false;
  const entries = signature.split(',').map(part => part.trim().split('='));
  if (entries.some(entry => entry.length !== 2)) return false;
  const parts = Object.fromEntries(entries);
  if (new Set(entries.map(([key]) => key)).size !== entries.length ||
      !/^\d{10}$/.test(parts.t || '') || !/^[a-fA-F0-9]{64}$/.test(parts.li || '') ||
      Math.abs(now / 1000 - Number(parts.t)) > 300) return false;
  const expected = crypto.createHmac('sha256', secret).update(parts.t).update('.').update(rawBody).digest();
  return crypto.timingSafeEqual(expected, Buffer.from(parts.li, 'hex'));
}

async function transaction(action) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await action(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }
}

async function lockReference(client, reference) {
  // The same lock order is used by receipt submissions and incoming webhooks.
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`todago-merchant-qr:${reference}`]);
}

async function lockPassenger(client, userId, allowUnavailable = false) {
  const passenger = (await client.query(`SELECT id FROM users WHERE id = $1
    AND is_active = true AND role IN ('passenger','commuter') FOR UPDATE`, [userId])).rows[0];
  if (!passenger && !allowUnavailable) throw failure('Passenger account is unavailable.', 403);
  return Boolean(passenger);
}

function presentation(row) {
  return { transactionId: row.transaction_id, status: row.status, testMode: false,
    payment: { kind: 'merchant_qr', provider: 'qrph', amount: Number(row.amount),
      currency: 'PHP', status: row.status, reference: row.reference || null,
      qrPageUrl: QR_PAGE_URL, expiresAt: row.expires_at, requiresReference: true } };
}

async function createTopUp(userId, amount) {
  requireConfiguration();
  const cents = amountInCentavos(amount, MIN_TOP_UP);
  if (cents === null) throw failure(`Choose an amount between PHP ${MIN_TOP_UP} and PHP ${MAX_AMOUNT}.`);
  return transaction(async client => {
    await lockPassenger(client, userId);
    await client.query(`UPDATE wallet_transactions wt SET status = 'cancelled', updated_at = NOW(),
      description = 'QR Ph top-up expired'
      FROM merchant_qr_top_up_requests r WHERE wt.transaction_id = r.transaction_id
      AND wt.user_id = $1 AND wt.status = 'pending' AND r.expires_at < NOW()`, [userId]);
    const pending = (await client.query(`SELECT wt.*, r.reference, r.expires_at
      FROM wallet_transactions wt JOIN merchant_qr_top_up_requests r USING (transaction_id)
      WHERE wt.user_id = $1 AND wt.status = 'pending' FOR UPDATE OF wt, r`, [userId])).rows[0];
    if (pending) return presentation(pending);
    const row = (await client.query(`INSERT INTO wallet_transactions
      (user_id, type, provider, direction, amount, status, title, description, merchant_qr)
      VALUES ($1,'topup','qrph','credit',$2,'pending','QR Ph Top-up','Awaiting payment confirmation',true)
      RETURNING *`, [userId, cents / 100])).rows[0];
    const request = (await client.query(`INSERT INTO merchant_qr_top_up_requests (transaction_id)
      VALUES ($1) RETURNING reference, expires_at`, [row.transaction_id])).rows[0];
    return presentation({ ...row, ...request });
  });
}

async function readTopUp(userId, id) {
  return transaction(async client => {
    const row = (await client.query(`SELECT wt.*, r.reference, r.expires_at
      FROM wallet_transactions wt JOIN merchant_qr_top_up_requests r USING (transaction_id)
      WHERE wt.transaction_id = $1 AND wt.user_id = $2`, [id, userId])).rows[0];
    if (!row) throw failure('Top-up not found.', 404);
    if (row.status === 'pending' && new Date(row.expires_at).getTime() < Date.now()) {
      await client.query(`UPDATE wallet_transactions SET status = 'cancelled', updated_at = NOW(),
        description = 'QR Ph top-up expired' WHERE transaction_id = $1 AND status = 'pending'`, [id]);
      // A webhook might have completed the row while this request was waiting.
      row.status = (await client.query('SELECT status FROM wallet_transactions WHERE transaction_id = $1', [id])).rows[0].status;
    }
    return presentation(row);
  });
}

async function matchReference(client, reference) {
  const payments = (await client.query(`SELECT * FROM merchant_qr_payments
    WHERE reference = $1 FOR UPDATE`, [reference])).rows;
  if (payments.length === 0) return 'pending';
  if (payments.length !== 1) return 'review';
  const payment = payments[0];
  if (payment.claimed_transaction_id) return 'claimed';
  if (!payment.paid_at) return 'review';
  const candidates = (await client.query(`SELECT wt.transaction_id, wt.user_id, wt.amount,
    wt.created_at, r.expires_at FROM wallet_transactions wt
    JOIN merchant_qr_top_up_requests r USING (transaction_id)
    WHERE r.reference = $1 AND wt.status = 'pending'
      AND ROUND(wt.amount * 100) = $2
      AND wt.created_at <= $3::timestamptz + INTERVAL '5 seconds'
      AND r.expires_at >= $3::timestamptz`, [reference, payment.amount_cents, payment.paid_at])).rows;
  // Ambiguous claims always require review; never pick a passenger by amount.
  if (candidates.length !== 1) return candidates.length ? 'review' : 'pending';
  const candidate = candidates[0];
  if (!await lockPassenger(client, candidate.user_id, true)) return 'review';
  const current = (await client.query(`SELECT wt.*, r.reference, r.expires_at
    FROM wallet_transactions wt JOIN merchant_qr_top_up_requests r USING (transaction_id)
    WHERE wt.transaction_id = $1 FOR UPDATE OF wt, r`, [candidate.transaction_id])).rows[0];
  if (!current || current.status !== 'pending' || current.reference !== reference ||
      amountInCentavos(current.amount, MIN_TOP_UP) !== payment.amount_cents ||
      new Date(current.created_at).getTime() > new Date(payment.paid_at).getTime() + 5000 ||
      new Date(current.expires_at) < new Date(payment.paid_at)) return 'pending';
  const used = (await client.query(`SELECT transaction_id FROM wallet_transactions
    WHERE provider_payment_id = $1 OR external_reference = $1`, [payment.payment_id])).rows[0];
  if (used) return 'claimed';
  await client.query(`UPDATE wallet_transactions SET status = 'completed', provider_payment_id = $2,
    external_reference = $3, completed_at = NOW(), updated_at = NOW(),
    description = 'Confirmed in-store QR Ph payment'
    WHERE transaction_id = $1 AND status = 'pending'`, [current.transaction_id, payment.payment_id, reference]);
  await client.query(`UPDATE merchant_qr_payments SET claimed_transaction_id = $2
    WHERE payment_id = $1 AND claimed_transaction_id IS NULL`, [payment.payment_id, current.transaction_id]);
  return 'completed';
}

async function submitReference(userId, id, value) {
  requireConfiguration();
  const reference = normalizeReference(value);
  if (!reference) throw failure('Enter the complete transaction reference from your payment receipt.');
  return transaction(async client => {
    await lockReference(client, reference);
    await lockPassenger(client, userId);
    const row = (await client.query(`SELECT wt.*, r.reference, r.expires_at, r.claim_attempts
      FROM wallet_transactions wt JOIN merchant_qr_top_up_requests r USING (transaction_id)
      WHERE wt.transaction_id = $1 AND wt.user_id = $2 FOR UPDATE OF wt, r`, [id, userId])).rows[0];
    if (!row) throw failure('Top-up not found.', 404);
    if (row.status !== 'pending') return presentation(row);
    if (new Date(row.expires_at).getTime() < Date.now()) throw failure('This top-up has expired. Please contact support if you have paid.', 409);
    if (row.reference !== reference) {
      if (row.claim_attempts >= 8) throw failure('Too many reference changes. Please contact support.', 429);
      await client.query(`UPDATE merchant_qr_top_up_requests SET reference = $2,
        claim_attempts = claim_attempts + 1 WHERE transaction_id = $1`, [id, reference]);
    }
    const result = await matchReference(client, reference);
    const updated = (await client.query(`SELECT wt.*, r.reference, r.expires_at
      FROM wallet_transactions wt JOIN merchant_qr_top_up_requests r USING (transaction_id)
      WHERE wt.transaction_id = $1 AND wt.user_id = $2`, [id, userId])).rows[0];
    return { ...presentation(updated), reviewRequired: result === 'review',
      message: updated.status === 'completed' ? 'Payment confirmed. Your wallet has been updated.'
        : result === 'review' || result === 'claimed' ? 'This payment needs review. Please contact support.'
          : 'Reference submitted. Waiting for a matching payment confirmation.' };
  });
}

async function receivePaidEvent(event) {
  const { qrId } = requireConfiguration();
  if (event?.type !== 'event' || event.attributes?.type !== 'payment.paid') return false;
  const payment = event.attributes.data;
  const attrs = payment?.attributes;
  if (event.attributes.livemode !== true || attrs?.livemode !== true ||
      attrs?.source?.type !== 'qrph' || attrs?.source?.provider?.code_id !== qrId) return false;
  if (!/^evt_[A-Za-z0-9_-]+$/.test(event.id || '') || !/^pay_[A-Za-z0-9_-]+$/.test(payment?.id || '') ||
      attrs.status !== 'paid' || attrs.currency !== 'PHP' ||
      !Number.isSafeInteger(attrs.amount) || attrs.amount <= 0 || attrs.amount > MAX_AMOUNT * 100 ||
      attrs.disputed === true || (attrs.refunds?.length || 0) > 0) throw failure('Invalid payment event.');
  const reference = normalizeReference(attrs.external_reference_number);
  const paidAt = Number.isSafeInteger(attrs.paid_at) && attrs.paid_at > 0 &&
    attrs.paid_at * 1000 <= Date.now() + 300000 ? new Date(attrs.paid_at * 1000) : null;
  await transaction(async client => {
    await lockReference(client, reference || `missing:${payment.id}`);
    await client.query(`INSERT INTO merchant_qr_payments
      (payment_id, event_id, qr_id, reference, amount_cents, paid_at)
      VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (payment_id) DO NOTHING`,
    [payment.id, event.id, qrId, reference, attrs.amount, paidAt]);
    const stored = (await client.query(`SELECT * FROM merchant_qr_payments WHERE payment_id = $1 FOR UPDATE`, [payment.id])).rows[0];
    if (!stored || stored.qr_id !== qrId || stored.reference !== reference || stored.amount_cents !== attrs.amount ||
        (stored.paid_at ? new Date(stored.paid_at).getTime() : null) !== (paidAt ? paidAt.getTime() : null)) {
      throw failure('Conflicting payment event.', 409);
    }
    if (reference) await matchReference(client, reference);
  });
  return true;
}

module.exports = { QR_PAGE_URL, REQUEST_LIFETIME_MS, configuration, requireConfiguration,
  normalizeReference, verifyLiveSignature, createTopUp, readTopUp, submitReference, receivePaidEvent };
