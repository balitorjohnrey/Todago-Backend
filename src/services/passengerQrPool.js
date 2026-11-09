const { pool } = require('../db/database');
const manifest = require('../data/passengerQrPool.json');
const { MAX_AMOUNT } = require('./paymentLimits');

const SITE = 'https://todago-qrph.johnmejio11.chatgpt.site';
const error = (message, statusCode = 422) => Object.assign(new Error(message), { statusCode });
const enabled = () => process.env.PAYMONGO_WALLET_QR_MODE === 'passenger_pool';
const ready = () => enabled() && Boolean(process.env.PAYMONGO_INSTORE_WEBHOOK_SECRET?.trim());

async function transaction(action) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await action(client);
    await client.query('COMMIT');
    return result;
  } catch (cause) {
    await client.query('ROLLBACK');
    throw cause;
  } finally { client.release(); }
}

async function initialize(client) {
  await client.query(`CREATE TABLE IF NOT EXISTS wallet_qr_pool (
    qr_id TEXT PRIMARY KEY,
    label TEXT NOT NULL UNIQUE,
    image_sha256 TEXT NOT NULL CHECK (image_sha256 ~ '^[a-f0-9]{64}$'),
    assigned_user_id TEXT UNIQUE REFERENCES users(id),
    assigned_at TIMESTAMPTZ,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK ((assigned_user_id IS NULL) = (assigned_at IS NULL))
  )`);
  await client.query(`ALTER TABLE wallet_transactions ADD COLUMN IF NOT EXISTS
    pool_qr_id TEXT REFERENCES wallet_qr_pool(qr_id)`);
  await client.query(`ALTER TABLE merchant_qr_payments ADD COLUMN IF NOT EXISTS pool_user_id TEXT REFERENCES users(id)`);
  await client.query(`ALTER TABLE merchant_qr_payments ADD COLUMN IF NOT EXISTS review_reason TEXT`);
  await client.query(`CREATE TABLE IF NOT EXISTS wallet_qr_recoveries (
    payment_id TEXT PRIMARY KEY REFERENCES merchant_qr_payments(payment_id),
    transaction_id TEXT NOT NULL UNIQUE REFERENCES wallet_transactions(transaction_id),
    user_id TEXT NOT NULL REFERENCES users(id),
    request_id TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  for (const entry of manifest.entries) {
    if (!/^qr_[a-z0-9]{24}$/.test(entry.qrId) || !/^[a-f0-9]{64}$/.test(entry.sha256)) {
      throw new Error('Invalid passenger QR pool manifest.');
    }
    await client.query(`INSERT INTO wallet_qr_pool (qr_id, label, image_sha256)
      VALUES ($1,$2,$3) ON CONFLICT (qr_id) DO NOTHING`, [entry.qrId, entry.label, entry.sha256]);
    const existing = (await client.query('SELECT * FROM wallet_qr_pool WHERE qr_id = $1', [entry.qrId])).rows[0];
    if (existing.label !== entry.label || existing.image_sha256 !== entry.sha256) {
      throw new Error('An imported QR cannot be replaced with a different image or label.');
    }
  }
}

// Assignment and receipt ingestion share this lock: a payment received before
// assignment must never become a later passenger's money.
async function lockPool(client) {
  await client.query(`SELECT pg_advisory_xact_lock(hashtextextended('todago-passenger-qr-pool', 0))`);
}

async function assign(userId) {
  if (!ready()) return null;
  return transaction(async client => {
    await lockPool(client);
    const owner = (await client.query(`SELECT id FROM users WHERE id = $1
      AND is_active = true AND role IN ('passenger','commuter') FOR UPDATE`, [userId])).rows[0];
    if (!owner) throw error('Passenger account is unavailable.', 403);
    const current = (await client.query('SELECT * FROM wallet_qr_pool WHERE assigned_user_id = $1', [userId])).rows[0];
    if (current) return current;
    const unused = (await client.query(`SELECT * FROM wallet_qr_pool WHERE assigned_user_id IS NULL
      AND enabled = true ORDER BY label, qr_id LIMIT 1 FOR UPDATE`, [])).rows[0];
    if (!unused) return null;
    return (await client.query(`UPDATE wallet_qr_pool SET assigned_user_id = $2, assigned_at = NOW()
      WHERE qr_id = $1 AND assigned_user_id IS NULL RETURNING *`, [unused.qr_id, userId])).rows[0];
  });
}

async function getPassengerQr(userId) {
  if (!ready()) throw error('QR Ph top-ups are not available yet.', 503);
  const assigned = await assign(userId);
  if (!assigned || !assigned.enabled) return { available: false, testMode: false,
    kind: 'passenger_pool', message: 'Your top-up QR is being prepared. Please try again later.' };
  const latest = (await pool.query(`SELECT transaction_id, provider_payment_id, amount, completed_at
    FROM wallet_transactions WHERE user_id = $1 AND pool_qr_id = $2 AND status = 'completed'
    ORDER BY completed_at DESC, transaction_id DESC LIMIT 1`, [userId, assigned.qr_id])).rows[0];
  return { available: true, testMode: false, kind: 'passenger_pool',
    qrCodeId: assigned.qr_id, qrImageUrl: `${SITE}/${assigned.qr_id}.jpg`,
    qrImageSha256: assigned.image_sha256, qrPageUrl: SITE + '/',
    latestPayment: latest ? { transactionId: latest.transaction_id, paymentId: latest.provider_payment_id,
      amount: Number(latest.amount), completedAt: latest.completed_at } : null };
}

async function receivePaidEvent(event) {
  if (!ready()) throw error('Passenger QR configuration is unavailable.', 503);
  if (event?.type !== 'event' || event.attributes?.type !== 'payment.paid') return false;
  const payment = event.attributes.data;
  const attrs = payment?.attributes;
  const qrId = attrs?.source?.provider?.code_id;
  if (event.attributes.livemode !== true || attrs?.livemode !== true ||
      attrs?.source?.type !== 'qrph' || attrs.origin !== 'instore_qrph' ||
      attrs.organization_id !== manifest.organizationId || !/^qr_[a-z0-9]{24}$/.test(qrId || '')) return false;
  if (!/^evt_[A-Za-z0-9_-]+$/.test(event.id || '') || payment?.type !== 'payment' ||
      !/^pay_[A-Za-z0-9_-]+$/.test(payment?.id || '') || attrs.status !== 'paid' || attrs.currency !== 'PHP' ||
      !Number.isSafeInteger(attrs.amount) || attrs.amount <= 0 || attrs.amount > MAX_AMOUNT * 100 ||
      attrs.disputed === true || (attrs.refunds?.length || 0) > 0) throw error('Invalid live payment event.');
  const paidAt = Number.isSafeInteger(attrs.paid_at) && attrs.paid_at > 0 &&
    attrs.paid_at * 1000 <= Date.now() + 300000 ? new Date(attrs.paid_at * 1000) : null;
  return transaction(async client => {
    await lockPool(client);
    const assigned = (await client.query('SELECT * FROM wallet_qr_pool WHERE qr_id = $1', [qrId])).rows[0];
    if (!assigned) return false;
    await client.query(`INSERT INTO merchant_qr_payments
      (payment_id, event_id, qr_id, reference, amount_cents, paid_at, pool_user_id)
      VALUES ($1,$2,$3,NULL,$4,$5,$6) ON CONFLICT (payment_id) DO NOTHING`,
    [payment.id, event.id, qrId, attrs.amount, paidAt, assigned.assigned_user_id]);
    const stored = (await client.query('SELECT * FROM merchant_qr_payments WHERE payment_id = $1 FOR UPDATE', [payment.id])).rows[0];
    if (!stored || stored.qr_id !== qrId || stored.amount_cents !== attrs.amount ||
      (stored.paid_at ? new Date(stored.paid_at).getTime() : null) !== (paidAt ? paidAt.getTime() : null)) {
      throw error('Conflicting payment event.', 409);
    }
    if (stored.claimed_transaction_id) return true;
    let reason = null;
    if (!stored.pool_user_id || stored.pool_user_id !== assigned.assigned_user_id) reason = 'unassigned_qr';
    else if (!paidAt) reason = 'missing_paid_at';
    else if (Math.floor(new Date(assigned.assigned_at).getTime() / 1000) > attrs.paid_at) reason = 'predates_assignment';
    else if (!assigned.enabled) reason = 'disabled_qr';
    if (!reason) {
      const owner = (await client.query(`SELECT id FROM users WHERE id = $1
        AND is_active = true AND role IN ('passenger','commuter') FOR UPDATE`, [assigned.assigned_user_id])).rows[0];
      if (!owner) reason = 'inactive_passenger';
    }
    const used = (await client.query(`SELECT transaction_id FROM wallet_transactions
      WHERE provider_payment_id = $1 OR external_reference = $1`, [payment.id])).rows[0];
    if (used) reason = 'already_used_payment';
    if (reason) {
      await client.query('UPDATE merchant_qr_payments SET review_reason = $2 WHERE payment_id = $1', [payment.id, reason]);
      return true;
    }
    const row = (await client.query(`INSERT INTO wallet_transactions
      (user_id, type, provider, direction, amount, status, title, description,
       pool_qr_id, provider_payment_id, external_reference, completed_at, created_at)
      VALUES ($1,'topup','qrph','credit',$2,'completed','QR Ph Top-up','Confirmed QR Ph payment',
        $3,$4,$4,NOW(),$5) RETURNING transaction_id`,
    [assigned.assigned_user_id, attrs.amount / 100, qrId, payment.id, paidAt])).rows[0];
    await client.query(`UPDATE merchant_qr_payments SET claimed_transaction_id = $2, review_reason = NULL
      WHERE payment_id = $1 AND claimed_transaction_id IS NULL`, [payment.id, row.transaction_id]);
    return true;
  });
}

// Explicit operator request for the previously paid, shared-QR transaction.
// Uses the server's verified payment inbox; a screenshot cannot create credit.
async function recoverApprovedPayment() {
  const requestId = process.env.WALLET_QR_RECOVERY_REQUEST_ID?.trim();
  if (!requestId) return { status: 'not_requested' };
  const paymentId = process.env.WALLET_QR_RECOVERY_PAYMENT_ID?.trim();
  const transactionId = process.env.WALLET_QR_RECOVERY_TRANSACTION_ID?.trim();
  const email = process.env.WALLET_QR_RECOVERY_EMAIL?.trim().toLowerCase();
  if (!/^pay_[A-Za-z0-9_-]+$/.test(paymentId || '') || !transactionId || !email) throw error('Incomplete wallet recovery configuration.');
  return transaction(async client => {
    await lockPool(client);
    const done = (await client.query('SELECT * FROM wallet_qr_recoveries WHERE request_id = $1', [requestId])).rows[0];
    if (done) return { status: 'already_applied', transactionId: done.transaction_id };
    const payment = (await client.query('SELECT * FROM merchant_qr_payments WHERE payment_id = $1 FOR UPDATE', [paymentId])).rows[0];
    if (!payment) return { status: 'awaiting_verified_webhook' };
    const row = (await client.query(`SELECT wt.*, u.email, r.expires_at FROM wallet_transactions wt
      JOIN users u ON u.id = wt.user_id JOIN merchant_qr_top_up_requests r USING (transaction_id)
      WHERE wt.transaction_id = $1 AND LOWER(u.email) = $2 AND u.is_active = true
      AND u.role IN ('passenger','commuter') FOR UPDATE OF wt, u, r`, [transactionId, email])).rows[0];
    if (!row || row.archived_at || row.merchant_qr !== true || payment.claimed_transaction_id ||
        payment.qr_id !== process.env.PAYMONGO_INSTORE_QR_ID?.trim() ||
        !payment.paid_at || Math.round(Number(row.amount) * 100) !== payment.amount_cents ||
        !['pending', 'cancelled'].includes(row.status) ||
        (row.status === 'cancelled' && row.description !== 'QR Ph top-up expired') ||
        new Date(row.created_at).getTime() > new Date(payment.paid_at).getTime() + 5000 ||
        new Date(row.expires_at) < new Date(payment.paid_at)) throw error('The approved shared-QR payment cannot be reconciled safely.', 409);
    const used = (await client.query(`SELECT transaction_id FROM wallet_transactions
      WHERE provider_payment_id = $1 OR external_reference = $1`, [paymentId])).rows[0];
    if (used) throw error('Payment was already credited.', 409);
    await client.query(`UPDATE wallet_transactions SET status = 'completed', provider_payment_id = $2,
      external_reference = $2, completed_at = NOW(), updated_at = NOW(),
      description = 'Confirmed shared QR Ph payment; account verified by owner'
      WHERE transaction_id = $1`, [transactionId, paymentId]);
    await client.query(`UPDATE merchant_qr_payments SET claimed_transaction_id = $2, review_reason = NULL
      WHERE payment_id = $1 AND claimed_transaction_id IS NULL`, [paymentId, transactionId]);
    await client.query(`INSERT INTO wallet_qr_recoveries (payment_id, transaction_id, user_id, request_id)
      VALUES ($1,$2,$3,$4)`, [paymentId, transactionId, row.user_id, requestId]);
    return { status: 'completed', transactionId, amount: payment.amount_cents / 100 };
  });
}

module.exports = { enabled, ready, initialize, assign, getPassengerQr, receivePaidEvent, recoverApprovedPayment };
