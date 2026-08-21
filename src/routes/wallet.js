const express = require('express');
const { body, param, validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid');

const { requireAuth } = require('./auth');
const { dbAll, dbGet, dbRun } = require('../db/database');
const {
  createCheckoutSession,
  verifyWebhookSignature,
} = require('../services/paymongo');
const {
  completeWalletTopUp,
  getWalletBalance,
} = require('../services/walletLedger');

const router = express.Router();
const PROVIDERS = ['gcash', 'maya'];

function getPublicBaseUrl() {
  return (
    process.env.TODAGO_PUBLIC_URL ||
    process.env.PUBLIC_BASE_URL ||
    process.env.APP_BASE_URL ||
    'https://todago-backend-production.up.railway.app'
  ).replace(/\/+$/, '');
}

function providerLabel(provider) {
  return provider === 'maya' ? 'Maya' : 'GCash';
}

function providerEmoji(provider) {
  return provider === 'maya' ? 'purple' : 'blue';
}

function toAmount(value) {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function maskAccountNumber(raw) {
  const digits = String(raw || '').replace(/\D/g, '');
  const last4 = digits.slice(-4);
  return {
    last4,
    masked: last4 ? `****${last4}` : 'Linked account',
  };
}

function requirePassenger(req, res) {
  if (req.userRole === 'driver' || req.userRole === 'operator' || req.userRole === 'admin') {
    res.status(403).json({ success: false, message: 'Passenger access only' });
    return false;
  }
  return true;
}

function serializeLedgerTransaction(row) {
  const unsignedAmount = toAmount(row.amount);
  const signedAmount = row.direction === 'credit' ? unsignedAmount : -unsignedAmount;
  return {
    id: row.id,
    type: row.type,
    provider: row.provider,
    status: row.status,
    title: row.title,
    subtitle: row.description,
    amount: signedAmount,
    occurred_at: row.occurred_at,
    trip_id: row.trip_id,
    checkout_url: row.checkout_url,
  };
}

async function loadWalletPayload(userId) {
  const balance = await getWalletBalance(userId);

  const [accounts, stats, rewards, walletRows, tripRows] = await Promise.all([
    dbAll(
      `SELECT provider, account_name, masked_number, status, linked_at, updated_at
       FROM linked_payment_accounts
       WHERE user_id = $1
         AND status = 'linked'
       ORDER BY provider`,
      [userId]
    ),
    dbGet(
      `SELECT
         COALESCE(SUM(
           CASE
             WHEN status = 'completed'
              AND (payment_status = 'paid' OR payment_method = 'cash')
             THEN fare
             ELSE 0
           END
         ), 0) AS total_spent,
         COUNT(*) FILTER (WHERE status = 'completed') AS completed_trips
       FROM trips
       WHERE commuter_id = $1`,
      [userId]
    ),
    dbGet(
      `SELECT COALESCE(SUM(amount), 0) AS rewards
       FROM wallet_transactions
       WHERE user_id = $1
         AND type = 'reward'
         AND direction = 'credit'
         AND status = 'completed'`,
      [userId]
    ),
    dbAll(
      `SELECT
         transaction_id AS id,
         type,
         provider,
         direction,
         amount,
         status,
         title,
         description,
         checkout_url,
         trip_id,
         COALESCE(completed_at, created_at) AS occurred_at
       FROM wallet_transactions
       WHERE user_id = $1
         AND status <> 'failed'
       ORDER BY COALESCE(completed_at, created_at) DESC
       LIMIT 50`,
      [userId]
    ),
    dbAll(
      `SELECT
         'trip:' || tr.trip_id AS id,
         'trip' AS type,
         tr.payment_method AS provider,
         'debit' AS direction,
         tr.fare AS amount,
         CASE
           WHEN tr.payment_status = 'paid'
             OR (tr.status = 'completed' AND tr.payment_method = 'cash')
           THEN 'completed'
           ELSE COALESCE(tr.payment_status, 'unpaid')
         END AS status,
         (
           CASE tr.service_type
             WHEN 'shared' THEN 'Shared Ride'
             WHEN 'express' THEN 'Toda-Express'
             WHEN 'pickup' THEN 'Pickup'
             ELSE 'Solo Ride'
           END
           || CASE
                WHEN tr.destination IS NULL OR tr.destination = '' THEN ''
                ELSE ' - ' || tr.destination
              END
         ) AS title,
         COALESCE('Paid to ' || d.driver_name, 'Ride payment') AS description,
         NULL::text AS checkout_url,
         tr.trip_id,
         COALESCE(
           tr.payment_collected_at,
           tr.paymongo_paid_at,
           tr.end_timestamp,
           tr.request_timestamp
         ) AS occurred_at
       FROM trips tr
       LEFT JOIN drivers d ON d.driver_id = tr.driver_id
       WHERE tr.commuter_id = $1
         AND (
           tr.payment_status = 'paid'
           OR tr.status = 'completed'
         )
         AND NOT EXISTS (
           SELECT 1
           FROM wallet_transactions wt
           WHERE wt.trip_id = tr.trip_id
             AND wt.type = 'trip'
             AND wt.status <> 'failed'
         )
       ORDER BY COALESCE(
         tr.payment_collected_at,
         tr.paymongo_paid_at,
         tr.end_timestamp,
         tr.request_timestamp
       ) DESC
       LIMIT 50`,
      [userId]
    ),
  ]);

  const linkedAccounts = PROVIDERS.map((provider) => {
    const account = accounts.find((item) => item.provider === provider);
    return {
      provider,
      label: providerLabel(provider),
      color_hint: providerEmoji(provider),
      connected: !!account,
      account_name: account?.account_name || null,
      masked_number: account?.masked_number || null,
      linked_at: account?.linked_at || null,
    };
  });

  const transactions = [...walletRows, ...tripRows]
    .map(serializeLedgerTransaction)
    .sort((a, b) => new Date(b.occurred_at || 0) - new Date(a.occurred_at || 0))
    .slice(0, 50);

  return {
    balance,
    stats: {
      total_spent: toAmount(stats?.total_spent),
      completed_trips: Number.parseInt(stats?.completed_trips, 10) || 0,
      rewards: toAmount(rewards?.rewards),
    },
    linked_accounts: linkedAccounts,
    transactions,
    refreshed_at: new Date().toISOString(),
  };
}

router.get('/', requireAuth, async (req, res) => {
  if (!requirePassenger(req, res)) return;
  try {
    const payload = await loadWalletPayload(req.userId);
    return res.json({ success: true, wallet: payload });
  } catch (error) {
    console.error('[Wallet] Summary error:', error.message);
    return res.status(500).json({ success: false, message: 'Unable to load wallet' });
  }
});

router.post('/linked-accounts', requireAuth, [
  body('provider').isIn(PROVIDERS).withMessage('Choose GCash or Maya'),
  body('accountNumber')
    .trim()
    .isLength({ min: 4, max: 32 })
    .withMessage('Account number must be 4-32 characters'),
  body('accountName')
    .optional({ nullable: true })
    .trim()
    .isLength({ max: 120 })
    .withMessage('Account name must be 120 characters or less'),
], async (req, res) => {
  if (!requirePassenger(req, res)) return;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  try {
    const provider = req.body.provider;
    const { masked, last4 } = maskAccountNumber(req.body.accountNumber);
    const user = await dbGet('SELECT full_name FROM users WHERE id = $1', [req.userId]);
    const accountName = (req.body.accountName || user?.full_name || '').toString().trim() || null;

    const account = await dbGet(
      `INSERT INTO linked_payment_accounts
         (user_id, provider, account_name, masked_number, account_number_last4,
          status, linked_at, updated_at)
       VALUES ($1,$2,$3,$4,$5,'linked',NOW(),NOW())
       ON CONFLICT (user_id, provider)
       DO UPDATE SET
         account_name = EXCLUDED.account_name,
         masked_number = EXCLUDED.masked_number,
         account_number_last4 = EXCLUDED.account_number_last4,
         status = 'linked',
         linked_at = NOW(),
         updated_at = NOW()
       RETURNING provider, account_name, masked_number, status, linked_at`,
      [req.userId, provider, accountName, masked, last4 || null]
    );

    return res.json({
      success: true,
      message: `${providerLabel(provider)} linked.`,
      account,
      wallet: await loadWalletPayload(req.userId),
    });
  } catch (error) {
    console.error('[Wallet] Link account error:', error.message);
    return res.status(500).json({ success: false, message: 'Could not link account' });
  }
});

router.delete('/linked-accounts/:provider', requireAuth, [
  param('provider').isIn(PROVIDERS).withMessage('Invalid provider'),
], async (req, res) => {
  if (!requirePassenger(req, res)) return;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  try {
    await dbRun(
      `UPDATE linked_payment_accounts
       SET status = 'unlinked',
           updated_at = NOW()
       WHERE user_id = $1
         AND provider = $2`,
      [req.userId, req.params.provider]
    );
    return res.json({
      success: true,
      message: `${providerLabel(req.params.provider)} unlinked.`,
      wallet: await loadWalletPayload(req.userId),
    });
  } catch (error) {
    console.error('[Wallet] Unlink account error:', error.message);
    return res.status(500).json({ success: false, message: 'Could not unlink account' });
  }
});

router.post('/top-up', requireAuth, [
  body('provider').isIn(PROVIDERS).withMessage('Choose GCash or Maya'),
  body('amount')
    .isFloat({ min: 1, max: 50000 })
    .withMessage('Top-up amount must be between PHP 1 and PHP 50,000'),
], async (req, res) => {
  if (!requirePassenger(req, res)) return;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  const provider = req.body.provider;
  const amount = toAmount(req.body.amount);

  try {
    const linked = await dbGet(
      `SELECT account_id
       FROM linked_payment_accounts
       WHERE user_id = $1
         AND provider = $2
         AND status = 'linked'`,
      [req.userId, provider]
    );
    if (!linked) {
      return res.status(409).json({
        success: false,
        message: `Link a real ${providerLabel(provider)} account before topping up.`,
      });
    }

    const user = await dbGet(
      `SELECT full_name, phone
       FROM users
       WHERE id = $1 AND is_active = true`,
      [req.userId]
    );
    if (!user) {
      return res.status(404).json({ success: false, message: 'Passenger account not found' });
    }

    const transactionId = uuidv4();
    await dbRun(
      `INSERT INTO wallet_transactions
        (transaction_id, user_id, type, provider, direction, amount, status,
         title, description, external_reference)
       VALUES ($1,$2,'topup',$3,'credit',$4,'pending',$5,$6,$7)`,
      [
        transactionId,
        req.userId,
        provider,
        amount,
        `${providerLabel(provider)} Top-up`,
        `Via linked ${providerLabel(provider)} account`,
        `wallet_topup:${transactionId}`,
      ]
    );

    const publicBaseUrl = getPublicBaseUrl();
    let session;
    try {
      session = await createCheckoutSession({
        referenceId: transactionId,
        amount,
        paymentMethod: provider,
        passengerName: user.full_name,
        passengerPhone: user.phone,
        lineItemName: 'TodaGo wallet top-up',
        description: `TodaGo wallet top-up via ${providerLabel(provider)}`,
        successUrl: `${publicBaseUrl}/api/wallet/paymongo/return?transactionId=${encodeURIComponent(transactionId)}&status=success`,
        cancelUrl: `${publicBaseUrl}/api/wallet/paymongo/return?transactionId=${encodeURIComponent(transactionId)}&status=cancelled`,
        metadata: {
          payment_type: 'wallet_topup',
          wallet_transaction_id: transactionId,
          user_id: req.userId,
        },
        idempotencyKey: `todago-wallet-topup-${transactionId}-${provider}`,
      });
    } catch (error) {
      await dbRun(
        `UPDATE wallet_transactions
         SET status = 'failed',
             updated_at = NOW()
         WHERE transaction_id = $1`,
        [transactionId]
      );
      throw error;
    }

    const checkoutUrl = session.attributes?.checkout_url;
    await dbRun(
      `UPDATE wallet_transactions
       SET checkout_session_id = $1,
           checkout_url = $2,
           updated_at = NOW()
       WHERE transaction_id = $3`,
      [session.id, checkoutUrl || null, transactionId]
    );

    return res.status(201).json({
      success: true,
      message: 'PayMongo top-up checkout created.',
      checkoutSessionId: session.id,
      checkoutUrl,
      transactionId,
      wallet: await loadWalletPayload(req.userId),
    });
  } catch (error) {
    console.error('[Wallet] Top-up error:', error.message);
    return res.status(error.statusCode || 500).json({
      success: false,
      message: error.statusCode === 503
        ? 'PayMongo is not configured yet. Add PAYMONGO_SECRET_KEY on the backend.'
        : error.message || 'Unable to start top-up',
    });
  }
});

router.get('/paymongo/return', (req, res) => {
  const status = req.query.status === 'success' ? 'successful' : 'cancelled';
  res
    .status(200)
    .type('html')
    .send(`<!doctype html>
<html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>TodaGo Wallet</title></head>
<body style="font-family:Arial,sans-serif;padding:28px;line-height:1.45">
<h1>TodaGo wallet top-up ${status}</h1>
<p>You can return to the TodaGo app. Your wallet will update once payment is confirmed.</p>
</body></html>`);
});

router.post('/paymongo/webhook', async (req, res) => {
  try {
    const root = req.body?.data;
    const livemode = root?.livemode ?? root?.attributes?.livemode ?? false;
    const signature = req.get('Paymongo-Signature') || req.get('X-Paymongo-Signature');
    if (!verifyWebhookSignature({
      rawBody: req.rawBody,
      signatureHeader: signature,
      livemode,
    })) {
      return res.status(401).json({ success: false, message: 'Invalid webhook signature' });
    }

    const eventType = root?.type === 'event'
      ? root?.attributes?.type
      : (root?.type || root?.attributes?.type);
    if (eventType !== 'checkout_session.payment.paid') {
      return res.status(200).json({ success: true, ignored: true });
    }

    const session = root?.data || root?.attributes?.data;
    const attrs = session?.attributes || {};
    const payment = attrs.payment_intent?.attributes?.payments?.[0] ||
      attrs.payments?.[0] ||
      null;
    const transactionId = attrs.metadata?.wallet_transaction_id || attrs.reference_number;

    await completeWalletTopUp({
      transactionId,
      checkoutSessionId: session?.id || null,
      paymentId: payment?.id || null,
    });

    return res.status(200).json({ success: true });
  } catch (error) {
    console.error('[Wallet] Webhook error:', error.message);
    return res.status(200).json({ success: false });
  }
});

module.exports = router;
