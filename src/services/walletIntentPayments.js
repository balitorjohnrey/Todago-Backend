const { dbGet, dbRun } = require('../db/database');
const { completeWalletTopUp } = require('./walletLedger');
const { retrievePaymentIntent, getPaidPayment, isLiveMode } = require('./paymongo');

function validateIntent(intent, transaction) {
  const attrs = intent?.attributes || {};
  if (attrs.livemode !== isLiveMode()) throw new Error('Payment environment does not match');
  if (intent.id !== transaction.payment_intent_id ||
      attrs.metadata?.wallet_transaction_id !== transaction.transaction_id ||
      attrs.metadata?.payment_type !== 'wallet_topup') {
    throw new Error('Payment intent does not match this top-up');
  }
  return attrs;
}

async function reconcileWalletIntent(transaction) {
  const intent = await retrievePaymentIntent(transaction.payment_intent_id);
  const attrs = validateIntent(intent, transaction);
  const payment = getPaidPayment(intent);
  if (payment) {
    const paid = payment.attributes || payment;
    if (attrs.status !== 'succeeded' || paid.livemode !== isLiveMode() ||
        paid.payment_intent_id !== intent.id || paid.amount !== attrs.amount ||
        paid.currency !== attrs.currency) throw new Error('Payment details do not match the intent');
    await completeWalletTopUp({ transactionId: transaction.transaction_id,
      paymentIntentId: intent.id, paymentId: payment.id,
      amountInCentavos: paid.amount, currency: paid.currency });
  } else if (attrs.status === 'cancelled') {
    await dbRun(`UPDATE wallet_transactions SET status = 'cancelled', updated_at = NOW()
      WHERE transaction_id = $1 AND status = 'pending'`, [transaction.transaction_id]);
  } else {
    await dbRun(`UPDATE wallet_transactions SET updated_at = NOW()
      WHERE transaction_id = $1 AND status = 'pending'`, [transaction.transaction_id]);
  }
  return intent;
}

function walletIntentPresentation(intent, provider) {
  const attrs = intent?.attributes || {};
  const action = attrs.next_action || {};
  const qr = action.code || {};
  const testUrl = !isLiveMode() ? (qr.test_url || action.test_url || attrs.test_url || null) : null;
  // Return only customer-facing action data, never client_key or full provider payloads.
  return {
    kind: provider === 'qrph' ? 'qr' : 'redirect', provider,
    amount: attrs.amount / 100, currency: attrs.currency,
    testMode: !isLiveMode(), status: attrs.status,
    authorizationUrl: action.redirect?.url || null,
    qrImageUrl: qr.image_url || null,
    expiresAt: qr.expires_at || action.expires_at || null,
    testUrl,
  };
}

async function handleWalletPaymentEvent(payment, eventLivemode) {
  if (eventLivemode !== isLiveMode()) throw new Error('Payment environment does not match');
  const intentId = payment?.attributes?.payment_intent_id;
  if (!intentId) return false;
  const transaction = await dbGet(`SELECT transaction_id, payment_intent_id, status
    FROM wallet_transactions WHERE type = 'topup' AND payment_intent_id = $1`, [intentId]);
  if (!transaction) return false;
  // Retrieve the stored intent: an event or redirect alone never creates a credit.
  await reconcileWalletIntent(transaction);
  return true;
}

module.exports = { reconcileWalletIntent, walletIntentPresentation, handleWalletPaymentEvent };
