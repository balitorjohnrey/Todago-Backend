const { dbAll, dbRun } = require('../db/database');
const { completeWalletTopUp } = require('./walletLedger');
const { retrieveCheckoutSession, getPaidPayment, isLiveMode } = require('./paymongo');

async function settleWalletCheckout(session, eventLivemode) {
  const attrs = session?.attributes || {};
  if ((attrs.livemode ?? eventLivemode) !== isLiveMode()) throw new Error('Payment environment does not match');
  const payment = getPaidPayment(session);
  if (!payment) throw new Error('Checkout has no successful payment');
  const paid = payment.attributes || payment;
  const transactionId = attrs.metadata?.wallet_transaction_id || attrs.reference_number;
  if (!transactionId || (attrs.reference_number && attrs.reference_number !== transactionId)) {
    throw new Error('Payment reference does not match the top-up');
  }
  return completeWalletTopUp({
    transactionId,
    checkoutSessionId: session.id,
    paymentId: payment.id,
    amountInCentavos: paid.amount,
    currency: paid.currency,
  });
}

async function reconcileWalletTopUp(transaction) {
  if (transaction.status !== 'pending' || !transaction.checkout_session_id) return;
  const session = await retrieveCheckoutSession(transaction.checkout_session_id);
  if (session?.id !== transaction.checkout_session_id ||
      (session.attributes?.reference_number !== transaction.transaction_id &&
       session.attributes?.metadata?.wallet_transaction_id !== transaction.transaction_id)) {
    throw new Error('Checkout does not match this top-up');
  }
  if (getPaidPayment(session)) {
    await settleWalletCheckout(session);
  } else if (session.attributes?.status === 'expired') {
    await dbRun(`UPDATE wallet_transactions SET status = 'cancelled', updated_at = NOW()
      WHERE transaction_id = $1 AND status = 'pending'`, [transaction.transaction_id]);
  } else {
    // Also throttles summary reconciliation without treating an unfinished attempt as a failure.
    await dbRun(`UPDATE wallet_transactions SET updated_at = NOW()
      WHERE transaction_id = $1 AND status = 'pending'`, [transaction.transaction_id]);
  }
}

async function reconcileRecentTopUps(userId) {
  const pending = await dbAll(`SELECT transaction_id, checkout_session_id, status
    FROM wallet_transactions WHERE user_id = $1 AND type = 'topup' AND status = 'pending'
      AND checkout_session_id IS NOT NULL AND created_at > NOW() - INTERVAL '1 day'
      AND updated_at < NOW() - INTERVAL '20 seconds'
    ORDER BY created_at DESC LIMIT 3`, [userId]);
  await Promise.all(pending.map(async (transaction) => {
    try { await reconcileWalletTopUp(transaction); }
    catch (error) { console.error('[Wallet] Payment verification pending:', error.message); }
  }));
}

module.exports = { settleWalletCheckout, reconcileWalletTopUp, reconcileRecentTopUps };
