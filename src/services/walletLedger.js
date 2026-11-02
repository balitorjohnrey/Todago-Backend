const { pool } = require('../db/database');
const { amountInCentavos } = require('./paymentLimits');

function money(value) {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

async function getWalletBalance(userId, client = pool) {
  const result = await client.query(
    `SELECT COALESCE(SUM(
       CASE WHEN direction = 'credit' THEN amount ELSE -amount END
     ), 0) AS balance
     FROM wallet_transactions
     WHERE user_id = $1
       AND status = 'completed'`,
    [userId]
  );
  return money(result.rows[0]?.balance);
}

async function debitWalletForTrip(trip) {
  if (!trip?.commuter_id || !trip?.trip_id) {
    return { success: false, message: 'Invalid wallet payment request' };
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Serialize all spending by this passenger, including different trips.
    // Re-read the fare and payment state after locking: the route's snapshot
    // may have changed while a concurrent request was in flight.
    const passenger = await client.query(
      'SELECT id FROM users WHERE id = $1 AND is_active = true FOR UPDATE',
      [trip.commuter_id]
    );
    const current = await client.query(
      'SELECT * FROM trips WHERE trip_id = $1 FOR UPDATE', [trip.trip_id]
    );
    const payable = current.rows[0];
    if (!passenger.rows[0] || !payable || payable.commuter_id !== trip.commuter_id) {
      await client.query('ROLLBACK');
      return { success: false, message: 'Passenger or trip unavailable' };
    }
    const cents = amountInCentavos(payable.fare, 0.01);
    if (cents === null || !payable.driver_id || payable.status === 'cancelled') {
      await client.query('ROLLBACK');
      return { success: false, message: 'This trip cannot be paid from TodaGo Wallet' };
    }
    const amount = cents / 100;

    const existing = await client.query(
      `SELECT transaction_id
       FROM wallet_transactions
       WHERE trip_id = $1
         AND user_id = $2 AND amount = $3 AND direction = 'debit'
         AND type = 'trip'
         AND status = 'completed'
       LIMIT 1`,
      [trip.trip_id, trip.commuter_id, amount]
    );
    if (existing.rows[0]) {
      await client.query(
        `UPDATE trips
         SET payment_status = 'paid',
             payment_method = 'wallet',
             paymongo_checkout_session_id = NULL,
             paymongo_checkout_url = NULL,
             paymongo_payment_id = NULL,
             payment_reference = COALESCE(payment_reference, $1),
             payment_collected_at = COALESCE(payment_collected_at, NOW())
         WHERE trip_id = $2`,
        [`wallet:${existing.rows[0].transaction_id}`, trip.trip_id]
      );
      const balance = await getWalletBalance(trip.commuter_id, client);
      await client.query('COMMIT');
      return {
        success: true,
        transactionId: existing.rows[0].transaction_id,
        balance,
      };
    }

    if (payable.status !== 'arrived' || payable.payment_status === 'paid' || payable.paymongo_checkout_session_id) {
      await client.query('ROLLBACK');
      return { success: false, message: 'Payment is already settled or this trip is not ready for payment' };
    }

    const balance = await getWalletBalance(trip.commuter_id, client);
    const balanceCents = Math.round(balance * 100);
    if (balanceCents < cents) {
      await client.query('ROLLBACK');
      return {
        success: false,
        code: 'INSUFFICIENT_WALLET_BALANCE',
        message: 'Insufficient TodaGo Wallet balance. Top up first.',
        balance,
      };
    }

    const title = `TodaGo ride to ${payable.destination || 'destination'}`;
    const inserted = await client.query(
      `INSERT INTO wallet_transactions
        (user_id, trip_id, type, provider, direction, amount, status,
         title, description, external_reference, completed_at)
       VALUES ($1,$2,'trip','wallet','debit',$3,'completed',$4,$5,$6,NOW())
       RETURNING transaction_id`,
      [
        trip.commuter_id,
        trip.trip_id,
        amount,
        title,
        trip.driver_name ? `Paid to ${trip.driver_name}` : 'Paid from TodaGo Wallet',
        `trip:${trip.trip_id}`,
      ]
    );
    const transactionId = inserted.rows[0].transaction_id;

    await client.query(
      `UPDATE trips
       SET payment_status = 'paid',
           payment_method = 'wallet',
           paymongo_checkout_session_id = NULL,
           paymongo_checkout_url = NULL,
           paymongo_payment_id = NULL,
           payment_reference = $1,
           payment_collected_at = COALESCE(payment_collected_at, NOW())
       WHERE trip_id = $2`,
      [`wallet:${transactionId}`, trip.trip_id]
    );

    await client.query('COMMIT');
    return {
      success: true,
      transactionId,
      balance: (balanceCents - cents) / 100,
    };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function completeWalletTopUp({
  transactionId,
  checkoutSessionId,
  paymentIntentId,
  paymentId,
  amountInCentavos,
  currency,
}) {
  if ((Boolean(checkoutSessionId) === Boolean(paymentIntentId)) || !paymentId || currency !== 'PHP' ||
      !Number.isSafeInteger(amountInCentavos) || amountInCentavos <= 0) {
    throw new Error('A verified PHP payment is required to complete a top-up');
  }
  const existing = await pool.query(
    `SELECT transaction_id, user_id, amount, status, checkout_session_id, payment_intent_id
     FROM wallet_transactions
     WHERE type = 'topup' AND ${transactionId ? 'transaction_id = $1' : paymentIntentId ? 'payment_intent_id = $1' : 'checkout_session_id = $1'}`,
    [transactionId || paymentIntentId || checkoutSessionId]
  );
  const transaction = existing.rows[0];
  if (!transaction) throw new Error('Wallet top-up not found');
  if (Math.round(money(transaction.amount) * 100) !== amountInCentavos ||
      (paymentIntentId
        ? transaction.payment_intent_id !== paymentIntentId || Boolean(transaction.checkout_session_id)
        : transaction.checkout_session_id !== checkoutSessionId || Boolean(transaction.payment_intent_id))) {
    throw new Error('Payment does not match the wallet top-up');
  }
  if (transaction.status === 'completed') return { updated: false, transaction };
  if (transaction.status !== 'pending') throw new Error('This top-up is no longer pending');
  const result = await pool.query(
    `UPDATE wallet_transactions
     SET status = 'completed',
         external_reference = COALESCE($2, external_reference),
         completed_at = COALESCE(completed_at, NOW()),
         updated_at = NOW()
      WHERE type = 'topup' AND status = 'pending'
        AND transaction_id = $3
        AND ${paymentIntentId ? 'payment_intent_id' : 'checkout_session_id'} = $1
     RETURNING transaction_id, user_id`,
    [paymentIntentId || checkoutSessionId, paymentId, transaction.transaction_id]
  );

  return {
    updated: result.rowCount > 0,
    transaction: result.rows[0] || null,
  };
}

module.exports = {
  completeWalletTopUp,
  debitWalletForTrip,
  getWalletBalance,
};
