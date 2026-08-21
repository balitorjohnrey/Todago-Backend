const { pool } = require('../db/database');

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
  const amount = money(trip.fare);
  if (!trip?.commuter_id || !trip?.trip_id || amount <= 0) {
    return { success: false, message: 'Invalid wallet payment request' };
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const existing = await client.query(
      `SELECT transaction_id
       FROM wallet_transactions
       WHERE trip_id = $1
         AND type = 'trip'
         AND status = 'completed'
       LIMIT 1`,
      [trip.trip_id]
    );
    if (existing.rows[0]) {
      await client.query(
        `UPDATE trips
         SET payment_status = 'paid',
             payment_reference = COALESCE(payment_reference, $1),
             payment_collected_at = COALESCE(payment_collected_at, NOW())
         WHERE trip_id = $2`,
        [`wallet:${existing.rows[0].transaction_id}`, trip.trip_id]
      );
      await client.query('COMMIT');
      return {
        success: true,
        transactionId: existing.rows[0].transaction_id,
        balance: await getWalletBalance(trip.commuter_id),
      };
    }

    const balance = await getWalletBalance(trip.commuter_id, client);
    if (balance < amount) {
      await client.query('ROLLBACK');
      return {
        success: false,
        code: 'INSUFFICIENT_WALLET_BALANCE',
        message: 'Insufficient TodaGo Wallet balance. Top up first.',
        balance,
      };
    }

    const title = `TodaGo ride to ${trip.destination || 'destination'}`;
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
           payment_reference = $1,
           payment_collected_at = COALESCE(payment_collected_at, NOW())
       WHERE trip_id = $2`,
      [`wallet:${transactionId}`, trip.trip_id]
    );

    await client.query('COMMIT');
    return {
      success: true,
      transactionId,
      balance: balance - amount,
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
  paymentId,
}) {
  if (!transactionId && !checkoutSessionId) {
    return { updated: false };
  }

  const result = await pool.query(
    `UPDATE wallet_transactions
     SET status = 'completed',
         checkout_session_id = COALESCE(checkout_session_id, $1),
         external_reference = COALESCE($2, external_reference),
         completed_at = COALESCE(completed_at, NOW()),
         updated_at = NOW()
     WHERE type = 'topup'
       AND (
         transaction_id = $3
         OR checkout_session_id = $1
       )
     RETURNING transaction_id, user_id`,
    [checkoutSessionId || null, paymentId || checkoutSessionId || null, transactionId || null]
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
