const { pool } = require('../db/database');
const { syncEarnings } = require('./driverWallet');

function fail(message, statusCode = 409) {
  const error = new Error(message);
  error.statusCode = statusCode;
  throw error;
}

// Complete the ride and credit the driver in the same database transaction.
// Lock order matches driver-wallet operations, avoiding double trip counts and
// ensuring retries cannot turn a cancelled/unpaid ride into withdrawable money.
async function completePaidTrip(tripId, driverId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const driver = (await client.query(
      'SELECT driver_id FROM drivers WHERE driver_id = $1 FOR UPDATE', [driverId]
    )).rows[0];
    const trip = (await client.query(
      'SELECT * FROM trips WHERE trip_id = $1 FOR UPDATE', [tripId]
    )).rows[0];
    if (!driver || !trip || trip.driver_id !== driverId) fail('Trip not found', 404);
    if (!['arrived', 'completed'].includes(trip.status)) {
      fail('Mark arrived at destination before collecting payment');
    }
    let dropoffs = trip.shared_dropoffs || [];
    if (typeof dropoffs === 'string') dropoffs = JSON.parse(dropoffs);
    if (trip.service_type === 'shared' && dropoffs.length && Number(trip.remaining_passenger_count) > 0) {
      fail('Drop the remaining passengers before collecting payment.');
    }
    if (trip.payment_method !== 'cash' && trip.payment_status !== 'paid') {
      fail('Waiting for confirmed passenger payment.');
    }
    if (trip.payment_method === 'wallet') {
      const debit = await client.query(`SELECT transaction_id FROM wallet_transactions
        WHERE trip_id = $1 AND user_id = $2 AND amount = $3
          AND type = 'trip' AND direction = 'debit' AND status = 'completed'`,
      [tripId, trip.commuter_id, trip.fare]);
      if (!debit.rows[0]) fail('No matching TodaGo Wallet payment was found.');
    } else if (['gcash', 'maya'].includes(trip.payment_method)) {
      if (!trip.paymongo_payment_id) fail('No confirmed provider payment was found.');
    } else if (trip.payment_method !== 'cash') {
      fail('Unsupported trip payment method.');
    }

    if (trip.status !== 'completed') {
      await client.query(`UPDATE trips SET status = 'completed', payment_status = 'paid',
        end_timestamp = COALESCE(end_timestamp, NOW()),
        payment_collected_at = COALESCE(payment_collected_at, NOW()),
        payment_reference = COALESCE(payment_reference, $2)
        WHERE trip_id = $1`, [tripId, trip.payment_method === 'cash' ? `cash:${tripId}` : null]);
      await client.query(`UPDATE drivers SET total_trips = total_trips + 1,
        status = 'online', online_since = COALESCE(online_since, NOW()), updated_at = NOW()
        WHERE driver_id = $1`, [driverId]);
    }
    await syncEarnings(client, driverId);
    await client.query('COMMIT');
    const fare = Number(trip.fare);
    return { gross_fare: fare, your_earnings: fare };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

module.exports = { completePaidTrip };
