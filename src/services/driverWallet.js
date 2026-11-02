const { pool } = require('../db/database');
const { MIN_DRIVER_CASHOUT, amountInCentavos } = require('./paymentLimits');
const { isLiveMode } = require('./paymongo');

function fail(message, statusCode = 409) {
  const error = new Error(message);
  error.statusCode = statusCode;
  throw error;
}

async function lockedDriver(driverId, work) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const driver = (await client.query(`SELECT driver_id, is_active FROM drivers
      WHERE driver_id = $1 FOR UPDATE`, [driverId])).rows[0];
    if (!driver || driver.is_active === false) fail('Driver account unavailable', 403);
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { client.release(); }
}

async function syncEarnings(client, driverId) {
  // Cash is already in the driver's hands. A completed ride alone is not proof
  // of online payment: match the wallet debit or the confirmed provider payment.
  await client.query(`INSERT INTO driver_earnings (trip_id, driver_id, amount)
    SELECT tr.trip_id, tr.driver_id, tr.fare FROM trips tr
    WHERE tr.driver_id = $1 AND tr.status = 'completed' AND tr.payment_status = 'paid'
      AND tr.fare > 0 AND (
        (tr.payment_method = 'wallet' AND EXISTS (
          SELECT 1 FROM wallet_transactions wt WHERE wt.trip_id = tr.trip_id
            AND wt.user_id = tr.commuter_id AND wt.type = 'trip'
            AND wt.direction = 'debit' AND wt.status = 'completed' AND wt.amount = tr.fare
        )) OR (tr.payment_method IN ('gcash','maya') AND tr.paymongo_payment_id IS NOT NULL)
      ) ON CONFLICT (trip_id) DO NOTHING`, [driverId]);
}

async function balance(client, driverId) {
  const row = (await client.query(`SELECT
    (SELECT COALESCE(SUM(amount), 0) FROM driver_earnings WHERE driver_id = $1) AS earned,
    (SELECT COALESCE(SUM(amount), 0) FROM driver_cashouts WHERE driver_id = $1
      AND status IN ('pending','processing')) AS reserved,
    (SELECT COALESCE(SUM(amount), 0) FROM driver_cashouts WHERE driver_id = $1
      AND status = 'paid') AS paid`, [driverId])).rows[0];
  const cents = key => Math.round(Number(row[key] || 0) * 100);
  return { earned: cents('earned') / 100, reserved: cents('reserved') / 100,
    paid: cents('paid') / 100, available: Math.max(0, cents('earned') - cents('reserved') - cents('paid')) / 100 };
}

async function getDriverWallet(driverId) {
  return lockedDriver(driverId, async client => {
    await syncEarnings(client, driverId);
    const totals = await balance(client, driverId);
    const requests = (await client.query(`SELECT cashout_id, amount, provider, account_name,
      account_number, status, payment_reference, review_note, created_at, paid_at
      FROM driver_cashouts WHERE driver_id = $1 ORDER BY created_at DESC LIMIT 50`, [driverId])).rows;
    return { ...totals, minimumCashOut: MIN_DRIVER_CASHOUT, fee: 0,
      payoutMode: 'manual', cashOutEnabled: isLiveMode(), testMode: !isLiveMode(), requests };
  });
}

async function requestCashOut(driverId, { amount, provider, accountName, accountNumber, requestKey }) {
  if (!isLiveMode()) fail('Cash-out requests are disabled in payment test mode. Test balances cannot be withdrawn.');
  const cents = amountInCentavos(amount, MIN_DRIVER_CASHOUT);
  if (cents === null) fail('Cash-out must be between PHP 50 and PHP 50,000 with at most two decimal places.', 422);
  if (!['gcash', 'maya'].includes(provider) || !/^09\d{9}$/.test(accountNumber || '') ||
      typeof accountName !== 'string' || accountName.trim().length < 2 || accountName.length > 120 ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(requestKey || '')) {
    fail('Enter a valid GCash/Maya account name, 11-digit mobile number and request key.', 422);
  }
  return lockedDriver(driverId, async client => {
    const existing = (await client.query(`SELECT * FROM driver_cashouts
      WHERE driver_id = $1 AND request_key = $2`, [driverId, requestKey])).rows[0];
    if (existing) {
      if (Math.round(Number(existing.amount) * 100) !== cents || existing.provider !== provider ||
          existing.account_name !== accountName.trim() || existing.account_number !== accountNumber) {
        fail('This request key was already used for a different cash-out.');
      }
      return existing;
    }
    await syncEarnings(client, driverId);
    const totals = await balance(client, driverId);
    if (cents > Math.round(totals.available * 100)) fail('Insufficient available cashless earnings.');
    const active = (await client.query(`SELECT cashout_id FROM driver_cashouts
      WHERE driver_id = $1 AND status IN ('pending','processing') LIMIT 1`, [driverId])).rows[0];
    if (active) fail('You already have a pending cash-out. Refresh your history before requesting another.');
    return (await client.query(`INSERT INTO driver_cashouts
      (driver_id, amount, provider, account_name, account_number, request_key)
      VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [driverId, cents / 100, provider, accountName.trim(), accountNumber, requestKey])).rows[0];
  });
}

async function cancelCashOut(driverId, cashoutId) {
  return lockedDriver(driverId, async client => {
    const row = (await client.query(`SELECT * FROM driver_cashouts
      WHERE cashout_id = $1 AND driver_id = $2 FOR UPDATE`, [cashoutId, driverId])).rows[0];
    if (!row) fail('Cash-out request not found', 404);
    if (row.status === 'cancelled') return row;
    if (row.status !== 'pending') fail('Only pending requests can be cancelled. Contact TodaGo staff for a processing payout.');
    return (await client.query(`UPDATE driver_cashouts SET status = 'cancelled', updated_at = NOW()
      WHERE cashout_id = $1 RETURNING *`, [cashoutId])).rows[0];
  });
}

async function reviewCashOut(cashoutId, { action, reference, note, adminId, confirmedNotSent }) {
  if (!['processing', 'paid', 'rejected'].includes(action)) fail('Invalid cash-out action', 422);
  const cleanReference = String(reference || '').trim();
  const cleanNote = String(note || '').trim();
  if (action === 'paid' && !/^[a-zA-Z0-9-]{5,100}$/.test(cleanReference)) fail('Enter the actual e-wallet transfer reference.', 422);
  if (cleanNote.length > 300 || (action === 'rejected' && cleanNote.length < 3)) fail('Provide a review note of 3–300 characters.', 422);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const row = (await client.query(`SELECT * FROM driver_cashouts WHERE cashout_id = $1 FOR UPDATE`, [cashoutId])).rows[0];
    if (!row) fail('Cash-out request not found', 404);
    if (row.status === 'paid' && action === 'paid' && row.payment_reference === cleanReference) {
      await client.query('COMMIT'); return row;
    }
    const allowed = (row.status === 'pending' && ['processing', 'rejected'].includes(action)) ||
      (row.status === 'processing' && (action === 'paid' || (action === 'rejected' && confirmedNotSent === true)));
    if (!allowed) fail('This cash-out has already changed. Refresh before taking any action.');
    const updated = (await client.query(`UPDATE driver_cashouts SET status = $2,
      payment_reference = $3, review_note = $4, reviewed_by = $5,
      paid_at = CASE WHEN $2 = 'paid' THEN NOW() ELSE paid_at END, updated_at = NOW()
      WHERE cashout_id = $1 RETURNING *`,
    [cashoutId, action, action === 'paid' ? cleanReference : null, cleanNote || null, adminId])).rows[0];
    await client.query('COMMIT');
    return updated;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    if (error.code === '23505') fail('That transfer reference is already recorded. Do not send another payment.');
    throw error;
  } finally { client.release(); }
}

module.exports = { getDriverWallet, requestCashOut, cancelCashOut, reviewCashOut, syncEarnings };
