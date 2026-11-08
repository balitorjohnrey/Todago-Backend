const { pool, dbGet } = require('../db/database');
const { createPassengerStaticQr, listPayments, isLiveMode } = require('./paymongo');
const { amountInCentavos, MIN_TOP_UP, MAX_AMOUNT } = require('./paymentLimits');

function staticQrEnabled() {
  return process.env.PAYMONGO_WALLET_QR_MODE === 'passenger_static';
}

function requireStaticQrConfiguration() {
  if (!isLiveMode() || !process.env.PAYMONGO_WEBHOOK_SECRET?.trim()) {
    const error = new Error('Passenger QR top-ups are not ready. Configure the live PayMongo key and live webhook signing secret.');
    error.statusCode = 503;
    throw error;
  }
}

function validCodeId(value) {
  return typeof value === 'string' && /^(code|qr)_[a-zA-Z0-9_-]+$/.test(value);
}

function validQrImage(value) {
  // Use the original provider image. Do not rebuild or modify a payment QR.
  return typeof value === 'string' && value.length <= 1500000 &&
    /^data:image\/(png|jpeg);base64,[a-zA-Z0-9+/]+={0,2}$/.test(value);
}

function staticQrPresentation(assignment, amount) {
  return {
    kind: 'static_qr', provider: 'qrph', testMode: false, currency: 'PHP',
    amount: Number(amount), status: 'awaiting_next_action',
    qrImageUrl: assignment.qr_image, qrCodeId: assignment.qr_code_id,
    amountEntryRequired: true,
  };
}

async function getAssignedStaticQr(userId, qrCodeId) {
  return dbGet(`SELECT qr_code_id, qr_image FROM passenger_wallet_qr_codes
    WHERE user_id = $1 AND qr_code_id = $2 AND livemode = true`, [userId, qrCodeId]);
}

async function createStaticQrTopUp(userId, amount) {
  requireStaticQrConfiguration();
  if (amountInCentavos(amount, MIN_TOP_UP) === null) {
    const error = new Error('Choose a valid top-up amount.');
    error.statusCode = 422;
    throw error;
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Serialize both QR provisioning and pending requests for this passenger.
    const owner = (await client.query(`SELECT id FROM users WHERE id = $1
      AND is_active = true AND role IN ('passenger','commuter') FOR UPDATE`, [userId])).rows[0];
    if (!owner) throw new Error('Passenger account is unavailable.');
    let assignment = (await client.query(`SELECT * FROM passenger_wallet_qr_codes
      WHERE user_id = $1`, [userId])).rows[0];
    if (!assignment) {
      const generated = await createPassengerStaticQr({ userId });
      const image = generated?.attributes?.qr_image;
      if (!validCodeId(generated?.id) || !validQrImage(image) ||
          generated.livemode === false || generated.attributes?.livemode === false) {
        throw new Error('PayMongo did not return a usable passenger QR.');
      }
      assignment = (await client.query(`INSERT INTO passenger_wallet_qr_codes
        (user_id, qr_code_id, qr_image, livemode) VALUES ($1,$2,$3,true) RETURNING *`,
      [userId, generated.id, image])).rows[0];
    }
    let transaction = (await client.query(`SELECT transaction_id FROM wallet_transactions
      WHERE user_id = $1 AND static_qr_id = $2 AND status = 'pending' FOR UPDATE`,
    [userId, assignment.qr_code_id])).rows[0];
    if (transaction) {
      await client.query(`UPDATE wallet_transactions SET amount = $2, updated_at = NOW()
        WHERE transaction_id = $1 AND status = 'pending'`, [transaction.transaction_id, amount]);
    } else {
      transaction = (await client.query(`INSERT INTO wallet_transactions
        (user_id, type, provider, direction, amount, status, title, description, static_qr_id)
        VALUES ($1,'topup','qrph','credit',$2,'pending','QR Ph Top-up',
          'Via your passenger QR Ph code',$3) RETURNING transaction_id`,
      [userId, amount, assignment.qr_code_id])).rows[0];
    }
    await client.query('COMMIT');
    return { transactionId: transaction.transaction_id, testMode: false,
      payment: staticQrPresentation(assignment, amount) };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { client.release(); }
}

async function settleStaticQrPayment(payment, eventLivemode) {
  const attrs = payment?.attributes || {};
  const codeId = attrs.source?.provider?.code_id;
  if (attrs.source?.type !== 'qrph' || !validCodeId(codeId)) return false;
  const assignment = await dbGet(`SELECT user_id, qr_code_id FROM passenger_wallet_qr_codes
    WHERE qr_code_id = $1 AND livemode = true`, [codeId]);
  if (!assignment) return false; // Includes the shared merchant standee and dynamic QR codes.
  if (!isLiveMode() || (attrs.livemode ?? eventLivemode) !== true ||
      (eventLivemode !== undefined && eventLivemode !== true) || attrs.status !== 'paid' ||
      !/^pay_[a-zA-Z0-9_-]+$/.test(payment.id || '') || attrs.currency !== 'PHP' ||
      !Number.isSafeInteger(attrs.amount) || attrs.amount <= 0 || attrs.amount > MAX_AMOUNT * 100 ||
      attrs.disputed === true || (attrs.refunds?.length || 0) > 0) {
    throw new Error('Passenger QR payment could not be verified.');
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Lock the owner before the pending row. This also serializes duplicate
    // events and different payments for the same reusable QR.
    const owner = (await client.query(`SELECT id FROM users WHERE id = $1
      AND is_active = true FOR UPDATE`, [assignment.user_id])).rows[0];
    if (!owner) throw new Error('Passenger account is unavailable.');
    const existing = (await client.query(`SELECT transaction_id, user_id, static_qr_id
      FROM wallet_transactions WHERE provider_payment_id = $1`, [payment.id])).rows[0];
    if (existing) {
      if (existing.user_id !== assignment.user_id || existing.static_qr_id !== codeId) {
        throw new Error('Payment was already assigned to another wallet.');
      }
      await client.query('COMMIT');
      return true;
    }
    const pending = (await client.query(`SELECT transaction_id FROM wallet_transactions
      WHERE user_id = $1 AND static_qr_id = $2 AND status = 'pending' FOR UPDATE`,
    [assignment.user_id, codeId])).rows[0];
    const amount = attrs.amount / 100;
    if (pending) {
      await client.query(`UPDATE wallet_transactions SET amount = $2, status = 'completed',
        external_reference = $3, provider_payment_id = $3, completed_at = NOW(), updated_at = NOW(),
        description = 'Confirmed QR Ph payment'
        WHERE transaction_id = $1 AND status = 'pending'`, [pending.transaction_id, amount, payment.id]);
    } else {
      // A reusable QR can be paid again without opening a new top-up screen.
      await client.query(`INSERT INTO wallet_transactions
        (user_id, type, provider, direction, amount, status, title, description,
          static_qr_id, external_reference, provider_payment_id, completed_at)
        VALUES ($1,'topup','qrph','credit',$2,'completed','QR Ph Top-up',
          'Confirmed QR Ph payment',$3,$4,$4,NOW())`,
      [assignment.user_id, amount, codeId, payment.id]);
    }
    await client.query('COMMIT');
    return true;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { client.release(); }
}

// Shared short-lived provider snapshot avoids one merchant-wide API scan per
// passenger poll. Webhooks remain the immediate confirmation path.
let recentPayments;
async function reconcileStaticQrPayments(userId) {
  if (!staticQrEnabled() || !isLiveMode()) return;
  const assigned = await dbGet(`SELECT qr_code_id FROM passenger_wallet_qr_codes
    WHERE user_id = $1 AND livemode = true`, [userId]);
  if (!assigned) return;
  if (!recentPayments || recentPayments.until < Date.now()) {
    const promise = (async () => {
      const payments = [];
      let after;
      for (let page = 0; page < 10; page++) {
        const result = await listPayments({ after });
        if (!Array.isArray(result?.data)) throw new Error('Unable to read PayMongo payments.');
        payments.push(...result.data);
        if (result.has_more === false || result.data.length < 100) break;
        const lastId = result.data.at(-1)?.id;
        if (!lastId || lastId === after) break;
        after = lastId;
      }
      return payments;
    })();
    recentPayments = { until: Date.now() + 20000, promise };
    promise.catch(() => { if (recentPayments?.promise === promise) recentPayments = undefined; });
  }
  for (const payment of await recentPayments.promise) {
    if (payment.attributes?.status === 'paid' &&
        payment.attributes?.source?.provider?.code_id === assigned.qr_code_id) {
      await settleStaticQrPayment(payment);
    }
  }
}

module.exports = { staticQrEnabled, requireStaticQrConfiguration, createStaticQrTopUp,
  staticQrPresentation, getAssignedStaticQr, settleStaticQrPayment, reconcileStaticQrPayments };
