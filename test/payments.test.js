const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const paymongo = require('../src/services/paymongo');

function loadWith(filename, stubs) {
  const file = path.join(__dirname, '..', filename);
  const module = { exports: {} };
  const actualRequire = createRequire(file);
  vm.runInNewContext(fs.readFileSync(file, 'utf8'), {
    module, exports: module.exports,
    require: (name) => Object.hasOwn(stubs, name) ? stubs[name] : actualRequire(name),
    process, console, Buffer, Date,
  }, { filename: file });
  return module.exports;
}

function checkout(overrides = {}) {
  return { id: 'cs_example', attributes: {
    livemode: false, reference_number: 'topup-1',
    metadata: { payment_type: 'wallet_topup', wallet_transaction_id: 'topup-1' },
    payments: [
      { id: 'pay_failed', attributes: { status: 'failed', amount: 10000, currency: 'PHP' } },
      { id: 'pay_paid', attributes: { status: 'paid', amount: 10000, currency: 'PHP' } },
    ], ...overrides,
  } };
}

test('PayMongo checkout and wallet safety', async (t) => {
  const originalFetch = global.fetch;
  const originalKey = process.env.PAYMONGO_SECRET_KEY;
  const originalWebhook = process.env.PAYMONGO_WEBHOOK_SECRET;
  process.env.PAYMONGO_SECRET_KEY = 'sk_test_unit_tests';
  process.env.PAYMONGO_WEBHOOK_SECRET = 'webhook-unit-tests';
  t.after(() => {
    global.fetch = originalFetch;
    for (const [name, value] of Object.entries({ PAYMONGO_SECRET_KEY: originalKey, PAYMONGO_WEBHOOK_SECRET: originalWebhook })) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  });

  await t.test('webhooks require a secret, the exact raw body, and a matching environment', () => {
    const rawBody = Buffer.from('{"data":{"livemode":false}}');
    const timestamp = String(Math.floor(Date.now() / 1000));
    const digest = crypto.createHmac('sha256', process.env.PAYMONGO_WEBHOOK_SECRET)
      .update(`${timestamp}.${rawBody}`).digest('hex');
    const args = { rawBody, signatureHeader: `t=${timestamp},te=${digest},li=`, livemode: false };
    assert.equal(paymongo.verifyWebhookSignature(args), true);
    assert.equal(paymongo.verifyWebhookSignature({ ...args, rawBody: Buffer.from('{}') }), false);
    assert.equal(paymongo.verifyWebhookSignature({ ...args, livemode: true }), false);
    delete process.env.PAYMONGO_WEBHOOK_SECRET;
    assert.equal(paymongo.verifyWebhookSignature(args), false);
    process.env.PAYMONGO_WEBHOOK_SECRET = 'webhook-unit-tests';
  });

  await t.test('the successful payment is found after earlier failed attempts', () => {
    assert.equal(paymongo.getPaidPayment(checkout()).id, 'pay_paid');
    assert.equal(paymongo.getPaidPayment(checkout({ payments: [] })), null);
  });

  await t.test('account capabilities include QR Ph, other wallets and banks, without BNPL', () => {
    assert.deepEqual(paymongo.normalizeCapabilities(['qrph', 'gcash', 'paymaya', 'grab_pay',
      'shopeepay', 'dob', 'dob_ubp', 'brankas_bdo', 'qrph', 'bill_ease']),
    ['qrph', 'gcash', 'paymaya', 'grab_pay', 'shopeepay', 'dob', 'dob_ubp', 'brankas_bdo']);
    assert.throws(() => paymongo.normalizeCapabilities({ data: {} }), /Unable to read/);
  });

  await t.test('checkout only offers enabled methods and converts pesos to centavos', async () => {
    const requests = [];
    global.fetch = async (url, options) => {
      requests.push({ url, options });
      return { ok: true, json: async () => url.includes('capabilities') ? ['qrph'] :
        { data: { id: 'cs_new', attributes: { checkout_url: 'https://checkout.paymongo.com/new' } } } };
    };
    await paymongo.createCheckoutSession({ referenceId: 'topup-1', amount: 100,
      paymentMethodTypes: ['gcash', 'qrph'], successUrl: 'https://example.com/success', cancelUrl: 'https://example.com/cancel' });
    const body = JSON.parse(requests[1].options.body).data.attributes;
    assert.deepEqual(body.payment_method_types, ['qrph']);
    assert.equal(body.line_items[0].amount, 10000);
    assert.equal(body.line_items[0].currency, 'PHP');
    const before = requests.length;
    await assert.rejects(paymongo.createCheckoutSession({ referenceId: 'topup-2', amount: 100, paymentMethod: 'gcash' }), /not available/);
    assert.equal(requests.length, before, 'an unavailable method must never create a checkout');
  });

  const row = { transaction_id: 'topup-1', user_id: 'passenger-1', amount: '100.00',
    status: 'pending', checkout_session_id: 'cs_example' };
  let credits = 0;
  const ledger = loadWith('src/services/walletLedger.js', { '../db/database': { pool: {
    query: async (sql, params) => {
      if (sql.includes('SELECT transaction_id')) return { rows: [{ ...row }] };
      assert.equal(params[2], row.transaction_id);
      assert.match(sql, /status = 'pending'/);
      if (row.status === 'pending') { row.status = 'completed'; credits++; return { rows: [{ ...row }], rowCount: 1 }; }
      return { rows: [], rowCount: 0 };
    },
  } } });
  const valid = { transactionId: 'topup-1', checkoutSessionId: 'cs_example', paymentId: 'pay_paid',
    amountInCentavos: 10000, currency: 'PHP' };

  await t.test('a mismatched amount, session or currency cannot credit a wallet', async () => {
    for (const changed of [{ amountInCentavos: 1000 }, { checkoutSessionId: 'cs_other' }, { currency: 'USD' }]) {
      await assert.rejects(ledger.completeWalletTopUp({ ...valid, ...changed }));
    }
    assert.equal(credits, 0);
    assert.equal(row.status, 'pending');
  });

  await t.test('duplicate payment notifications credit the wallet only once', async () => {
    assert.equal((await ledger.completeWalletTopUp(valid)).updated, true);
    assert.equal((await ledger.completeWalletTopUp(valid)).updated, false);
    assert.equal(credits, 1);
  });

  let completed;
  let serverSession = checkout();
  const writes = [];
  const payments = loadWith('src/services/walletPayments.js', {
    './walletIntentPayments': {},
    '../db/database': { dbAll: async () => [], dbRun: async (sql) => writes.push(sql) },
    './walletLedger': { completeWalletTopUp: async (args) => { completed = args; return { updated: true }; } },
    './paymongo': { retrieveCheckoutSession: async () => serverSession,
      getPaidPayment: paymongo.getPaidPayment, isLiveMode: () => false },
  });

  await t.test('missed webhook recovery verifies the stored checkout through the server', async () => {
    await payments.reconcileWalletTopUp({ transaction_id: 'topup-1', checkout_session_id: 'cs_example', status: 'pending' });
    assert.equal(completed.paymentId, 'pay_paid');
    assert.equal(completed.amountInCentavos, 10000);
    assert.equal(completed.currency, 'PHP');
  });

  await t.test('an unfinished checkout or a forged success return cannot credit a wallet', async () => {
    completed = null;
    serverSession = checkout({ payments: [], status: 'active', success_url: 'https://example.com/?status=success' });
    await payments.reconcileWalletTopUp({ transaction_id: 'topup-1', checkout_session_id: 'cs_example', status: 'pending' });
    assert.equal(completed, null);
    assert.equal(writes.some((sql) => sql.includes("status = 'cancelled'")), false);
  });

  await t.test('expired QR attempts do not cancel an active checkout; expired sessions do', async () => {
    serverSession = checkout({ payments: [], status: 'active' });
    const transaction = { transaction_id: 'topup-1', checkout_session_id: 'cs_example', status: 'pending' };
    writes.length = 0;
    await payments.reconcileWalletTopUp(transaction);
    assert.equal(writes.some((sql) => sql.includes("status = 'cancelled'")), false);
    serverSession = checkout({ payments: [], status: 'expired' });
    await payments.reconcileWalletTopUp(transaction);
    assert.equal(writes.some((sql) => sql.includes("status = 'cancelled'")), true);
  });

  await t.test('a different reference or live-mode payment cannot settle a test top-up', async () => {
    await assert.rejects(payments.settleWalletCheckout(checkout({ payments: [] })), /no successful payment/);
    await assert.rejects(payments.settleWalletCheckout(checkout({ livemode: true })), /environment/);
    await assert.rejects(payments.settleWalletCheckout(checkout({ reference_number: 'someone-else' })), /reference/);
  });

  await t.test('top-up status is scoped to its authenticated passenger', async () => {
    let boundUser;
    const router = loadWith('src/routes/wallet.js', {
      './auth': { requireAuth: (_req, _res, next) => next() },
      '../db/database': { dbGet: async (_sql, params) => { boundUser = params[1]; return null; } },
      '../services/paymongo': paymongo,
      '../services/walletLedger': {}, '../services/walletPayments': {},
      '../services/walletIntentPayments': {},
    });
    const route = router.stack.find((layer) => layer.route?.path === '/top-ups/:transactionId').route;
    let status;
    const res = { status: (code) => { status = code; return res; }, json: () => res };
    await route.stack.at(-1).handle({ userId: 'different-passenger', userRole: 'passenger',
      params: { transactionId: '0ccaa023-79ca-4f3a-b9bc-f7536dcc5ca3' } }, res);
    assert.equal(boundUser, 'different-passenger');
    assert.equal(status, 404);
  });
});
