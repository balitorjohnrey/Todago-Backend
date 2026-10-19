const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');

function loadWith(filename, stubs) {
  const file = path.join(__dirname, '..', filename);
  const module = { exports: {} };
  const actualRequire = createRequire(file);
  vm.runInNewContext(fs.readFileSync(file, 'utf8'), {
    module, exports: module.exports, process, console, Buffer, Date, URL, AbortSignal,
    fetch: (...args) => global.fetch(...args),
    require: (name) => Object.hasOwn(stubs, name) ? stubs[name] : actualRequire(name),
  }, { filename: file });
  return module.exports;
}

function intent(overrides = {}) {
  return { id: 'pi_example', attributes: {
    livemode: false, status: 'succeeded', amount: 10000, currency: 'PHP',
    client_key: 'never-return-this',
    metadata: { payment_type: 'wallet_topup', wallet_transaction_id: 'topup-1' },
    payments: [{ id: 'pay_example', attributes: { status: 'paid', livemode: false,
      amount: 10000, currency: 'PHP', payment_intent_id: 'pi_example' } }],
    ...overrides,
  } };
}

test('native wallet payments', async (t) => {
  const originalKey = process.env.PAYMONGO_SECRET_KEY;
  const originalFetch = global.fetch;
  process.env.PAYMONGO_SECRET_KEY = 'sk_test_native_unit_tests';
  t.after(() => {
    global.fetch = originalFetch;
    if (originalKey === undefined) delete process.env.PAYMONGO_SECRET_KEY;
    else process.env.PAYMONGO_SECRET_KEY = originalKey;
  });
  const paymongo = loadWith('src/services/paymongo.js', {});

  await t.test('GCash and Maya use their direct provider flow, with the verified amount and return URL', async () => {
    const requests = [];
    global.fetch = async (url, options) => {
      requests.push({ url, body: options.body ? JSON.parse(options.body).data.attributes : null });
      const data = url.includes('capabilities') ? ['gcash', 'paymaya', 'qrph'] :
        url.endsWith('/payment_methods') ? { data: { id: 'pm_test' } } : { data: intent() };
      return { ok: true, json: async () => data };
    };
    for (const methodType of ['gcash', 'paymaya', 'qrph']) {
      await paymongo.createWalletPaymentIntent({ transactionId: 'topup-1', userId: 'user-1', amount: 100, methodType });
      const body = requests.at(-1).body;
      assert.equal(body.amount, 10000);
      assert.equal(body.currency, 'PHP');
      assert.deepEqual(body.payment_method_allowed, [methodType]);
      assert.equal(body.metadata.wallet_transaction_id, 'topup-1');
      await paymongo.attachWalletPaymentMethod({ intentId: 'pi_example', methodType, transactionId: 'topup-1' });
      assert.equal(requests.at(-2).body.type, methodType);
      assert.equal(requests.at(-1).body.payment_method, 'pm_test');
      assert.match(requests.at(-1).body.return_url, /\/api\/wallet\/paymongo\/return\?transactionId=topup-1/);
    }
  });

  await t.test('an inactive GCash capability cannot be bypassed by the app', async () => {
    const service = loadWith('src/services/paymongo.js', {});
    let calls = 0;
    global.fetch = async () => { calls++; return { ok: true, json: async () => ['qrph'] }; };
    await assert.rejects(service.createWalletPaymentIntent({ transactionId: 'topup-1', amount: 100, methodType: 'gcash' }), /not available/);
    assert.equal(calls, 1);
  });

  await t.test('native checkout persists its intent before authorization; older apps keep Hosted Checkout', async () => {
    const calls = [];
    let attachFails = false;
    const router = loadWith('src/routes/wallet.js', {
      './auth': { requireAuth: (_req, _res, next) => next() },
      '../db/database': {
        dbGet: async () => ({ full_name: 'Test Passenger', phone: '09170000000' }),
        dbAll: async () => [],
        dbRun: async (sql) => { calls.push(sql.includes('SET payment_intent_id') ? 'persist' : sql.includes("status = 'failed'") ? 'fail' : 'write'); },
      },
      '../services/walletLedger': { getWalletBalance: async () => 0 },
      '../services/walletPayments': {},
      '../services/walletIntentPayments': { walletIntentPresentation: () => ({ kind: 'redirect', provider: 'gcash' }) },
      '../services/paymongo': {
        getAvailablePaymentMethods: async () => [{ id: 'gcash', type: 'gcash', label: 'GCash' }],
        isLiveMode: () => false,
        createWalletPaymentIntent: async () => { calls.push('intent'); return intent(); },
        attachWalletPaymentMethod: async () => { calls.push('attach'); if (attachFails) throw new Error('Provider timeout'); return intent(); },
        createCheckoutSession: async () => { calls.push('hosted'); return { id: 'cs_example', attributes: { checkout_url: 'https://checkout.paymongo.com/cs_example' } }; },
      },
    });
    const route = router.stack.find((layer) => layer.route?.path === '/top-up').route.stack.at(-1).handle;
    let response;
    let status;
    const res = { status: code => { status = code; return res; }, json: data => { response = data; return res; } };
    const req = { userId: 'passenger-1', userRole: 'passenger', body: { provider: 'gcash', amount: 100, checkoutExperience: 'native' } };
    await route(req, res);
    assert.equal(status, 201);
    assert.equal(response.payment.kind, 'redirect');
    assert.ok(calls.indexOf('persist') < calls.indexOf('attach'));
    assert.equal(calls.includes('hosted'), false);
    calls.length = 0;
    await route({ ...req, body: { provider: 'gcash', amount: 100 } }, res);
    assert.equal(status, 201);
    assert.equal(response.checkoutUrl, 'https://checkout.paymongo.com/cs_example');
    assert.equal(calls.includes('hosted'), true);
    assert.equal(calls.includes('intent'), false);
    calls.length = 0;
    attachFails = true;
    await route(req, res);
    assert.equal(status, 500);
    assert.equal(calls.includes('persist'), true);
    assert.equal(calls.includes('fail'), false, 'an uncertain provider outcome must remain recoverable');
  });

  const transaction = { transaction_id: 'topup-1', payment_intent_id: 'pi_example', status: 'pending' };
  let serverIntent = intent();
  let completed;
  let knownTransaction = transaction;
  let live = false;
  const writes = [];
  const payments = loadWith('src/services/walletIntentPayments.js', {
    '../db/database': { dbGet: async () => knownTransaction, dbRun: async (sql) => writes.push(sql) },
    './walletLedger': { completeWalletTopUp: async (args) => { completed = args; } },
    './paymongo': { retrievePaymentIntent: async () => serverIntent,
      getPaidPayment: paymongo.getPaidPayment, isLiveMode: () => live },
  });

  await t.test('polling recovers a missed webhook only after the stored intent succeeds', async () => {
    await payments.reconcileWalletIntent(transaction);
    assert.equal(completed.paymentIntentId, 'pi_example');
    assert.equal(completed.paymentId, 'pay_example');
    assert.equal(completed.amountInCentavos, 10000);
    completed = null;
    serverIntent = intent({ status: 'awaiting_next_action', payments: [] });
    await payments.reconcileWalletIntent(transaction);
    assert.equal(completed, null);
  });

  await t.test('mismatched intent, metadata, currency and environment cannot settle a wallet', async () => {
    for (const changed of [
      { ...intent(), id: 'pi_other' },
      intent({ metadata: { payment_type: 'wallet_topup', wallet_transaction_id: 'different' } }),
      intent({ livemode: true }), intent({ currency: 'USD' }), intent({ amount: 20000 }),
      intent({ payments: [{ id: 'pay_other', attributes: { status: 'paid', amount: 10000,
        currency: 'PHP', livemode: false, payment_intent_id: 'pi_other' } }] }),
    ]) {
      serverIntent = changed;
      await assert.rejects(payments.reconcileWalletIntent(transaction));
    }
  });

  await t.test('a payment webhook looks up the stored intent and cannot create a new top-up', async () => {
    knownTransaction = null;
    completed = null;
    assert.equal(await payments.handleWalletPaymentEvent({ attributes: { payment_intent_id: 'pi_unknown' } }, false), false);
    assert.equal(completed, null);
    knownTransaction = transaction;
    serverIntent = intent();
    assert.equal(await payments.handleWalletPaymentEvent({ attributes: { payment_intent_id: 'pi_example' } }, false), true);
    assert.equal(completed.paymentId, 'pay_example');
  });

  await t.test('customer action data excludes secrets and never exposes a live simulator', () => {
    const qrIntent = intent({ next_action: { code: { image_url: 'data:image/png;base64,abc',
      test_url: 'https://test-sources.paymongo.com/qrph/example', expires_at: 123 } } });
    const testPresentation = payments.walletIntentPresentation(qrIntent, 'qrph');
    assert.equal(testPresentation.testMode, true);
    assert.match(testPresentation.testUrl, /test-sources/);
    assert.equal(JSON.stringify(testPresentation).includes('never-return-this'), false);
    live = true;
    assert.equal(payments.walletIntentPresentation(qrIntent, 'qrph').testUrl, null);
    live = false;
  });

  await t.test('the ledger binds a direct payment to exactly one stored intent and credits once', async () => {
    const row = { ...transaction, checkout_session_id: null, amount: 100, user_id: 'user-1' };
    let credits = 0;
    const ledger = loadWith('src/services/walletLedger.js', { '../db/database': { pool: {
      query: async (sql, params) => {
        if (sql.includes('SELECT transaction_id')) return { rows: [{ ...row }] };
        assert.match(sql, /AND payment_intent_id = \$1/);
        assert.equal(params[0], 'pi_example');
        assert.equal(params[2], row.transaction_id);
        if (row.status === 'pending') { row.status = 'completed'; credits++; return { rows: [row], rowCount: 1 }; }
        return { rows: [], rowCount: 0 };
      },
    } } });
    const args = { transactionId: 'topup-1', paymentIntentId: 'pi_example', paymentId: 'pay_example', amountInCentavos: 10000, currency: 'PHP' };
    await assert.rejects(ledger.completeWalletTopUp({ ...args, paymentIntentId: 'pi_other' }));
    await assert.rejects(ledger.completeWalletTopUp({ ...args, checkoutSessionId: 'cs_other' }));
    await assert.rejects(ledger.completeWalletTopUp({ ...args, amountInCentavos: 5000 }));
    assert.equal((await ledger.completeWalletTopUp(args)).updated, true);
    assert.equal((await ledger.completeWalletTopUp(args)).updated, false);
    assert.equal(credits, 1);
  });
});
