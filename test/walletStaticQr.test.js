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
    require: name => Object.hasOwn(stubs, name) ? stubs[name] : actualRequire(name),
  }, { filename: file });
  return module.exports;
}

function setup() {
  const state = { assignments: [], transactions: [], generated: 0, live: true, reads: 0,
    payments: [], generation: null };
  let tail = Promise.resolve();
  const database = {
    dbGet: async (sql, values) => state.assignments.find(row =>
      sql.includes('user_id = $1') ? row.user_id === values[0] : row.qr_code_id === values[0]),
    pool: { connect: async () => {
      let releaseLock;
      let snapshot;
      const client = {
        release() {},
        async query(sql, values = []) {
          sql = sql.replace(/\s+/g, ' ').trim();
          let rows = [];
          if (sql === 'BEGIN') return { rows };
          if (sql === 'COMMIT' || sql === 'ROLLBACK') {
            if (sql === 'ROLLBACK' && snapshot) {
              state.assignments = snapshot.assignments;
              state.transactions = snapshot.transactions;
            }
            releaseLock?.(); releaseLock = null;
            return { rows };
          }
          if (sql.startsWith('SELECT id FROM users')) {
            const previous = tail;
            tail = new Promise(resolve => { releaseLock = resolve; });
            await previous;
            snapshot = structuredClone({ assignments: state.assignments, transactions: state.transactions });
            rows = ['alice', 'bob'].includes(values[0]) ? [{ id: values[0] }] : [];
          } else if (sql.startsWith('SELECT * FROM passenger_wallet_qr_codes')) {
            rows = state.assignments.filter(row => row.user_id === values[0]);
          } else if (sql.startsWith('INSERT INTO passenger_wallet_qr_codes')) {
            if (state.assignments.some(row => row.qr_code_id === values[1])) throw new Error('duplicate QR');
            rows = [{ user_id: values[0], qr_code_id: values[1], qr_image: values[2], livemode: true }];
            state.assignments.push(...rows);
          } else if (sql.startsWith('SELECT') && sql.includes('provider_payment_id = $1')) {
            rows = state.transactions.filter(row => row.provider_payment_id === values[0]);
          } else if (sql.startsWith('SELECT') && sql.includes("status = 'pending'")) {
            rows = state.transactions.filter(row => row.user_id === values[0] &&
              row.static_qr_id === values[1] && row.status === 'pending');
          } else if (sql.startsWith('INSERT INTO wallet_transactions')) {
            const completed = values.length === 4;
            if (completed && state.transactions.some(row => row.provider_payment_id === values[3])) {
              throw new Error('duplicate payment');
            }
            rows = [{ transaction_id: `tx-${state.transactions.length + 1}`, user_id: values[0],
              amount: values[1], static_qr_id: values[2], status: completed ? 'completed' : 'pending',
              provider_payment_id: completed ? values[3] : null }];
            state.transactions.push(...rows);
          } else if (sql.startsWith('UPDATE wallet_transactions')) {
            const row = state.transactions.find(item => item.transaction_id === values[0] && item.status === 'pending');
            if (row) {
              row.amount = values[1];
              if (values[2]) { row.status = 'completed'; row.provider_payment_id = values[2]; }
              rows = [row];
            }
          } else throw new Error(`Unexpected database query: ${sql}`);
          return { rows: rows.map(row => ({ ...row })), rowCount: rows.length };
        },
      };
      return client;
    } },
  };
  const paymongo = { isLiveMode: () => state.live,
    createPassengerStaticQr: async ({ userId }) => {
      state.generated++;
      return state.generation || { id: `code_${userId}`, attributes: { qr_image: 'data:image/png;base64,aW1hZ2U=' } };
    },
    listPayments: async ({ after }) => {
      state.reads++;
      const start = after ? state.payments.findIndex(row => row.id === after) + 1 : 0;
      return { data: state.payments.slice(start, start + 100), has_more: start + 100 < state.payments.length };
    },
  };
  const service = loadWith('src/services/walletStaticQr.js', { '../db/database': database, './paymongo': paymongo });
  return { state, database, service };
}

function paid(code = 'code_alice', id = 'pay_one', overrides = {}) {
  return { id, attributes: { status: 'paid', currency: 'PHP', amount: 2000, livemode: true,
    source: { type: 'qrph', provider: { code_id: code } }, ...overrides } };
}

test('passenger static QR payments', async t => {
  const oldMode = process.env.PAYMONGO_WALLET_QR_MODE;
  const oldSecret = process.env.PAYMONGO_WEBHOOK_SECRET;
  process.env.PAYMONGO_WALLET_QR_MODE = 'passenger_static';
  process.env.PAYMONGO_WEBHOOK_SECRET = 'unit-tests-only';
  t.after(() => {
    for (const [name, value] of [['PAYMONGO_WALLET_QR_MODE', oldMode], ['PAYMONGO_WEBHOOK_SECRET', oldSecret]]) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  });

  await t.test('reuses one QR per passenger and assigns a different QR to another passenger', async () => {
    const { service, state } = setup();
    const [first, second] = await Promise.all([
      service.createStaticQrTopUp('alice', 20), service.createStaticQrTopUp('alice', 50),
    ]);
    const bob = await service.createStaticQrTopUp('bob', 20);
    assert.equal(first.payment.qrCodeId, second.payment.qrCodeId);
    assert.notEqual(first.payment.qrCodeId, bob.payment.qrCodeId);
    assert.equal(first.transactionId, second.transactionId);
    assert.equal(state.generated, 2);
    assert.equal(state.transactions.length, 2);
    assert.equal(state.transactions[0].amount, 50);
    assert.equal(first.payment.kind, 'static_qr');
    assert.equal(first.payment.testMode, false);
    assert.equal(first.payment.amountEntryRequired, true);
  });

  await t.test('never displays a payable static QR with a test key or missing webhook secret', async () => {
    const { service, state } = setup();
    state.live = false;
    await assert.rejects(service.createStaticQrTopUp('alice', 20), error => error.statusCode === 503);
    state.live = true;
    delete process.env.PAYMONGO_WEBHOOK_SECRET;
    await assert.rejects(service.createStaticQrTopUp('alice', 20), error => error.statusCode === 503);
    process.env.PAYMONGO_WEBHOOK_SECRET = 'unit-tests-only';
    assert.equal(state.generated, 0);
    assert.equal(state.transactions.length, 0);
  });

  await t.test('unavailable users and invalid provider images cannot create an assignment', async () => {
    const { service, state } = setup();
    await assert.rejects(service.createStaticQrTopUp('not-a-passenger', 20), /unavailable/);
    state.generation = { id: 'code_wrong', attributes: { qr_image: 'https://example.com/shared-qr.png' } };
    await assert.rejects(service.createStaticQrTopUp('alice', 20), /usable passenger QR/);
    assert.equal(state.assignments.length, 0);
    assert.equal(state.transactions.length, 0);
  });

  await t.test('credits the QR owner and actual paid amount even when two users select the same amount', async () => {
    const { service, state } = setup();
    await service.createStaticQrTopUp('alice', 100);
    await service.createStaticQrTopUp('bob', 100);
    assert.equal(await service.settleStaticQrPayment(paid('code_bob', 'pay_bob', { amount: 5000 }), true), true);
    assert.equal(state.transactions[0].status, 'pending');
    assert.equal(state.transactions[1].status, 'completed');
    assert.equal(state.transactions[1].user_id, 'bob');
    assert.equal(state.transactions[1].amount, 50);
  });

  await t.test('duplicate/concurrent deliveries credit once; another payment to the reusable QR credits again', async () => {
    const { service, state } = setup();
    await service.createStaticQrTopUp('alice', 20);
    await Promise.all([service.settleStaticQrPayment(paid(), true), service.settleStaticQrPayment(paid(), true)]);
    assert.equal(state.transactions.length, 1);
    assert.equal(state.transactions[0].status, 'completed');
    await service.settleStaticQrPayment(paid('code_alice', 'pay_two', { amount: 100 }), true);
    assert.equal(state.transactions.length, 2);
    assert.equal(state.transactions[1].amount, 1);
  });

  await t.test('the shared merchant standee and unknown QR IDs cannot select a passenger by amount', async () => {
    const { service, state } = setup();
    await service.createStaticQrTopUp('alice', 20);
    assert.equal(await service.settleStaticQrPayment(paid('qr_be9cd139efbb7b6632b31e6f'), true), false);
    assert.equal(await service.settleStaticQrPayment(paid('code_unknown'), true), false);
    assert.equal(state.transactions[0].status, 'pending');
  });

  await t.test('rejects failed, test-mode, non-PHP, refunded, disputed and invalid-amount payments', async () => {
    const { service, state } = setup();
    await service.createStaticQrTopUp('alice', 20);
    for (const attrs of [{ status: 'failed' }, { livemode: false }, { currency: 'USD' },
      { amount: 0 }, { amount: -1 }, { amount: 2.5 }, { amount: 5000001 },
      { refunds: [{ status: 'succeeded' }] }, { disputed: true }]) {
      await assert.rejects(service.settleStaticQrPayment(paid('code_alice', 'pay_invalid', attrs), true), /verified/);
    }
    await assert.rejects(service.settleStaticQrPayment(paid(), false), /verified/);
    assert.equal(state.transactions[0].status, 'pending');
  });

  await t.test('a payment ID already credited to another wallet cannot be reassigned', async () => {
    const { service, state } = setup();
    await service.createStaticQrTopUp('alice', 20);
    await service.createStaticQrTopUp('bob', 20);
    await service.settleStaticQrPayment(paid(), true);
    await assert.rejects(service.settleStaticQrPayment(paid('code_bob'), true), /another wallet/);
    assert.equal(state.transactions[1].status, 'pending');
  });

  await t.test('recovers missed webhooks through paginated provider records and scopes recovery to the owner', async () => {
    const { service, state } = setup();
    await service.createStaticQrTopUp('alice', 20);
    await service.createStaticQrTopUp('bob', 20);
    state.payments = Array.from({ length: 100 }, (_, i) => paid('code_bob', `pay_other${i}`));
    state.payments.push(paid());
    await service.reconcileStaticQrPayments('alice');
    await service.reconcileStaticQrPayments('alice');
    assert.equal(state.reads, 2);
    assert.equal(state.transactions[0].status, 'completed');
    assert.equal(state.transactions[1].status, 'pending');
    assert.equal(state.transactions.length, 2);
  });
});

test('static QR provider request uses the documented endpoint and keeps credentials server-side', async t => {
  const oldKey = process.env.PAYMONGO_SECRET_KEY;
  const oldFetch = global.fetch;
  process.env.PAYMONGO_SECRET_KEY = 'sk_live_unit_tests_only';
  t.after(() => { global.fetch = oldFetch;
    if (oldKey === undefined) delete process.env.PAYMONGO_SECRET_KEY; else process.env.PAYMONGO_SECRET_KEY = oldKey;
  });
  const requests = [];
  global.fetch = async (url, options) => {
    requests.push({ url, options });
    return { ok: true, json: async () => ({ data: { id: 'code_alice', attributes: { qr_image: 'data:image/png;base64,aW1hZ2U=' } } }) };
  };
  const paymongo = loadWith('src/services/paymongo.js', {});
  await paymongo.createPassengerStaticQr({ userId: 'alice' });
  assert.equal(requests[0].url, 'https://api.paymongo.com/v1/qrph/generate');
  assert.equal(requests[0].options.method, 'POST');
  assert.deepEqual(JSON.parse(requests[0].options.body), { data: { attributes: {
    kind: 'instore', notes: 'TodaGo passenger wallet alice',
  } } });
  assert.match(requests[0].options.headers['Idempotency-Key'], /alice/);
  process.env.PAYMONGO_SECRET_KEY = 'sk_test_unit_tests_only';
  await assert.rejects(paymongo.createPassengerStaticQr({ userId: 'bob' }), /live PayMongo/);
  assert.equal(requests.length, 1);
});

test('static QR routes select the authenticated passenger and verify webhooks before settlement', async () => {
  const calls = [];
  let validSignature = false;
  let canReadTopUp = false;
  const stubs = {
    './auth': { requireAuth: (_req, _res, next) => next() },
    '../db/database': {
      dbAll: async () => [], dbRun: async () => {},
      dbGet: async (sql, params) => {
        if (sql.includes("AND user_id = $2 AND type = 'topup'")) {
          assert.equal(params[1], 'alice');
          return canReadTopUp ? { transaction_id: 'tx-one', static_qr_id: 'code_alice', amount: 20 } : null;
        }
        return { status: 'pending', amount: 20 };
      },
    },
    '../services/paymongo': {
      isLiveMode: () => true, verifyWebhookSignature: () => validSignature,
      getAvailablePaymentMethods: () => { throw new Error('Static mode must not create a dynamic payment.'); },
    },
    '../services/walletLedger': { getWalletBalance: async () => 0 },
    '../services/walletPayments': {},
    '../services/walletIntentPayments': { handleWalletPaymentEvent: async () => false },
    '../services/walletStaticQr': {
      staticQrEnabled: () => true, requireStaticQrConfiguration: () => {},
      createStaticQrTopUp: async (userId, amount) => {
        calls.push({ userId, amount });
        return { transactionId: 'tx-one', payment: { kind: 'static_qr', qrCodeId: `code_${userId}` } };
      },
      settleStaticQrPayment: async (payment, livemode) => {
        assert.equal(validSignature, true);
        assert.equal(livemode, true);
        calls.push({ payment: payment.id });
        return true;
      },
      reconcileStaticQrPayments: async () => {},
      getAssignedStaticQr: async (userId, codeId) => {
        assert.equal(userId, 'alice'); assert.equal(codeId, 'code_alice');
        return { qr_code_id: codeId };
      },
      staticQrPresentation: row => ({ kind: 'static_qr', qrCodeId: row.qr_code_id }),
    },
    '../utils/adminReports': {}, '../services/reportPenalties': {}, '../services/tripPayments': {},
    '../services/driverTracking': {},
  };
  const wallet = loadWith('src/routes/wallet.js', stubs);
  const trips = loadWith('src/routes/trips.js', stubs);
  async function request(router, path, req) {
    let status = 200, body;
    const res = { status(value) { status = value; return res; }, json(value) { body = value; return res; } };
    const handler = router.stack.find(layer => layer.route?.path === path).route.stack.at(-1).handle;
    await handler(req, res);
    return { status, body };
  }
  const created = await request(wallet, '/top-up', { userId: 'alice', userRole: 'passenger',
    body: { provider: 'qrph', amount: 20, userId: 'bob', qrCodeId: 'code_bob' } });
  assert.equal(created.status, 201);
  assert.equal(created.body.payment.qrCodeId, 'code_alice');
  assert.deepEqual(calls[0], { userId: 'alice', amount: 20 });
  const foreign = await request(wallet, '/top-ups/:transactionId', { userId: 'alice', userRole: 'passenger',
    params: { transactionId: 'someone-elses-topup' } });
  assert.equal(foreign.status, 404);
  canReadTopUp = true;
  const own = await request(wallet, '/top-ups/:transactionId', { userId: 'alice', userRole: 'passenger',
    params: { transactionId: 'own-topup' } });
  assert.equal(own.body.payment.qrCodeId, 'code_alice');

  for (const router of [wallet, trips]) {
    const req = { body: { data: { type: 'event', attributes: {
      type: 'payment.paid', livemode: true, data: paid(),
    } } }, get: () => 'signature', rawBody: Buffer.from('example') };
    validSignature = false;
    const before = calls.length;
    assert.equal((await request(router, '/paymongo/webhook', req)).status, 401);
    assert.equal(calls.length, before);
    validSignature = true;
    assert.equal((await request(router, '/paymongo/webhook', req)).status, 200);
    assert.equal(calls.length, before + 1);
    assert.equal(calls.at(-1).payment, 'pay_one');
  }
});
