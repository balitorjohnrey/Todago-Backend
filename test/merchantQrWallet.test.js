const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');

function loadWith(filename, stubs) {
  const file = path.join(__dirname, '..', filename);
  const module = { exports: {} };
  const realRequire = createRequire(file);
  vm.runInNewContext(fs.readFileSync(file, 'utf8'), {
    module, exports: module.exports, Buffer, Date, process, console,
    require: name => Object.hasOwn(stubs, name) ? stubs[name] : realRequire(name),
  }, { filename: file });
  return module.exports;
}

function database() {
  const state = { wallets: [], requests: [], payments: [], locks: [], inactive: [], failCredit: false };
  let tail = Promise.resolve();
  const pool = { connect: async () => {
    let unlock, snapshot;
    return { release() {}, async query(text, values = []) {
      const sql = text.replace(/\s+/g, ' ').trim();
      let rows = [];
      if (sql === 'BEGIN') {
        const previous = tail;
        tail = new Promise(resolve => { unlock = resolve; });
        await previous;
        snapshot = structuredClone({ wallets: state.wallets, requests: state.requests, payments: state.payments });
      } else if (sql === 'COMMIT' || sql === 'ROLLBACK') {
        if (sql === 'ROLLBACK') Object.assign(state, snapshot);
        unlock();
      } else if (sql.startsWith('SELECT pg_advisory_xact_lock')) {
        state.locks.push(values[0]);
      } else if (sql.startsWith('SELECT id FROM users')) {
        rows = ['alice', 'bob'].includes(values[0]) && !state.inactive.includes(values[0]) ? [{ id: values[0] }] : [];
      } else if (sql.startsWith('INSERT INTO wallet_transactions')) {
        assert.ok(!state.wallets.some(row => row.user_id === values[0] && row.status === 'pending'));
        rows = [{ transaction_id: crypto.randomUUID(), user_id: values[0], amount: values[1],
          status: 'pending', merchant_qr: true, created_at: new Date(Date.now() - 1000) }];
        state.wallets.push(...rows);
      } else if (sql.startsWith('INSERT INTO merchant_qr_top_up_requests')) {
        rows = [{ transaction_id: values[0], reference: null, claim_attempts: 0, expires_at: new Date(Date.now() + 86400000) }];
        state.requests.push(...rows);
      } else if (sql.startsWith('UPDATE merchant_qr_top_up_requests')) {
        const request = state.requests.find(row => row.transaction_id === values[0]);
        request.reference = values[1]; request.claim_attempts++;
      } else if (sql.startsWith('INSERT INTO merchant_qr_payments')) {
        if (!state.payments.some(row => row.payment_id === values[0])) {
          assert.ok(!state.payments.some(row => row.event_id === values[1]), 'unique provider event');
          state.payments.push({ payment_id: values[0], event_id: values[1], qr_id: values[2],
            reference: values[3], amount_cents: values[4], paid_at: values[5], claimed_transaction_id: null });
        }
      } else if (sql.startsWith('SELECT * FROM merchant_qr_payments')) {
        rows = state.payments.filter(row => sql.includes('reference = $1') ? row.reference === values[0] : row.payment_id === values[0]);
      } else if (sql.startsWith('UPDATE merchant_qr_payments')) {
        const payment = state.payments.find(row => row.payment_id === values[0]);
        assert.equal(payment.claimed_transaction_id, null);
        payment.claimed_transaction_id = values[1];
      } else if (sql.startsWith('SELECT') && sql.includes('provider_payment_id = $1')) {
        rows = state.wallets.filter(row => row.provider_payment_id === values[0] || row.external_reference === values[0]);
      } else if (sql.startsWith('UPDATE wallet_transactions wt')) {
        for (const row of state.wallets) {
          const request = state.requests.find(r => r.transaction_id === row.transaction_id);
          if (row.user_id === values[0] && row.status === 'pending' && request.expires_at < new Date()) row.status = 'cancelled';
        }
      } else if (sql.startsWith('UPDATE wallet_transactions SET status')) {
        const row = state.wallets.find(r => r.transaction_id === values[0]);
        if (sql.includes("status = 'completed'")) {
          if (state.failCredit) throw new Error('Simulated database failure');
          assert.ok(!state.wallets.some(r => r.provider_payment_id === values[1]), 'unique payment credit');
          row.status = 'completed'; row.provider_payment_id = values[1]; row.external_reference = values[2];
        } else if (row.status === 'pending') row.status = 'cancelled';
      } else if (sql.startsWith('SELECT status FROM wallet_transactions')) {
        rows = state.wallets.filter(row => row.transaction_id === values[0]);
      } else if (sql.startsWith('SELECT') && sql.includes('JOIN merchant_qr_top_up_requests')) {
        rows = state.wallets.map(row => ({ ...row, ...state.requests.find(r => r.transaction_id === row.transaction_id) }));
        if (sql.includes('WHERE r.reference = $1')) {
          rows = rows.filter(row => row.reference === values[0] && row.status === 'pending' &&
            Math.round(row.amount * 100) === values[1] &&
            new Date(row.created_at).getTime() <= new Date(values[2]).getTime() + 5000 && new Date(row.expires_at) >= new Date(values[2]));
        } else if (sql.includes('WHERE wt.user_id = $1')) {
          rows = rows.filter(row => row.user_id === values[0] && row.status === 'pending');
        } else {
          rows = rows.filter(row => row.transaction_id === values[0] && (values.length < 2 || row.user_id === values[1]));
        }
      } else throw new Error('Unhandled database query: ' + sql);
      return { rows: structuredClone(rows), rowCount: rows.length };
    } };
  } };
  return { state, pool };
}

function setup() {
  const db = database();
  const service = loadWith('src/services/merchantQrWallet.js', {
    '../db/database': { pool: db.pool },
    './paymongo': new Proxy({}, { get() { throw new Error('Live QR receipts must not use an API key.'); } }),
  });
  return { ...db, service };
}

function paid({ id = 'pay_123', reference = 'INSTAPAY202611080001', amount = 2000, code = 'qr_confirmed', ...extra } = {}) {
  return { id: 'evt_' + id, type: 'event', attributes: { type: 'payment.paid', livemode: true,
    data: { id, type: 'payment', attributes: { amount, status: 'paid', currency: 'PHP', livemode: true,
      source: { type: 'qrph', provider: { code_id: code } }, external_reference_number: reference,
      paid_at: Math.floor(Date.now() / 1000), ...extra } } } };
}

test('merchant QR webhook-only top-ups', async t => {
  const names = ['PAYMONGO_WALLET_QR_MODE', 'PAYMONGO_INSTORE_QR_ID', 'PAYMONGO_INSTORE_WEBHOOK_SECRET', 'PAYMONGO_SECRET_KEY'];
  const previous = Object.fromEntries(names.map(name => [name, process.env[name]]));
  Object.assign(process.env, { PAYMONGO_WALLET_QR_MODE: 'merchant_webhook', PAYMONGO_INSTORE_QR_ID: 'qr_confirmed',
    PAYMONGO_INSTORE_WEBHOOK_SECRET: 'unit-test-signing-secret-only' });
  delete process.env.PAYMONGO_SECRET_KEY;
  t.after(() => { for (const name of names) {
    if (previous[name] === undefined) delete process.env[name]; else process.env[name] = previous[name];
  } });

  await t.test('validates raw-body live signatures, recency and duplicate headers without an API key', () => {
    const { service } = setup();
    const raw = Buffer.from(JSON.stringify({ data: paid() }));
    const now = Date.now(); const timestamp = Math.floor(now / 1000);
    const sign = (body, time = timestamp) => `t=${time},te=,li=` + crypto.createHmac('sha256', process.env.PAYMONGO_INSTORE_WEBHOOK_SECRET).update(`${time}.`).update(body).digest('hex');
    assert.equal(service.configuration().ready, true);
    assert.equal(service.verifyLiveSignature(raw, sign(raw), now), true);
    assert.equal(service.verifyLiveSignature(Buffer.from('{}'), sign(raw), now), false);
    assert.equal(service.verifyLiveSignature(raw, sign(raw, timestamp - 301), now), false);
    assert.equal(service.verifyLiveSignature(raw, sign(raw, timestamp + 301), now), false);
    assert.equal(service.verifyLiveSignature(raw, sign(raw) + `,t=${timestamp}`, now), false);
    assert.equal(service.verifyLiveSignature(raw, `t=${timestamp},te=${'a'.repeat(64)},li=`, now), false);
  });

  await t.test('fails closed when mode, signing secret or verified merchant QR ID is missing', async () => {
    for (const name of names.slice(0, 3)) {
      const saved = process.env[name]; delete process.env[name];
      const { service, state } = setup();
      await assert.rejects(service.createTopUp('alice', 20), error => error.statusCode === 503);
      assert.equal(state.wallets.length, 0); process.env[name] = saved;
    }
  });

  await t.test('requires a passenger and valid amount; concurrent creates reuse the same pending row', async () => {
    const { service, state } = setup();
    await assert.rejects(service.createTopUp('unknown', 20), error => error.statusCode === 403);
    for (const amount of [0, 19, 50001, '20.001', {}, true]) await assert.rejects(service.createTopUp('alice', amount));
    const [first, second] = await Promise.all([service.createTopUp('alice', 20), service.createTopUp('alice', 50)]);
    assert.equal(first.transactionId, second.transactionId);
    assert.equal(second.payment.amount, 20);
    assert.equal(state.wallets.length, 1);
    assert.equal(state.wallets[0].status, 'pending');
  });

  await t.test('webhook before reference submission credits the exact payment once', async () => {
    const { service, state } = setup();
    const request = await service.createTopUp('alice', 20);
    await service.receivePaidEvent(paid());
    assert.equal(state.wallets[0].status, 'pending');
    const claim = () => service.submitReference('alice', request.transactionId, 'instapay-202611080001');
    const results = await Promise.all([claim(), claim(), service.receivePaidEvent(paid())]);
    assert.equal(results[0].status, 'completed');
    assert.equal(state.wallets.filter(row => row.status === 'completed').length, 1);
    assert.equal(state.payments.length, 1);
    assert.equal(state.payments[0].claimed_transaction_id, request.transactionId);
  });

  await t.test('reference submission before the webhook remains pending until a signed payment is recorded', async () => {
    const { service, state } = setup();
    const request = await service.createTopUp('alice', 20);
    assert.equal((await service.submitReference('alice', request.transactionId, 'INSTAPAY202611080001')).status, 'pending');
    assert.equal((await service.readTopUp('alice', request.transactionId)).status, 'pending');
    await service.receivePaidEvent(paid());
    assert.equal((await service.readTopUp('alice', request.transactionId)).status, 'completed');
    assert.equal(state.wallets[0].amount, 20);
  });

  await t.test('test events, other QR codes, unpaid payments and malformed amounts do not credit', async () => {
    const { service, state } = setup();
    const request = await service.createTopUp('alice', 20);
    await service.submitReference('alice', request.transactionId, 'INSTAPAY202611080001');
    const testEvent = paid(); testEvent.attributes.livemode = false;
    assert.equal(await service.receivePaidEvent(testEvent), false);
    assert.equal(await service.receivePaidEvent(paid({ code: 'qr_someone_else' })), false);
    for (const change of [{ amount: 20.5 }, { amount: -1 }, { currency: 'USD' }, { status: 'pending' }, { disputed: true }, { refunds: [{}] }]) {
      await assert.rejects(service.receivePaidEvent(paid(change)));
    }
    assert.equal(state.wallets[0].status, 'pending');
    assert.equal(state.payments.length, 0);
  });

  await t.test('another passenger cannot read or update a request, or reuse a credited receipt', async () => {
    const { service, state } = setup();
    const alice = await service.createTopUp('alice', 20);
    const bob = await service.createTopUp('bob', 20);
    await assert.rejects(service.readTopUp('bob', alice.transactionId), error => error.statusCode === 404);
    await assert.rejects(service.submitReference('bob', alice.transactionId, 'INSTAPAY202611080001'), error => error.statusCode === 404);
    await service.receivePaidEvent(paid());
    await service.submitReference('alice', alice.transactionId, 'INSTAPAY202611080001');
    assert.equal((await service.submitReference('bob', bob.transactionId, 'INSTAPAY202611080001')).status, 'pending');
    assert.equal(state.wallets.filter(row => row.status === 'completed').length, 1);
  });

  await t.test('wrong amounts, old receipts, missing fields and duplicate references stay uncredited', async () => {
    for (const overrides of [{ amount: 5000 }, { paid_at: Math.floor(Date.now() / 1000) - 600 },
      { external_reference_number: null }, { paid_at: undefined }]) {
      const { service, state } = setup();
      const request = await service.createTopUp('alice', 20);
      await service.receivePaidEvent(paid(overrides));
      await service.submitReference('alice', request.transactionId, 'INSTAPAY202611080001');
      assert.equal(state.wallets[0].status, 'pending');
    }
    const { service, state } = setup();
    const request = await service.createTopUp('alice', 20);
    await service.receivePaidEvent(paid()); await service.receivePaidEvent(paid({ id: 'pay_second' }));
    assert.equal((await service.submitReference('alice', request.transactionId, 'INSTAPAY202611080001')).reviewRequired, true);
    assert.equal(state.wallets[0].status, 'pending');
  });

  await t.test('ambiguous passenger claims require review and database errors roll back the credit', async () => {
    const { service, state } = setup();
    const alice = await service.createTopUp('alice', 20);
    const bob = await service.createTopUp('bob', 20);
    await service.submitReference('alice', alice.transactionId, 'INSTAPAY202611080001');
    await service.submitReference('bob', bob.transactionId, 'INSTAPAY202611080001');
    await service.receivePaidEvent(paid());
    assert.equal(state.wallets.filter(row => row.status === 'completed').length, 0);
    state.requests.find(row => row.transaction_id === bob.transactionId).reference = 'OTHERREFERENCE';
    state.failCredit = true;
    await assert.rejects(service.submitReference('alice', alice.transactionId, 'INSTAPAY202611080001'));
    assert.equal(state.wallets[0].status, 'pending');
    assert.equal(state.payments[0].claimed_transaction_id, null);
    state.failCredit = false;
    assert.equal((await service.submitReference('alice', alice.transactionId, 'INSTAPAY202611080001')).status, 'completed');
  });

  await t.test('bounded reference changes and expired requests cannot add funds', async () => {
    const { service, state } = setup();
    const request = await service.createTopUp('alice', 20);
    for (let attempt = 0; attempt < 8; attempt++) await service.submitReference('alice', request.transactionId, 'REFERENCE' + attempt);
    await assert.rejects(service.submitReference('alice', request.transactionId, 'REFERENCE9'), error => error.statusCode === 429);
    state.requests[0].expires_at = new Date(Date.now() - 1000);
    assert.equal((await service.readTopUp('alice', request.transactionId)).status, 'cancelled');
    assert.equal(state.wallets[0].status, 'cancelled');
  });

  await t.test('an inactive recipient cannot receive a credit but the verified receipt is retained', async () => {
    const { service, state } = setup();
    const request = await service.createTopUp('alice', 20);
    await service.submitReference('alice', request.transactionId, 'INSTAPAY202611080001');
    state.inactive.push('alice');
    assert.equal(await service.receivePaidEvent(paid()), true);
    assert.equal(state.payments.length, 1);
    assert.equal(state.wallets[0].status, 'pending');
  });

  await t.test('a payment already credited through a legacy provider reference cannot fund another wallet', async () => {
    const { service, state } = setup();
    state.wallets.push({ transaction_id: 'legacy-credit', user_id: 'bob', amount: 20,
      status: 'completed', external_reference: 'pay_123' });
    const request = await service.createTopUp('alice', 20);
    await service.receivePaidEvent(paid());
    assert.equal((await service.submitReference('alice', request.transactionId, 'INSTAPAY202611080001')).status, 'pending');
    assert.equal(state.wallets.filter(row => row.status === 'completed').length, 1);
  });
});

test('the mounted webhook verifies the signature before recording a payment; passenger endpoints enforce authentication', async t => {
  const http = require('node:http');
  const express = require('express');
  const { service, state } = setup();
  const previous = {};
  for (const [key, value] of Object.entries({ PAYMONGO_WALLET_QR_MODE: 'merchant_webhook',
    PAYMONGO_INSTORE_QR_ID: 'qr_confirmed', PAYMONGO_INSTORE_WEBHOOK_SECRET: 'unit-test-http-signature' })) {
    previous[key] = process.env[key]; process.env[key] = value;
  }
  t.after(() => { for (const [key, value] of Object.entries(previous)) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  } });
  const router = loadWith('src/routes/merchantQrWallet.js', {
    '../services/merchantQrWallet': service,
    './auth': { requireAuth(req, res, next) {
      if (!req.get('Authorization')) return res.status(401).json({ success: false });
      req.userId = 'alice'; req.userRole = req.get('Authorization') === 'Bearer driver' ? 'driver' : 'passenger'; next();
    } },
  });
  const app = express();
  app.use(express.json({ verify(req, _res, bytes) { req.rawBody = Buffer.from(bytes); } }));
  app.use('/api/wallet/in-store-qr', router);
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const request = (method, suffix, body, headers = {}) => new Promise((resolve, reject) => {
    const raw = body ? JSON.stringify(body) : '';
    const req = http.request({ hostname: '127.0.0.1', port: server.address().port,
      path: '/api/wallet/in-store-qr' + suffix, method,
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(raw), ...headers } }, res => {
      let response = ''; res.on('data', bytes => { response += bytes; });
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(response) }));
    });
    req.on('error', reject); req.end(raw);
  });
  assert.equal((await request('GET', '/configuration')).status, 401);
  assert.equal((await request('GET', '/configuration', null, { authorization: 'Bearer driver' })).status, 403);
  const created = await request('POST', '/top-ups', { amount: 73.45, userId: 'bob' }, { authorization: 'Bearer passenger' });
  assert.equal(created.body.success, true);
  assert.equal(state.wallets[0].user_id, 'alice');
  assert.equal(state.wallets[0].amount, 73.45);
  const body = { data: paid({ amount: 7345 }) };
  assert.equal((await request('POST', '/webhook', body)).status, 401);
  assert.equal(state.payments.length, 0);
  const timestamp = Math.floor(Date.now() / 1000);
  const digest = crypto.createHmac('sha256', process.env.PAYMONGO_INSTORE_WEBHOOK_SECRET)
    .update(`${timestamp}.`).update(JSON.stringify(body)).digest('hex');
  const signature = { 'Paymongo-Signature': `t=${timestamp},te=,li=${digest}` };
  assert.equal((await request('POST', '/webhook', body, signature)).status, 200);
  assert.equal(state.payments.length, 1);
  assert.equal(state.wallets[0].status, 'pending');
  assert.equal((await request('POST', '/webhook', { data: paid({ amount: 9999 }) }, signature)).status, 401);
  assert.equal(state.wallets[0].status, 'pending');
});
