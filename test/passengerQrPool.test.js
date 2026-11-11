const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const { createRequire } = require('node:module');
const manifest = require('../src/data/passengerQrPool.json');

function setup() {
  const state = { qrs: [], payments: [], wallets: [], recoveries: [], inactive: [], failCredit: false };
  let tail = Promise.resolve();
  async function query(text, values = []) {
    const sql = text.replace(/\s+/g, ' ').trim();
    let rows = [];
    if (/^(CREATE|ALTER|BEGIN|COMMIT|ROLLBACK)/.test(sql) || sql.startsWith('SELECT pg_advisory')) return { rows };
    if (sql.startsWith('INSERT INTO wallet_qr_pool')) {
      if (!state.qrs.some(q => q.qr_id === values[0])) state.qrs.push({ qr_id: values[0], label: values[1], image_sha256: values[2], organization_id: values[3], assigned_user_id: null, assigned_at: null, enabled: true });
    } else if (sql.startsWith('SELECT * FROM wallet_qr_pool')) {
      rows = state.qrs.filter(q => sql.includes('qr_id = $1') ? q.qr_id === values[0]
        : sql.includes('assigned_user_id = $1') ? q.assigned_user_id === values[0] : !q.assigned_user_id && q.enabled).sort((a,b) => a.label.localeCompare(b.label));
      if (sql.includes('LIMIT 1')) rows = rows.slice(0,1);
    } else if (sql.startsWith('UPDATE wallet_qr_pool SET organization_id')) {
      assert.ok(state.qrs.every(q => q.organization_id));
    } else if (sql.startsWith('UPDATE wallet_qr_pool SET retired_at')) {
      assert.ok(state.qrs.every(q => values[0].includes(q.qr_id)));
    } else if (sql.startsWith('UPDATE wallet_qr_pool SET assigned_user_id')) {
      const qr = state.qrs.find(q => q.qr_id === values[0]);
      assert.equal(qr.assigned_user_id, null);
      assert.ok(!state.qrs.some(q => q.assigned_user_id === values[1]));
      Object.assign(qr, { assigned_user_id: values[1], assigned_at: new Date() }); rows = [qr];
    } else if (sql.startsWith('SELECT id FROM users')) {
      rows = (['alice','bob','carol'].includes(values[0]) || /^user\d+$/.test(values[0])) && !state.inactive.includes(values[0]) ? [{ id: values[0] }] : [];
    } else if (sql.startsWith('INSERT INTO merchant_qr_payments')) {
      if (!state.payments.some(p => p.payment_id === values[0])) {
        assert.ok(!state.payments.some(p => p.event_id === values[1]));
        state.payments.push({ payment_id: values[0], event_id: values[1], qr_id: values[2], reference: null,
          amount_cents: values[3], paid_at: values[4], pool_user_id: values[5], claimed_transaction_id: null });
      }
    } else if (sql.startsWith('SELECT * FROM merchant_qr_payments')) {
      rows = state.payments.filter(p => p.payment_id === values[0]);
    } else if (sql.startsWith('UPDATE merchant_qr_payments')) {
      const p = state.payments.find(p => p.payment_id === values[0]);
      if (sql.includes('SET review_reason')) p.review_reason = values[1];
      else { assert.equal(p.claimed_transaction_id, null); p.claimed_transaction_id = values[1]; p.review_reason = null; }
    } else if (sql.startsWith('SELECT transaction_id FROM wallet_transactions')) {
      rows = state.wallets.filter(w => w.provider_payment_id === values[0] || w.external_reference === values[0]);
    } else if (sql.startsWith('INSERT INTO wallet_transactions')) {
      if (state.failCredit) throw new Error('Database write failed');
      assert.ok(!state.wallets.some(w => w.provider_payment_id === values[3]));
      const w = { transaction_id: crypto.randomUUID(), user_id: values[0], amount: values[1], pool_qr_id: values[2],
        provider_payment_id: values[3], external_reference: values[3], status: 'completed', completed_at: new Date(), created_at: values[4] };
      state.wallets.push(w); rows = [w];
    } else if (sql.startsWith('SELECT transaction_id, provider_payment_id')) {
      rows = state.wallets.filter(w => w.user_id === values[0] && w.pool_qr_id === values[1] && w.status === 'completed').slice(-1);
    } else if (sql.startsWith('SELECT * FROM wallet_qr_recoveries')) {
      rows = state.recoveries.filter(r => r.request_id === values[0]);
    } else if (sql.startsWith('SELECT wt.*, u.email')) {
      rows = state.wallets.filter(w => w.transaction_id === values[0] && w.email === values[1]);
    } else if (sql.startsWith('UPDATE wallet_transactions')) {
      if (state.failCredit) throw new Error('Database write failed');
      const w = state.wallets.find(w => w.transaction_id === values[0]);
      Object.assign(w, { status: 'completed', provider_payment_id: values[1], external_reference: values[1] });
    } else if (sql.startsWith('INSERT INTO wallet_qr_recoveries')) {
      state.recoveries.push({ payment_id: values[0], transaction_id: values[1], user_id: values[2], request_id: values[3] });
    } else throw new Error('Unhandled query: ' + sql);
    return { rows: structuredClone(rows) };
  }
  const pool = { query, connect: async () => {
    let unlock, snapshot;
    return { release() {}, query: async (sql, values) => {
      if (sql === 'BEGIN') {
        const previous = tail; tail = new Promise(resolve => { unlock = resolve; }); await previous;
        snapshot = structuredClone({ qrs: state.qrs, wallets: state.wallets, payments: state.payments, recoveries: state.recoveries });
        return { rows: [] };
      }
      if (sql === 'COMMIT' || sql === 'ROLLBACK') {
        if (sql === 'ROLLBACK') Object.assign(state, snapshot);
        unlock(); return { rows: [] };
      }
      return query(sql, values);
    } };
  } };
  const env = new Proxy({ PAYMONGO_WALLET_QR_MODE: 'passenger_pool', PAYMONGO_INSTORE_WEBHOOK_SECRET: 'legacy-test-secret',
    PAYMONGO_INSTORE_POOL_WEBHOOK_SECRET: 'current-test-secret' }, {
    get(target, key) { if (key === 'PAYMONGO_SECRET_KEY') throw new Error('An API key must never be read'); return target[key]; },
  });
  const filename = path.join(__dirname, '../src/services/passengerQrPool.js');
  const module = { exports: {} }, realRequire = createRequire(filename);
  vm.runInNewContext(fs.readFileSync(filename, 'utf8'), { module, exports: module.exports, Date, console,
    process: { env }, require: name => name === '../db/database' ? { pool } : realRequire(name) }, { filename });
  return { service: module.exports, state, pool, env };
}

function event(qrId = manifest.entries[0].qrId, id = 'one', amount = 2000) {
  return { id: 'evt_' + id, type: 'event', attributes: { type: 'payment.paid', livemode: true,
    data: { id: 'pay_' + id, type: 'payment', attributes: { amount, currency: 'PHP', status: 'paid', livemode: true,
      external_reference_number: null, fee: 30, net_amount: amount - 30, origin: 'instore_qrph',
      organization_id: manifest.organizationId, source: { type: 'qrph', provider: { code_id: qrId } },
      paid_at: Math.floor(Date.now()/1000), refunds: [] } } } };
}

test('passenger QR pool imports and assignments are permanent, unique and safe under concurrent registration', async () => {
  const { service, state, pool } = setup();
  await service.initialize(pool); await service.initialize(pool);
  const [a, a2, b] = await Promise.all([service.assign('alice'), service.assign('alice'), service.assign('bob')]);
  assert.equal(a.qr_id, a2.qr_id); assert.notEqual(a.qr_id, b.qr_id);
  assert.equal(state.qrs.length, manifest.entries.length);
  for (let i = 2; i < manifest.entries.length; i++) await service.assign('user' + i);
  assert.equal(await service.assign('carol'), null);
  assert.equal((await service.getPassengerQr('carol')).available, false);
  assert.equal((await service.getPassengerQr('alice')).qrCodeId, a.qr_id);
  await assert.rejects(service.assign('driver'), e => e.statusCode === 403);
  state.qrs[0].image_sha256 = '0'.repeat(64);
  await assert.rejects(service.initialize(pool), /cannot be replaced/);
});

test('a signed-live payment shape with a null reference credits the QR owner at the actual gross amount once', async () => {
  const { service, state, pool } = setup(); await service.initialize(pool);
  const a = await service.assign('alice'); const b = await service.assign('bob');
  const paid = event(b.qr_id, 'payment', 7345);
  await Promise.all(Array.from({ length: 5 }, () => service.receivePaidEvent(paid)));
  assert.equal(state.wallets.length, 1); assert.equal(state.wallets[0].user_id, 'bob');
  assert.equal(state.wallets[0].amount, 73.45); assert.equal(state.payments.length, 1);
  await service.receivePaidEvent(event(b.qr_id, 'second', 100));
  assert.equal(state.wallets.length, 2); assert.equal(state.wallets[1].amount, 1);
  assert.equal((await service.getPassengerQr('alice')).latestPayment, null);
  assert.equal((await service.getPassengerQr('bob')).latestPayment.paymentId, 'pay_second');
  const changed = structuredClone(paid); changed.attributes.data.attributes.amount = 9999;
  await assert.rejects(service.receivePaidEvent(changed), e => e.statusCode === 409);
  assert.equal(state.wallets.length, 2);
  assert.notEqual(a.qr_id, b.qr_id);
});

test('test, wrong-organization, unknown-QR and invalid payments cannot create credit', async () => {
  const { service, state, pool } = setup(); await service.initialize(pool); await service.assign('alice');
  for (const mutate of [e => e.attributes.livemode = false, e => e.attributes.data.attributes.livemode = false,
    e => e.attributes.type = 'qr.paid', e => e.attributes.data.attributes.organization_id = 'org_other',
    e => e.attributes.data.attributes.origin = 'api', e => e.attributes.data.attributes.source.type = 'gcash']) {
    const e = event(); mutate(e); assert.equal(await service.receivePaidEvent(e), false);
  }
  assert.equal(await service.receivePaidEvent(event('qr_' + 'a'.repeat(24))), false);
  const legacyOrganization = event();
  legacyOrganization.attributes.data.attributes.organization_id = manifest.legacyOrganizationId;
  assert.equal(await service.receivePaidEvent(legacyOrganization), false);
  for (const amount of [0,-1,20.001,5000001]) await assert.rejects(service.receivePaidEvent(event(undefined, 'invalid', amount)));
  for (const mutate of [a => a.status = 'pending', a => a.currency = 'USD', a => a.disputed = true, a => a.refunds = [{}]]) {
    const e = event(); mutate(e.attributes.data.attributes); await assert.rejects(service.receivePaidEvent(e));
  }
  assert.equal(state.wallets.length, 0);
});

test('unassigned, pre-assignment, untimed and inactive payments remain in review without credit', async () => {
  const { service, state, pool } = setup(); await service.initialize(pool);
  const e = event(); await service.receivePaidEvent(e); await service.assign('alice');
  await service.receivePaidEvent(e);
  assert.equal(state.payments[0].review_reason, 'unassigned_qr');
  const old = event(undefined, 'old'); old.attributes.data.attributes.paid_at -= 60; await service.receivePaidEvent(old);
  const untimed = event(undefined, 'untimed'); delete untimed.attributes.data.attributes.paid_at; await service.receivePaidEvent(untimed);
  state.inactive.push('alice'); await service.receivePaidEvent(event(undefined, 'inactive'));
  assert.equal(state.payments[1].review_reason, 'predates_assignment');
  assert.equal(state.payments[2].review_reason, 'missing_paid_at');
  assert.equal(state.payments[3].review_reason, 'inactive_passenger');
  assert.equal(state.wallets.length, 0);
});

test('a database failure rolls back the inbox and credit, allowing a safe provider retry', async () => {
  const { service, state, pool } = setup(); await service.initialize(pool); await service.assign('alice');
  state.failCredit = true; await assert.rejects(service.receivePaidEvent(event()), /Database write failed/);
  assert.equal(state.payments.length, 0); assert.equal(state.wallets.length, 0);
  state.failCredit = false; await service.receivePaidEvent(event()); assert.equal(state.wallets.length, 1);
});

test('a payment already used by another wallet flow cannot fund the pool a second time', async () => {
  const { service, state, pool } = setup(); await service.initialize(pool); await service.assign('alice');
  state.wallets.push({ user_id: 'bob', provider_payment_id: 'pay_one', transaction_id: 'legacy-credit' });
  await service.receivePaidEvent(event()); assert.equal(state.wallets.length, 1);
  assert.equal(state.payments[0].review_reason, 'already_used_payment');
});

test('owner-approved shared-QR recovery needs the verified inbox, exact beneficiary and amount; it is idempotent', async () => {
  const { service, state, pool, env } = setup(); await service.initialize(pool);
  Object.assign(env, { WALLET_QR_RECOVERY_REQUEST_ID: 'owner-confirmed-one', WALLET_QR_RECOVERY_PAYMENT_ID: 'pay_old',
    WALLET_QR_RECOVERY_TRANSACTION_ID: 'pending-old', WALLET_QR_RECOVERY_EMAIL: 'alice@example.com', PAYMONGO_INSTORE_QR_ID: 'qr_shared' });
  assert.equal((await service.recoverApprovedPayment()).status, 'awaiting_verified_webhook');
  state.payments.push({ payment_id: 'pay_old', qr_id: 'qr_shared', amount_cents: 2000, paid_at: new Date(), claimed_transaction_id: null });
  state.wallets.push({ transaction_id: 'pending-old', user_id: 'alice', email: 'wrong@example.com', merchant_qr: true,
    amount: 20, status: 'pending', created_at: new Date(Date.now()-1000), expires_at: new Date(Date.now()+86400000) });
  await assert.rejects(service.recoverApprovedPayment(), e => e.statusCode === 409);
  state.wallets[0].email = 'alice@example.com'; state.wallets[0].amount = 50;
  await assert.rejects(service.recoverApprovedPayment(), e => e.statusCode === 409);
  state.wallets[0].amount = 20;
  assert.equal((await service.recoverApprovedPayment()).status, 'completed');
  assert.equal((await service.recoverApprovedPayment()).status, 'already_applied');
  assert.equal(state.wallets[0].provider_payment_id, 'pay_old'); assert.equal(state.recoveries.length, 1);
});

test('HTTP pool routes bind assignments to authentication, reject legacy creation, and verify webhooks before settlement', async t => {
  const { service, state, pool, env } = setup(); await service.initialize(pool);
  const filename = path.join(__dirname, '../src/routes/merchantQrWallet.js');
  const module = { exports: {} }, realRequire = createRequire(filename);
  const stubs = {
    '../services/passengerQrPool': service,
    '../services/merchantQrWallet': {
      verifyLiveSignature: (raw, signature, _now, secret = env.PAYMONGO_INSTORE_WEBHOOK_SECRET) =>
        Buffer.isBuffer(raw) && secret !== null && signature === `signed-with-${secret}`,
      receivePaidEvent: async () => false,
    },
    './auth': { requireAuth(req, res, next) {
      const token = req.get('authorization');
      if (!['Bearer alice', 'Bearer bob', 'Bearer driver'].includes(token)) return res.status(401).json({ success: false });
      req.userId = token.split(' ')[1]; req.userRole = token === 'Bearer driver' ? 'driver' : 'passenger'; next();
    } },
  };
  vm.runInNewContext(fs.readFileSync(filename, 'utf8'), { module, exports: module.exports, Buffer, console, process,
    require: name => Object.hasOwn(stubs, name) ? stubs[name] : realRequire(name) }, { filename });
  const express = require('express'), app = express();
  app.use(express.json({ verify(req, _res, raw) { req.rawBody = raw; } }));
  app.use(module.exports);
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const base = 'http://127.0.0.1:' + server.address().port;
  const get = (target, token) => fetch(base + target, { headers: token ? { authorization: token } : {} });
  assert.equal((await get('/passenger-qr')).status, 401);
  assert.equal((await get('/passenger-qr', 'Bearer driver')).status, 403);
  const alice = await (await get('/passenger-qr?userId=bob', 'Bearer alice')).json();
  const bob = await (await get('/passenger-qr', 'Bearer bob')).json();
  assert.notEqual(alice.qrCodeId, bob.qrCodeId);
  assert.equal(state.qrs.find(q => q.qr_id === alice.qrCodeId).assigned_user_id, 'alice');
  const post = (target, body, headers = {}) => fetch(base + target, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
  assert.equal((await post('/top-ups', { amount: 20 }, { authorization: 'Bearer alice' })).status, 409);
  const paid = { data: event(bob.qrCodeId, 'one_peso', 100) };
  assert.equal((await post('/webhook', paid)).status, 401);
  const priorKey = { 'paymongo-signature': 'signed-with-legacy-test-secret' };
  assert.equal((await post('/webhook', paid, priorKey)).status, 401);
  const currentKey = { 'paymongo-signature': 'signed-with-current-test-secret' };
  delete env.PAYMONGO_INSTORE_POOL_WEBHOOK_SECRET;
  assert.equal((await post('/webhook', paid, priorKey)).status, 401);
  assert.equal(state.wallets.length, 0);
  env.PAYMONGO_INSTORE_POOL_WEBHOOK_SECRET = 'current-test-secret';
  for (let delivery = 0; delivery < 2; delivery++) {
    assert.equal((await post('/webhook', paid, currentKey)).status, 200);
  }
  assert.equal(state.wallets.length, 1);
  assert.equal(state.wallets[0].user_id, 'bob');
  assert.equal(state.wallets[0].amount, 1);
  assert.equal((await get('/passenger-qr', 'Bearer bob').then(res => res.json())).latestPayment.paymentId, 'pay_one_peso');
});
