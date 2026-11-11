const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const jwt = require('jsonwebtoken');

function fixture(t) {
  const state = {
    trips: new Map([['trip-1', { trip_id: 'trip-1', driver_id: 'driver-1',
      commuter_id: 'passenger-1', status: 'completed', payment_status: 'paid' }]]),
    feedback: new Map(), passenger_feedback: new Map(), average: 0,
    failUpdate: false, failConnection: false, releases: 0,
  };
  let queue = Promise.resolve();
  const result = rows => ({ rows, rowCount: rows.length });
  function select(sql, args) {
    if (sql.includes('FROM trips')) return result(state.trips.has(args[0]) ? [{ ...state.trips.get(args[0]) }] : []);
    for (const table of ['passenger_feedback', 'feedback']) {
      if (sql.includes(`FROM ${table} `)) {
        const row = state[table].get(args[0]);
        const owned = args.length < 2 || (table === 'feedback' ? row?.commuter_id : row?.driver_id) === args[1];
        return result(row && owned ? [{ ...row }] : []);
      }
    }
    throw new Error(`Unexpected select: ${sql}`);
  }
  const pool = { async connect() {
    if (state.failConnection) throw new Error('Connection unavailable');
    let unlock, staged, average;
    const finish = () => { if (unlock) { unlock(); unlock = null; } };
    return {
      release() { state.releases++; finish(); },
      async query(raw, args = []) {
        const sql = raw.replace(/\s+/g, ' ').trim();
        if (sql === 'BEGIN') return result([]);
        if (sql === 'COMMIT') {
          if (staged) state[staged.table].set(staged.row.trip_id, staged.row);
          if (average != null) state.average = average;
          finish(); return result([]);
        }
        if (sql === 'ROLLBACK') { staged = null; finish(); return result([]); }
        if (sql.includes('FROM drivers') && sql.includes('FOR UPDATE')) {
          const previous = queue;
          queue = new Promise(resolve => { unlock = resolve; });
          await previous;
          return result([{ driver_id: args[0] }]);
        }
        if (sql.startsWith('SELECT')) return select(sql, args);
        const table = ['passenger_feedback', 'feedback'].find(name => sql.startsWith(`INSERT INTO ${name} `));
        if (table) {
          const [feedback_id, trip_id, commuter_id, driver_id, rating_score, comments] = args;
          staged = { table, row: { feedback_id, trip_id, commuter_id, driver_id, rating_score, comments } };
          return result([]);
        }
        if (sql.startsWith('UPDATE drivers')) {
          assert.ok(staged?.table === 'feedback', 'only passenger feedback changes the driver average');
          const scores = [...state.feedback.values(), staged.row].map(row => row.rating_score);
          average = scores.reduce((sum, value) => sum + value, 0) / scores.length;
          return result([]);
        }
        if (sql.includes('performance_reports')) {
          if (state.failUpdate) throw new Error('Performance update failed');
          return result([]);
        }
        throw new Error(`Unexpected query: ${sql}`);
      },
    };
  } };
  const database = { pool, dbGet: async (sql, args) => select(sql.replace(/\s+/g, ' ').trim(), args).rows[0] || null };
  const filename = path.join(__dirname, '../src/routes/trips.js');
  const module = { exports: {} }, actualRequire = createRequire(filename);
  const stubs = { '../db/database': database, '../utils/adminReports': {},
    '../services/reportPenalties': {}, '../services/paymongo': {}, '../services/walletLedger': {},
    '../services/walletPayments': {}, '../services/walletIntentPayments': {},
    '../services/walletStaticQr': {}, '../services/tripPayments': {}, '../services/driverTracking': {} };
  vm.runInNewContext(fs.readFileSync(filename, 'utf8'), { module, exports: module.exports,
    require: name => Object.hasOwn(stubs, name) ? stubs[name] : actualRequire(name),
    process, console, Buffer, Date }, { filename });
  const secret = process.env.JWT_SECRET;
  process.env.JWT_SECRET = 'trip-rating-tests-only';
  t.after(() => { if (secret == null) delete process.env.JWT_SECRET; else process.env.JWT_SECRET = secret; });

  async function request(method, role, body, { tripId = 'trip-1', id } = {}) {
    const token = jwt.sign({ sub: id || (role === 'commuter' ? 'passenger-1' : `${role}-1`), role },
      process.env.JWT_SECRET, { issuer: 'todago-api', audience: 'todago-app', expiresIn: '1h' });
    const route = module.exports.stack.find(layer => layer.route?.path ===
      (method === 'POST' ? '/:tripId/rate' : '/:tripId/rating') && layer.route.methods[method.toLowerCase()]).route;
    const req = { headers: { authorization: `Bearer ${token}` }, body: body || {}, params: { tripId } };
    let code = 200, data;
    const res = { status(value) { code = value; return res; }, json(value) { data = value; return res; } };
    for (const layer of route.stack) {
      await layer.handle(req, res, error => { if (error) throw error; });
      if (data !== undefined) break;
    }
    return { code, data };
  }
  return { state, request };
}

test('both paid-trip participants can rate one another independently and read their own feedback', async t => {
  const f = fixture(t);
  assert.equal((await f.request('GET', 'driver')).data.hasRated, false);
  assert.equal((await f.request('POST', 'driver', { rating: 2, comment: ' Late to pickup ' })).code, 201);
  assert.equal(f.state.average, 0);
  assert.equal(f.state.passenger_feedback.get('trip-1').commuter_id, 'passenger-1');
  assert.equal((await f.request('POST', 'commuter', { rating: 5, comment: ' Safe trip ' })).code, 201);
  assert.equal(f.state.average, 5);
  const passengerView = await f.request('GET', 'passenger');
  const driverView = await f.request('GET', 'driver');
  assert.equal(passengerView.data.feedback.rating_score, 5);
  assert.equal(passengerView.data.feedback.comments, 'Safe trip');
  assert.equal(driverView.data.feedback.rating_score, 2);
  assert.equal(driverView.data.feedback.comments, 'Late to pickup');
  assert.equal((await f.request('POST', 'driver', { rating: 4 })).code, 409);
  assert.equal((await f.request('POST', 'passenger', { rating: 4 })).code, 409);
});

test('ratings require ownership, completion, confirmed payment, and a valid score', async t => {
  const f = fixture(t);
  for (const role of ['driver', 'passenger']) {
    assert.equal((await f.request('POST', role, { rating: 5 }, { id: 'someone-else' })).code, 404);
    assert.equal((await f.request('GET', role, null, { id: 'someone-else' })).code, 404);
    for (const [status, payment_status] of [['arrived', 'paid'], ['completed', 'unpaid'], ['cancelled', 'paid']]) {
      Object.assign(f.state.trips.get('trip-1'), { status, payment_status });
      assert.equal((await f.request('POST', role, { rating: 5 })).code, 409);
    }
    for (const rating of [0, 6, 2.5, 'bad']) {
      assert.equal((await f.request('POST', role, { rating })).code, 422);
    }
  }
  assert.equal((await f.request('POST', 'operator', { rating: 5 })).code, 403);
  assert.equal((await f.request('GET', 'operator')).code, 403);
  assert.equal((await f.request('POST', 'passenger', { rating: 5, comment: 'x'.repeat(501) })).code, 422);
  assert.equal(f.state.feedback.size + f.state.passenger_feedback.size, 0);
});

for (const role of ['driver', 'passenger']) {
  test(`concurrent ${role} ratings save once; retries return a duplicate response`, async t => {
    const f = fixture(t);
    const responses = await Promise.all([f.request('POST', role, { rating: 4 }), f.request('POST', role, { rating: 1 })]);
    assert.deepEqual(responses.map(row => row.code).sort(), [201, 409]);
    assert.equal(f.state[role === 'driver' ? 'passenger_feedback' : 'feedback'].size, 1);
    assert.equal(f.state.releases, 2);
  });
}

test('failed rating transactions roll back so a retry can save the feedback', async t => {
  const f = fixture(t);
  f.state.failUpdate = true;
  assert.equal((await f.request('POST', 'passenger', { rating: 3 })).code, 500);
  assert.equal(f.state.feedback.size, 0);
  assert.equal(f.state.average, 0);
  f.state.failUpdate = false;
  assert.equal((await f.request('POST', 'passenger', { rating: 3 })).code, 201);
  assert.equal(f.state.average, 3);
  f.state.failConnection = true;
  assert.equal((await f.request('POST', 'driver', { rating: 4 })).code, 500);
});
