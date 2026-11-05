const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');

function loadWith(filename, stubs) {
  const file = path.join(__dirname, '..', filename), module = { exports: {} };
  const actualRequire = createRequire(file);
  vm.runInNewContext(fs.readFileSync(file, 'utf8'), { module, exports: module.exports,
    require: name => Object.hasOwn(stubs, name) ? stubs[name] : actualRequire(name),
    process, console, Buffer, Date }, { filename: file });
  return module.exports;
}

// Isolated transaction adapter: writes become visible only on COMMIT; row locks
// serialize callers. These tests exercise the actual services together without
// connecting to a merchant account, production database or sending any money.
function fixture(initialBalance = 100) {
  const state = { trips: new Map(), drivers: new Map([['driver-1', { driver_id: 'driver-1', is_active: true, total_trips: 0 }]]),
    transactions: [{ transaction_id: 'funding', user_id: 'passenger-1', direction: 'credit', status: 'completed', amount: initialBalance }],
    earnings: new Map(), cashouts: new Map(), fault: null };
  const queues = new Map();
  let nextId = 0;
  function connection() {
    const staged = { trips: new Map(), drivers: new Map(), transactions: [], earnings: new Map(), cashouts: new Map() };
    const unlocks = [];
    const held = new Set();
    function finish(commit) {
      if (commit) {
        for (const key of ['trips', 'drivers', 'earnings', 'cashouts']) {
          for (const [id, row] of staged[key]) state[key].set(id, row);
        }
        state.transactions.push(...staged.transactions);
      }
      for (const unlock of unlocks.splice(0)) unlock();
      held.clear();
    }
    const rows = key => new Map([...state[key], ...staged[key]]);
    const transactions = () => [...state.transactions, ...staged.transactions];
    return { release() { finish(false); }, async query(raw, args = []) {
      const sql = raw.replace(/\s+/g, ' ').trim();
      const result = entries => ({ rows: entries.map(row => ({ ...row })), rowCount: entries.length });
      if (sql === 'BEGIN') return result([]);
      if (sql === 'COMMIT' || sql === 'ROLLBACK') { finish(sql === 'COMMIT'); return result([]); }
      if (sql.includes('FOR UPDATE') || sql.startsWith('UPDATE trips')) {
        const table = sql.startsWith('UPDATE trips') ? 'trips' : /FROM (users|drivers|trips|driver_cashouts)/.exec(sql)?.[1];
        assert.ok(table, sql);
        const tripFirst = /SET status = '(completed|cancelled)'/.test(sql);
        const id = sql.startsWith('UPDATE trips') ? args[tripFirst ? 0 : 1] : args[0];
        const key = `${table}:${id}`;
        if (!held.has(key)) {
          const previous = queues.get(key) || Promise.resolve();
          queues.set(key, new Promise(resolve => unlocks.push(resolve)));
          await previous;
          held.add(key);
        }
      }
      if (sql.startsWith('SELECT') && sql.includes('FROM users')) return result(args[0] === 'passenger-1' ? [{ id: args[0] }] : []);
      if (sql.startsWith('SELECT') && sql.includes('FROM drivers')) return result([rows('drivers').get(args[0])].filter(Boolean));
      if (sql.startsWith('SELECT') && (sql.includes('FROM trips WHERE') || sql.includes('FROM trips tr'))) {
        return result([rows('trips').get(args[0])].filter(Boolean));
      }
      if (sql.startsWith('SELECT') && sql.includes('AS balance')) {
        const balance = transactions().filter(r => r.user_id === args[0] && r.status === 'completed')
          .reduce((sum, r) => sum + (r.direction === 'credit' ? 1 : -1) * Number(r.amount), 0);
        return result([{ balance }]);
      }
      if (sql.startsWith('SELECT transaction_id') && sql.includes('FROM wallet_transactions')) {
        return result(transactions().filter(r => r.trip_id === args[0] && r.user_id === args[1] &&
          Number(r.amount) === Number(args[2]) && r.type === 'trip' && r.direction === 'debit' && r.status === 'completed'));
      }
      if (sql.startsWith('INSERT INTO wallet_transactions')) {
        const row = { transaction_id: `debit-${++nextId}`, user_id: args[0], trip_id: args[1], amount: args[2],
          type: 'trip', direction: 'debit', status: 'completed' };
        staged.transactions.push(row); return result([row]);
      }
      if (sql.startsWith('UPDATE trips')) {
        const completing = sql.includes("status = 'completed'");
        const cancelling = sql.includes("SET status = 'cancelled'");
        const changing = sql.includes('SET payment_method = $1');
        const trip = { ...rows('trips').get(args[completing || cancelling ? 0 : 1]) };
        if (cancelling || changing) {
          assert.match(sql, /payment_status IS DISTINCT FROM 'paid'/);
          assert.match(sql, /status NOT IN \('completed','cancelled'\)/);
          if (trip.payment_status === 'paid' || ['completed','cancelled'].includes(trip.status)) return result([]);
          if (changing && trip.paymongo_checkout_session_id) return result([]);
          if (cancelling) trip.status = 'cancelled';
          else Object.assign(trip, { payment_method:args[0], payment_status:'unpaid' });
        } else if (completing) { trip.status = 'completed'; trip.payment_status = 'paid'; }
        else {
          assert.match(sql, /payment_method = 'wallet'/);
          Object.assign(trip, { payment_method: 'wallet', payment_status: 'paid', payment_reference: args[0],
            paymongo_checkout_session_id: null, paymongo_checkout_url: null, paymongo_payment_id: null });
        }
        staged.trips.set(trip.trip_id, trip); return result([trip]);
      }
      if (sql.startsWith('UPDATE drivers')) {
        const driver = { ...rows('drivers').get(args[0]) }; driver.total_trips++;
        staged.drivers.set(args[0], driver); return result([driver]);
      }
      if (sql.startsWith('INSERT INTO driver_earnings')) {
        if (state.fault === 'earnings') throw new Error('Simulated earnings write failure');
        assert.match(sql, /tr.status = 'completed' AND tr.payment_status = 'paid'/);
        assert.match(sql, /wt.user_id = tr.commuter_id/);
        assert.match(sql, /wt.amount = tr.fare/);
        assert.match(sql, /ON CONFLICT \(trip_id\) DO NOTHING/);
        for (const trip of rows('trips').values()) {
          const walletPaid = trip.payment_method === 'wallet' && transactions().some(r => r.trip_id === trip.trip_id &&
            r.user_id === trip.commuter_id && r.type === 'trip' && r.direction === 'debit' && r.status === 'completed' && Number(r.amount) === Number(trip.fare));
          const providerPaid = ['gcash', 'maya'].includes(trip.payment_method) && trip.paymongo_payment_id;
          if (trip.driver_id === args[0] && trip.status === 'completed' && trip.payment_status === 'paid' && Number(trip.fare) > 0 &&
              (walletPaid || providerPaid) && !rows('earnings').has(trip.trip_id)) {
            staged.earnings.set(trip.trip_id, { trip_id: trip.trip_id, driver_id: args[0], amount: trip.fare });
          }
        }
        return result([]);
      }
      if (sql.startsWith('SELECT') && sql.includes('AS earned')) {
        const cashouts = [...rows('cashouts').values()].filter(r => r.driver_id === args[0]);
        return result([{ earned: [...rows('earnings').values()].filter(r => r.driver_id === args[0]).reduce((sum, r) => sum + Number(r.amount), 0),
          reserved: cashouts.filter(r => ['pending','processing'].includes(r.status)).reduce((sum,r) => sum + Number(r.amount),0),
          paid: cashouts.filter(r => r.status === 'paid').reduce((sum,r) => sum + Number(r.amount),0) }]);
      }
      if (sql.startsWith('INSERT INTO driver_cashouts')) {
        const row = { cashout_id: `cashout-${++nextId}`, driver_id: args[0], amount: args[1], provider: args[2],
          account_name: args[3], account_number: args[4], request_key: args[5], status: 'pending' };
        staged.cashouts.set(row.cashout_id, row); return result([row]);
      }
      if (sql.startsWith('SELECT') && sql.includes('FROM driver_cashouts')) {
        let entries = [...rows('cashouts').values()];
        if (sql.includes('WHERE cashout_id')) entries = entries.filter(r => r.cashout_id === args[0]);
        else entries = entries.filter(r => r.driver_id === args[0]);
        if (sql.includes('request_key =')) entries = entries.filter(r => r.request_key === args[1]);
        if (sql.includes("status IN ('pending','processing')")) entries = entries.filter(r => ['pending','processing'].includes(r.status));
        return result(entries);
      }
      if (sql.startsWith('UPDATE driver_cashouts')) {
        const row = { ...rows('cashouts').get(args[0]), status: args[1], payment_reference: args[2], review_note: args[3] };
        staged.cashouts.set(args[0], row); return result([row]);
      }
      throw new Error(`Unhandled test query: ${sql}`);
    } };
  }
  const pool = { connect: async () => connection(), query: async (sql, args) => {
    const client = connection();
    try { const result = await client.query(sql, args); await client.query('COMMIT'); return result; }
    finally { client.release(); }
  } };
  const database = { pool, dbRun: pool.query, dbGet: async (sql,args) => (await pool.query(sql,args)).rows[0] };
  const ledger = loadWith('src/services/walletLedger.js', { '../db/database': database });
  const driverWallet = loadWith('src/services/driverWallet.js', { '../db/database': database, './paymongo': { isLiveMode: () => true } });
  const settlement = loadWith('src/services/tripPayments.js', { '../db/database': database, './driverWallet': driverWallet });
  function addTrip(id = 'trip-1', overrides = {}) {
    const row = { trip_id: id, commuter_id: 'passenger-1', driver_id: 'driver-1', status: 'arrived',
      fare: '60.00', payment_method: 'wallet', payment_status: 'unpaid', destination: 'Panabo', ...overrides };
    state.trips.set(id, row); return { ...row };
  }
  const router = loadWith('src/routes/trips.js', {
    '../db/database': database, '../utils/adminReports': {}, '../services/paymongo': {},
    '../services/reportPenalties': loadWith('src/services/reportPenalties.js', { '../db/database': database }),
    '../services/walletLedger': ledger, '../services/walletPayments': {},
    '../services/walletIntentPayments': {}, '../services/tripPayments': settlement,
  });
  async function request(routePath, id, userId, role, body = {}) {
    const handler = router.stack.find(layer => layer.route?.path === routePath).route.stack.at(-1).handle;
    let code = 200, data;
    const res = { status(value) { code = value; return res; }, json(value) { data = value; return res; } };
    await handler({ params: { tripId: id }, userId, userRole: role, body }, res);
    return { code, data };
  }
  return { state, ledger, driverWallet, settlement, addTrip, request };
}

const payout = { amount: 50, provider: 'gcash', accountName: 'Test Driver', accountNumber: '09123456789',
  requestKey: '37cd393c-679d-4c2a-80b1-b54733c342aa' };

test('passenger pays a fare, driver completes it and receives one withdrawable credit, then cashes out', async () => {
  const f = fixture(); f.addTrip('trip-1', { payment_method: 'cash' });
  const paid = await f.request('/:tripId/payment/checkout','trip-1','passenger-1','passenger',{ paymentMethod:'wallet' });
  assert.equal(paid.code,200); assert.equal(paid.data.wallet.balance,40);
  assert.equal(paid.data.trip.payment_method,'wallet');
  assert.equal((await f.driverWallet.getDriverWallet('driver-1')).available,0);
  const completed = await f.request('/:tripId/payment/collect','trip-1','driver-1','driver');
  assert.equal(completed.code,200); assert.equal(completed.data.earnings.your_earnings,60);
  // The credit is committed by completion, before any wallet GET is needed.
  assert.equal(f.state.earnings.size,1);
  assert.equal((await f.driverWallet.getDriverWallet('driver-1')).available,60);
  await Promise.all([f.settlement.completePaidTrip('trip-1','driver-1'), f.settlement.completePaidTrip('trip-1','driver-1')]);
  assert.equal(f.state.drivers.get('driver-1').total_trips,1);
  assert.equal(f.state.earnings.size,1);
  const cashout = await f.driverWallet.requestCashOut('driver-1',payout);
  assert.equal((await f.driverWallet.getDriverWallet('driver-1')).available,10);
  assert.equal((await f.driverWallet.getDriverWallet('driver-1')).reserved,50);
  await f.driverWallet.reviewCashOut(cashout.cashout_id,{ action:'processing', adminId:'payout-admin' });
  await f.driverWallet.reviewCashOut(cashout.cashout_id,{ action:'paid', reference:'TEST-123456', adminId:'payout-admin' });
  const wallet = await f.driverWallet.getDriverWallet('driver-1');
  assert.equal(wallet.available,10); assert.equal(wallet.reserved,0); assert.equal(wallet.paid,50);
  assert.equal(wallet.requests[0].status,'paid');
});

test('simultaneous payments for different trips cannot overspend one passenger wallet', async () => {
  const f = fixture(), first = f.addTrip(), second = f.addTrip('trip-2');
  const results = await Promise.all([f.ledger.debitWalletForTrip(first), f.ledger.debitWalletForTrip(second)]);
  assert.equal(results.filter(r => r.success).length,1);
  assert.equal(results.find(r => !r.success).code,'INSUFFICIENT_WALLET_BALANCE');
  assert.equal(await f.ledger.getWalletBalance('passenger-1'),40);
  assert.equal(f.state.transactions.filter(r => r.type === 'trip').length,1);
});

test('simultaneous retries of the same fare debit exactly once and use the current database fare', async () => {
  const f = fixture(), stale = f.addTrip('trip-1', { fare:'60.10' }); stale.fare = 1;
  const results = await Promise.all([f.ledger.debitWalletForTrip(stale),f.ledger.debitWalletForTrip(stale)]);
  assert.ok(results.every(r => r.success));
  assert.equal(results[0].transactionId,results[1].transactionId);
  assert.equal(await f.ledger.getWalletBalance('passenger-1'),39.9);
});

test('wrong passengers and drivers cannot pay or collect another account trip', async () => {
  const f = fixture(); f.addTrip();
  assert.equal((await f.request('/:tripId/payment/checkout','trip-1','stranger','passenger',{ paymentMethod:'wallet' })).code,403);
  assert.equal((await f.request('/:tripId/payment/collect','trip-1','stranger','driver')).code,404);
  assert.equal((await f.request('/:tripId/payment/collect','trip-1','passenger-1','passenger')).code,403);
  assert.equal(f.state.transactions.length,1); assert.equal(f.state.earnings.size,0);
});

test('insufficient funds, unpaid rides, cancelled rides and mismatched debit proofs cannot become earnings', async () => {
  const f = fixture(20), trip = f.addTrip();
  assert.equal((await f.ledger.debitWalletForTrip(trip)).code,'INSUFFICIENT_WALLET_BALANCE');
  await assert.rejects(f.settlement.completePaidTrip(trip.trip_id,'driver-1'),/Waiting/);
  f.state.trips.get(trip.trip_id).payment_status = 'paid';
  await assert.rejects(f.settlement.completePaidTrip(trip.trip_id,'driver-1'),/matching/);
  f.state.trips.get(trip.trip_id).status = 'cancelled';
  assert.equal((await f.ledger.debitWalletForTrip(trip)).success,false);
  await assert.rejects(f.settlement.completePaidTrip(trip.trip_id,'driver-1'),/arrived/);
  assert.equal((await f.driverWallet.getDriverWallet('driver-1')).available,0);
});

test('cash collection completes a ride without creating withdrawable digital earnings', async () => {
  const f = fixture(); f.addTrip('trip-1',{ payment_method:'cash' });
  assert.equal((await f.request('/:tripId/payment/collect','trip-1','driver-1','driver')).code,200);
  assert.equal((await f.driverWallet.getDriverWallet('driver-1')).available,0);
  assert.equal(await f.ledger.getWalletBalance('passenger-1'),100);
});

test('a driver-credit write failure rolls back completion and a retry credits exactly once', async () => {
  const f = fixture(), trip = f.addTrip();
  await f.ledger.debitWalletForTrip(trip);
  f.state.fault = 'earnings';
  await assert.rejects(f.settlement.completePaidTrip(trip.trip_id,'driver-1'),/Simulated/);
  assert.equal(f.state.trips.get(trip.trip_id).status,'arrived');
  assert.equal(f.state.drivers.get('driver-1').total_trips,0);
  assert.equal(f.state.earnings.size,0);
  f.state.fault = null;
  await f.settlement.completePaidTrip(trip.trip_id,'driver-1');
  assert.equal(f.state.earnings.size,1);
  assert.equal(await f.ledger.getWalletBalance('passenger-1'),40);
});

test('shared trips require all drop-offs and direct provider trips require a confirmed payment id', async () => {
  const f = fixture();
  f.addTrip('shared',{ payment_method:'cash',service_type:'shared',shared_dropoffs:[{}],remaining_passenger_count:1 });
  await assert.rejects(f.settlement.completePaidTrip('shared','driver-1'),/remaining/);
  f.addTrip('provider',{ payment_method:'gcash', payment_status:'paid' });
  await assert.rejects(f.settlement.completePaidTrip('provider','driver-1'),/provider/);
  f.state.trips.get('provider').paymongo_payment_id = 'pay_test';
  await f.settlement.completePaidTrip('provider','driver-1');
  assert.equal((await f.driverWallet.getDriverWallet('driver-1')).available,60);
});

test('a concurrent cancellation cannot discard a paid fare or leave a charge on a cancelled trip', async () => {
  const f = fixture(), trip = f.addTrip();
  const [paid,cancelled] = await Promise.all([
    f.ledger.debitWalletForTrip(trip),
    f.request('/:tripId/status','trip-1','passenger-1','passenger',{ status:'cancelled' }),
  ]);
  const actual = f.state.trips.get('trip-1');
  if (paid.success) {
    assert.equal(cancelled.code,409); assert.equal(actual.status,'arrived');
    assert.equal(await f.ledger.getWalletBalance('passenger-1'),40);
  } else {
    assert.equal(cancelled.code,200); assert.equal(actual.status,'cancelled');
    assert.equal(await f.ledger.getWalletBalance('passenger-1'),100);
  }
});

test('changing payment method while a wallet debit arrives cannot reset a paid trip', async () => {
  const f = fixture(), trip = f.addTrip();
  const [paid,changed] = await Promise.all([
    f.ledger.debitWalletForTrip(trip),
    f.request('/:tripId/payment-method','trip-1','passenger-1','passenger',{ paymentMethod:'cash' }),
  ]);
  assert.equal(paid.success,true);
  assert.equal(changed.code,409);
  assert.equal(f.state.trips.get('trip-1').payment_method,'wallet');
  assert.equal(f.state.trips.get('trip-1').payment_status,'paid');
});
