const test = require('node:test');
const assert = require('node:assert/strict');
const { runWalletReset } = require('../src/services/walletReset');

function setup() {
  const state = { wallets: [
    { transaction_id: 'alice-topup', user_id: 'alice', direction: 'credit', amount: 100, status: 'completed' },
    { transaction_id: 'alice-ride', user_id: 'alice', direction: 'debit', amount: 30, status: 'completed', trip_id: 'ride-one' },
    { transaction_id: 'bob-topup', user_id: 'bob', direction: 'credit', amount: 50, status: 'completed' },
    { transaction_id: 'bob-pending', user_id: 'bob', direction: 'credit', amount: 100, status: 'pending' },
    { transaction_id: 'negative', user_id: 'charlie', direction: 'debit', amount: 10, status: 'completed' },
  ], audits: [], users: [{ id: 'alice' }, { id: 'bob' }, { id: 'charlie' }],
  trips: [{ trip_id: 'ride-one', payment_status: 'paid', payment_method: 'wallet' }],
  operations: [], failAdjustment: false };
  const balances = () => {
    const totals = {};
    for (const row of state.wallets) if (row.status === 'completed') {
      totals[row.user_id] = (totals[row.user_id] || 0) + (row.direction === 'credit' ? row.amount : -row.amount);
    }
    return totals;
  };
  let tail = Promise.resolve();
  const pool = { connect: async () => {
    let release, before;
    return { release() {}, async query(text, values = []) {
      const sql = text.replace(/\s+/g, ' ').trim();
      state.operations.push(sql);
      assert.doesNotMatch(sql, /DELETE|TRUNCATE|DROP|UPDATE users|UPDATE trips/i);
      let rows = [];
      if (sql === 'BEGIN') {
        const previous = tail; tail = new Promise(resolve => { release = resolve; });
        await previous; before = structuredClone({ wallets: state.wallets, audits: state.audits });
      } else if (sql === 'COMMIT' || sql === 'ROLLBACK') {
        if (sql === 'ROLLBACK') Object.assign(state, before);
        release();
      } else if (sql.startsWith('SELECT pg_advisory') || sql.startsWith('LOCK TABLE') || sql.startsWith('SELECT id FROM users')) {
        // Transaction serialization is deterministic in this isolated adapter.
      } else if (sql.startsWith('SELECT summary FROM wallet_reset_runs')) {
        rows = state.audits.filter(row => row.reset_id === values[0]);
      } else if (sql.startsWith('SELECT (SELECT COUNT')) {
        rows = [{ accounts: state.users.length, rides: state.trips.length,
          transactions: state.wallets.filter(row => !row.archived_at).length,
          pending: state.wallets.filter(row => row.status === 'pending').length,
          wallets: Object.values(balances()).filter(value => value !== 0).length }];
      } else if (sql.startsWith('INSERT INTO wallet_reset_runs')) {
        state.audits.push({ reset_id: values[0], summary: JSON.parse(values[1]), ledger_before: structuredClone(state.wallets) });
      } else if (sql.startsWith("UPDATE wallet_transactions SET status = 'cancelled'")) {
        for (const row of state.wallets) if (row.status === 'pending') row.status = 'cancelled';
      } else if (sql.startsWith('UPDATE wallet_transactions SET archived_at')) {
        for (const row of state.wallets) row.archived_at ||= new Date();
      } else if (sql.startsWith('INSERT INTO wallet_transactions')) {
        if (state.failAdjustment) throw new Error('Simulated adjustment failure');
        for (const [userId, balance] of Object.entries(balances())) if (balance !== 0) {
          state.wallets.push({ transaction_id: 'adjust-' + userId, user_id: userId,
            direction: balance > 0 ? 'debit' : 'credit', amount: Math.abs(balance),
            status: 'completed', type: 'adjustment', external_reference: values[0], archived_at: new Date() });
        }
      } else if (sql.startsWith('SELECT COUNT(*)::int AS count')) {
        rows = [{ count: Object.values(balances()).filter(value => value !== 0).length }];
      } else throw new Error('Unhandled reset query: ' + sql);
      return { rows: structuredClone(rows), rowCount: rows.length };
    } };
  } };
  return { state, pool, balances };
}

test('fresh wallet reset zeroes positive and negative balances and archives history while preserving accounts and rides', async () => {
  const { state, pool, balances } = setup();
  const users = structuredClone(state.users), trips = structuredClone(state.trips);
  const result = await runWalletReset(pool, 'fresh-start-one');
  assert.equal(result.balancesReset, 3);
  assert.equal(result.pendingCancelled, 1);
  assert.equal(result.transactionsArchived, 5);
  assert.deepEqual(balances(), { alice: 0, bob: 0, charlie: 0 });
  assert.deepEqual(state.users, users); assert.deepEqual(state.trips, trips);
  assert.equal(state.wallets.find(row => row.transaction_id === 'alice-ride').trip_id, 'ride-one');
  assert.equal(state.wallets.find(row => row.transaction_id === 'bob-pending').status, 'cancelled');
  assert.equal(state.wallets.filter(row => !row.archived_at).length, 0);
  assert.equal(state.audits[0].ledger_before.length, 5);
  assert.equal(state.audits[0].ledger_before.find(row => row.transaction_id === 'bob-pending').status, 'pending');
  assert.ok(state.operations.indexOf('SELECT id FROM users ORDER BY id FOR UPDATE') <
    state.operations.indexOf('LOCK TABLE wallet_transactions IN SHARE ROW EXCLUSIVE MODE'));
});

test('a restart or concurrent retry never resets new money after the first run', async () => {
  const { state, pool, balances } = setup();
  await Promise.all([runWalletReset(pool, 'fresh-start-once'), runWalletReset(pool, 'fresh-start-once')]);
  assert.equal(state.audits.length, 1);
  state.wallets.push({ transaction_id: 'new-real-funds', user_id: 'alice', direction: 'credit', amount: 73.45, status: 'completed' });
  const result = await runWalletReset(pool, 'fresh-start-once');
  assert.equal(result.alreadyApplied, true);
  assert.equal(balances().alice, 73.45);
  assert.equal(state.wallets.find(row => row.transaction_id === 'new-real-funds').archived_at, undefined);
});

test('a failure rolls back the audit, pending cancellation, archive flags and reset adjustments together', async () => {
  const { state, pool } = setup();
  const before = structuredClone(state.wallets);
  state.failAdjustment = true;
  await assert.rejects(runWalletReset(pool, 'fresh-start-failure'), /adjustment failure/);
  assert.deepEqual(state.wallets, before);
  assert.deepEqual(state.audits, []);
});
