// Operator-only startup migration. No HTTP endpoint exposes this operation.
// Each request ID is applied once, retaining an in-database backup and the
// ledger rows required to verify historical ride payments.
async function runWalletReset(pool, resetId) {
  if (!/^[A-Za-z0-9_-]{8,80}$/.test(resetId || '')) throw new Error('Invalid wallet reset request ID');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended('todago-wallet-reset', 0))");
    const existing = (await client.query('SELECT summary FROM wallet_reset_runs WHERE reset_id = $1', [resetId])).rows[0];
    if (existing) { await client.query('COMMIT'); return { ...existing.summary, alreadyApplied: true }; }
    // Match the lock order of wallet spending before blocking ledger writes.
    await client.query('SELECT id FROM users ORDER BY id FOR UPDATE');
    await client.query('LOCK TABLE wallet_transactions IN SHARE ROW EXCLUSIVE MODE');
    const counts = (await client.query(`SELECT
      (SELECT COUNT(*)::int FROM users) AS accounts,
      (SELECT COUNT(*)::int FROM trips) AS rides,
      (SELECT COUNT(*)::int FROM wallet_transactions WHERE archived_at IS NULL) AS transactions,
      (SELECT COUNT(*)::int FROM wallet_transactions WHERE status = 'pending') AS pending,
      (SELECT COUNT(*)::int FROM (SELECT user_id FROM wallet_transactions
        WHERE status = 'completed' GROUP BY user_id
        HAVING SUM(CASE WHEN direction = 'credit' THEN amount ELSE -amount END) <> 0) balances) AS wallets`)).rows[0];
    const summary = { resetId, accountsPreserved: counts.accounts, ridesPreserved: counts.rides,
      transactionsArchived: counts.transactions, pendingCancelled: counts.pending, balancesReset: counts.wallets };
    // This backup and the reset are committed atomically. No financial rows,
    // accounts, trips, driver earnings or payout records are deleted.
    await client.query(`INSERT INTO wallet_reset_runs (reset_id, summary, ledger_before)
      SELECT $1, $2::jsonb, COALESCE(jsonb_agg(to_jsonb(wt)), '[]'::jsonb)
      FROM wallet_transactions wt`, [resetId, JSON.stringify(summary)]);
    await client.query(`UPDATE wallet_transactions SET status = 'cancelled', updated_at = NOW()
      WHERE status = 'pending'`);
    await client.query('UPDATE wallet_transactions SET archived_at = COALESCE(archived_at, NOW())');
    await client.query(`INSERT INTO wallet_transactions
      (user_id, type, provider, direction, amount, status, title, description,
        external_reference, completed_at, archived_at)
      SELECT user_id, 'adjustment', 'system', CASE WHEN balance > 0 THEN 'debit' ELSE 'credit' END,
        ABS(balance), 'completed', 'Wallet reset adjustment', 'Operator-requested fresh wallet',
        $1, NOW(), NOW()
      FROM (SELECT user_id, SUM(CASE WHEN direction = 'credit' THEN amount ELSE -amount END) AS balance
        FROM wallet_transactions WHERE status = 'completed' GROUP BY user_id) balances
      WHERE balance <> 0`, [`reset:${resetId}`]);
    const remaining = (await client.query(`SELECT COUNT(*)::int AS count FROM (
      SELECT user_id FROM wallet_transactions WHERE status = 'completed' GROUP BY user_id
      HAVING SUM(CASE WHEN direction = 'credit' THEN amount ELSE -amount END) <> 0
    ) balances`)).rows[0].count;
    if (remaining !== 0) throw new Error('Wallet reset balance verification failed');
    await client.query('COMMIT');
    return summary;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }
}

module.exports = { runWalletReset };
