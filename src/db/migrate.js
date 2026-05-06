/**
 * Migration — run once to fix FK constraints
 * POST /api/migrate/fix
 */
const express = require('express');
const { pool } = require('../db/database');
const router = express.Router();

router.post('/fix', async (req, res) => {
  const client = await pool.connect();
  const results = [];
  try {
    // 1. Find and drop ALL FK constraints on trips table
    const fks = await client.query(`
      SELECT conname
      FROM pg_constraint
      WHERE conrelid = 'trips'::regclass
        AND contype = 'f'
    `);
    for (const fk of fks.rows) {
      await client.query(`ALTER TABLE trips DROP CONSTRAINT IF EXISTS "${fk.conname}"`);
      results.push(`Dropped FK: ${fk.conname}`);
    }

    // 2. Find and drop FK constraints on feedback table
    const fks2 = await client.query(`
      SELECT conname FROM pg_constraint
      WHERE conrelid = 'feedback'::regclass AND contype = 'f'
        AND conname LIKE '%commuter%'
    `);
    for (const fk of fks2.rows) {
      await client.query(`ALTER TABLE feedback DROP CONSTRAINT IF EXISTS "${fk.conname}"`);
      results.push(`Dropped feedback FK: ${fk.conname}`);
    }

    // 3. Ensure users table has needed columns
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS salt TEXT NOT NULL DEFAULT 'legacy'`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone)`);
    results.push('users table columns ensured');

    // 4. Ensure login_attempts has columns
    await client.query(`ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS user_type TEXT DEFAULT 'commuter'`);
    await client.query(`ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS ip_address TEXT`);
    await client.query(`ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS success BOOLEAN DEFAULT false`);
    results.push('login_attempts columns ensured');

    // 5. Check trips table structure
    const cols = await client.query(`
      SELECT column_name FROM information_schema.columns
      WHERE table_name = 'trips' ORDER BY ordinal_position
    `);
    results.push('trips columns: ' + cols.rows.map(r => r.column_name).join(', '));

    return res.json({ success: true, message: 'Migration complete!', results });
  } catch (err) {
    console.error('[Migration] Error:', err.message);
    return res.status(500).json({ success: false, message: err.message, results });
  } finally {
    client.release();
  }
});

// Health check — shows current FK constraints
router.get('/status', async (req, res) => {
  const client = await pool.connect();
  try {
    const fks = await client.query(`
      SELECT tc.table_name, tc.constraint_name, ccu.table_name AS foreign_table
      FROM information_schema.table_constraints tc
      JOIN information_schema.constraint_column_usage ccu
        ON ccu.constraint_name = tc.constraint_name
      WHERE tc.constraint_type = 'FOREIGN KEY'
        AND tc.table_name IN ('trips','feedback')
      ORDER BY tc.table_name
    `);
    const lastTrips = await client.query(
      `SELECT trip_id, commuter_id, driver_id, status FROM trips ORDER BY request_timestamp DESC LIMIT 3`
    );
    return res.json({ success: true, fk_constraints: fks.rows, last_trips: lastTrips.rows });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

module.exports = router;