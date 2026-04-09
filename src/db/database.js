require('dotenv').config();
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.error('[DB] ERROR: DATABASE_URL is not set in environment variables.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('connect', () => console.log('[DB] PostgreSQL connected'));
pool.on('error', (err) => {
  console.error('[DB] Unexpected error:', err.message);
});

async function initializeDatabase() {
  const client = await pool.connect();
  try {
    // Users table — with separate salt column for security transparency
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id            TEXT PRIMARY KEY,
        full_name     TEXT NOT NULL,
        email         TEXT UNIQUE NOT NULL,
        phone         TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt          TEXT NOT NULL,
        role          TEXT DEFAULT 'passenger',
        is_verified   BOOLEAN DEFAULT false,
        is_active     BOOLEAN DEFAULT true,
        created_at    TIMESTAMPTZ DEFAULT NOW(),
        updated_at    TIMESTAMPTZ DEFAULT NOW(),
        last_login    TIMESTAMPTZ
      );
    `);

    // Add salt column if it doesn't exist (for existing deployments)
    await client.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS salt TEXT NOT NULL DEFAULT 'legacy';
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS login_attempts (
        id            SERIAL PRIMARY KEY,
        email         TEXT NOT NULL,
        ip_address    TEXT,
        success       BOOLEAN DEFAULT false,
        attempted_at  TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    `);

    console.log('[DB] All tables initialized');
  } finally {
    client.release();
  }
}

async function dbRun(sql, params = []) {
  return await pool.query(sql, params);
}

async function dbGet(sql, params = []) {
  const result = await pool.query(sql, params);
  return result.rows[0] || null;
}

async function dbAll(sql, params = []) {
  const result = await pool.query(sql, params);
  return result.rows;
}

module.exports = { pool, initializeDatabase, dbRun, dbGet, dbAll };