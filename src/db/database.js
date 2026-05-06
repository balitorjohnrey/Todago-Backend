require('dotenv').config();
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.error('[DB] ERROR: DATABASE_URL is not set.');
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
pool.on('error', (err) => console.error('[DB] Pool error:', err.message));

async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto";');

    // ── USERS (main account — used by auth.js) ────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id            TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        full_name     TEXT NOT NULL,
        email         TEXT UNIQUE NOT NULL,
        phone         TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt          TEXT NOT NULL DEFAULT 'legacy',
        role          TEXT DEFAULT 'passenger',
        is_verified   BOOLEAN DEFAULT false,
        is_active     BOOLEAN DEFAULT true,
        created_at    TIMESTAMPTZ DEFAULT NOW(),
        updated_at    TIMESTAMPTZ DEFAULT NOW(),
        last_login    TIMESTAMPTZ
      )
    `);
    // Ensure is_active defaults to true for any NULL rows
    await client.query(
      `UPDATE users SET is_active = true WHERE is_active IS NULL`
    );
    await client.query(
      `ALTER TABLE users ALTER COLUMN is_active SET DEFAULT true`
    );

    // ── COMMUTERS (kept for backward compat — legacy table) ───────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS commuters (
        commuter_id   TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        full_name     TEXT NOT NULL,
        email         TEXT UNIQUE NOT NULL,
        phone_no      TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt          TEXT NOT NULL DEFAULT 'legacy',
        is_verified   BOOLEAN DEFAULT false,
        is_active     BOOLEAN DEFAULT true,
        role          TEXT DEFAULT 'passenger',
        created_at    TIMESTAMPTZ DEFAULT NOW(),
        updated_at    TIMESTAMPTZ DEFAULT NOW(),
        last_login    TIMESTAMPTZ
      )
    `);
    await client.query(
      `ALTER TABLE commuters ADD COLUMN IF NOT EXISTS salt TEXT NOT NULL DEFAULT 'legacy'`
    );

    // ── TODA ASSOCIATIONS ─────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS toda_associations (
        toda_id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        association_name TEXT NOT NULL,
        association_code TEXT UNIQUE NOT NULL,
        ltfrb_number     TEXT UNIQUE NOT NULL,
        region           TEXT NOT NULL,
        service_area     TEXT,
        total_tricycles  INT DEFAULT 0,
        is_verified      BOOLEAN DEFAULT false,
        is_active        BOOLEAN DEFAULT true,
        created_at       TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // ── OPERATORS ─────────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS operators (
        operator_id   TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        toda_id       TEXT REFERENCES toda_associations(toda_id) ON DELETE SET NULL,
        contact_name  TEXT NOT NULL,
        email         TEXT UNIQUE NOT NULL,
        phone         TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt          TEXT NOT NULL DEFAULT 'legacy',
        toda_body_id  TEXT UNIQUE,
        is_verified   BOOLEAN DEFAULT false,
        is_active     BOOLEAN DEFAULT true,
        role          TEXT DEFAULT 'operator',
        created_at    TIMESTAMPTZ DEFAULT NOW(),
        updated_at    TIMESTAMPTZ DEFAULT NOW(),
        last_login    TIMESTAMPTZ
      )
    `);
    await client.query(
      `ALTER TABLE operators ADD COLUMN IF NOT EXISTS salt TEXT NOT NULL DEFAULT 'legacy'`
    );
    // Link operators back to users table
    await client.query(
      `ALTER TABLE operators ADD COLUMN IF NOT EXISTS user_id TEXT REFERENCES users(id)`
    );

    // ── DRIVERS ───────────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS drivers (
        driver_id        TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        toda_id          TEXT REFERENCES toda_associations(toda_id) ON DELETE SET NULL,
        driver_name      TEXT NOT NULL,
        email            TEXT UNIQUE,
        phone            TEXT UNIQUE NOT NULL,
        license_no       TEXT UNIQUE NOT NULL,
        toda_body_number TEXT UNIQUE NOT NULL,
        password_hash    TEXT NOT NULL,
        salt             TEXT NOT NULL DEFAULT 'legacy',
        status           TEXT DEFAULT 'offline'
                           CHECK (status IN ('online','offline','on_trip','suspended')),
        avg_rating       FLOAT DEFAULT 0.0,
        total_trips      INT DEFAULT 0,
        is_verified      BOOLEAN DEFAULT false,
        is_active        BOOLEAN DEFAULT true,
        role             TEXT DEFAULT 'driver',
        created_at       TIMESTAMPTZ DEFAULT NOW(),
        updated_at       TIMESTAMPTZ DEFAULT NOW(),
        last_login       TIMESTAMPTZ
      )
    `);
    await client.query(
      `ALTER TABLE drivers ADD COLUMN IF NOT EXISTS salt TEXT NOT NULL DEFAULT 'legacy'`
    );
    // Link drivers back to users table
    await client.query(
      `ALTER TABLE drivers ADD COLUMN IF NOT EXISTS user_id TEXT REFERENCES users(id)`
    );
    // Store free-text TODA branch name (no FK constraint)
    await client.query(
      `ALTER TABLE drivers ADD COLUMN IF NOT EXISTS toda_branch_name TEXT`
    );

    // ── TRICYCLES ─────────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS tricycles (
        tricycle_id   TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        driver_id     TEXT REFERENCES drivers(driver_id) ON DELETE SET NULL,
        toda_id       TEXT REFERENCES toda_associations(toda_id) ON DELETE SET NULL,
        plate_no      TEXT UNIQUE NOT NULL,
        body_number   TEXT UNIQUE NOT NULL,
        vehicle_color TEXT,
        status        TEXT DEFAULT 'inactive'
                        CHECK (status IN ('active','inactive','maintenance')),
        created_at    TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    // Drop toda_id FK on tricycles to allow null toda_id
    await client.query(
      `ALTER TABLE tricycles DROP CONSTRAINT IF EXISTS tricycles_toda_id_fkey`
    );
    await client.query(
      `ALTER TABLE tricycles ALTER COLUMN toda_id DROP NOT NULL`
    );

    // ── SUBSCRIPTION PLANS ────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS subscription_plans (
        plan_id       TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        plan_name     TEXT UNIQUE NOT NULL,
        plan_type     TEXT NOT NULL CHECK (plan_type IN ('driver','operator','commuter')),
        price         NUMERIC(10,2) NOT NULL,
        duration_days INT NOT NULL,
        features      TEXT[],
        is_active     BOOLEAN DEFAULT true,
        created_at    TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    const plans = [
      ['Driver Basic',   'driver',    0.00, 30,
       '{Accept rides,GPS tracking,Earnings dashboard}'],
      ['Driver Pro',     'driver',  299.00, 30,
       '{All Basic features,Priority dispatch,Lower commission 8%,Performance analytics}'],
      ['Operator Basic', 'operator',  0.00, 30,
       '{Fleet dashboard,Driver management,Basic reports}'],
      ['Operator Pro',   'operator',999.00, 30,
       '{All Basic features,Live fleet map,Advanced analytics,Reduced commission 8%,Priority support}'],
      ['Commuter Plus',  'commuter', 99.00, 30,
       '{Advance booking,Ride history,Priority matching,Exclusive discounts}'],
    ];
    for (const [name, type, price, days, features] of plans) {
      await client.query(
        `INSERT INTO subscription_plans (plan_name, plan_type, price, duration_days, features)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (plan_name) DO NOTHING`,
        [name, type, price, days, features]
      );
    }

    // ── USER SUBSCRIPTIONS ────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS subscriptions (
        subscription_id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        user_id         TEXT NOT NULL,
        user_type       TEXT NOT NULL CHECK (user_type IN ('driver','operator','commuter')),
        plan_id         TEXT REFERENCES subscription_plans(plan_id) ON DELETE SET NULL,
        status          TEXT DEFAULT 'active'
                          CHECK (status IN ('active','expired','cancelled')),
        started_at      TIMESTAMPTZ DEFAULT NOW(),
        expires_at      TIMESTAMPTZ NOT NULL,
        payment_method  TEXT DEFAULT 'gcash',
        amount_paid     NUMERIC(10,2) DEFAULT 0,
        created_at      TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await client.query(
      `CREATE INDEX IF NOT EXISTS idx_sub_user ON subscriptions(user_id, user_type)`
    );

    // ── COMMISSION RATES ──────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS commission_rates (
        rate_id        TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        user_type      TEXT NOT NULL CHECK (user_type IN ('driver','operator')),
        plan_type      TEXT NOT NULL CHECK (plan_type IN ('basic','pro','none')),
        rate_percent   NUMERIC(5,2) NOT NULL,
        description    TEXT,
        is_active      BOOLEAN DEFAULT true,
        UNIQUE(user_type, plan_type)
      )
    `);

    const rates = [
      ['driver',   'none',  10.00, 'Standard driver commission'],
      ['driver',   'basic', 10.00, 'Driver Basic commission'],
      ['driver',   'pro',    8.00, 'Driver Pro reduced commission'],
      ['operator', 'none',  10.00, 'Standard operator commission'],
      ['operator', 'basic', 10.00, 'Operator Basic commission'],
      ['operator', 'pro',    8.00, 'Operator Pro reduced commission'],
    ];
    for (const [utype, ptype, rate, desc] of rates) {
      await client.query(
        `INSERT INTO commission_rates (user_type, plan_type, rate_percent, description)
         VALUES ($1,$2,$3,$4)
         ON CONFLICT (user_type, plan_type) DO NOTHING`,
        [utype, ptype, rate, desc]
      );
    }

    // ── COMMISSION LEDGER ─────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS commission_ledger (
        ledger_id      TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        trip_id        TEXT,
        driver_id      TEXT REFERENCES drivers(driver_id) ON DELETE SET NULL,
        toda_id        TEXT REFERENCES toda_associations(toda_id) ON DELETE SET NULL,
        gross_fare     NUMERIC(10,2) NOT NULL,
        commission_pct NUMERIC(5,2) NOT NULL,
        commission_amt NUMERIC(10,2) NOT NULL,
        driver_payout  NUMERIC(10,2) NOT NULL,
        status         TEXT DEFAULT 'pending'
                         CHECK (status IN ('pending','paid','disputed')),
        paid_at        TIMESTAMPTZ,
        created_at     TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await client.query(
      `CREATE INDEX IF NOT EXISTS idx_ledger_driver ON commission_ledger(driver_id)`
    );
    await client.query(
      `CREATE INDEX IF NOT EXISTS idx_ledger_toda ON commission_ledger(toda_id)`
    );

    // ── TRIPS ─────────────────────────────────────────────────────────────────
    // commuter_id references users.id (not commuters)
    await client.query(`
      CREATE TABLE IF NOT EXISTS trips (
        trip_id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        commuter_id       TEXT,
        tricycle_id       TEXT REFERENCES tricycles(tricycle_id) ON DELETE SET NULL,
        driver_id         TEXT REFERENCES drivers(driver_id) ON DELETE SET NULL,
        route_segment     TEXT,
        service_type      TEXT DEFAULT 'solo'
                            CHECK (service_type IN ('solo','shared','express')),
        pickup_location   TEXT,
        destination       TEXT,
        fare              NUMERIC(10,2) DEFAULT 0,
        payment_method    TEXT DEFAULT 'cash'
                            CHECK (payment_method IN ('cash','gcash','maya','wallet')),
        wait_time_seconds INT DEFAULT 0,
        avg_speed_kmh     FLOAT DEFAULT 0,
        status            TEXT DEFAULT 'requested'
                            CHECK (status IN ('requested','accepted','pickup','ongoing','completed','cancelled')),
        request_timestamp TIMESTAMPTZ DEFAULT NOW(),
        pickup_timestamp  TIMESTAMPTZ,
        end_timestamp     TIMESTAMPTZ,
        created_at        TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    // Drop old FK pointing to commuters, add new one pointing to users
    await client.query(
      `ALTER TABLE trips DROP CONSTRAINT IF EXISTS trips_commuter_id_fkey`
    );
    await client.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_constraint
          WHERE conname = 'trips_commuter_id_fkey'
            AND conrelid = 'trips'::regclass
        ) THEN
          ALTER TABLE trips
            ADD CONSTRAINT trips_commuter_id_fkey
            FOREIGN KEY (commuter_id) REFERENCES users(id) ON DELETE SET NULL;
        END IF;
      END $$;
    `);
    // Add missing columns if upgrading from old schema
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS wait_time_seconds INT DEFAULT 0`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS avg_speed_kmh FLOAT DEFAULT 0`
    );

    // ── GPS LOCATIONS ─────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS gps_locations (
        location_id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        tricycle_id TEXT REFERENCES tricycles(tricycle_id) ON DELETE CASCADE,
        latitude    FLOAT NOT NULL,
        longitude   FLOAT NOT NULL,
        speed_kmh   FLOAT DEFAULT 0,
        timestamp   TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // ── PERFORMANCE REPORTS ───────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS performance_reports (
        report_id     TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        driver_id     TEXT REFERENCES drivers(driver_id) ON DELETE CASCADE,
        report_date   DATE NOT NULL,
        avg_rating    FLOAT DEFAULT 0.0,
        total_trips   INT DEFAULT 0,
        gross_revenue NUMERIC(12,2) DEFAULT 0,
        created_at    TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // ── FEEDBACK ──────────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS feedback (
        feedback_id  TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        trip_id      TEXT REFERENCES trips(trip_id) ON DELETE CASCADE,
        commuter_id  TEXT,
        driver_id    TEXT REFERENCES drivers(driver_id) ON DELETE SET NULL,
        rating_score INT NOT NULL CHECK (rating_score BETWEEN 1 AND 5),
        comments     TEXT,
        created_at   TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // ── PEAK HOUR LOGS ────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS peak_hour_logs (
        log_id        TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        route_segment TEXT NOT NULL,
        hour_of_day   INT NOT NULL CHECK (hour_of_day BETWEEN 0 AND 23),
        trip_count    INT DEFAULT 0,
        avg_wait_time FLOAT DEFAULT 0,
        logged_at     TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // ── LOGIN ATTEMPTS ────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS login_attempts (
        id           SERIAL PRIMARY KEY,
        user_type    TEXT DEFAULT 'passenger',
        email        TEXT NOT NULL,
        ip_address   TEXT,
        success      BOOLEAN DEFAULT false,
        attempted_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await client.query(
      `ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS user_type TEXT DEFAULT 'passenger'`
    );

    // ── REFRESH TOKENS ────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id         SERIAL PRIMARY KEY,
        user_id    TEXT NOT NULL,
        token      TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // ── INDEXES ───────────────────────────────────────────────────────────────
    await client.query(
      `CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`
    );
    await client.query(
      `CREATE INDEX IF NOT EXISTS idx_commuters_email ON commuters(email)`
    );
    await client.query(
      `CREATE INDEX IF NOT EXISTS idx_drivers_email ON drivers(email)`
    );
    await client.query(
      `CREATE INDEX IF NOT EXISTS idx_drivers_body ON drivers(toda_body_number)`
    );
    await client.query(
      `CREATE INDEX IF NOT EXISTS idx_operators_email ON operators(email)`
    );
    await client.query(
      `CREATE INDEX IF NOT EXISTS idx_trips_driver ON trips(driver_id)`
    );
    await client.query(
      `CREATE INDEX IF NOT EXISTS idx_trips_commuter ON trips(commuter_id)`
    );

    console.log('[DB] All tables initialized successfully ✅');
  } catch (err) {
    console.error('[DB] Initialization error:', err.message);
    throw err;
  } finally {
    client.release();
  }
}

async function dbRun(sql, params = []) {
  return await pool.query(sql, params);
}
async function dbGet(sql, params = []) {
  const r = await pool.query(sql, params);
  return r.rows[0] || null;
}
async function dbAll(sql, params = []) {
  const r = await pool.query(sql, params);
  return r.rows;
}

module.exports = { pool, initializeDatabase, dbRun, dbGet, dbAll };