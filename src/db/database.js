require('dotenv').config();
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.error('[DB] ERROR: DATABASE_URL is not set.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('connect', () => console.log('[DB] PostgreSQL connected'));
pool.on('error', (err) => console.error('[DB] Pool error:', err.message));

async function initializeDatabase() {
  const client = await pool.connect();
  try {
    // ── Enable UUID extension ──────────────────────────────────────────────
    await client.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);

    // ══════════════════════════════════════════════════════════════════════
    // COMMUTER (Passenger) — from ERD
    // ══════════════════════════════════════════════════════════════════════
    await client.query(`
      CREATE TABLE IF NOT EXISTS commuters (
        commuter_id   TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        full_name     TEXT NOT NULL,
        email         TEXT UNIQUE NOT NULL,
        phone_no      TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt          TEXT NOT NULL,
        is_verified   BOOLEAN DEFAULT false,
        is_active     BOOLEAN DEFAULT true,
        role          TEXT DEFAULT 'passenger',
        created_at    TIMESTAMPTZ DEFAULT NOW(),
        updated_at    TIMESTAMPTZ DEFAULT NOW(),
        last_login    TIMESTAMPTZ
      );
    `);
    await client.query(`ALTER TABLE commuters ADD COLUMN IF NOT EXISTS salt TEXT NOT NULL DEFAULT 'legacy';`);

    // ══════════════════════════════════════════════════════════════════════
    // TODA ASSOCIATION (Operator Organization)
    // ══════════════════════════════════════════════════════════════════════
    await client.query(`
      CREATE TABLE IF NOT EXISTS toda_associations (
        toda_id         TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        association_name TEXT NOT NULL,
        association_code TEXT UNIQUE NOT NULL,
        ltfrb_number    TEXT UNIQUE NOT NULL,
        region          TEXT NOT NULL,
        service_area    TEXT,
        total_tricycles INT DEFAULT 0,
        is_verified     BOOLEAN DEFAULT false,
        is_active       BOOLEAN DEFAULT true,
        created_at      TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // ══════════════════════════════════════════════════════════════════════
    // OPERATOR — from ERD (manages fleet/association)
    // ══════════════════════════════════════════════════════════════════════
    await client.query(`
      CREATE TABLE IF NOT EXISTS operators (
        operator_id     TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        toda_id         TEXT REFERENCES toda_associations(toda_id) ON DELETE SET NULL,
        contact_name    TEXT NOT NULL,
        email           TEXT UNIQUE NOT NULL,
        phone           TEXT UNIQUE NOT NULL,
        password_hash   TEXT NOT NULL,
        salt            TEXT NOT NULL,
        toda_body_id    TEXT UNIQUE,
        is_verified     BOOLEAN DEFAULT false,
        is_active       BOOLEAN DEFAULT true,
        role            TEXT DEFAULT 'operator',
        created_at      TIMESTAMPTZ DEFAULT NOW(),
        updated_at      TIMESTAMPTZ DEFAULT NOW(),
        last_login      TIMESTAMPTZ
      );
    `);
    await client.query(`ALTER TABLE operators ADD COLUMN IF NOT EXISTS salt TEXT NOT NULL DEFAULT 'legacy';`);

    // ══════════════════════════════════════════════════════════════════════
    // DRIVER — from ERD
    // ══════════════════════════════════════════════════════════════════════
    await client.query(`
      CREATE TABLE IF NOT EXISTS drivers (
        driver_id       TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        toda_id         TEXT REFERENCES toda_associations(toda_id) ON DELETE SET NULL,
        driver_name     TEXT NOT NULL,
        email           TEXT UNIQUE,
        phone           TEXT UNIQUE NOT NULL,
        license_no      TEXT UNIQUE NOT NULL,
        toda_body_number TEXT UNIQUE NOT NULL,
        password_hash   TEXT NOT NULL,
        salt            TEXT NOT NULL,
        status          TEXT DEFAULT 'offline'
                          CHECK (status IN ('online','offline','on_trip','suspended')),
        avg_rating      FLOAT DEFAULT 0.0,
        total_trips     INT DEFAULT 0,
        is_verified     BOOLEAN DEFAULT false,
        is_active       BOOLEAN DEFAULT true,
        role            TEXT DEFAULT 'driver',
        created_at      TIMESTAMPTZ DEFAULT NOW(),
        updated_at      TIMESTAMPTZ DEFAULT NOW(),
        last_login      TIMESTAMPTZ
      );
    `);
    await client.query(`ALTER TABLE drivers ADD COLUMN IF NOT EXISTS salt TEXT NOT NULL DEFAULT 'legacy';`);

    // ══════════════════════════════════════════════════════════════════════
    // TRICYCLE — from ERD
    // ══════════════════════════════════════════════════════════════════════
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
      );
    `);

    // ══════════════════════════════════════════════════════════════════════
    // TRIP — from ERD
    // ══════════════════════════════════════════════════════════════════════
    await client.query(`
      CREATE TABLE IF NOT EXISTS trips (
        trip_id             TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        commuter_id         TEXT REFERENCES commuters(commuter_id) ON DELETE SET NULL,
        tricycle_id         TEXT REFERENCES tricycles(tricycle_id) ON DELETE SET NULL,
        driver_id           TEXT REFERENCES drivers(driver_id) ON DELETE SET NULL,
        route_segment       TEXT,
        service_type        TEXT DEFAULT 'solo'
                              CHECK (service_type IN ('solo','shared','express')),
        pickup_location     TEXT,
        destination         TEXT,
        fare                NUMERIC(10,2) DEFAULT 0,
        payment_method      TEXT DEFAULT 'cash'
                              CHECK (payment_method IN ('cash','gcash','maya','wallet')),
        wait_time_seconds   INT DEFAULT 0,
        avg_speed_kmh       FLOAT DEFAULT 0,
        status              TEXT DEFAULT 'requested'
                              CHECK (status IN ('requested','accepted','pickup','ongoing','completed','cancelled')),
        request_timestamp   TIMESTAMPTZ DEFAULT NOW(),
        pickup_timestamp    TIMESTAMPTZ,
        end_timestamp       TIMESTAMPTZ,
        created_at          TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // ══════════════════════════════════════════════════════════════════════
    // GPS_LOCATION — from ERD
    // ══════════════════════════════════════════════════════════════════════
    await client.query(`
      CREATE TABLE IF NOT EXISTS gps_locations (
        location_id   TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        tricycle_id   TEXT REFERENCES tricycles(tricycle_id) ON DELETE CASCADE,
        latitude      FLOAT NOT NULL,
        longitude     FLOAT NOT NULL,
        speed_kmh     FLOAT DEFAULT 0,
        timestamp     TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // ══════════════════════════════════════════════════════════════════════
    // PERFORMANCE_REPORT — from ERD
    // ══════════════════════════════════════════════════════════════════════
    await client.query(`
      CREATE TABLE IF NOT EXISTS performance_reports (
        report_id     TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        driver_id     TEXT REFERENCES drivers(driver_id) ON DELETE CASCADE,
        report_date   DATE NOT NULL,
        avg_rating    FLOAT DEFAULT 0.0,
        total_trips   INT DEFAULT 0,
        gross_revenue NUMERIC(12,2) DEFAULT 0,
        created_at    TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // ══════════════════════════════════════════════════════════════════════
    // FEEDBACK — from ERD
    // ══════════════════════════════════════════════════════════════════════
    await client.query(`
      CREATE TABLE IF NOT EXISTS feedback (
        feedback_id   TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        trip_id       TEXT REFERENCES trips(trip_id) ON DELETE CASCADE,
        commuter_id   TEXT REFERENCES commuters(commuter_id) ON DELETE SET NULL,
        driver_id     TEXT REFERENCES drivers(driver_id) ON DELETE SET NULL,
        rating_score  INT NOT NULL CHECK (rating_score BETWEEN 1 AND 5),
        comments      TEXT,
        created_at    TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // ══════════════════════════════════════════════════════════════════════
    // PEAK_HOUR_LOG — from ERD
    // ══════════════════════════════════════════════════════════════════════
    await client.query(`
      CREATE TABLE IF NOT EXISTS peak_hour_logs (
        log_id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        route_segment   TEXT NOT NULL,
        hour_of_day     INT NOT NULL CHECK (hour_of_day BETWEEN 0 AND 23),
        trip_count      INT DEFAULT 0,
        avg_wait_time   FLOAT DEFAULT 0,
        logged_at       TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // ══════════════════════════════════════════════════════════════════════
    // LOGIN ATTEMPTS — security audit
    // ══════════════════════════════════════════════════════════════════════
    await client.query(`
      CREATE TABLE IF NOT EXISTS login_attempts (
        id            SERIAL PRIMARY KEY,
        user_type     TEXT NOT NULL CHECK (user_type IN ('commuter','driver','operator')),
        email         TEXT NOT NULL,
        ip_address    TEXT,
        success       BOOLEAN DEFAULT false,
        attempted_at  TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // ══════════════════════════════════════════════════════════════════════
    // INDEXES for performance
    // ══════════════════════════════════════════════════════════════════════
    await client.query(`CREATE INDEX IF NOT EXISTS idx_commuters_email ON commuters(email);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_drivers_email ON drivers(email);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_drivers_toda_body ON drivers(toda_body_number);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_drivers_license ON drivers(license_no);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_operators_email ON operators(email);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_trips_commuter ON trips(commuter_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_trips_driver ON trips(driver_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_gps_tricycle ON gps_locations(tricycle_id);`);

    console.log('[DB] All tables initialized ✅');
  } finally {
    client.release();
  }
}

async function dbRun(sql, params = []) { return await pool.query(sql, params); }
async function dbGet(sql, params = []) { const r = await pool.query(sql, params); return r.rows[0] || null; }
async function dbAll(sql, params = []) { const r = await pool.query(sql, params); return r.rows; }

module.exports = { pool, initializeDatabase, dbRun, dbGet, dbAll };