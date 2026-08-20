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

    // ── USERS (passenger accounts — used by auth.js) ─────────────────────────
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
        profile_photo_url TEXT,
        valid_id_type TEXT,
        valid_id_number TEXT,
        valid_id_image_url TEXT,
        face_verification_image_url TEXT,
        identity_verification_status TEXT DEFAULT 'not_submitted',
        identity_submitted_at TIMESTAMPTZ,
        identity_verified_at TIMESTAMPTZ,
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
    await client.query(
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_photo_url TEXT`
    );
    await client.query(
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS valid_id_type TEXT`
    );
    await client.query(
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS valid_id_number TEXT`
    );
    await client.query(
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS valid_id_image_url TEXT`
    );
    await client.query(
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS face_verification_image_url TEXT`
    );
    await client.query(
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS identity_verification_status TEXT DEFAULT 'not_submitted'`
    );
    await client.query(
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS identity_submitted_at TIMESTAMPTZ`
    );
    await client.query(
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS identity_verified_at TIMESTAMPTZ`
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
        valid_id_type TEXT,
        valid_id_number TEXT,
        valid_id_image_url TEXT,
        face_verification_image_url TEXT,
        identity_verification_status TEXT DEFAULT 'not_submitted',
        identity_submitted_at TIMESTAMPTZ,
        identity_verified_at TIMESTAMPTZ,
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
    await client.query(
      `ALTER TABLE operators ADD COLUMN IF NOT EXISTS valid_id_type TEXT`
    );
    await client.query(
      `ALTER TABLE operators ADD COLUMN IF NOT EXISTS valid_id_number TEXT`
    );
    await client.query(
      `ALTER TABLE operators ADD COLUMN IF NOT EXISTS valid_id_image_url TEXT`
    );
    await client.query(
      `ALTER TABLE operators ADD COLUMN IF NOT EXISTS face_verification_image_url TEXT`
    );
    await client.query(
      `ALTER TABLE operators ADD COLUMN IF NOT EXISTS identity_verification_status TEXT DEFAULT 'not_submitted'`
    );
    await client.query(
      `ALTER TABLE operators ADD COLUMN IF NOT EXISTS identity_submitted_at TIMESTAMPTZ`
    );
    await client.query(
      `ALTER TABLE operators ADD COLUMN IF NOT EXISTS identity_verified_at TIMESTAMPTZ`
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
        online_since     TIMESTAMPTZ,
        online_seconds_today INT DEFAULT 0,
        online_seconds_date  DATE DEFAULT CURRENT_DATE,
        is_verified      BOOLEAN DEFAULT false,
        is_active        BOOLEAN DEFAULT true,
        profile_photo_url TEXT,
        role             TEXT DEFAULT 'driver',
        valid_id_type TEXT,
        valid_id_number TEXT,
        valid_id_image_url TEXT,
        face_verification_image_url TEXT,
        identity_verification_status TEXT DEFAULT 'not_submitted',
        identity_submitted_at TIMESTAMPTZ,
        identity_verified_at TIMESTAMPTZ,
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
    await client.query(
      `ALTER TABLE drivers ADD COLUMN IF NOT EXISTS online_since TIMESTAMPTZ`
    );
    await client.query(
      `ALTER TABLE drivers ADD COLUMN IF NOT EXISTS online_seconds_today INT DEFAULT 0`
    );
    await client.query(
      `ALTER TABLE drivers ADD COLUMN IF NOT EXISTS online_seconds_date DATE DEFAULT CURRENT_DATE`
    );
    await client.query(
      `ALTER TABLE drivers ADD COLUMN IF NOT EXISTS profile_photo_url TEXT`
    );
    await client.query(
      `ALTER TABLE drivers ADD COLUMN IF NOT EXISTS valid_id_type TEXT`
    );
    await client.query(
      `ALTER TABLE drivers ADD COLUMN IF NOT EXISTS valid_id_number TEXT`
    );
    await client.query(
      `ALTER TABLE drivers ADD COLUMN IF NOT EXISTS valid_id_image_url TEXT`
    );
    await client.query(
      `ALTER TABLE drivers ADD COLUMN IF NOT EXISTS face_verification_image_url TEXT`
    );
    await client.query(
      `ALTER TABLE drivers ADD COLUMN IF NOT EXISTS identity_verification_status TEXT DEFAULT 'not_submitted'`
    );
    await client.query(
      `ALTER TABLE drivers ADD COLUMN IF NOT EXISTS identity_submitted_at TIMESTAMPTZ`
    );
    await client.query(
      `ALTER TABLE drivers ADD COLUMN IF NOT EXISTS identity_verified_at TIMESTAMPTZ`
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
       '{All Basic features,Priority dispatch,Performance analytics}'],
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
    await client.query(
      `UPDATE subscription_plans
       SET is_active = false
       WHERE plan_type = 'operator'`
    );

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
    await client.query(
      `UPDATE subscriptions
       SET status = 'cancelled'
       WHERE user_type = 'operator'
         AND status = 'active'`
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
                            CHECK (service_type IN ('solo','shared','express','pickup')),
        passenger_count   INT DEFAULT 1,
        passenger_fare_type TEXT DEFAULT 'regular'
                            CHECK (passenger_fare_type IN ('regular','student','senior','pwd')),
        pickup_location   TEXT,
        pickup_lat        FLOAT,
        pickup_lng        FLOAT,
        destination       TEXT,
        destination_lat   FLOAT,
        destination_lng   FLOAT,
        fare              NUMERIC(10,2) DEFAULT 0,
        other_fee_label   TEXT,
        other_fee_amount  NUMERIC(10,2) DEFAULT 0,
        booking_notes     TEXT,
        pickup_item_description TEXT,
        pickup_item_weight TEXT,
        shared_dropoffs   JSONB DEFAULT '[]'::jsonb,
        remaining_passenger_count INT,
        payment_method    TEXT DEFAULT 'cash'
                            CHECK (payment_method IN ('cash','gcash','maya','wallet')),
        payment_status    TEXT DEFAULT 'unpaid'
                            CHECK (payment_status IN ('unpaid','pending','paid','failed')),
        payment_reference TEXT,
        payment_collected_at TIMESTAMPTZ,
        paymongo_checkout_session_id TEXT,
        paymongo_checkout_url TEXT,
        paymongo_payment_id TEXT,
        paymongo_paid_at TIMESTAMPTZ,
        wait_time_seconds INT DEFAULT 0,
        avg_speed_kmh     FLOAT DEFAULT 0,
        status            TEXT DEFAULT 'requested'
                            CHECK (status IN ('scheduled','requested','accepted','pickup','ongoing','arrived','completed','cancelled')),
        trip_type         TEXT DEFAULT 'instant'
                            CHECK (trip_type IN ('instant','scheduled')),
        scheduled_pickup_at TIMESTAMPTZ,
        driver_lat        FLOAT,
        driver_lng        FLOAT,
        driver_location_updated_at TIMESTAMPTZ,
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
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS trip_type TEXT DEFAULT 'instant'`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS scheduled_pickup_at TIMESTAMPTZ`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS pickup_lat FLOAT`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS pickup_lng FLOAT`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS destination_lat FLOAT`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS destination_lng FLOAT`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS passenger_count INT DEFAULT 1`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS passenger_fare_type TEXT DEFAULT 'regular'`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS other_fee_label TEXT`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS other_fee_amount NUMERIC(10,2) DEFAULT 0`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS booking_notes TEXT`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS pickup_item_description TEXT`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS pickup_item_weight TEXT`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS shared_dropoffs JSONB DEFAULT '[]'::jsonb`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS remaining_passenger_count INT`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS payment_status TEXT DEFAULT 'unpaid'`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS payment_reference TEXT`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS payment_collected_at TIMESTAMPTZ`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS paymongo_checkout_session_id TEXT`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS paymongo_checkout_url TEXT`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS paymongo_payment_id TEXT`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS paymongo_paid_at TIMESTAMPTZ`
    );
    await client.query(
      `UPDATE trips SET payment_status = 'unpaid' WHERE payment_status IS NULL`
    );
    await client.query(
      `UPDATE trips SET passenger_count = 1 WHERE passenger_count IS NULL`
    );
    await client.query(
      `UPDATE trips SET passenger_fare_type = 'regular' WHERE passenger_fare_type IS NULL`
    );
    await client.query(
      `ALTER TABLE trips DROP CONSTRAINT IF EXISTS trips_passenger_fare_type_check`
    );
    await client.query(
      `ALTER TABLE trips ADD CONSTRAINT trips_passenger_fare_type_check
       CHECK (passenger_fare_type IN ('regular','student','senior','pwd'))`
    );
    await client.query(
      `ALTER TABLE trips DROP CONSTRAINT IF EXISTS trips_service_type_check`
    );
    await client.query(
      `ALTER TABLE trips ADD CONSTRAINT trips_service_type_check
       CHECK (service_type IN ('solo','shared','express','pickup'))`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS driver_lat FLOAT`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS driver_lng FLOAT`
    );
    await client.query(
      `ALTER TABLE trips ADD COLUMN IF NOT EXISTS driver_location_updated_at TIMESTAMPTZ`
    );
    await client.query(
      `ALTER TABLE trips DROP CONSTRAINT IF EXISTS trips_status_check`
    );
    await client.query(
      `ALTER TABLE trips ADD CONSTRAINT trips_status_check
       CHECK (status IN ('scheduled','requested','accepted','pickup','ongoing','arrived','completed','cancelled'))`
    );
    await client.query(
      `ALTER TABLE trips DROP CONSTRAINT IF EXISTS trips_payment_method_check`
    );
    await client.query(
      `ALTER TABLE trips ADD CONSTRAINT trips_payment_method_check
       CHECK (payment_method IN ('cash','gcash','maya','wallet'))`
    );
    await client.query(
      `ALTER TABLE trips DROP CONSTRAINT IF EXISTS trips_payment_status_check`
    );
    await client.query(
      `ALTER TABLE trips ADD CONSTRAINT trips_payment_status_check
       CHECK (payment_status IN ('unpaid','pending','paid','failed'))`
    );
    await client.query(
      `CREATE INDEX IF NOT EXISTS idx_trips_scheduled_pickup
       ON trips(scheduled_pickup_at)`
    );
    await client.query(
      `CREATE INDEX IF NOT EXISTS idx_trips_paymongo_session
       ON trips(paymongo_checkout_session_id)`
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
    await client.query(
      `CREATE INDEX IF NOT EXISTS idx_gps_locations_tricycle_timestamp
       ON gps_locations(tricycle_id, timestamp DESC)`
    );

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

    // Admin-validatable issue reports and system alerts.
    await client.query(`
      CREATE TABLE IF NOT EXISTS issue_reports (
        issue_id       TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        reporter_role  TEXT NOT NULL
                       CHECK (reporter_role IN ('passenger','commuter','driver','operator','system')),
        reporter_id    TEXT,
        reporter_name  TEXT,
        report_type    TEXT NOT NULL,
        subject_role   TEXT
                       CHECK (subject_role IS NULL OR subject_role IN ('passenger','commuter','driver','operator','vehicle','trip','system')),
        subject_id     TEXT,
        subject_name   TEXT,
        trip_id        TEXT REFERENCES trips(trip_id) ON DELETE SET NULL,
        title          TEXT NOT NULL,
        details        TEXT,
        metadata       JSONB DEFAULT '{}'::jsonb,
        priority       TEXT DEFAULT 'normal'
                       CHECK (priority IN ('low','normal','high','urgent')),
        status         TEXT DEFAULT 'pending'
                       CHECK (status IN ('pending','validated','rejected','resolved')),
        admin_notes    TEXT,
        validated_at   TIMESTAMPTZ,
        created_at     TIMESTAMPTZ DEFAULT NOW(),
        updated_at     TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await client.query(
      `ALTER TABLE issue_reports ADD COLUMN IF NOT EXISTS reporter_name TEXT`
    );
    await client.query(
      `ALTER TABLE issue_reports ADD COLUMN IF NOT EXISTS subject_name TEXT`
    );
    await client.query(
      `ALTER TABLE issue_reports ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb`
    );
    await client.query(
      `ALTER TABLE issue_reports ADD COLUMN IF NOT EXISTS priority TEXT DEFAULT 'normal'`
    );
    await client.query(
      `ALTER TABLE issue_reports ADD COLUMN IF NOT EXISTS admin_notes TEXT`
    );
    await client.query(
      `ALTER TABLE issue_reports ADD COLUMN IF NOT EXISTS validated_at TIMESTAMPTZ`
    );
    await client.query(
      `CREATE INDEX IF NOT EXISTS idx_issue_reports_status_created
       ON issue_reports(status, created_at DESC)`
    );
    await client.query(
      `CREATE INDEX IF NOT EXISTS idx_issue_reports_subject
       ON issue_reports(subject_role, subject_id)`
    );
    await client.query(
      `CREATE INDEX IF NOT EXISTS idx_issue_reports_trip
       ON issue_reports(trip_id)`
    );

    await client.query(`
      CREATE TABLE IF NOT EXISTS passenger_blacklist (
        blacklist_id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        passenger_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        driver_id    TEXT REFERENCES drivers(driver_id) ON DELETE CASCADE,
        issue_id     TEXT REFERENCES issue_reports(issue_id) ON DELETE SET NULL,
        reason       TEXT,
        is_active    BOOLEAN DEFAULT true,
        created_at   TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await client.query(
      `CREATE INDEX IF NOT EXISTS idx_passenger_blacklist_lookup
       ON passenger_blacklist(passenger_id, driver_id, is_active)`
    );
    await client.query(
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_passenger_blacklist_active_unique
       ON passenger_blacklist(passenger_id, driver_id)
       WHERE is_active = true`
    );

    // App-wide operational settings controlled by admin.
    await client.query(`
      CREATE TABLE IF NOT EXISTS app_settings (
        key        TEXT PRIMARY KEY,
        value      TEXT NOT NULL,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await client.query(
      `INSERT INTO app_settings (key, value)
       VALUES ('fare_fuel_price_per_liter', '80.00')
       ON CONFLICT (key) DO NOTHING`
    );
    await client.query(
      `INSERT INTO app_settings (key, value)
       VALUES ('fare_premium_multiplier', '1.30')
       ON CONFLICT (key) DO NOTHING`
    );

    // ── INDEXES ───────────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS fare_rate_bands (
        band_id          SERIAL PRIMARY KEY,
        sort_order       INT UNIQUE NOT NULL,
        min_fuel_price   NUMERIC(10,2) NOT NULL,
        max_fuel_price   NUMERIC(10,2),
        regular_fare     NUMERIC(10,2) NOT NULL,
        discounted_fare  NUMERIC(10,2) NOT NULL,
        updated_at       TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    const fareBands = [
      [1, 20, 29.99, 10, 8],
      [2, 30, 39.99, 12, 10],
      [3, 40, 49.99, 13, 11],
      [4, 50, 59.99, 14, 12],
      [5, 60, 69.99, 15, 13],
      [6, 70, 79.99, 16, 14],
      [7, 80, 89.99, 17, 15],
      [8, 90, 99.99, 18, 16],
      [9, 100, null, 20, 18],
    ];
    for (const band of fareBands) {
      await client.query(
        `INSERT INTO fare_rate_bands
          (sort_order, min_fuel_price, max_fuel_price, regular_fare, discounted_fare)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (sort_order) DO NOTHING`,
        band
      );
    }

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
