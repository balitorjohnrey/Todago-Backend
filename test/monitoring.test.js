const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const jwt = require('jsonwebtoken');
const { PGlite } = require('@electric-sql/pglite');
const { pgcrypto } = require('@electric-sql/pglite/contrib/pgcrypto');
const { syncDriverPerformance } = require('../src/services/driverPerformance');
const { distanceToRouteMeters, currentRouteLeg } = require('../src/utils/routeMonitoring');

const road = [{ lat: 7.30, lng: 125.65 }, { lat: 7.30, lng: 125.70 }];

async function fixture() {
  const pg = await PGlite.create('memory://', { extensions: { pgcrypto } });
  let queue = Promise.resolve();
  const query = async (sql, params = []) => {
    const result = await pg.query(sql, params);
    return { ...result, rowCount: result.affectedRows, rows: result.rows || [] };
  };
  const pool = {
    on() {},
    async connect() {
      const previous = queue;
      let unlock;
      queue = new Promise(resolve => { unlock = resolve; });
      await previous;
      return { query, release() { unlock?.(); unlock = null; } };
    },
    async query(sql, params) {
      const client = await pool.connect();
      try { return await client.query(sql, params); } finally { client.release(); }
    },
  };
  const database = { pool, dbRun: pool.query,
    dbGet: async (sql, params) => (await pool.query(sql, params)).rows[0] || null,
    dbAll: async (sql, params) => (await pool.query(sql, params)).rows };
  const sourceRoot = path.resolve(__dirname, '../src');
  const modules = new Map();
  const env = { DATABASE_URL: 'memory://', JWT_SECRET: 'monitoring-tests-only',
    PASSWORD_PEPPER: 'monitoring-tests-only-pepper', NODE_ENV: 'test' };
  function load(relative, initialize = false) {
    const filename = path.resolve(sourceRoot, relative);
    if (!initialize && filename === path.join(sourceRoot, 'db/database.js')) return database;
    if (modules.has(filename)) return modules.get(filename).exports;
    const module = { exports: {} };
    modules.set(filename, module);
    const actualRequire = createRequire(filename);
    const isolatedRequire = name => {
      if (name === 'dotenv') return { config() {} };
      if (name === 'pg') return { Pool: function () { return pool; } };
      const resolved = actualRequire.resolve(name);
      return resolved.startsWith(sourceRoot + path.sep) && resolved.endsWith('.js')
        ? load(path.relative(sourceRoot, resolved)) : actualRequire(name);
    };
    vm.runInNewContext(fs.readFileSync(filename, 'utf8'), {
      module, exports: module.exports, require: isolatedRequire,
      process: { env, exit(code) { throw new Error(`Unexpected exit: ${code}`); } },
      console, Buffer, Date, URL, setTimeout, clearTimeout,
      __dirname: path.dirname(filename), __filename: filename,
    }, { filename });
    return module.exports;
  }
  const initializer = load('db/database.js', true);
  try { await initializer.initializeDatabase(); }
  catch (error) { await pg.close(); throw error; }
  const routers = { trips: load('routes/trips.js'), admin: load('routes/admin_auth.js'),
    operator: load('routes/operator_auth.js'), reports: load('routes/reports.js') };

  async function request(router, routePath, { method = 'get', role = 'admin', id = `${role}-1`,
    body = {}, query: queryParams = {}, params = {} } = {}) {
    const token = jwt.sign({ sub: id, role }, env.JWT_SECRET,
      { issuer: 'todago-api', audience: 'todago-app', expiresIn: '1h' });
    const route = routers[router].stack.find(layer => layer.route?.path === routePath && layer.route.methods[method]).route;
    const req = { headers: { authorization: `Bearer ${token}` }, body, params, query: queryParams };
    let code = 200, data;
    const res = { status(value) { code = value; return res; }, json(value) { data = value; return res; } };
    for (const layer of route.stack) {
      await layer.handle(req, res, error => { if (error) throw error; });
      if (data !== undefined) break;
    }
    return { code, data };
  }

  async function seed() {
    await pg.exec(`TRUNCATE users, toda_associations, drivers, operators, trips CASCADE;
      INSERT INTO users(id, full_name, email, phone, password_hash)
        VALUES ('passenger-1','Passenger One','passenger@test.invalid','0911','test');
      INSERT INTO toda_associations(toda_id, association_name, association_code, ltfrb_number, region)
        VALUES ('toda-1','Fleet One','ONE','one','Test'), ('toda-2','Fleet Two','TWO','two','Test');
      INSERT INTO operators(operator_id,toda_id,contact_name,email,phone,password_hash)
        VALUES ('operator-1','toda-1','Operator One','operator@test.invalid','0922','test');
      INSERT INTO drivers(driver_id,toda_id,driver_name,phone,license_no,toda_body_number,password_hash,status,is_verified)
        VALUES ('driver-1','toda-1','Driver One','0933','license-1','body-1','test','online',true),
               ('driver-2','toda-2','Driver Two','0944','license-2','body-2','test','online',true);
      INSERT INTO tricycles(tricycle_id,driver_id,toda_id,plate_no,body_number,status)
        VALUES ('tricycle-1','driver-1','toda-1','PLATE-1','body-1','active');`);
  }
  async function book(overrides = {}) {
    await database.dbRun("UPDATE drivers SET status = 'online' WHERE driver_id = 'driver-1'");
    return request('trips', '/request', { method: 'post', role: 'passenger', id: 'passenger-1', body: {
      driverId: 'driver-1', pickupLocation: 'Pickup', destination: 'Destination', serviceType: 'solo',
      pickupLat: road[0].lat, pickupLng: road[0].lng,
      destinationLat: road[1].lat, destinationLng: road[1].lng,
      fare: 29.5, otherFeeAmount: 12.5, otherFeeLabel: 'Tip', paymentMethod: 'cash', routePoints: road,
      ...overrides,
    } });
  }
  return { pg, database, request, seed, book, load, initializer, close: () => pg.close() };
}

test('trip monitoring uses real isolated PostgreSQL migrations and transactions', async t => {
  const f = await fixture();
  t.after(f.close);
  t.beforeEach(f.seed);

  await t.test('the fare type migration accepts Pregnant and preserves existing bookings', async () => {
    await f.pg.exec(`ALTER TABLE trips
      DROP CONSTRAINT trips_passenger_fare_type_check,
      ADD CONSTRAINT trips_passenger_fare_type_check
        CHECK (passenger_fare_type IN ('regular','student','senior','pwd'))`);
    const student = await f.book({ passengerFareType: 'student' });
    assert.equal(student.code, 201, student.data?.message);

    await f.initializer.initializeDatabase();
    const pregnant = await f.book({ passengerFareType: 'pregnant', fare: 15, otherFeeAmount: 0, otherFeeLabel: null });
    assert.equal(pregnant.code, 201, pregnant.data?.message);
    assert.equal(pregnant.data.trip.passenger_fare_type, 'pregnant');
    const existing = await f.database.dbGet('SELECT passenger_fare_type FROM trips WHERE trip_id = $1',
      [student.data.trip.trip_id]);
    assert.equal(existing.passenger_fare_type, 'student');
  });

  await t.test('additional charges are itemized, attributed, and included once in the fare', async () => {
    const booked = await f.book();
    assert.equal(booked.code, 201, booked.data?.message);
    const result = await f.request('admin', '/monitoring/charges');
    assert.equal(result.code, 200);
    const charge = result.data.charges[0];
    assert.equal(charge.label, 'Tip');
    assert.equal(Number(charge.amount), 12.5);
    assert.equal(Number(charge.base_fare), 17);
    assert.equal(Number(charge.total_fare), 29.5);
    assert.equal(charge.added_by, 'passenger-1');
    assert.equal(charge.intent_confirmed, true);
    assert.equal(Number(result.data.summary.tip_amount), 12.5);
    assert.equal((await f.request('admin', '/monitoring/charges', { role: 'driver' })).code, 403);
    for (const invalid of [{ otherFeeLabel: '' }, { otherFeeAmount: 30 },
      { otherFeeAmount: 12.555 }, { otherFeeAmount: 0.00000001 }]) {
      assert.equal((await f.book(invalid)).code, 422);
    }
    assert.equal((await f.book({ otherFeeAmount: 0, otherFeeLabel: null })).code, 201);
    assert.equal((await f.database.dbGet('SELECT COUNT(*) FROM trip_additional_charges')).count, 1);
    const others = await f.book({ otherFeeLabel: 'Others', otherFeeAmount: 7.25, fare: 24.25 });
    assert.equal(others.code, 201);
    const filtered = await f.request('admin', '/monitoring/charges', { query: { label: 'Others', limit: 1 } });
    assert.equal(filtered.data.charges[0].label, 'Others');
    assert.equal(Number(filtered.data.summary.total_amount), 7.25);
  });

  await t.test('a charge-write failure rolls back the trip insert', async () => {
    await f.pg.exec(`ALTER TABLE trip_additional_charges ADD CONSTRAINT test_charge_failure CHECK (label <> 'Tip')`);
    try {
      assert.equal((await f.book()).code, 500);
      assert.equal((await f.database.dbGet('SELECT COUNT(*) FROM trips')).count, 0);
    } finally { await f.pg.exec('ALTER TABLE trip_additional_charges DROP CONSTRAINT test_charge_failure'); }
  });

  await t.test('paid unrated trips and ratings refresh one performance report; operator data is scoped', async () => {
    const settlement = f.load('services/tripPayments.js');
    const booked = await f.book();
    const tripId = booked.data.trip.trip_id;
    await f.database.dbRun("UPDATE trips SET status = 'arrived' WHERE trip_id = $1", [tripId]);
    await settlement.completePaidTrip(tripId, 'driver-1');
    let report = await f.database.dbGet("SELECT * FROM performance_reports WHERE driver_id='driver-1' AND report_scope='lifetime'");
    assert.equal(report.total_trips, 1);
    assert.equal(report.rating_count, 0);
    assert.equal(report.avg_rating, 0);
    const rated = await f.request('trips', '/:tripId/rate', { method: 'post', role: 'passenger',
      id: 'passenger-1', params: { tripId }, body: { rating: 5 } });
    assert.equal(rated.code, 201, rated.data?.message);
    await settlement.completePaidTrip(tripId, 'driver-1');
    await syncDriverPerformance(f.database.pool, 'driver-2');
    const admin = await f.request('admin', '/monitoring/drivers');
    assert.equal(admin.data.drivers[0].driver_id, 'driver-1');
    assert.equal(admin.data.drivers[0].avg_rating, 5);
    assert.equal(admin.data.drivers[0].rating_count, 1);
    assert.equal(admin.data.drivers[0].total_trips, 1);
    const operator = await f.request('operator', '/analytics/drivers', { role: 'operator' });
    assert.equal(operator.data.drivers.length, 1);
    assert.equal(operator.data.drivers[0].driver_id, 'driver-1');
    assert.equal((await f.database.dbGet("SELECT COUNT(*) FROM performance_reports WHERE driver_id='driver-1' AND report_scope='lifetime'")).count, 1);
  });

  await t.test('performance-write failure rolls back payment completion and can be retried', async () => {
    const tripId = (await f.book()).data.trip.trip_id;
    await f.database.dbRun("UPDATE trips SET status='arrived' WHERE trip_id=$1", [tripId]);
    const settlement = f.load('services/tripPayments.js');
    await f.pg.exec('ALTER TABLE performance_reports ADD CONSTRAINT test_performance_failure CHECK (total_trips = 0)');
    try {
      await assert.rejects(settlement.completePaidTrip(tripId, 'driver-1'));
      const trip = await f.database.dbGet('SELECT * FROM trips WHERE trip_id=$1', [tripId]);
      assert.equal(trip.status, 'arrived');
      assert.equal(trip.payment_status, 'unpaid');
      assert.equal((await f.database.dbGet("SELECT total_trips FROM drivers WHERE driver_id='driver-1'")).total_trips, 0);
    } finally { await f.pg.exec('ALTER TABLE performance_reports DROP CONSTRAINT test_performance_failure'); }
    await settlement.completePaidTrip(tripId, 'driver-1');
    assert.equal((await f.database.dbGet('SELECT status FROM trips WHERE trip_id=$1', [tripId])).status, 'completed');
  });

  await t.test('manual reports cannot impersonate automatic GPS alerts', async () => {
    for (const role of ['passenger', 'driver', 'operator']) {
      for (const reportType of ['driver_route_deviation', 'driver_outside_service_area']) {
        const submitted = await f.request('reports', '/', { method: 'post', role,
          body: { reportType, title: 'Forged automatic GPS alert' } });
        assert.equal(submitted.code, 422);
      }
    }
    assert.equal((await f.database.dbGet('SELECT COUNT(*) FROM issue_reports')).count, 0);
    // A legacy manual report with a reserved type must not suppress a real alert.
    await f.database.dbRun(`INSERT INTO issue_reports
      (reporter_role, report_type, subject_role, subject_id, title)
      VALUES ('driver', 'driver_outside_service_area', 'driver', 'driver-2', 'Legacy manual report')`);
    await f.load('services/driverTracking.js').recordDriverGpsLocation('driver-2', 8, 126);
    assert.equal((await f.database.dbGet("SELECT COUNT(*) FROM issue_reports WHERE reporter_role='system'")).count, 1);
  });

  await t.test('GPS samples, route deviations, service-area alerts, and latest alert coordinates are recorded', async () => {
    const tripId = (await f.book()).data.trip.trip_id;
    await f.database.dbRun("UPDATE trips SET status='ongoing' WHERE trip_id=$1", [tripId]);
    const tracking = f.load('services/driverTracking.js');
    const sample = (lat, lng) => tracking.recordDriverGpsLocation('driver-1', lat, lng, { tripId, source: 'active_trip' });
    await sample(7.30, 125.675);
    await sample(7.31, 125.675);
    await sample(8, 126);
    await sample(8.01, 126.01);
    const reports = await f.database.dbAll('SELECT * FROM issue_reports ORDER BY report_type');
    assert.equal(reports.length, 2, 'repeated samples update pending alerts instead of duplicating them');
    for (const report of reports) {
      assert.equal(report.trip_id, tripId);
      assert.equal(report.metadata.lat, 8.01);
      assert.equal(report.metadata.lng, 126.01);
      assert.equal(report.subject_id, 'driver-1');
    }
    const stats = (await f.request('admin', '/stats')).data.stats;
    assert.equal(stats.gps_alerts, 2);
    assert.equal(stats.service_area_alerts, 1);
    const gps = await f.request('admin', '/monitoring/gps', { query: { tripId, limit: 2 } });
    assert.equal(gps.data.locations.length, 2);
    assert.equal(gps.data.has_more, true);
    const older = await f.request('admin', '/monitoring/gps', { query: { tripId, limit: 2, ...gps.data.next_cursor } });
    assert.equal(older.data.locations.length, 2);
    assert.equal(new Set([...gps.data.locations, ...older.data.locations].map(row => row.location_id)).size, 4);
    assert.equal((await f.request('admin', '/monitoring/gps', { role: 'passenger' })).code, 403);
    assert.equal((await f.request('admin', '/monitoring/gps', { query: { before: 'invalid' } })).code, 422);
    await tracking.recordDriverGpsLocation('driver-2', 7.30, 125.67);
    assert.equal((await f.database.dbGet("SELECT * FROM gps_locations WHERE driver_id='driver-2'")).tricycle_id, null);
    const updated = await f.request('trips', '/:tripId/driver-location', { method: 'put', role: 'driver',
      params: { tripId }, body: { lat: 7.30, lng: 125.67 } });
    assert.equal(updated.code, 200, updated.data?.message);
    assert.equal((await f.database.dbGet('SELECT COUNT(*) FROM gps_locations WHERE trip_id=$1', [tripId])).count, 5);
    // A location request may finish after a simultaneous completion. Keep its
    // known trip attribution while stopping route checks for that finished leg.
    await f.database.dbRun("UPDATE trips SET status='completed', payment_status='paid' WHERE trip_id=$1", [tripId]);
    await sample(7.30, 125.67);
    const last = await f.database.dbGet('SELECT * FROM gps_locations ORDER BY timestamp DESC LIMIT 1');
    assert.equal(last.trip_id, tripId);
    assert.equal(last.route_distance_m, null);
  });

  await t.test('a failed alert rolls back its GPS sample; retry records both', async () => {
    const tracking = f.load('services/driverTracking.js');
    await f.pg.exec("ALTER TABLE issue_reports ADD CONSTRAINT test_alert_failure CHECK (report_type <> 'driver_outside_service_area')");
    try {
      await assert.rejects(tracking.recordDriverGpsLocation('driver-2', 8, 126));
      assert.equal((await f.database.dbGet('SELECT COUNT(*) FROM gps_locations')).count, 0);
    } finally { await f.pg.exec('ALTER TABLE issue_reports DROP CONSTRAINT test_alert_failure'); }
    await tracking.recordDriverGpsLocation('driver-2', 8, 126);
    assert.equal((await f.database.dbGet('SELECT COUNT(*) FROM gps_locations')).count, 1);
    assert.equal((await f.database.dbGet('SELECT COUNT(*) FROM issue_reports')).count, 1);
  });

  await t.test('designated routes cannot be overwritten by a refreshed navigation route', async () => {
    const tripId = (await f.book()).data.trip.trip_id;
    await f.database.dbRun("UPDATE trips SET status='ongoing', driver_lat=7.3, driver_lng=125.65 WHERE trip_id=$1", [tripId]);
    const routeRequest = options => f.request('trips', '/:tripId/designated-route', {
      method: 'put', role: 'driver', params: { tripId }, body: { leg: 'dropoff:0', points: road }, ...options,
    });
    const existing = await routeRequest({ body: { leg: 'dropoff:0', points: [road[0], { lat: 7.31, lng: 125.70 }] } });
    assert.equal(existing.code, 200);
    assert.equal(existing.data.saved, false);
    assert.equal((await f.database.dbGet('SELECT designated_routes FROM trips WHERE trip_id=$1', [tripId])).designated_routes['dropoff:0'].points[1].lat, 7.3);
    assert.equal((await routeRequest({ id: 'driver-2' })).code, 404);
    assert.equal((await routeRequest({ role: 'passenger' })).code, 403);
    await f.database.dbRun("UPDATE trips SET status='accepted' WHERE trip_id=$1", [tripId]);
    const pickup = await routeRequest({ body: { leg: 'pickup', points: [road[1], road[0]] } });
    assert.equal(pickup.code, 422, 'route origin must match the driver GPS point');
    const goodPickup = await routeRequest({ body: { leg: 'pickup', points: [road[0], road[0]] } });
    assert.equal(goodPickup.code, 200, goodPickup.data?.message);
    assert.equal(goodPickup.data.saved, true);
    assert.equal(currentRouteLeg({ status: 'ongoing', service_type: 'shared', shared_dropoffs: [
      { status: 'dropped', lat: 7.3, lng: 125.65 }, { status: 'pending', lat: 7.4, lng: 125.7 },
    ] }).key, 'dropoff:1');
    assert.ok(distanceToRouteMeters({ lat: 7.3, lng: 125.675 }, road) < 0.01);
    assert.ok(distanceToRouteMeters({ lat: 7.31, lng: 125.675 }, road) > 1000);
  });

  await t.test('repeated migrations preserve historical reports and classify old charges accurately', async () => {
    const trip = await f.book({ otherFeeLabel: 'Baggage', otherFeeAmount: 10, fare: 27 });
    const tripId = trip.data.trip.trip_id;
    await f.database.dbRun('DELETE FROM trip_additional_charges WHERE trip_id=$1', [tripId]);
    await f.database.dbRun(`INSERT INTO performance_reports(driver_id,report_date,total_trips)
      VALUES ('driver-1', CURRENT_DATE - 1, 7)`);
    await f.initializer.initializeDatabase();
    await f.initializer.initializeDatabase();
    const charges = await f.database.dbAll('SELECT * FROM trip_additional_charges WHERE trip_id=$1', [tripId]);
    assert.equal(charges.length, 1);
    assert.equal(charges[0].label, 'Baggage');
    assert.equal(charges[0].intent_confirmed, null);
    assert.equal(charges[0].source, 'legacy_booking');
    assert.equal((await f.database.dbGet("SELECT total_trips FROM performance_reports WHERE report_scope='daily'")).total_trips, 7);
  });
});
