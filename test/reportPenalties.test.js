const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const jwt = require('jsonwebtoken');

function loadWith(filename, stubs) {
  const file = path.join(__dirname, '..', filename), module = { exports: {} };
  const actualRequire = createRequire(file);
  vm.runInNewContext(fs.readFileSync(file, 'utf8'), {
    module, exports: module.exports,
    require: name => Object.hasOwn(stubs, name) ? stubs[name] : actualRequire(name),
    process, console, Buffer, Date,
  }, { filename: file });
  return module.exports;
}

// Test the real Express middleware, report service, and ride routes together.
// Only database I/O and unrelated payment/KYC integrations are replaced.
async function fixture(t) {
  const state = { now: Date.parse('2026-11-05T00:00:00Z'), reports: new Map(), trips: new Map(), writes: 0 };
  const driver = { driver_id: 'driver-1', driver_name: 'Driver One', status: 'online', is_verified: true, is_active: true };
  const passenger = { id: 'passenger-1', full_name: 'Passenger One', is_active: true };
  const active = (roles, id) => [...state.reports.values()].filter(r => roles.includes(r.subject_role)
    && r.subject_id === id && ['validated', 'resolved'].includes(r.status)
    && Date.parse(r.restriction_until) > state.now)
    .sort((a, b) => Date.parse(b.restriction_until) - Date.parse(a.restriction_until));
  const database = {
    async dbGet(raw, args = []) {
      const sql = raw.replace(/\s+/g, ' ').trim();
      if (sql.startsWith('UPDATE issue_reports')) {
        const [status, notes, id, minutes, severity] = args;
        const r = state.reports.get(id);
        // COALESCE models PostgreSQL's atomic preservation of an existing timer.
        r.status = status; r.admin_notes = notes;
        if (minutes != null) {
          r.penalty_minutes ??= minutes;
          r.penalty_severity ??= severity;
          r.restriction_until ??= new Date(state.now + minutes * 60000).toISOString();
        }
        state.writes++;
        return { ...r };
      }
      if (sql.includes('FROM issue_reports') && sql.includes('subject_role = ANY')) {
        const r = active(args[0], args[1])[0];
        return r ? { ...r, remaining_seconds: Math.ceil((Date.parse(r.restriction_until) - state.now) / 1000) } : null;
      }
      if (sql.includes('FROM issue_reports')) return state.reports.get(args[0]) || null;
      if (sql.includes('FROM passenger_blacklist')) return null;
      if (sql.includes('FROM drivers')) return { ...driver, name: driver.driver_name };
      if (sql.includes('FROM users')) return { ...passenger, name: passenger.full_name };
      if (sql.includes('FROM trips')) return state.trips.get(args[0]) || null;
      throw new Error(`Unexpected test query: ${sql}`);
    },
    async dbAll(raw, args = []) {
      const sql = raw.replace(/\s+/g, ' ').trim();
      if (sql.includes('FROM drivers d')) {
        const excluded = sql.includes('ir.restriction_until > NOW()') && active(['driver'], driver.driver_id).length;
        return excluded ? [] : [{ ...driver }];
      }
      if (sql.includes('FROM issue_reports ir')) return [...state.reports.values()]
        .filter(r => !args.length || r.status === args[0]);
      throw new Error(`Unexpected test query: ${sql}`);
    },
    async dbRun(raw, args = []) {
      const sql = raw.replace(/\s+/g, ' ').trim();
      state.writes++;
      if (sql.startsWith('INSERT INTO issue_reports')) {
        const [id, role, reporterId, name, type, subjectRole, subjectId, subjectName, tripId, title, details] = args;
        state.reports.set(id, { issue_id: id, reporter_role: role, reporter_id: reporterId, reporter_name: name,
          report_type: type, subject_role: subjectRole, subject_id: subjectId, subject_name: subjectName,
          trip_id: tripId, title, details, status: 'pending' });
      } else if (sql.startsWith('INSERT INTO trips')) {
        state.trips.set(args[0], { trip_id: args[0], commuter_id: args[1], driver_id: args[3], status: args[23] });
      } else if (sql.startsWith('UPDATE trips')) {
        const id = sql.includes("status = 'accepted'") ? args[0] : args[1];
        const trip = state.trips.get(id);
        if (trip) trip.status = sql.includes("status = 'accepted'") ? 'accepted' : args[0];
      }
      return { rowCount: 1 };
    },
  };
  const penalties = loadWith('src/services/reportPenalties.js', { '../db/database': database });
  const reports = loadWith('src/utils/adminReports.js', { '../db/database': database });
  const stubs = { '../db/database': database, '../services/reportPenalties': penalties,
    '../utils/adminReports': reports, '../utils/routeAnalytics': {}, '../utils/peakHourAnalytics': {},
    '../services/driverWallet': {}, '../services/paymongo': {}, '../services/walletLedger': {},
    '../services/walletPayments': {}, '../services/walletIntentPayments': {},
    '../utils/password': {},
    '../services/tripPayments': { completePaidTrip: async () => ({ gross_fare: 60 }) }, './kyc': {} };
  const routers = {
    reports: loadWith('src/routes/reports.js', stubs),
    admin: loadWith('src/routes/admin_auth.js', stubs),
    trips: loadWith('src/routes/trips.js', stubs),
    driver: loadWith('src/routes/driver_auth.js', stubs),
  };
  const originalSecret = process.env.JWT_SECRET;
  process.env.JWT_SECRET = 'report-tests-only';
  t.after(() => { if (originalSecret == null) delete process.env.JWT_SECRET; else process.env.JWT_SECRET = originalSecret; });
  async function request(method, url, role = 'admin', body, id) {
    const token = jwt.sign({ sub: id || (role === 'admin' ? 'admin-1' : `${role}-1`), role }, process.env.JWT_SECRET,
      { issuer: 'todago-api', audience: 'todago-app', expiresIn: '1h' });
    // Invoke every route middleware in order, without requiring network access.
    const parsed = new URL(url, 'http://test.local');
    const [, prefix, ...segments] = parsed.pathname.split('/');
    let params;
    const route = routers[prefix].stack.find(layer => {
      if (!layer.route?.methods[method.toLowerCase()]) return false;
      const parts = layer.route.path.split('/').filter(Boolean);
      if (parts.length !== segments.length) return false;
      const matched = {};
      if (!parts.every((part, i) => part.startsWith(':') ? (matched[part.slice(1)] = segments[i], true) : part === segments[i])) return false;
      params = matched;
      return true;
    })?.route;
    assert.ok(route, `${method} ${url}`);
    const req = { method, headers: { authorization: `Bearer ${token}` },
      body: body || {}, params, query: Object.fromEntries(parsed.searchParams) };
    let code = 200, data;
    const res = { status(value) { code = value; return res; }, json(value) { data = value; return res; } };
    for (const layer of route.stack) {
      await layer.handle(req, res, error => { if (error) throw error; });
      if (data !== undefined) break;
    }
    return { code, data };
  }
  function addReport(id, target, overrides = {}) {
    state.reports.set(id, { issue_id: id, reporter_role: target === 'driver' ? 'passenger' : 'driver',
      reporter_id: target === 'driver' ? passenger.id : driver.driver_id,
      subject_role: target, subject_id: target === 'driver' ? driver.driver_id : passenger.id,
      title: 'Incident', report_type: target === 'driver' ? 'driver_behavior' : 'passenger_issue',
      status: 'pending', ...overrides });
  }
  const book = { driverId: driver.driver_id, pickupLocation: 'Panabo', destination: 'Carmen', fare: 60, paymentMethod: 'cash' };
  return { state, request, addReport, penalties, book };
}

test('trip reports reach the admin queue pending, linked to the actual reported account', async t => {
  const f = await fixture(t);
  f.state.trips.set('trip-1', { commuter_id: 'passenger-1', driver_id: 'driver-1' });
  const report = await f.request('POST', '/reports', 'passenger', {
    reportType: 'driver_behavior', title: 'Unsafe driving', tripId: 'trip-1', subjectId: 'wrong-driver',
  });
  assert.equal(report.code, 201);
  assert.equal(report.data.report.status, 'pending');
  assert.equal(report.data.report.subject_id, 'driver-1');
  const queue = await f.request('GET', '/admin/reports');
  assert.equal(queue.code, 200);
  assert.equal(queue.data.reports[0].issue_id, report.data.report.issue_id);
  assert.equal(await f.penalties.getRideRestriction('driver', 'driver-1'), null);
  assert.equal((await f.request('GET', '/admin/reports', 'passenger')).code, 403);
  assert.equal((await f.request('PATCH', `/admin/reports/${report.data.report.issue_id}/status`, 'driver', { status: 'validated' })).code, 403);
  assert.equal((await f.request('POST', '/reports', 'driver', {
    reportType: 'passenger_issue', title: 'Other trip', tripId: 'trip-1',
  }, 'different-driver')).code, 403);
});

for (const [severity, minutes] of [['standard', 30], ['severe', 60]]) {
  test(`validated passenger report blocks instant and scheduled bookings for ${minutes} minutes`, async t => {
    const f = await fixture(t);
    f.addReport('passenger-report', 'passenger');
    const result = await f.request('PATCH', '/admin/reports/passenger-report/status', 'admin', {
      status: 'validated', penaltySeverity: severity, adminNotes: 'Reviewed incident',
    });
    assert.equal(result.code, 200);
    assert.equal(result.data.report.penalty_minutes, minutes);
    assert.equal(Date.parse(result.data.report.restriction_until) - f.state.now, minutes * 60000);
    assert.equal(result.data.report.admin_notes, 'Reviewed incident');
    for (const body of [f.book, { ...f.book, scheduledPickupAt: '2099-01-01T00:00:00Z' }]) {
      const response = await f.request('POST', '/trips/request', 'passenger', body);
      assert.equal(response.code, 403);
      assert.equal(response.data.code, 'PASSENGER_BOOKING_COOLDOWN');
      assert.equal(response.data.retryAfterSeconds, minutes * 60);
    }
    assert.equal(await f.penalties.getRideRestriction('passenger', 'different-passenger'), null);
    f.state.now += minutes * 60000 - 1;
    assert.ok(await f.penalties.getRideRestriction('passenger', 'passenger-1'));
    f.state.now++;
    assert.equal((await f.request('POST', '/trips/request', 'passenger', f.book)).code, 201);
  });
}

for (const [severity, days] of [['standard', 1], ['severe', 2]]) {
  test(`validated driver report blocks availability, bookings and acceptance for ${days} day(s)`, async t => {
    const f = await fixture(t);
    f.addReport('driver-report', 'driver');
    f.state.trips.set('request-1', { trip_id: 'request-1', driver_id: 'driver-1', commuter_id: 'passenger-1', status: 'requested' });
    const decision = await f.request('PATCH', '/admin/reports/driver-report/status', 'admin', { status: 'validated', penaltySeverity: severity });
    assert.equal(decision.data.report.penalty_minutes, days * 1440);
    assert.equal((await f.request('GET', '/trips/drivers/online', 'passenger')).data.total, 0);
    assert.equal((await f.request('POST', '/trips/request', 'passenger', f.book)).code, 403);
    for (const [method, url, body] of [
      ['PUT', '/driver/status', { status: 'online' }], ['GET', '/trips/driver/pending'],
      ['PUT', '/trips/request-1/accept'], ['PUT', '/trips/request-1/status', { status: 'pickup' }],
    ]) {
      const response = await f.request(method, url, 'driver', body);
      assert.equal(response.code, 403, url);
      assert.equal(response.data.code, 'DRIVER_RIDE_SUSPENDED');
    }
    assert.equal((await f.request('PUT', '/driver/status', 'driver', { status: 'offline' })).code, 200);
    const profile = await f.request('GET', '/driver/me', 'driver');
    assert.equal(profile.data.driver.ride_restriction.code, 'DRIVER_RIDE_SUSPENDED');
    f.state.trips.set('accepted-1', { trip_id: 'accepted-1', driver_id: 'driver-1', status: 'accepted' });
    assert.equal((await f.request('PUT', '/trips/accepted-1/status', 'driver', { status: 'ongoing' })).code, 200);
    f.state.now += days * 86400000;
    assert.equal((await f.request('GET', '/trips/drivers/online', 'passenger')).data.total, 1);
    assert.equal((await f.request('PUT', '/driver/status', 'driver', { status: 'online' })).code, 200);
    assert.equal((await f.request('PUT', '/trips/request-1/accept', 'driver')).code, 200);
  });
}

test('repeat and concurrent validations preserve the timer; separate incidents use the latest expiry', async t => {
  const f = await fixture(t);
  f.addReport('first', 'driver');
  const review = severity => f.request('PATCH', '/admin/reports/first/status', 'admin', { status: 'validated', penaltySeverity: severity });
  const first = await review('standard');
  f.state.now += 3600000;
  await Promise.all([review('standard'), review('severe')]);
  assert.equal(f.state.reports.get('first').restriction_until, first.data.report.restriction_until);
  f.addReport('second', 'driver');
  const second = await f.request('PATCH', '/admin/reports/second/status', 'admin', { status: 'validated', penaltySeverity: 'severe' });
  assert.equal((await f.penalties.getRideRestriction('driver', 'driver-1')).restriction_until, second.data.report.restriction_until);
  f.state.now += 3 * 86400000;
  await review('severe');
  assert.equal(await f.penalties.getRideRestriction('driver', 'driver-1'), null);
});

test('rejecting applies no penalty, resolution preserves an active penalty, and invalid decisions fail', async t => {
  const f = await fixture(t);
  f.addReport('incident', 'passenger');
  await f.request('PATCH', '/admin/reports/incident/status', 'admin', { status: 'rejected' });
  assert.equal(await f.penalties.getRideRestriction('passenger', 'passenger-1'), null);
  const invalid = await f.request('PATCH', '/admin/reports/incident/status', 'admin', { status: 'validated', penaltySeverity: 'arbitrary' });
  assert.equal(invalid.code, 422);
  assert.equal(f.state.reports.get('incident').status, 'rejected');
  await f.request('PATCH', '/admin/reports/incident/status', 'admin', { status: 'validated' });
  await f.request('PATCH', '/admin/reports/incident/status', 'admin', { status: 'resolved' });
  assert.ok(await f.penalties.getRideRestriction('passenger', 'passenger-1'));
  await f.request('PATCH', '/admin/reports/incident/status', 'admin', { status: 'rejected' });
  assert.equal(await f.penalties.getRideRestriction('passenger', 'passenger-1'), null);
  f.addReport('unlinked', 'driver', { subject_id: null });
  assert.equal((await f.request('PATCH', '/admin/reports/unlinked/status', 'admin', { status: 'validated' })).code, 422);
  assert.equal(f.state.reports.get('unlinked').status, 'pending');
  f.addReport('system-alert', 'driver', { reporter_role: 'system' });
  const alert = await f.request('PATCH', '/admin/reports/system-alert/status', 'admin', { status: 'validated', penaltySeverity: 'severe' });
  assert.equal(alert.data.report.restriction_until, undefined);
  assert.equal((await f.request('PATCH', '/admin/reports/missing/status', 'admin', { status: 'validated' })).code, 404);
});
