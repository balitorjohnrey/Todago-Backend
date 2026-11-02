const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const { amountInCentavos, MIN_TOP_UP, MIN_DRIVER_CASHOUT } = require('../src/services/paymentLimits');

function loadWith(filename, stubs) {
  const file = path.join(__dirname, '..', filename), module = { exports: {} };
  const actualRequire = createRequire(file);
  vm.runInNewContext(fs.readFileSync(file, 'utf8'), { module, exports: module.exports,
    require: name => Object.hasOwn(stubs, name) ? stubs[name] : actualRequire(name), process, console, Buffer, Date }, { filename: file });
  return module.exports;
}

// A transactional in-memory adapter exercises the service's public operations.
// The driver row lock serializes request creation, just as FOR UPDATE does in PG.
function fixture(earned = 100) {
  let queue = Promise.resolve();
  const rows = [];
  const queries = [];
  const pool = { connect: async () => {
    let unlock;
    return { release() { if (unlock) { unlock(); unlock = null; } },
      async query(sql, args = []) {
        queries.push(sql);
        if (sql.includes('FROM drivers') && sql.includes('FOR UPDATE')) {
          const previous = queue;
          queue = new Promise(resolve => { unlock = resolve; });
          await previous;
          return { rows: [{ driver_id: args[0], is_active: args[0] !== 'inactive' }] };
        }
        if (sql.includes('INSERT INTO driver_earnings')) {
          assert.match(sql, /tr.status = 'completed' AND tr.payment_status = 'paid'/);
          assert.match(sql, /wt.user_id = tr.commuter_id/);
          assert.match(sql, /wt.amount = tr.fare/);
          assert.match(sql, /ON CONFLICT \(trip_id\) DO NOTHING/);
          return { rows: [] };
        }
        if (sql.includes('AS earned')) return { rows: [{ earned,
          reserved: rows.filter(r => ['pending','processing'].includes(r.status)).reduce((sum,r) => sum + Number(r.amount), 0),
          paid: rows.filter(r => r.status === 'paid').reduce((sum,r) => sum + Number(r.amount), 0) }] };
        if (sql.includes('INSERT INTO driver_cashouts')) {
          const row = { cashout_id: `request-${rows.length}`, driver_id: args[0], amount: args[1], provider: args[2],
            account_name: args[3], account_number: args[4], request_key: args[5], status: 'pending' };
          rows.push(row); return { rows: [{ ...row }] };
        }
        if (sql.includes('SELECT cashout_id FROM')) return { rows: rows.filter(r => r.driver_id === args[0] && ['pending','processing'].includes(r.status)).slice(0,1) };
        if (sql.includes('SELECT * FROM driver_cashouts')) {
          const row = sql.includes('request_key =') ? rows.find(r => r.driver_id === args[0] && r.request_key === args[1])
            : rows.find(r => r.cashout_id === args[0] && (!sql.includes('AND driver_id =') || r.driver_id === args[1]));
          return { rows: row ? [{ ...row }] : [] };
        }
        if (sql.includes('UPDATE driver_cashouts')) {
          const row = rows.find(r => r.cashout_id === args[0]);
          const next = sql.includes("status = 'cancelled'") ? 'cancelled' : args[1];
          if (next === 'paid' && rows.some(r => r !== row && r.provider === row.provider && r.payment_reference === args[2])) {
            const error = new Error('unique reference'); error.code = '23505'; throw error;
          }
          row.status = next;
          if (next !== 'cancelled') { row.payment_reference = args[2]; row.review_note = args[3]; }
          return { rows: [{ ...row }] };
        }
        if (sql.includes('FROM driver_cashouts WHERE driver_id')) return { rows: rows.filter(r => r.driver_id === args[0]).map(r => ({ ...r })) };
        return { rows: [] };
      },
    };
  } };
  const service = loadWith('src/services/driverWallet.js', { '../db/database': { pool }, './paymongo': { isLiveMode: () => true } });
  return { service, rows, queries };
}

const firstKey = '37cd393c-679d-4c2a-80b1-b54733c342aa';
const secondKey = '37cd393c-679d-4c2a-80b1-b54733c342ab';
const request = { amount: 50, provider: 'gcash', accountName: 'Test Driver', accountNumber: '09123456789', requestKey: firstKey };

test('payment minimums use exact cents and reject invalid numeric input', () => {
  assert.equal(amountInCentavos(20, MIN_TOP_UP), 2000);
  assert.equal(amountInCentavos('50.25', MIN_DRIVER_CASHOUT), 5025);
  for (const value of [19.99, -20, NaN, Infinity, '20x', '20.001', true, {}, 50001]) assert.equal(amountInCentavos(value, MIN_TOP_UP), null);
  assert.equal(amountInCentavos(49.99, MIN_DRIVER_CASHOUT), null);
});

test('cash-outs reserve confirmed cashless earnings and identical retries do not reserve twice', async () => {
  const { service } = fixture();
  const row = await service.requestCashOut('driver-1', request);
  const retry = await service.requestCashOut('driver-1', request);
  assert.equal(row.cashout_id, retry.cashout_id);
  const wallet = await service.getDriverWallet('driver-1');
  assert.equal(wallet.available, 50);
  assert.equal(wallet.reserved, 50);
  assert.equal(wallet.fee, 0);
  assert.equal(wallet.requests.length, 1);
  await assert.rejects(service.requestCashOut('driver-1', { ...request, amount: 60 }), /different cash-out/);
});

test('insufficient earnings, under-minimum amounts and invalid destinations cannot create a request', async () => {
  const { service, rows } = fixture(40);
  await assert.rejects(service.requestCashOut('driver-1', request), /Insufficient/);
  await assert.rejects(service.requestCashOut('driver-1', { ...request, amount:49 }), /PHP 50/);
  await assert.rejects(service.requestCashOut('driver-1', { ...request, accountNumber:'bad' }), /valid GCash/);
  await assert.rejects(service.requestCashOut('inactive', request), /unavailable/);
  assert.equal(rows.length, 0);
});

test('simultaneous new requests serialize and cannot reserve the same earnings twice', async () => {
  const { service, rows } = fixture();
  const result = await Promise.allSettled([
    service.requestCashOut('driver-1', request),
    service.requestCashOut('driver-1', { ...request, requestKey: secondKey }),
  ]);
  assert.equal(result.filter(r => r.status === 'fulfilled').length, 1);
  assert.equal(rows.length, 1);
});

test('only the owner can cancel a pending request; cancellation releases the reserve', async () => {
  const { service } = fixture();
  const row = await service.requestCashOut('driver-1', request);
  await assert.rejects(service.cancelCashOut('other-driver', row.cashout_id), /not found/);
  await service.cancelCashOut('driver-1', row.cashout_id);
  assert.equal((await service.getDriverWallet('driver-1')).available, 100);
});

test('paid recording requires processing and a reference, remains idempotent and cannot be cancelled', async () => {
  const { service } = fixture();
  const row = await service.requestCashOut('driver-1', request);
  await assert.rejects(service.reviewCashOut(row.cashout_id, { action:'paid', reference:'123456789', adminId:'admin' }), /already changed/);
  await service.reviewCashOut(row.cashout_id, { action:'processing', adminId:'admin' });
  await assert.rejects(service.cancelCashOut('driver-1', row.cashout_id), /Only pending/);
  await assert.rejects(service.reviewCashOut(row.cashout_id, { action:'paid', reference:'', adminId:'admin' }), /actual e-wallet/);
  for (let i=0;i<2;i++) await service.reviewCashOut(row.cashout_id, { action:'paid', reference:'123456789', adminId:'admin' });
  const wallet = await service.getDriverWallet('driver-1');
  assert.equal(wallet.paid,50); assert.equal(wallet.reserved,0); assert.equal(wallet.available,50);
});

test('rejection releases the reserve and requires a reason', async () => {
  const { service } = fixture();
  const row = await service.requestCashOut('driver-1', request);
  await assert.rejects(service.reviewCashOut(row.cashout_id, { action:'rejected' }), /review note/);
  await service.reviewCashOut(row.cashout_id, { action:'rejected', note:'Wrong payout details', adminId:'admin' });
  assert.equal((await service.getDriverWallet('driver-1')).available,100);
});

test('duplicate transfer references cannot pay a second request, and an uncertain transfer stays reserved', async () => {
  const { service } = fixture(150);
  const first = await service.requestCashOut('driver-1', request);
  await service.reviewCashOut(first.cashout_id, { action:'processing', adminId:'payout-admin' });
  await service.reviewCashOut(first.cashout_id, { action:'paid', reference:'987654321', adminId:'payout-admin' });
  const second = await service.requestCashOut('driver-1', { ...request, requestKey: secondKey });
  await service.reviewCashOut(second.cashout_id, { action:'processing', adminId:'payout-admin' });
  await assert.rejects(service.reviewCashOut(second.cashout_id, { action:'paid', reference:'987654321' }), /already recorded/);
  await assert.rejects(service.reviewCashOut(second.cashout_id, { action:'rejected', note:'Unknown transfer result' }), /already changed/);
  assert.equal((await service.getDriverWallet('driver-1')).reserved,50);
  await service.reviewCashOut(second.cashout_id, { action:'rejected', note:'Confirmed no money sent', confirmedNotSent:true, adminId:'payout-admin' });
  assert.equal((await service.getDriverWallet('driver-1')).reserved,0);
});

test('simulated payment balances cannot request a real cash-out', async () => {
  let connected=false;
  const service=loadWith('src/services/driverWallet.js', {
    '../db/database': { pool: { connect:async()=>{connected=true;} } }, './paymongo': { isLiveMode:()=>false },
  });
  await assert.rejects(service.requestCashOut('driver-1',request),/test mode/);
  assert.equal(connected,false);
});

test('QR Ph is the only top-up method and the endpoint rejects less than PHP 20 before creating payments', async () => {
  let writes = 0;
  const router = loadWith('src/routes/wallet.js', {
    './auth': { requireAuth: (_req,_res,next) => next() },
    '../db/database': { dbRun: async () => writes++ },
    '../services/paymongo': { getAvailablePaymentMethods: async () => [{ id:'gcash' },{ id:'maya' },{ id:'qrph' }], isLiveMode:()=>true },
    '../services/walletLedger': {}, '../services/walletPayments': {}, '../services/walletIntentPayments': {},
  });
  let output, code;
  const res = { status: value => { code=value;return res; }, json: data => { output=data;return res; } };
  const methods=router.stack.find(layer=>layer.route?.path==='/payment-methods').route.stack.at(-1).handle;
  await methods({userRole:'passenger'},res);
  assert.deepEqual(Array.from(output.methods,m=>m.id),['qrph']);
  assert.equal(output.minimumTopUp,20);
  const topup=router.stack.find(layer=>layer.route?.path==='/top-up').route.stack.at(-1).handle;
  for (const body of [{provider:'gcash',amount:100},{provider:'qrph',amount:19.99}]) {
    await topup({userRole:'passenger',body},res);assert.equal(code,422);
  }
  assert.equal(writes,0);
});

test('payout login uses a separate role and secret, denied access to the main admin dashboard', async () => {
  const jwt = require('jsonwebtoken');
  const saved = { JWT_SECRET:process.env.JWT_SECRET, PAYOUT_ADMIN_SECRET:process.env.PAYOUT_ADMIN_SECRET };
  process.env.JWT_SECRET = 'unit-test-jwt';
  process.env.PAYOUT_ADMIN_SECRET = 'unit-test-payout-secret';
  try {
    const queries=[];
    const router=loadWith('src/routes/admin_auth.js', {
      '../db/database': {dbAll:async sql=>{queries.push(sql);return [];}}, '../utils/routeAnalytics': {}, '../utils/peakHourAnalytics': {}, '../services/driverWallet': {},
    });
    const route=router.stack.find(layer=>layer.route?.path==='/driver-cashouts').route;
    const res={status(value){this.code=value;return this;},json(data){this.data=data;return this;}};
    let next=false;
    route.stack[0].handle({headers:{}},res,()=>{next=true;});assert.equal(res.code,401);assert.equal(next,false);
    const token=role=>jwt.sign({sub:'test',role},process.env.JWT_SECRET,{issuer:'todago-api',audience:'todago-app'});
    for(const role of ['driver','passenger','admin']){
      route.stack[0].handle({headers:{authorization:'Bearer '+token(role)}},res,()=>{});assert.equal(res.code,403);
    }
    const login=router.stack.find(layer=>layer.route?.path==='/login').route.stack.at(-1).handle;
    await login({body:{secret:'unit-test-payout-secret'}},res);
    assert.equal(res.data.admin.role,'payout_admin');
    const payoutToken=res.data.token;
    assert.equal(jwt.verify(payoutToken,process.env.JWT_SECRET).role,'payout_admin');
    const req={headers:{authorization:'Bearer '+payoutToken},query:{}};
    route.stack[0].handle(req,res,()=>{next=true;});assert.equal(next,true);
    await route.stack.at(-1).handle(req,res);assert.match(queries.at(-1),/co.status IN \('pending','processing'\)/);
    await route.stack.at(-1).handle({...req,query:{view:'history'}},res);assert.match(queries.at(-1),/co.status IN \('paid','rejected','cancelled'\)/);
    const stats=router.stack.find(layer=>layer.route?.path==='/stats').route;
    stats.stack[0].handle(req,res,()=>{});assert.equal(res.code,403);
    process.env.PAYOUT_ADMIN_SECRET='rotated-test-secret';
    route.stack[0].handle(req,res,()=>{});assert.equal(res.code,401);
    delete process.env.PAYOUT_ADMIN_SECRET;
    await login({body:{secret:'unit-test-payout-secret'}},res);assert.equal(res.code,401);
  } finally {
    for(const [key,value] of Object.entries(saved)){if(value===undefined)delete process.env[key];else process.env[key]=value;}
  }
});
