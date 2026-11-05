const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const jwt = require('jsonwebtoken');

const secret = 'isolated-kyc-status-test-secret';

function fixture(account) {
  const filename = path.join(__dirname, '../src/routes/kyc.js');
  const actualRequire = createRequire(filename);
  const routes = new Map();
  const router = {
    get: (url, ...handlers) => routes.set(url, handlers),
    post() {},
  };
  const module = { exports: {} };
  vm.runInNewContext(fs.readFileSync(filename, 'utf8'), {
    module, exports: module.exports, console, Buffer, Date,
    process: { env: { JWT_SECRET: secret } },
    require: name => {
      if (name === 'express') return { Router: () => router };
      if (name === '../db/database') return {
        dbGet: async (_sql, args) => args[0] === 'account-1' ? account : null,
        dbRun: async () => {},
      };
      return actualRequire(name);
    },
  }, { filename });
  const kyc = {
    provider: 'didit', referenceId: 'driver:account-1', sessionId: 'session-1',
    verificationUrl: 'https://verify.didit.me/session-1',
    callbackUrl: 'todago://kyc-complete',
  };
  const payload = module.exports.publicKycPayload(kyc);
  async function request(token = payload.statusToken, url = '/session/status') {
    const req = { headers: token ? { authorization: `Bearer ${token}` } : {} };
    const res = {
      statusCode: 200, headers: {},
      set(key, value) { this.headers[key] = value; return this; },
      status(value) { this.statusCode = value; return this; },
      json(body) { this.body = body; return this; },
    };
    await routes.get(url)[0](req, res, () => {});
    return res;
  }
  return { request, payload };
}

const pending = {
  identity_provider: 'didit', didit_session_id: 'session-1',
  identity_verification_status: 'pending', identity_is_verified: false,
};

test('pending accounts can only read their session status with a scoped token', async () => {
  const { payload, request } = fixture(pending);
  const claims = jwt.verify(payload.statusToken, secret, { audience: 'todago-kyc-status' });
  assert.equal(claims.sub, 'account-1');
  assert.equal(claims.sessionId, 'session-1');
  assert.equal(claims.exp - claims.iat, 7200);
  assert.equal(payload.callbackUrl, 'todago://kyc-complete');
  const res = await request();
  assert.equal(res.statusCode, 200);
  assert.equal(res.headers['Cache-Control'], 'no-store');
  assert.equal(res.body.identity.isVerified, false);
  assert.equal(res.body.identity.status, 'pending');
});

test('success comes from the server-approved account', async () => {
  const { request } = fixture({ ...pending,
    identity_verification_status: 'approved', identity_is_verified: true });
  const res = await request();
  assert.equal(res.body.identity.isVerified, true);
  assert.equal(res.body.identity.status, 'approved');
});

test('missing, forged and expired status tokens are rejected', async () => {
  const { request } = fixture(pending);
  for (const token of [null, 'forged', jwt.sign({ sub: 'account-1' }, secret, {
    issuer: 'todago-api', audience: 'todago-kyc-status', expiresIn: -1,
  })]) {
    assert.equal((await request(token)).statusCode, 401);
  }
});

test('a login token cannot be used as a session status token', async () => {
  const { request } = fixture(pending);
  const login = jwt.sign({ sub: 'account-1', role: 'driver' }, secret, {
    issuer: 'todago-api', audience: 'todago-app',
  });
  assert.equal((await request(login)).statusCode, 401);
});

test('a status token cannot authorize authenticated app routes', async () => {
  const { request } = fixture(pending);
  assert.equal((await request(undefined, '/status')).statusCode, 401);
});

test('replaced sessions, mismatched providers and deleted accounts are rejected', async () => {
  for (const account of [null,
    { ...pending, didit_session_id: 'session-2' },
    { ...pending, identity_provider: 'persona' },
  ]) {
    assert.equal((await fixture(account).request()).statusCode, 404);
  }
});
