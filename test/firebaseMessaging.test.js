const test = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync } = require('node:crypto');
const jwt = require('jsonwebtoken');
const { createFirebaseSender } = require('../src/services/firebaseMessaging');

test('FCM sends visible Android and Apple notifications with a bounded lifetime', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const email = 'sender@example.invalid';
  const credentials = JSON.stringify({
    project_id: 'todago-test',
    client_email: email,
    private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  });
  let authRequests = 0;
  const messages = [];
  const send = createFirebaseSender(credentials, async (url, options) => {
    if (url === 'https://oauth2.googleapis.com/token') {
      authRequests++;
      const verified = jwt.verify(options.body.get('assertion'), publicKey, {
        issuer: email, audience: url, algorithms: ['RS256'],
      });
      assert.equal(verified.scope, 'https://www.googleapis.com/auth/firebase.messaging');
      return Response.json({ access_token: 'test-access-token', expires_in: 3600 });
    }
    assert.equal(url, 'https://fcm.googleapis.com/v1/projects/todago-test/messages:send');
    assert.equal(options.headers.Authorization, 'Bearer test-access-token');
    const { message } = JSON.parse(options.body);
    messages.push(message);
    return message.token === 'expired-device'
      ? Response.json({ error: { details: [{ errorCode: 'UNREGISTERED' }] } }, { status: 404 })
      : Response.json({ name: 'projects/todago-test/messages/test' });
  });

  const expiresAt = new Date(Date.now() + 90000);
  const job = { token: 'active-device', event_key: 'driver_near_pickup:trip-1', expires_at: expiresAt };
  const alert = { title: 'Your driver is nearby', body: 'Get ready and head to your pickup point.' };
  const outcomes = await Promise.all([send(job, alert), send({ ...job, token: 'expired-device' }, alert)]);
  assert.deepEqual(outcomes, ['sent', 'unregistered']);
  assert.equal(authRequests, 1);
  const [message] = messages;
  assert.deepEqual(message.notification, alert);
  assert.equal(message.android.priority, 'HIGH');
  assert.equal(message.android.notification.channel_id, 'todago_updates');
  assert.equal(message.android.notification.tag, job.event_key);
  assert.match(message.android.ttl, /^(8\d|90)s$/);
  assert.equal(message.apns.headers['apns-push-type'], 'alert');
  assert.equal(message.apns.headers['apns-expiration'], String(Math.floor(expiresAt.getTime() / 1000)));
});
