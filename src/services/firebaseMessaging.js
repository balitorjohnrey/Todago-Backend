const jwt = require('jsonwebtoken');
const { createHash, createPrivateKey } = require('node:crypto');

const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const CHANNEL_ID = 'todago_updates';

function createFirebaseSender(raw, request = fetch) {
  const credentials = JSON.parse(raw);
  if (!credentials.project_id || !credentials.client_email || !credentials.private_key) {
    throw new Error('Missing project ID, client email or private key');
  }
  const key = createPrivateKey(credentials.private_key);
  const sendUrl = `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(credentials.project_id)}/messages:send`;
  let accessToken;
  let refresh;

  async function refreshAccessToken() {
    const assertion = jwt.sign({ scope: 'https://www.googleapis.com/auth/firebase.messaging' }, key, {
      algorithm: 'RS256',
      issuer: credentials.client_email,
      audience: TOKEN_URL,
      expiresIn: '1h',
    });
    const response = await request(TOKEN_URL, {
      method: 'POST',
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion,
      }),
      signal: AbortSignal.timeout(8000),
    });
    const data = await response.json();
    if (!response.ok || !data.access_token) throw new Error(`FCM OAuth HTTP ${response.status}`);
    accessToken = { value: data.access_token, expiresAt: Date.now() + Number(data.expires_in) * 1000 };
    return accessToken.value;
  }

  async function getAccessToken() {
    if (accessToken?.expiresAt > Date.now() + 60000) return accessToken.value;
    refresh ||= refreshAccessToken().finally(() => { refresh = null; });
    return refresh;
  }

  return async function send(delivery, notification) {
    const bearer = await getAccessToken();
    const expiresAt = new Date(delivery.expires_at).getTime();
    const ttlSeconds = Math.floor((expiresAt - Date.now()) / 1000);
    if (ttlSeconds <= 0) return 'expired';

    const response = await request(sendUrl, {
      method: 'POST',
      headers: { Authorization: `Bearer ${bearer}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: {
        token: delivery.token,
        notification,
        android: {
          priority: 'HIGH',
          ttl: `${ttlSeconds}s`,
          notification: {
            channel_id: CHANNEL_ID,
            tag: delivery.event_key,
            notification_priority: 'PRIORITY_HIGH',
            visibility: 'PRIVATE',
            default_sound: true,
          },
        },
        apns: {
          headers: {
            'apns-push-type': 'alert',
            'apns-priority': '10',
            'apns-expiration': String(Math.floor(expiresAt / 1000)),
            'apns-collapse-id': createHash('sha256').update(delivery.event_key).digest('hex'),
          },
          payload: { aps: { sound: 'default' } },
        },
      } }),
      signal: AbortSignal.timeout(8000),
    });
    const data = await response.json().catch(() => null);
    if (response.ok) return 'sent';
    if (data?.error?.details?.some(detail => detail.errorCode === 'UNREGISTERED')) return 'unregistered';
    if (response.status === 401 && accessToken?.value === bearer) accessToken = null;

    const error = new Error(`FCM send HTTP ${response.status}`);
    const retryAfter = response.headers.get('Retry-After');
    if (retryAfter) {
      error.retrySeconds = /^\d+$/.test(retryAfter)
        ? Number(retryAfter) : Math.ceil((Date.parse(retryAfter) - Date.now()) / 1000);
    }
    if (response.status === 429) error.retrySeconds = Math.max(error.retrySeconds || 0, 60);
    throw error;
  };
}

module.exports = { createFirebaseSender };
