const crypto = require('crypto');

const PAYMONGO_API_BASE = 'https://api.paymongo.com';

function getSecretKey() {
  return process.env.PAYMONGO_SECRET_KEY || process.env.PAYMONGO_SK || '';
}

function getPublicBaseUrl() {
  return (
    process.env.TODAGO_PUBLIC_URL ||
    process.env.PUBLIC_BASE_URL ||
    process.env.APP_BASE_URL ||
    'https://todago-backend-production.up.railway.app'
  ).replace(/\/+$/, '');
}

function toCentavos(amount) {
  const parsed = Number.parseFloat(amount);
  if (!Number.isFinite(parsed) || parsed <= 0) return 0;
  return Math.round(parsed * 100);
}

function paymongoMethodTypes(paymentMethod) {
  switch ((paymentMethod || '').toString().toLowerCase()) {
    case 'gcash':
      return ['gcash'];
    case 'maya':
      return ['paymaya'];
    case 'wallet':
    case 'todago_payment':
      return ['gcash', 'paymaya', 'qrph'];
    default:
      return ['gcash', 'paymaya', 'qrph'];
  }
}

async function createCheckoutSession({
  tripId,
  amount,
  paymentMethod,
  passengerName,
  passengerPhone,
  description,
}) {
  const secretKey = getSecretKey();
  if (!secretKey) {
    const error = new Error('PAYMONGO_SECRET_KEY is not configured');
    error.statusCode = 503;
    throw error;
  }

  const amountInCentavos = toCentavos(amount);
  if (amountInCentavos < 100) {
    const error = new Error('Payment amount must be at least PHP 1.00');
    error.statusCode = 422;
    throw error;
  }

  const publicBaseUrl = getPublicBaseUrl();
  const billing = {
    name: passengerName || 'TodaGo Passenger',
  };
  if (passengerPhone) billing.phone = passengerPhone;

  const body = {
    data: {
      attributes: {
        line_items: [
          {
            name: 'TodaGo ride fare',
            amount: amountInCentavos,
            currency: 'PHP',
            quantity: 1,
            description: description || `Trip ${tripId}`,
          },
        ],
        payment_method_types: paymongoMethodTypes(paymentMethod),
        success_url: `${publicBaseUrl}/api/trips/paymongo/return?tripId=${encodeURIComponent(tripId)}&status=success`,
        cancel_url: `${publicBaseUrl}/api/trips/paymongo/return?tripId=${encodeURIComponent(tripId)}&status=cancelled`,
        reference_number: tripId,
        send_email_receipt: false,
        show_description: true,
        show_line_items: true,
        description: description || `TodaGo trip ${tripId}`,
        metadata: {
          app: 'todago',
          trip_id: tripId,
          payment_method: paymentMethod || 'wallet',
        },
        billing,
      },
    },
  };

  const response = await fetch(`${PAYMONGO_API_BASE}/v2/checkout_sessions`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${Buffer.from(`${secretKey}:`).toString('base64')}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'Idempotency-Key': `todago-trip-${tripId}-${paymentMethod || 'wallet'}`,
    },
    body: JSON.stringify(body),
  });
  const json = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail =
      json?.errors?.[0]?.detail ||
      json?.errors?.[0]?.message ||
      json?.message ||
      'Unable to create PayMongo checkout session';
    const error = new Error(detail);
    error.statusCode = response.status;
    error.response = json;
    throw error;
  }
  return json.data;
}

function verifyWebhookSignature({ rawBody, signatureHeader, livemode }) {
  const secret = process.env.PAYMONGO_WEBHOOK_SECRET;
  if (!secret) return true;
  if (!rawBody || !signatureHeader) return false;

  const parts = {};
  for (const segment of signatureHeader.split(',')) {
    const [key, ...rest] = segment.trim().split('=');
    if (key) parts[key] = rest.join('=');
  }

  const timestamp = parts.t;
  const expected = livemode ? parts.li : parts.te;
  if (!timestamp || !expected) return false;

  const payload = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : String(rawBody);
  const signedPayload = `${timestamp}.${payload}`;
  const digest = crypto
    .createHmac('sha256', secret)
    .update(signedPayload)
    .digest('hex');

  try {
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(expected));
  } catch {
    return false;
  }
}

module.exports = {
  createCheckoutSession,
  paymongoMethodTypes,
  verifyWebhookSignature,
};
