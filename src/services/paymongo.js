const crypto = require('crypto');

const PAYMONGO_API_BASE = 'https://api.paymongo.com';
let capabilitiesCache;

const PAYMENT_METHOD_LABELS = {
  gcash: 'GCash', paymaya: 'Maya', qrph: 'QR Ph', grab_pay: 'GrabPay',
  shopeepay: 'ShopeePay', card: 'Credit / debit card', dob: 'Online banking',
  dob_ubp: 'UnionBank', dob_bpi: 'BPI', brankas_bdo: 'BDO',
  brankas_landbank: 'Landbank', brankas_metrobank: 'Metrobank',
};

function isLiveMode() {
  return getSecretKey().startsWith('sk_live_');
}

async function paymongoRequest(path, { method = 'GET', body, idempotencyKey } = {}) {
  const secretKey = getSecretKey();
  if (!secretKey) {
    const error = new Error('PayMongo payments are not configured. Please try again later.');
    error.statusCode = 503;
    throw error;
  }
  const response = await fetch(`${PAYMONGO_API_BASE}${path}`, {
    method,
    headers: {
      Authorization: `Basic ${Buffer.from(`${secretKey}:`).toString('base64')}`,
      'Content-Type': 'application/json', Accept: 'application/json',
      ...(idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(15000),
  });
  const json = await response.json();
  if (!response.ok) {
    const error = new Error(json?.errors?.[0]?.detail || 'PayMongo could not process this request.');
    error.statusCode = response.status;
    throw error;
  }
  return json;
}

function normalizeCapabilities(json) {
  const data = json?.data ?? json;
  const methods = Array.isArray(data) ? data :
    data?.attributes?.payment_methods ?? data?.payment_methods ??
    data?.attributes?.payment_method_types ?? data?.payment_method_types;
  if (!Array.isArray(methods)) {
    throw new Error('Unable to read the payment methods available for this account.');
  }
  return [...new Set(methods.filter((item) =>
    typeof item === 'string' || !item?.status || ['active', 'enabled', 'configured'].includes(item.status)
  ).map((item) => typeof item === 'string' ? item : item.id || item.type || item.payment_method))]
    .filter((id) => typeof id === 'string' &&
      (PAYMENT_METHOD_LABELS[id] || /^(dob_|brankas_)[a-z0-9_]+$/.test(id)));
}

async function getAvailablePaymentMethods() {
  const cacheKey = getSecretKey();
  if (!capabilitiesCache || capabilitiesCache.key !== cacheKey || capabilitiesCache.until < Date.now()) {
    const json = await paymongoRequest('/v1/merchants/capabilities/payment_methods');
    capabilitiesCache = { key: cacheKey, until: Date.now() + 60000, methods: normalizeCapabilities(json) };
  }
  return capabilitiesCache.methods.map((type) => ({
    id: type === 'paymaya' ? 'maya' : type,
    type,
    label: PAYMENT_METHOD_LABELS[type] || type.replace(/_/g, ' ').toUpperCase(),
  }));
}

async function retrieveCheckoutSession(id) {
  if (!/^cs_[a-zA-Z0-9_-]+$/.test(id || '')) throw new Error('Invalid checkout session');
  return (await paymongoRequest(`/v1/checkout_sessions/${encodeURIComponent(id)}`)).data;
}

async function createWalletPaymentIntent({ transactionId, userId, amount, methodType }) {
  if (!['gcash', 'paymaya', 'qrph'].includes(methodType)) throw new Error('Unsupported wallet payment');
  const available = await getAvailablePaymentMethods();
  if (!available.some((method) => method.type === methodType)) {
    const error = new Error('This payment method is not available yet. Please choose another method.');
    error.statusCode = 422;
    throw error;
  }
  const centavos = toCentavos(amount);
  if (!Number.isSafeInteger(centavos) || centavos < 100) throw new Error('Invalid payment amount');
  return (await paymongoRequest('/v1/payment_intents', {
    method: 'POST', idempotencyKey: `todago-intent-${transactionId}`,
    body: { data: { attributes: {
      amount: centavos, currency: 'PHP', payment_method_allowed: [methodType],
      description: 'TodaGo wallet top-up',
      metadata: { payment_type: 'wallet_topup', wallet_transaction_id: transactionId, user_id: userId },
    } } },
  })).data;
}

async function attachWalletPaymentMethod({ intentId, methodType, name, phone, transactionId }) {
  if (!/^pi_[a-zA-Z0-9_-]+$/.test(intentId || '')) throw new Error('Invalid payment intent');
  if (!['gcash', 'paymaya', 'qrph'].includes(methodType)) throw new Error('Unsupported wallet payment');
  const method = (await paymongoRequest('/v1/payment_methods', {
    method: 'POST', idempotencyKey: `todago-method-${transactionId}`,
    body: { data: { attributes: { type: methodType,
      billing: { name: name || 'TodaGo Passenger', ...(phone ? { phone } : {}) },
    } } },
  })).data;
  return (await paymongoRequest(`/v1/payment_intents/${encodeURIComponent(intentId)}/attach`, {
    method: 'POST', idempotencyKey: `todago-attach-${transactionId}`,
    body: { data: { attributes: { payment_method: method.id,
      return_url: `${getPublicBaseUrl()}/api/wallet/paymongo/return?transactionId=${encodeURIComponent(transactionId)}&status=success`,
    } } },
  })).data;
}

async function retrievePaymentIntent(id) {
  if (!/^pi_[a-zA-Z0-9_-]+$/.test(id || '')) throw new Error('Invalid payment intent');
  return (await paymongoRequest(`/v1/payment_intents/${encodeURIComponent(id)}`)).data;
}

function getPaidPayment(session) {
  const attrs = session?.attributes || {};
  const payments = [...(attrs.payments || []), ...(attrs.payment_intent?.attributes?.payments || [])];
  return payments.find((payment) => (payment.attributes || payment).status === 'paid') || null;
}

function getSecretKey() {
  return (process.env.PAYMONGO_SECRET_KEY || process.env.PAYMONGO_SK || '').trim();
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
  referenceId,
  amount,
  paymentMethod,
  passengerName,
  passengerPhone,
  description,
  successUrl,
  cancelUrl,
  metadata = {},
  lineItemName,
  idempotencyKey,
  paymentMethodTypes,
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
  const available = await getAvailablePaymentMethods();
  const requested = paymentMethodTypes || paymongoMethodTypes(paymentMethod);
  const methodTypes = [...new Set(requested)].filter((type) => available.some((item) => item.type === type));
  if (!methodTypes.length) {
    const error = new Error('This payment method is not available on TodaGo right now. Please choose another method.');
    error.statusCode = 422;
    throw error;
  }
  const referenceNumber = referenceId || tripId;
  const billing = {
    name: passengerName || 'TodaGo Passenger',
  };
  if (passengerPhone) billing.phone = passengerPhone;

  const body = {
    data: {
      attributes: {
        line_items: [
          {
            name: lineItemName || 'TodaGo ride fare',
            amount: amountInCentavos,
            currency: 'PHP',
            quantity: 1,
            description: description || `TodaGo payment ${referenceNumber}`,
          },
        ],
        payment_method_types: methodTypes,
        success_url: successUrl || `${publicBaseUrl}/api/trips/paymongo/return?tripId=${encodeURIComponent(tripId)}&status=success`,
        cancel_url: cancelUrl || `${publicBaseUrl}/api/trips/paymongo/return?tripId=${encodeURIComponent(tripId)}&status=cancelled`,
        reference_number: referenceNumber,
        send_email_receipt: false,
        show_description: true,
        show_line_items: true,
        description: description || `TodaGo payment ${referenceNumber}`,
        metadata: {
          app: 'todago',
          ...(tripId ? { trip_id: tripId } : {}),
          payment_method: paymentMethod || 'wallet',
          ...metadata,
        },
        billing,
      },
    },
  };

  const json = await paymongoRequest('/v2/checkout_sessions', {
    method: 'POST', body,
    idempotencyKey: idempotencyKey || `todago-${referenceNumber}-${paymentMethod || 'wallet'}`,
  });
  if (Array.isArray(json.data?.attributes?.payment_method_types) &&
      json.data.attributes.payment_method_types.length === 0) {
    const error = new Error('No payment methods are available for this checkout. Please try another method.');
    error.statusCode = 422;
    throw error;
  }
  return json.data;
}

function verifyWebhookSignature({ rawBody, signatureHeader, livemode }) {
  const secret = process.env.PAYMONGO_WEBHOOK_SECRET;
  if (!secret) return false;
  if (Boolean(livemode) !== isLiveMode()) return false;
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
  getAvailablePaymentMethods,
  normalizeCapabilities,
  retrieveCheckoutSession,
  getPaidPayment,
  isLiveMode,
  createWalletPaymentIntent,
  attachWalletPaymentMethod,
  retrievePaymentIntent,
};
