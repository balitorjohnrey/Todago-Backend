const crypto = require('crypto');

const DIDIT_SESSION_API_URL = 'https://verification.didit.me/v3/session/';

function clean(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function isDiditConfigured() {
  return Boolean(clean(process.env.DIDIT_API_KEY) && clean(process.env.DIDIT_WORKFLOW_ID));
}

function buildReferenceId(role, entityId) {
  return `${role}:${entityId}`;
}

function safeTimingEqual(expected, actual) {
  if (!expected || !actual) return false;
  const expectedBuffer = Buffer.from(String(expected), 'utf8');
  const actualBuffer = Buffer.from(String(actual), 'utf8');
  return expectedBuffer.length === actualBuffer.length
    && crypto.timingSafeEqual(expectedBuffer, actualBuffer);
}

function shortenFloats(data) {
  if (Array.isArray(data)) return data.map(shortenFloats);
  if (data !== null && typeof data === 'object') {
    return Object.fromEntries(
      Object.entries(data).map(([key, value]) => [key, shortenFloats(value)])
    );
  }
  if (typeof data === 'number' && !Number.isInteger(data) && data % 1 === 0) {
    return Math.trunc(data);
  }
  return data;
}

function sortKeys(obj) {
  if (Array.isArray(obj)) return obj.map(sortKeys);
  if (obj !== null && typeof obj === 'object') {
    return Object.keys(obj).sort().reduce((acc, key) => {
      acc[key] = sortKeys(obj[key]);
      return acc;
    }, {});
  }
  return obj;
}

function readHeader(headers, name) {
  return headers?.[name.toLowerCase()] || headers?.[name] || '';
}

function isFreshTimestamp(timestampHeader) {
  const timestamp = Number.parseInt(timestampHeader, 10);
  if (!Number.isFinite(timestamp)) return false;
  const now = Math.floor(Date.now() / 1000);
  return Math.abs(now - timestamp) <= 300;
}

function verifySignatureV2(jsonBody, signatureHeader, timestampHeader, webhookSecret) {
  if (!jsonBody || !signatureHeader || !webhookSecret || !isFreshTimestamp(timestampHeader)) {
    return false;
  }

  const canonical = JSON.stringify(sortKeys(shortenFloats(jsonBody)));
  const expected = crypto
    .createHmac('sha256', webhookSecret)
    .update(canonical, 'utf8')
    .digest('hex');

  return safeTimingEqual(expected, signatureHeader);
}

function verifyRawSignature(rawBody, signatureHeader, timestampHeader, webhookSecret) {
  if (!rawBody || !signatureHeader || !webhookSecret || !isFreshTimestamp(timestampHeader)) {
    return false;
  }

  const expected = crypto
    .createHmac('sha256', webhookSecret)
    .update(Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody), 'utf8'))
    .digest('hex');

  return safeTimingEqual(expected, signatureHeader);
}

function verifySignatureSimple(jsonBody, signatureHeader, timestampHeader, webhookSecret) {
  if (!jsonBody || !signatureHeader || !webhookSecret || !isFreshTimestamp(timestampHeader)) {
    return false;
  }

  const canonical = [
    jsonBody.timestamp ?? '',
    jsonBody.session_id ?? '',
    jsonBody.status ?? '',
    jsonBody.webhook_type ?? '',
  ].join(':');
  const expected = crypto
    .createHmac('sha256', webhookSecret)
    .update(canonical, 'utf8')
    .digest('hex');

  return safeTimingEqual(expected, signatureHeader);
}

function verifyDiditWebhookSignature(jsonBody, rawBody, headers, webhookSecret) {
  const timestampHeader = readHeader(headers, 'x-timestamp');
  const signatureV2 = readHeader(headers, 'x-signature-v2');
  const signatureRaw = readHeader(headers, 'x-signature');
  const signatureSimple = readHeader(headers, 'x-signature-simple');

  if (signatureV2 && verifySignatureV2(jsonBody, signatureV2, timestampHeader, webhookSecret)) {
    return true;
  }
  if (signatureRaw && verifyRawSignature(rawBody, signatureRaw, timestampHeader, webhookSecret)) {
    return true;
  }
  return Boolean(
    signatureSimple
      && verifySignatureSimple(jsonBody, signatureSimple, timestampHeader, webhookSecret)
  );
}

async function createDiditSession({ role, entityId, fullName, email, phone }) {
  if (!isDiditConfigured()) {
    const err = new Error('Didit is not configured');
    err.code = 'DIDIT_NOT_CONFIGURED';
    throw err;
  }

  const referenceId = buildReferenceId(role, entityId);
  const body = {
    workflow_id: clean(process.env.DIDIT_WORKFLOW_ID),
    vendor_data: referenceId,
    metadata: {
      role,
      account_id: String(entityId),
      account_name: clean(fullName),
      source: 'todago',
    },
  };

  const callbackUrl = clean(process.env.DIDIT_CALLBACK_URL);
  if (callbackUrl) {
    body.callback = callbackUrl;
  }

  const contactDetails = {};
  if (clean(email)) contactDetails.email = clean(email).toLowerCase();
  if (clean(phone)) contactDetails.phone = clean(phone);
  if (Object.keys(contactDetails).length > 0) {
    body.contact_details = {
      ...contactDetails,
      send_notification_emails: false,
    };
  }

  const sandboxScenario = clean(process.env.DIDIT_SANDBOX_SCENARIO);
  if (sandboxScenario) {
    body.sandbox_scenario = sandboxScenario;
  }

  const response = await fetch(clean(process.env.DIDIT_SESSION_API_URL) || DIDIT_SESSION_API_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'x-api-key': clean(process.env.DIDIT_API_KEY),
    },
    body: JSON.stringify(body),
  });

  const text = await response.text();
  let payload = {};
  try {
    payload = text ? JSON.parse(text) : {};
  } catch (_) {
    payload = { raw: text };
  }

  if (!response.ok) {
    const diditMessage = payload?.detail
      || payload?.message
      || payload?.error
      || `Didit request failed with status ${response.status}`;
    const err = new Error(diditMessage);
    err.code = 'DIDIT_CREATE_FAILED';
    err.status = response.status;
    throw err;
  }

  return {
    sessionId: payload.session_id,
    workflowId: payload.workflow_id || body.workflow_id,
    referenceId: payload.vendor_data || referenceId,
    status: payload.status || 'Not Started',
    verificationUrl: payload.url || null,
  };
}

module.exports = {
  buildReferenceId,
  createDiditSession,
  isDiditConfigured,
  verifyDiditWebhookSignature,
};
