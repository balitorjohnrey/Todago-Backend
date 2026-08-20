const crypto = require('crypto');

const PERSONA_API_URL = 'https://api.withpersona.com/api/v1/inquiries';
const DEFAULT_PERSONA_VERSION = '2023-01-05';

function clean(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function isPersonaConfigured() {
  return Boolean(
    clean(process.env.PERSONA_API_KEY)
      && clean(process.env.PERSONA_INQUIRY_TEMPLATE_ID)
  );
}

function splitFullName(fullName) {
  const parts = clean(fullName).split(/\s+/).filter(Boolean);
  if (parts.length === 0) return { firstName: '', lastName: '' };
  if (parts.length === 1) return { firstName: parts[0], lastName: '' };
  return {
    firstName: parts[0],
    lastName: parts.slice(1).join(' '),
  };
}

function buildReferenceId(role, entityId) {
  return `${role}:${entityId}`;
}

function buildPrefillFields({ fullName, email, phone }) {
  const { firstName, lastName } = splitFullName(fullName);
  const fields = {};

  if (firstName) fields['name-first'] = firstName;
  if (lastName) fields['name-last'] = lastName;
  if (clean(email)) fields['email-address'] = clean(email).toLowerCase();
  if (clean(phone)) fields['phone-number'] = clean(phone);

  return fields;
}

async function createPersonaInquiry({ role, entityId, fullName, email, phone }) {
  if (!isPersonaConfigured()) {
    const err = new Error('Persona is not configured');
    err.code = 'PERSONA_NOT_CONFIGURED';
    throw err;
  }

  const referenceId = buildReferenceId(role, entityId);
  const attributes = {
    'inquiry-template-id': clean(process.env.PERSONA_INQUIRY_TEMPLATE_ID),
    'reference-id': referenceId,
  };
  const fields = buildPrefillFields({ fullName, email, phone });
  if (Object.keys(fields).length > 0) {
    attributes.fields = fields;
  }

  const response = await fetch(PERSONA_API_URL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${clean(process.env.PERSONA_API_KEY)}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'Persona-Version': clean(process.env.PERSONA_API_VERSION) || DEFAULT_PERSONA_VERSION,
    },
    body: JSON.stringify({
      data: { attributes },
    }),
  });

  const text = await response.text();
  let payload = {};
  try {
    payload = text ? JSON.parse(text) : {};
  } catch (_) {
    payload = { raw: text };
  }

  if (!response.ok) {
    const personaMessage = payload?.errors?.[0]?.detail
      || payload?.errors?.[0]?.title
      || payload?.message
      || `Persona request failed with status ${response.status}`;
    const err = new Error(personaMessage);
    err.code = 'PERSONA_CREATE_FAILED';
    err.status = response.status;
    err.personaRequestId = response.headers.get('request-id');
    throw err;
  }

  const inquiry = payload.data || {};
  const attributesOut = inquiry.attributes || {};
  const relationships = inquiry.relationships || {};
  const account = relationships.account?.data || {};
  const meta = payload.meta || {};

  return {
    inquiryId: inquiry.id,
    accountId: account.id || null,
    referenceId: attributesOut['reference-id'] || referenceId,
    status: attributesOut.status || 'created',
    verificationUrl: meta['one-time-link'] || meta['one-time-link-short'] || null,
  };
}

function verifyPersonaSignature(rawBody, signatureHeader, webhookSecret) {
  if (!rawBody || !signatureHeader || !webhookSecret) return false;

  try {
    const body = Buffer.isBuffer(rawBody)
      ? rawBody.toString('utf8')
      : String(rawBody);
    const signaturePairs = String(signatureHeader).split(' ');
    const timestamp = signaturePairs[0]?.split(',')?.[0]?.split('=')?.[1];
    const signatures = signaturePairs
      .map((pair) => {
        const match = pair.match(/v1=([^,]+)/);
        return match ? match[1] : null;
      })
      .filter(Boolean);

    if (!timestamp || signatures.length === 0) return false;

    const expectedSignature = crypto
      .createHmac('sha256', webhookSecret)
      .update(`${timestamp}.${body}`)
      .digest('hex');

    const expected = Buffer.from(expectedSignature);
    return signatures.some((signature) => {
      const actual = Buffer.from(signature);
      return actual.length === expected.length
        && crypto.timingSafeEqual(expected, actual);
    });
  } catch (_) {
    return false;
  }
}

module.exports = {
  buildReferenceId,
  createPersonaInquiry,
  isPersonaConfigured,
  verifyPersonaSignature,
};
