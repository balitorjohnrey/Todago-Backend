const express = require('express');
const jwt = require('jsonwebtoken');
const { dbRun, dbGet } = require('../db/database');
const {
  createPersonaInquiry,
  isPersonaConfigured,
  verifyPersonaSignature,
} = require('../services/persona');

const router = express.Router();

const ROLE_TABLES = {
  passenger: {
    table: 'users',
    idColumn: 'id',
    nameColumn: 'full_name',
    emailColumn: 'email',
    phoneColumn: 'phone',
    responseKey: 'user',
  },
  driver: {
    table: 'drivers',
    idColumn: 'driver_id',
    nameColumn: 'driver_name',
    emailColumn: 'email',
    phoneColumn: 'phone',
    responseKey: 'driver',
  },
  operator: {
    table: 'operators',
    idColumn: 'operator_id',
    nameColumn: 'contact_name',
    emailColumn: 'email',
    phoneColumn: 'phone',
    responseKey: 'operator',
  },
};

function requireRoleAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Authorization required' });
  }

  try {
    const payload = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET, {
      issuer: 'todago-api',
      audience: 'todago-app',
    });
    if (!ROLE_TABLES[payload.role]) {
      return res.status(403).json({ success: false, message: 'Unsupported account role' });
    }
    req.accountRole = payload.role;
    req.accountId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
}

function statusFromPersona(status, eventName) {
  const normalizedStatus = String(status || '').toLowerCase().replace('-', '_');
  const normalizedEvent = String(eventName || '').toLowerCase();

  if (normalizedEvent === 'inquiry.approved' || normalizedStatus === 'approved') {
    return 'approved';
  }
  if (normalizedEvent === 'inquiry.declined' || normalizedStatus === 'declined') {
    return 'declined';
  }
  if (normalizedEvent === 'inquiry.failed' || normalizedStatus === 'failed') {
    return 'failed';
  }
  if (normalizedEvent === 'inquiry.expired' || normalizedStatus === 'expired') {
    return 'expired';
  }
  if (normalizedStatus === 'needs_review' || normalizedStatus === 'needs review') {
    return 'needs_review';
  }
  if (normalizedEvent === 'inquiry.completed' || normalizedStatus === 'completed') {
    return 'completed';
  }
  if (normalizedEvent === 'inquiry.started' || normalizedStatus === 'pending') {
    return 'pending';
  }
  return normalizedStatus || 'submitted';
}

function parseReferenceId(referenceId) {
  const raw = String(referenceId || '');
  const separator = raw.indexOf(':');
  if (separator <= 0) return null;
  const role = raw.slice(0, separator);
  const id = raw.slice(separator + 1);
  if (!ROLE_TABLES[role] || !id) return null;
  return { role, id };
}

async function findTargetByInquiryId(inquiryId) {
  if (!inquiryId) return null;

  for (const [role, config] of Object.entries(ROLE_TABLES)) {
    const row = await dbGet(
      `SELECT '${role}' AS role, ${config.idColumn} AS id
       FROM ${config.table}
       WHERE persona_inquiry_id = $1
       LIMIT 1`,
      [inquiryId]
    );
    if (row) return row;
  }

  return null;
}

async function loadAccount(role, id) {
  const config = ROLE_TABLES[role];
  if (!config) return null;
  return dbGet(
    `SELECT *,
            ${config.idColumn} AS account_id,
            ${config.nameColumn} AS account_name,
            ${config.emailColumn} AS account_email,
            ${config.phoneColumn} AS account_phone
     FROM ${config.table}
     WHERE ${config.idColumn} = $1
       AND is_active IS NOT FALSE`,
    [id]
  );
}

async function savePersonaInquiry(role, id, persona) {
  const config = ROLE_TABLES[role];
  await dbRun(
    `UPDATE ${config.table}
     SET identity_provider = 'persona',
         identity_verification_status = $1,
         identity_is_verified = CASE
           WHEN $1 = 'approved' THEN true
           ELSE COALESCE(identity_is_verified, false)
         END,
         identity_submitted_at = COALESCE(identity_submitted_at, NOW()),
         identity_verified_at = CASE
           WHEN $1 = 'approved' THEN COALESCE(identity_verified_at, NOW())
           ELSE identity_verified_at
         END,
         persona_inquiry_id = $2,
         persona_account_id = $3,
         persona_reference_id = $4,
         persona_status = $5,
         updated_at = NOW()
     WHERE ${config.idColumn} = $6`,
    [
      statusFromPersona(persona.status),
      persona.inquiryId,
      persona.accountId,
      persona.referenceId,
      persona.status,
      id,
    ]
  );
}

async function updatePersonaStatus(target, personaEvent) {
  const config = ROLE_TABLES[target.role];
  const identityStatus = statusFromPersona(personaEvent.status, personaEvent.eventName);
  const identityVerified = identityStatus === 'approved';

  await dbRun(
    `UPDATE ${config.table}
     SET identity_provider = 'persona',
         identity_verification_status = $1,
         identity_is_verified = CASE WHEN $2 THEN true ELSE COALESCE(identity_is_verified, false) END,
         identity_submitted_at = COALESCE(identity_submitted_at, NOW()),
         identity_verified_at = CASE WHEN $2 THEN COALESCE(identity_verified_at, NOW()) ELSE identity_verified_at END,
         persona_status = $3,
         persona_inquiry_id = COALESCE(persona_inquiry_id, $4),
         persona_account_id = COALESCE($5, persona_account_id),
         persona_reference_id = COALESCE($6, persona_reference_id),
         persona_last_event = $7,
         persona_last_event_at = NOW(),
         updated_at = NOW()
     WHERE ${config.idColumn} = $8`,
    [
      identityStatus,
      identityVerified,
      personaEvent.status || identityStatus,
      personaEvent.inquiryId,
      personaEvent.accountId,
      personaEvent.referenceId,
      personaEvent.eventName,
      target.id,
    ]
  );

  return identityStatus;
}

router.get('/status', requireRoleAuth, async (req, res) => {
  try {
    const account = await loadAccount(req.accountRole, req.accountId);
    if (!account) {
      return res.status(404).json({ success: false, message: 'Account not found' });
    }

    return res.json({
      success: true,
      role: req.accountRole,
      identity: {
        provider: account.identity_provider,
        status: account.identity_verification_status,
        isVerified: account.identity_is_verified === true,
      },
    });
  } catch (error) {
    console.error('[KYC] Status error:', error.message);
    return res.status(500).json({ success: false, message: 'Unable to load identity status' });
  }
});

router.post('/persona/start', requireRoleAuth, async (req, res) => {
  if (!isPersonaConfigured()) {
    return res.status(503).json({
      success: false,
      message: 'Persona is not configured on the backend.',
    });
  }

  try {
    const account = await loadAccount(req.accountRole, req.accountId);
    if (!account) {
      return res.status(404).json({ success: false, message: 'Account not found' });
    }
    if (account.identity_is_verified === true) {
      return res.json({
        success: true,
        message: 'Identity already verified',
        identity: {
          provider: 'persona',
          status: account.identity_verification_status || 'approved',
          isVerified: true,
        },
      });
    }

    const persona = await createPersonaInquiry({
      role: req.accountRole,
      entityId: req.accountId,
      fullName: account.account_name,
      email: account.account_email,
      phone: account.account_phone,
    });
    await savePersonaInquiry(req.accountRole, req.accountId, persona);

    return res.status(201).json({
      success: true,
      message: 'Persona verification started',
      persona: {
        inquiryId: persona.inquiryId,
        verificationUrl: persona.verificationUrl,
        status: persona.status,
      },
    });
  } catch (error) {
    console.error('[KYC] Persona start error:', error.message);
    return res.status(502).json({
      success: false,
      message: 'Unable to start Persona verification right now.',
    });
  }
});

router.post('/persona/webhook', async (req, res) => {
  const webhookSecret = process.env.PERSONA_WEBHOOK_SECRET;
  const signature = req.headers['persona-signature'];

  if (!verifyPersonaSignature(req.rawBody, signature, webhookSecret)) {
    return res.status(401).json({ success: false, message: 'Invalid Persona signature' });
  }

  try {
    const event = req.body?.data?.attributes || {};
    const payload = event.payload?.data || {};
    const attributes = payload.attributes || {};
    const relationships = payload.relationships || {};
    const inquiryId = payload.id;
    const referenceId = attributes['reference-id'];
    const accountId = relationships.account?.data?.id || null;

    let target = await findTargetByInquiryId(inquiryId);
    if (!target) {
      target = parseReferenceId(referenceId);
    }

    if (!target) {
      console.warn('[KYC] Persona webhook did not match a local account:', inquiryId || referenceId);
      return res.json({ success: true, matched: false });
    }

    const identityStatus = await updatePersonaStatus(target, {
      eventName: event.name,
      status: attributes.status,
      inquiryId,
      accountId,
      referenceId,
    });

    console.log(`[KYC] Persona ${event.name} for ${target.role}:${target.id} -> ${identityStatus}`);
    return res.json({ success: true, matched: true });
  } catch (error) {
    console.error('[KYC] Persona webhook error:', error.message);
    return res.status(200).json({ success: false });
  }
});

module.exports = {
  router,
  savePersonaInquiry,
};
