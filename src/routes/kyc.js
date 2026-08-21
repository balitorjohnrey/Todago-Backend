const express = require('express');
const jwt = require('jsonwebtoken');
const { dbRun, dbGet } = require('../db/database');
const {
  createDiditSession,
  isDiditConfigured,
  verifyDiditWebhookSignature,
} = require('../services/didit');
const {
  createPersonaInquiry,
  isPersonaConfigured,
  verifyPersonaSignature,
} = require('../services/persona');

const router = express.Router();

const EXTERNAL_KYC_PROVIDERS = new Set(['didit', 'persona']);

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

function clean(value) {
  return typeof value === 'string' ? value.trim() : '';
}

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

function activeKycProvider() {
  const requestedProvider = clean(process.env.KYC_PROVIDER).toLowerCase();
  if (EXTERNAL_KYC_PROVIDERS.has(requestedProvider)) return requestedProvider;
  if (isDiditConfigured()) return 'didit';
  if (isPersonaConfigured()) return 'persona';
  return 'manual';
}

function isKycConfigured(provider = activeKycProvider()) {
  if (provider === 'didit') return isDiditConfigured();
  if (provider === 'persona') return isPersonaConfigured();
  return false;
}

function providerForNewAccount() {
  const provider = activeKycProvider();
  return isExternalKycProvider(provider) ? provider : 'manual';
}

function isExternalKycProvider(provider) {
  return EXTERNAL_KYC_PROVIDERS.has(clean(provider).toLowerCase());
}

function providerLabel(provider) {
  if (provider === 'didit') return 'Didit';
  if (provider === 'persona') return 'Persona';
  return 'KYC';
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

function statusFromDidit(status) {
  switch (clean(status).toLowerCase()) {
    case 'approved':
      return 'approved';
    case 'declined':
      return 'declined';
    case 'in review':
      return 'needs_review';
    case 'in progress':
      return 'pending';
    case 'not started':
      return 'not_started';
    case 'awaiting user':
      return 'awaiting_user';
    case 'resubmitted':
      return 'resubmitted';
    case 'expired':
      return 'expired';
    case 'abandoned':
      return 'abandoned';
    case 'kyc expired':
      return 'kyc_expired';
    default:
      return clean(status).toLowerCase().replace(/\s+/g, '_') || 'submitted';
  }
}

function publicKycPayload(kyc) {
  if (!kyc) return null;
  return {
    provider: kyc.provider,
    inquiryId: kyc.inquiryId,
    sessionId: kyc.sessionId,
    verificationUrl: kyc.verificationUrl,
    status: kyc.status,
    rawStatus: kyc.rawStatus,
  };
}

function legacyPersonaPayload(kyc) {
  if (!kyc?.verificationUrl) return null;
  return {
    provider: kyc.provider,
    inquiryId: kyc.inquiryId || kyc.sessionId,
    verificationUrl: kyc.verificationUrl,
    status: kyc.status,
  };
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

function parseMetadataTarget(metadata) {
  if (!metadata || typeof metadata !== 'object') return null;
  const role = clean(metadata.role);
  const id = clean(metadata.account_id || metadata.entity_id || metadata.id);
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

async function findTargetByDiditSessionId(sessionId) {
  if (!sessionId) return null;

  for (const [role, config] of Object.entries(ROLE_TABLES)) {
    const row = await dbGet(
      `SELECT '${role}' AS role, ${config.idColumn} AS id
       FROM ${config.table}
       WHERE didit_session_id = $1
       LIMIT 1`,
      [sessionId]
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

async function saveDiditSession(role, id, didit) {
  const config = ROLE_TABLES[role];
  const identityStatus = statusFromDidit(didit.status);
  await dbRun(
    `UPDATE ${config.table}
     SET identity_provider = 'didit',
         identity_verification_status = $1,
         identity_is_verified = CASE WHEN $1 = 'approved' THEN true ELSE false END,
         identity_submitted_at = COALESCE(identity_submitted_at, NOW()),
         identity_verified_at = CASE
           WHEN $1 = 'approved' THEN COALESCE(identity_verified_at, NOW())
           ELSE identity_verified_at
         END,
         didit_session_id = $2,
         didit_workflow_id = $3,
         didit_reference_id = $4,
         didit_status = $5,
         updated_at = NOW()
     WHERE ${config.idColumn} = $6`,
    [
      identityStatus,
      didit.sessionId,
      didit.workflowId,
      didit.referenceId,
      didit.status,
      id,
    ]
  );
}

async function createKycVerification({
  role,
  entityId,
  fullName,
  email,
  phone,
  provider = activeKycProvider(),
}) {
  if (provider === 'didit') {
    const didit = await createDiditSession({ role, entityId, fullName, email, phone });
    await saveDiditSession(role, entityId, didit);
    return {
      provider: 'didit',
      sessionId: didit.sessionId,
      workflowId: didit.workflowId,
      referenceId: didit.referenceId,
      verificationUrl: didit.verificationUrl,
      status: statusFromDidit(didit.status),
      rawStatus: didit.status,
    };
  }

  if (provider === 'persona') {
    const persona = await createPersonaInquiry({ role, entityId, fullName, email, phone });
    await savePersonaInquiry(role, entityId, persona);
    return {
      provider: 'persona',
      inquiryId: persona.inquiryId,
      accountId: persona.accountId,
      referenceId: persona.referenceId,
      verificationUrl: persona.verificationUrl,
      status: statusFromPersona(persona.status),
      rawStatus: persona.status,
    };
  }

  const err = new Error('No KYC provider is configured');
  err.code = 'KYC_NOT_CONFIGURED';
  throw err;
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

async function updateDiditStatus(target, diditEvent) {
  const config = ROLE_TABLES[target.role];
  const identityStatus = statusFromDidit(diditEvent.status);
  const identityVerified = identityStatus === 'approved';

  await dbRun(
    `UPDATE ${config.table}
     SET identity_provider = 'didit',
         identity_verification_status = $1,
         identity_is_verified = CASE
           WHEN $2 THEN true
           WHEN $1 IN ('declined', 'expired', 'abandoned', 'kyc_expired') THEN false
           ELSE COALESCE(identity_is_verified, false)
         END,
         identity_submitted_at = COALESCE(identity_submitted_at, NOW()),
         identity_verified_at = CASE WHEN $2 THEN COALESCE(identity_verified_at, NOW()) ELSE identity_verified_at END,
         didit_status = $3,
         didit_session_id = COALESCE(didit_session_id, $4),
         didit_workflow_id = COALESCE($5, didit_workflow_id),
         didit_reference_id = COALESCE($6, didit_reference_id),
         didit_last_event = $7,
         didit_last_event_id = COALESCE($8, didit_last_event_id),
         didit_last_event_at = NOW(),
         updated_at = NOW()
     WHERE ${config.idColumn} = $9`,
    [
      identityStatus,
      identityVerified,
      diditEvent.status || identityStatus,
      diditEvent.sessionId,
      diditEvent.workflowId,
      diditEvent.referenceId,
      diditEvent.eventName,
      diditEvent.eventId,
      target.id,
    ]
  );

  return identityStatus;
}

async function startVerification(req, res, providerOverride = null) {
  const provider = providerOverride || activeKycProvider();
  if (!isKycConfigured(provider)) {
    return res.status(503).json({
      success: false,
      message: `${providerLabel(provider)} is not configured on the backend.`,
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
          provider: account.identity_provider || provider,
          status: account.identity_verification_status || 'approved',
          isVerified: true,
        },
      });
    }

    const kyc = await createKycVerification({
      role: req.accountRole,
      entityId: req.accountId,
      fullName: account.account_name,
      email: account.account_email,
      phone: account.account_phone,
      provider,
    });

    return res.status(201).json({
      success: true,
      message: `${providerLabel(provider)} verification started`,
      kyc: publicKycPayload(kyc),
      didit: kyc.provider === 'didit' ? publicKycPayload(kyc) : null,
      persona: legacyPersonaPayload(kyc),
    });
  } catch (error) {
    console.error(`[KYC] ${providerLabel(provider)} start error:`, error.message);
    return res.status(502).json({
      success: false,
      message: `Unable to start ${providerLabel(provider)} verification right now.`,
    });
  }
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

router.post('/start', requireRoleAuth, (req, res) => startVerification(req, res));
router.post('/didit/start', requireRoleAuth, (req, res) => startVerification(req, res, 'didit'));
router.post('/persona/start', requireRoleAuth, (req, res) => startVerification(req, res, 'persona'));

router.post('/didit/webhook', async (req, res) => {
  const webhookSecret = process.env.DIDIT_WEBHOOK_SECRET;
  if (!verifyDiditWebhookSignature(req.body, req.rawBody, req.headers, webhookSecret)) {
    return res.status(401).json({ success: false, message: 'Invalid Didit signature' });
  }

  try {
    const eventName = clean(req.body?.webhook_type);
    if (!['status.updated', 'data.updated'].includes(eventName)) {
      return res.json({ success: true, ignored: true });
    }

    const sessionId = req.body?.session_id || req.body?.business_session_id || null;
    const referenceId = req.body?.vendor_data || null;
    let target = await findTargetByDiditSessionId(sessionId);
    if (!target) {
      target = parseReferenceId(referenceId);
    }
    if (!target) {
      target = parseMetadataTarget(req.body?.metadata);
    }

    if (!target) {
      console.warn('[KYC] Didit webhook did not match a local account:', sessionId || referenceId);
      return res.json({ success: true, matched: false });
    }

    const identityStatus = await updateDiditStatus(target, {
      eventName,
      eventId: req.body?.event_id,
      status: req.body?.status,
      sessionId,
      workflowId: req.body?.workflow_id,
      referenceId,
    });

    console.log(`[KYC] Didit ${eventName} for ${target.role}:${target.id} -> ${identityStatus}`);
    return res.json({ success: true, matched: true });
  } catch (error) {
    console.error('[KYC] Didit webhook error:', error.message);
    return res.status(200).json({ success: false });
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
  activeKycProvider,
  createKycVerification,
  isExternalKycProvider,
  isKycConfigured,
  legacyPersonaPayload,
  providerForNewAccount,
  publicKycPayload,
  router,
  savePersonaInquiry,
};
