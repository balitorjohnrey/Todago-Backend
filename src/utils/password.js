/**
 * TodaGo Password Security — Pepper + Salt + bcrypt
 * Used for ALL user types: passengers, drivers, operators.
 *
 * bcrypt only reads the first 72 bytes of input. We HMAC the salt + password
 * with the pe\pper first, then bcrypt that fixed-size digest.
 */
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const PEPPER = process.env.PASSWORD_PEPPER;
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
const HASH_PREFIX = 'v2:';
const BCRYPT_MAX_BYTES = 72;

if (!PEPPER || PEPPER.length < 16) {
  throw new Error('[Security] PASSWORD_PEPPER must be set and at least 16 chars.');
}

function generateSalt() {
  return crypto.randomBytes(16).toString('hex');
}

function passwordDigest(plainPassword, salt) {
  return crypto
    .createHmac('sha256', PEPPER)
    .update(`${salt}:${plainPassword}`, 'utf8')
    .digest('base64url');
}

function legacyPasswordInput(plainPassword, salt) {
  return `${PEPPER}:${salt}:${plainPassword}`;
}

async function hashPassword(plainPassword, salt) {
  if (!plainPassword || typeof plainPassword !== 'string') throw new Error('Invalid password');
  if (!salt || typeof salt !== 'string') throw new Error('Invalid salt');
  const digest = passwordDigest(plainPassword, salt);
  const bcryptHash = await bcrypt.hash(digest, BCRYPT_ROUNDS);
  return `${HASH_PREFIX}${bcryptHash}`;
}

async function verifyPassword(plainPassword, storedHash, storedSalt) {
  const result = await verifyPasswordDetailed(plainPassword, storedHash, storedSalt);
  return result.match;
}

async function verifyPasswordDetailed(plainPassword, storedHash, storedSalt) {
  if (!plainPassword) {
    return { match: false, legacy: false, resetRequired: false };
  }
  if (!storedHash || !storedSalt || storedSalt === 'legacy') {
    return { match: false, legacy: true, resetRequired: true };
  }

  if (storedHash.startsWith(HASH_PREFIX)) {
    const digest = passwordDigest(plainPassword, storedSalt);
    let match = false;
    try {
      match = await bcrypt.compare(digest, storedHash.slice(HASH_PREFIX.length));
    } catch {
      match = false;
    }
    return {
      match,
      legacy: false,
      resetRequired: false,
    };
  }

  if (!storedHash.startsWith('$2')) {
    return { match: false, legacy: true, resetRequired: true };
  }

  const legacyInput = legacyPasswordInput(plainPassword, storedSalt);
  let enteredMatches = false;
  try {
    enteredMatches = await bcrypt.compare(legacyInput, storedHash);
  } catch {
    return { match: false, legacy: true, resetRequired: true };
  }
  if (!enteredMatches) {
    return { match: false, legacy: true, resetRequired: false };
  }

  const legacyPrefix = `${PEPPER}:${storedSalt}:`;
  const passwordWasFullyIncluded =
    Buffer.byteLength(legacyPrefix, 'utf8') < BCRYPT_MAX_BYTES &&
    Buffer.byteLength(legacyInput, 'utf8') <= BCRYPT_MAX_BYTES;
  if (!passwordWasFullyIncluded) {
    return { match: false, legacy: true, resetRequired: true };
  }

  return { match: true, legacy: true, resetRequired: false };
}

function validatePasswordStrength(password) {
  const errors = [];
  if (!password || password.length < 8)  errors.push('Password must be at least 8 characters');
  if (password.length > 128)             errors.push('Password must not exceed 128 characters');
  if (!/[A-Z]/.test(password))           errors.push('Must contain at least one uppercase letter');
  if (!/[a-z]/.test(password))           errors.push('Must contain at least one lowercase letter');
  if (!/[0-9]/.test(password))           errors.push('Must contain at least one number');
  return errors;
}

module.exports = {
  generateSalt,
  hashPassword,
  verifyPassword,
  verifyPasswordDetailed,
  validatePasswordStrength,
};
