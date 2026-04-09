/**
 * TodaGo Password Security — Pepper + Salt + bcrypt
 *
 * Layer 1 — PEPPER  : Secret string from .env, prepended to password.
 *                      NEVER stored in DB. Server-side secret only.
 * Layer 2 — SALT    : Random unique string generated per user.
 *                      Stored in DB (safe to store — only useful with pepper+hash).
 * Layer 3 — BCRYPT  : Slow hashing with cost factor 12.
 *                      Makes brute-force computationally expensive.
 *
 * Final hash stored: bcrypt( pepper + salt + password )
 * Salt stored separately in DB for transparency and project requirements.
 */

const bcrypt = require('bcrypt');
const crypto = require('crypto');

const PEPPER = process.env.PASSWORD_PEPPER;
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);

if (!PEPPER || PEPPER.length < 16) {
  throw new Error('[Security] PASSWORD_PEPPER must be set and at least 16 characters.');
}

/**
 * Generate a random salt (32 hex characters = 16 bytes)
 * @returns {string} random salt
 */
function generateSalt() {
  return crypto.randomBytes(16).toString('hex'); // 32-char hex string
}

/**
 * Hash a plain password with pepper + salt + bcrypt
 * @param {string} plainPassword
 * @param {string} salt - unique salt for this user
 * @returns {Promise<string>} bcrypt hash (safe to store in DB)
 */
async function hashPassword(plainPassword, salt) {
  if (!plainPassword || typeof plainPassword !== 'string') {
    throw new Error('Password must be a non-empty string');
  }
  // Combine: PEPPER (secret) + SALT (stored) + PASSWORD (input)
  const combined = `${PEPPER}:${salt}:${plainPassword}`;
  return await bcrypt.hash(combined, BCRYPT_ROUNDS);
}

/**
 * Verify plain password against stored hash + salt
 * @param {string} plainPassword
 * @param {string} storedHash
 * @param {string} storedSalt
 * @returns {Promise<boolean>}
 */
async function verifyPassword(plainPassword, storedHash, storedSalt) {
  if (!plainPassword || !storedHash || !storedSalt) return false;
  const combined = `${PEPPER}:${storedSalt}:${plainPassword}`;
  return await bcrypt.compare(combined, storedHash);
}

/**
 * Validate password strength
 * @param {string} password
 * @returns {string[]} array of error messages (empty = valid)
 */
function validatePasswordStrength(password) {
  const errors = [];
  if (!password || password.length < 8)  errors.push('Password must be at least 8 characters');
  if (password.length > 128)             errors.push('Password must not exceed 128 characters');
  if (!/[A-Z]/.test(password))           errors.push('Password must contain at least one uppercase letter');
  if (!/[a-z]/.test(password))           errors.push('Password must contain at least one lowercase letter');
  if (!/[0-9]/.test(password))           errors.push('Password must contain at least one number');
  return errors;
}

module.exports = { generateSalt, hashPassword, verifyPassword, validatePasswordStrength };