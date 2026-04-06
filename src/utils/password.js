/**
 * TodaGo Password Security — Pepper + Salt + bcrypt
 *
 * Layer 1 — PEPPER  : Secret string from env, prepended before hashing.
 *                      Never stored in DB. Useless without the server secret.
 * Layer 2 — SALT    : Auto-generated per user by bcrypt. Embedded in the hash.
 *                      Prevents rainbow table attacks.
 * Layer 3 — BCRYPT  : Slow hashing algorithm with cost factor.
 *                      Makes brute-force computationally expensive.
 *
 * Stored in DB:  bcrypt( PEPPER + "::" + password,  auto-salt,  cost=12 )
 */

const bcrypt = require('bcrypt');

const PEPPER = process.env.PASSWORD_PEPPER;
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);

if (!PEPPER || PEPPER.length < 16) {
  throw new Error('[Security] PASSWORD_PEPPER must be set and at least 16 characters.');
}

/**
 * Hash a plain password with pepper + bcrypt (auto-salt included)
 * @param {string} plainPassword
 * @returns {Promise<string>} bcrypt hash (safe to store in DB)
 */
async function hashPassword(plainPassword) {
  if (!plainPassword || typeof plainPassword !== 'string') {
    throw new Error('Password must be a non-empty string');
  }
  const peppered = `${PEPPER}::${plainPassword}`;
  return await bcrypt.hash(peppered, BCRYPT_ROUNDS);
}

/**
 * Verify plain password against stored hash
 * @param {string} plainPassword
 * @param {string} storedHash
 * @returns {Promise<boolean>}
 */
async function verifyPassword(plainPassword, storedHash) {
  if (!plainPassword || !storedHash) return false;
  const peppered = `${PEPPER}::${plainPassword}`;
  return await bcrypt.compare(peppered, storedHash);
}

/**
 * Validate password strength — returns array of error messages
 * @param {string} password
 * @returns {string[]}
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

module.exports = { hashPassword, verifyPassword, validatePasswordStrength };