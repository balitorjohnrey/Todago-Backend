/**
 * TodaGo Password Security — Pepper + Salt + bcrypt
 * Used for ALL user types: passengers, drivers, operators
 */
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const PEPPER = process.env.PASSWORD_PEPPER;
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);

if (!PEPPER || PEPPER.length < 16) {
  throw new Error('[Security] PASSWORD_PEPPER must be set and at least 16 chars.');
}

function generateSalt() {
  return crypto.randomBytes(16).toString('hex');
}

async function hashPassword(plainPassword, salt) {
  if (!plainPassword || typeof plainPassword !== 'string') throw new Error('Invalid password');
  const combined = `${PEPPER}:${salt}:${plainPassword}`;
  return await bcrypt.hash(combined, BCRYPT_ROUNDS);
}

async function verifyPassword(plainPassword, storedHash, storedSalt) {
  if (!plainPassword || !storedHash || !storedSalt) return false;
  const combined = `${PEPPER}:${storedSalt}:${plainPassword}`;
  return await bcrypt.compare(combined, storedHash);
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

module.exports = { generateSalt, hashPassword, verifyPassword, validatePasswordStrength };