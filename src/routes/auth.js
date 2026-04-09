const express  = require('express');
const { body, validationResult } = require('express-validator');
const jwt      = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const { dbRun, dbGet }                                        = require('../db/database');
const { generateSalt, hashPassword,
        verifyPassword, validatePasswordStrength }             = require('../utils/password');

const router = express.Router();

function generateToken(userId) {
  return jwt.sign({ sub: userId }, process.env.JWT_SECRET, {
    expiresIn : process.env.JWT_EXPIRES_IN || '7d',
    issuer    : 'todago-api',
    audience  : 'todago-app',
  });
}

function sanitizeUser(user) {
  // Never send password_hash, salt, or pepper to client
  const { password_hash, salt, ...safe } = user;
  return safe;
}

function clientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]
    || req.socket?.remoteAddress || 'unknown';
}

// ── POST /api/auth/register ───────────────────────────────────────────────────
router.post('/register', [
  body('fullName').trim().isLength({ min: 2, max: 100 }).withMessage('Full name must be 2–100 characters'),
  body('email').trim().isEmail().normalizeEmail().withMessage('Enter a valid email address'),
  body('phone').trim().matches(/^[+\d\s\-()]{7,20}$/).withMessage('Enter a valid phone number'),
  body('password').isLength({ min: 8, max: 128 }).withMessage('Password must be 8–128 characters'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  const { fullName, email, phone, password } = req.body;

  try {
    const strengthErrors = validatePasswordStrength(password);
    if (strengthErrors.length > 0) {
      return res.status(400).json({ success: false, message: strengthErrors[0] });
    }

    const existingEmail = await dbGet('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existingEmail) {
      return res.status(409).json({ success: false, message: 'An account with this email already exists' });
    }

    const existingPhone = await dbGet('SELECT id FROM users WHERE phone = $1', [phone]);
    if (existingPhone) {
      return res.status(409).json({ success: false, message: 'An account with this phone number already exists' });
    }

    // Step 1: Generate unique random salt for this user
    const salt = generateSalt();

    // Step 2: Hash using pepper + salt + password
    const passwordHash = await hashPassword(password, salt);

    const userId = uuidv4();

    // Step 3: Store username, hashed password, AND salt in DB
    // Pepper is NOT stored — it lives only in environment variables
    await dbRun(
      `INSERT INTO users (id, full_name, email, phone, password_hash, salt)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [userId, fullName.trim(), email.toLowerCase(), phone.trim(), passwordHash, salt]
    );

    const user  = await dbGet('SELECT * FROM users WHERE id = $1', [userId]);
    const token = generateToken(userId);

    console.log(`[Auth] Registered: ${email} (${userId})`);

    return res.status(201).json({
      success : true,
      message : 'Account created successfully',
      token,
      user    : sanitizeUser(user),
    });

  } catch (error) {
    console.error('[Auth] Register error:', error.message);
    return res.status(500).json({ success: false, message: 'Registration failed. Please try again.' });
  }
});

// ── POST /api/auth/login ──────────────────────────────────────────────────────
router.post('/login', [
  body('email').trim().isEmail().normalizeEmail().withMessage('Enter a valid email address'),
  body('password').notEmpty().withMessage('Password is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  const { email, password } = req.body;
  const ip = clientIp(req);

  try {
    const user = await dbGet(
      'SELECT * FROM users WHERE email = $1 AND is_active = true',
      [email.toLowerCase()]
    );

    // Always run bcrypt even if user not found (prevent timing attacks)
    const dummyHash = '$2b$12$invalidhashfortimingattackprevention000000000000000000000';
    const dummySalt = 'dummy_salt_for_timing_attack_prevention';
    const passwordMatch = await verifyPassword(
      password,
      user ? user.password_hash : dummyHash,
      user ? user.salt : dummySalt
    );

    if (!user || !passwordMatch) {
      await dbRun(
        'INSERT INTO login_attempts (email, ip_address, success) VALUES ($1, $2, $3)',
        [email, ip, false]
      );
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    await dbRun('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
    await dbRun(
      'INSERT INTO login_attempts (email, ip_address, success) VALUES ($1, $2, $3)',
      [email, ip, true]
    );

    const token = generateToken(user.id);
    console.log(`[Auth] Login: ${email} from ${ip}`);

    return res.status(200).json({
      success : true,
      message : 'Login successful',
      token,
      user    : sanitizeUser(user),
    });

  } catch (error) {
    console.error('[Auth] Login error:', error.message);
    return res.status(500).json({ success: false, message: 'Login failed. Please try again.' });
  }
});

// ── GET /api/auth/me ──────────────────────────────────────────────────────────
router.get('/me', requireAuth, async (req, res) => {
  try {
    const user = await dbGet('SELECT * FROM users WHERE id = $1 AND is_active = true', [req.userId]);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    return res.json({ success: true, user: sanitizeUser(user) });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── POST /api/auth/logout ─────────────────────────────────────────────────────
router.post('/logout', requireAuth, (req, res) => {
  return res.json({ success: true, message: 'Logged out successfully' });
});

// ── PUT /api/auth/role ────────────────────────────────────────────────────────
router.put('/role', requireAuth, [
  body('role').isIn(['passenger', 'driver', 'operator']).withMessage('Invalid role'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    await dbRun(
      'UPDATE users SET role = $1, updated_at = NOW() WHERE id = $2',
      [req.body.role, req.userId]
    );
    return res.json({ success: true, message: 'Role updated successfully' });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Failed to update role' });
  }
});

// ── Auth Middleware ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Authorization token required' });
  }
  try {
    const payload = jwt.verify(authHeader.split(' ')[1], process.env.JWT_SECRET, {
      issuer: 'todago-api', audience: 'todago-app',
    });
    req.userId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
}

module.exports = router;