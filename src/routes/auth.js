const express  = require('express');
const { body, validationResult } = require('express-validator');
const jwt      = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const { dbRun, dbGet }                                        = require('../db/database');
const { generateSalt, hashPassword,
        verifyPasswordDetailed,
        validatePasswordStrength }                             = require('../utils/password');

const router = express.Router();

// ── Generate JWT ──────────────────────────────────────────────────────────────
function generateToken(userId) {
  return jwt.sign({ sub: userId, role: 'commuter' }, process.env.JWT_SECRET, {
    expiresIn : process.env.JWT_EXPIRES_IN || '7d',
    issuer    : 'todago-api',
    audience  : 'todago-app',
  });
}

function sanitizeUser(user) {
  const { password_hash, salt, ...safe } = user;
  return safe;
}

const MAX_PROFILE_PHOTO_DATA_URL_LENGTH = 750000;

function isProfilePhotoDataUrl(value) {
  if (typeof value !== 'string') return false;
  if (value.length > MAX_PROFILE_PHOTO_DATA_URL_LENGTH) return false;
  return /^data:image\/(jpeg|jpg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(value);
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

    const salt         = generateSalt();
    const passwordHash = await hashPassword(password, salt);
    const userId       = uuidv4();

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

    // ── FIX: Use constant-time comparison to prevent timing attacks
    //         and handle both old (no-salt) and new (with-salt) accounts
    let passwordMatch = false;
    let passwordResetRequired = false;

    if (user) {
      const userSalt = user.salt;

      if (!userSalt || userSalt === 'legacy') {
        // ── Old account: hash was made WITHOUT salt ──────────────────────
        // These users need to reset or re-register.
        // For now: try verifying with just pepper+password (no salt).
        console.log(`[Auth] Legacy account detected for ${email} — no valid salt`);
        passwordResetRequired = true;
      } else {
        // ── New account: proper pepper+salt+bcrypt ───────────────────────
        const passwordResult = await verifyPasswordDetailed(password, user.password_hash, userSalt);
        passwordMatch = passwordResult.match;
        passwordResetRequired = passwordResult.resetRequired;

        if (passwordResult.legacy && passwordResult.match) {
          const newSalt = generateSalt();
          const newHash = await hashPassword(password, newSalt);

          await dbRun(
            'UPDATE users SET password_hash = $1, salt = $2, updated_at = NOW() WHERE id = $3',
            [newHash, newSalt, user.id]
          );
          await dbRun(
            'UPDATE drivers SET password_hash = $1, salt = $2, updated_at = NOW() WHERE user_id = $3 OR email = $4',
            [newHash, newSalt, user.id, email.toLowerCase()]
          ).catch(() => {});
          await dbRun(
            'UPDATE operators SET password_hash = $1, salt = $2, updated_at = NOW() WHERE user_id = $3 OR email = $4',
            [newHash, newSalt, user.id, email.toLowerCase()]
          ).catch(() => {});

          user.password_hash = newHash;
          user.salt = newSalt;
          console.log(`[Auth] Migrated legacy password hash for ${email}`);
        } else if (passwordResult.resetRequired) {
          console.log(`[Auth] Password reset required for legacy hash: ${email}`);
        }
        console.log(`[Auth] Login attempt for ${email} — match: ${passwordMatch}`);
      }
    } else {
      // Run a dummy bcrypt to prevent timing attacks
      await verifyPasswordDetailed(
        password,
        'v2:$2b$12$rv45F04fsLv5.gOAt41RRevnVbwwjYIGP28gnv4G7tRNQz5TjQ7pC',
        'a1b2c3d4e5f6a7b8c9d0e1f2'
      );
      console.log(`[Auth] Login attempt for unknown email: ${email}`);
    }

    if (!user || !passwordMatch) {
      await dbRun(
        'INSERT INTO login_attempts (email, ip_address, success) VALUES ($1, $2, $3)',
        [email, ip, false]
      ).catch(() => {});
      if (passwordResetRequired) {
        return res.status(409).json({
          success: false,
          code: 'PASSWORD_RESET_REQUIRED',
          message: 'This older account needs a password reset before login.',
        });
      }
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    await dbRun('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
    await dbRun(
      'INSERT INTO login_attempts (email, ip_address, success) VALUES ($1, $2, $3)',
      [email, ip, true]
    ).catch(() => {});

    const token = generateToken(user.id);
    console.log(`[Auth] Login success: ${email} from ${ip}`);

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
// PUT /api/auth/profile-photo
router.put('/profile-photo', requireAuth, [
  body('profilePhotoUrl')
    .custom((value) => value == null || isProfilePhotoDataUrl(String(value).trim()))
    .withMessage('Profile photo must be a JPEG, PNG, or WebP image under 750 KB'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  const profilePhotoUrl = typeof req.body.profilePhotoUrl === 'string'
    ? req.body.profilePhotoUrl.trim()
    : null;

  try {
    await dbRun(
      'UPDATE users SET profile_photo_url = $1, updated_at = NOW() WHERE id = $2',
      [profilePhotoUrl, req.userId]
    );
    const user = await dbGet('SELECT * FROM users WHERE id = $1 AND is_active = true', [req.userId]);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    return res.json({
      success: true,
      message: 'Profile photo updated',
      user: sanitizeUser(user),
    });
  } catch (error) {
    console.error('[Auth] Profile photo update error:', error.message);
    return res.status(500).json({ success: false, message: 'Failed to update profile photo' });
  }
});

// POST /api/auth/logout
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

// ── POST /api/auth/fix-legacy-password ───────────────────────────────────────
// Call this to reset a legacy-salt account's password properly
router.post('/fix-legacy-password', [
  body('email').trim().isEmail().normalizeEmail().withMessage('Valid email required'),
  body('newPassword').isLength({ min: 8 }).withMessage('Password must be 8+ characters'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }
  const { email, newPassword } = req.body;
  try {
    const strengthErrors = validatePasswordStrength(newPassword);
    if (strengthErrors.length > 0) {
      return res.status(400).json({ success: false, message: strengthErrors[0] });
    }
    const user = await dbGet('SELECT id, salt FROM users WHERE email = $1', [email.toLowerCase()]);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const newSalt = generateSalt(); // fresh proper salt
    const newHash = await hashPassword(newPassword, newSalt);
    await dbRun(
      'UPDATE users SET password_hash = $1, salt = $2, updated_at = NOW() WHERE id = $3',
      [newHash, newSalt, user.id]
    );
    await dbRun(
      'UPDATE drivers SET password_hash = $1, salt = $2, updated_at = NOW() WHERE user_id = $3 OR email = $4',
      [newHash, newSalt, user.id, email.toLowerCase()]
    ).catch(() => {});
    await dbRun(
      'UPDATE operators SET password_hash = $1, salt = $2, updated_at = NOW() WHERE user_id = $3 OR email = $4',
      [newHash, newSalt, user.id, email.toLowerCase()]
    ).catch(() => {});
    console.log(`[Auth] Password fixed for legacy account: ${email}`);
    return res.json({ success: true, message: 'Password updated. You can now log in.' });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Failed to update password' });
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
    req.userId   = payload.sub;
    req.userRole = payload.role;
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
}

module.exports = router;
module.exports.requireAuth = requireAuth;
