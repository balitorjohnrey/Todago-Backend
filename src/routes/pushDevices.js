const express = require('express');
const { pool } = require('../db/database');
const { requireAuth } = require('./auth');

const router = express.Router();
const roles = new Set(['passenger', 'driver', 'operator', 'admin', 'payout_admin']);

function validateDevice(req, res, next) {
  const role = req.userRole === 'commuter' ? 'passenger' : req.userRole;
  if (!roles.has(role) || typeof req.userId !== 'string' || !req.userId) {
    return res.status(403).json({ success: false, message: 'Unsupported account' });
  }
  if (typeof req.body?.token !== 'string' || !/^[A-Za-z0-9_:-]{20,4096}$/.test(req.body.token)) {
    return res.status(422).json({ success: false, message: 'Invalid push token' });
  }
  req.pushRole = role;
  next();
}

router.put('/', requireAuth, validateDevice, async (req, res, next) => {
  try {
    await pool.query(`
      INSERT INTO push_devices (token, user_role, user_id) VALUES ($1, $2, $3)
      ON CONFLICT (token) DO UPDATE SET user_role = EXCLUDED.user_role,
        user_id = EXCLUDED.user_id, updated_at = NOW()`,
    [req.body.token, req.pushRole, req.userId]);
    return res.status(204).end();
  } catch (error) {
    next(error);
  }
});

router.delete('/', requireAuth, validateDevice, async (req, res, next) => {
  try {
    await pool.query(`
      DELETE FROM push_devices WHERE token = $1 AND user_role = $2 AND user_id = $3`,
    [req.body.token, req.pushRole, req.userId]);
    return res.status(204).end();
  } catch (error) {
    next(error);
  }
});

module.exports = router;
