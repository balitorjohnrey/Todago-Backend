const express = require('express');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { dbRun, dbGet, dbAll } = require('../db/database');

const router = express.Router();

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Authorization required' });
  }
  try {
    const payload = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET, {
      issuer: 'todago-api',
      audience: 'todago-app',
    });
    req.userId = payload.sub;
    req.userRole = payload.role;
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
}

router.get('/plans', async (req, res) => {
  try {
    const { type } = req.query;
    if (type === 'operator') {
      return res.json({ success: true, plans: [] });
    }

    let sql = `SELECT * FROM subscription_plans
               WHERE is_active = true
                 AND plan_type <> 'operator'`;
    const params = [];
    if (type) {
      sql += ` AND plan_type = $1`;
      params.push(type);
    }
    sql += ` ORDER BY price ASC`;

    const plans = await dbAll(sql, params);
    return res.json({ success: true, plans });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.post('/subscribe', requireAuth, async (req, res) => {
  const { planId, paymentMethod } = req.body;
  if (!planId) {
    return res.status(400).json({ success: false, message: 'planId is required' });
  }
  if (req.userRole === 'operator') {
    return res.status(403).json({
      success: false,
      message: 'Operator subscription plans have been removed.',
    });
  }

  try {
    const plan = await dbGet(
      `SELECT * FROM subscription_plans WHERE plan_id = $1 AND is_active = true`,
      [planId]
    );
    if (!plan || plan.plan_type === 'operator') {
      return res.status(404).json({ success: false, message: 'Plan not found' });
    }

    const roleMap = {
      commuter: 'commuter',
      passenger: 'commuter',
      driver: 'driver',
    };
    if (plan.plan_type !== roleMap[req.userRole]) {
      return res.status(400).json({
        success: false,
        message: `This plan is for ${plan.plan_type}s only`,
      });
    }

    await dbRun(
      `UPDATE subscriptions SET status = 'cancelled'
       WHERE user_id = $1 AND user_type = $2 AND status = 'active'`,
      [req.userId, req.userRole]
    );

    const subId = uuidv4();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + plan.duration_days);

    await dbRun(
      `INSERT INTO subscriptions
        (subscription_id, user_id, user_type, plan_id, status, expires_at, payment_method, amount_paid)
       VALUES ($1,$2,$3,$4,'active',$5,$6,$7)`,
      [
        subId,
        req.userId,
        req.userRole,
        planId,
        expiresAt,
        paymentMethod || 'gcash',
        plan.price,
      ]
    );

    const subscription = await dbGet(
      `SELECT * FROM subscriptions WHERE subscription_id = $1`,
      [subId]
    );
    return res.status(201).json({
      success: true,
      message: `Subscribed to ${plan.plan_name} successfully!`,
      subscription,
      plan,
    });
  } catch (err) {
    console.error('[Subscription] Error:', err.message);
    return res.status(500).json({ success: false, message: 'Subscription failed' });
  }
});

router.get('/my', requireAuth, async (req, res) => {
  try {
    if (req.userRole === 'operator') {
      return res.json({ success: true, subscription: null, hasSubscription: false });
    }

    const subscription = await dbGet(
      `SELECT s.*, p.plan_name, p.price, p.duration_days, p.features, p.plan_type
       FROM subscriptions s
       JOIN subscription_plans p ON p.plan_id = s.plan_id
       WHERE s.user_id = $1 AND s.user_type = $2 AND s.status = 'active'
         AND s.expires_at > NOW()
       ORDER BY s.started_at DESC LIMIT 1`,
      [req.userId, req.userRole]
    );
    return res.json({
      success: true,
      subscription: subscription || null,
      hasSubscription: !!subscription,
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

module.exports = router;
