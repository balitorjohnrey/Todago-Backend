/**
 * Subscription & Commission Routes
 * GET  /api/subscriptions/plans          — List all plans
 * POST /api/subscriptions/subscribe      — Subscribe to a plan
 * GET  /api/subscriptions/my             — Get my active subscription
 * GET  /api/subscriptions/commission     — Get commission rate for current user
 * GET  /api/subscriptions/ledger         — Get commission ledger (operator/driver)
 * POST /api/subscriptions/pay-commission — Mark commission as paid
 */

const express = require('express');
const jwt     = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { dbRun, dbGet, dbAll } = require('../db/database');

const router = express.Router();

// ─── Auth middleware (works for all roles) ────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Authorization required' });
  }
  try {
    const payload = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET, {
      issuer: 'todago-api', audience: 'todago-app',
    });
    req.userId   = payload.sub;
    req.userRole = payload.role; // 'driver' | 'operator' | 'commuter'
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
}

// ─── GET /api/subscriptions/plans ────────────────────────────────────────────
router.get('/plans', async (req, res) => {
  try {
    const { type } = req.query; // ?type=driver | operator | commuter
    let sql = `SELECT * FROM subscription_plans WHERE is_active = true`;
    const params = [];
    if (type) { sql += ` AND plan_type = $1`; params.push(type); }
    sql += ` ORDER BY price ASC`;
    const plans = await dbAll(sql, params);
    return res.json({ success: true, plans });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─── POST /api/subscriptions/subscribe ───────────────────────────────────────
router.post('/subscribe', requireAuth, async (req, res) => {
  const { planId, paymentMethod } = req.body;
  if (!planId) return res.status(400).json({ success: false, message: 'planId is required' });
  try {
    const plan = await dbGet(
      `SELECT * FROM subscription_plans WHERE plan_id = $1 AND is_active = true`, [planId]
    );
    if (!plan) return res.status(404).json({ success: false, message: 'Plan not found' });

    // Check plan matches user type
    const roleMap = { commuter: 'commuter', driver: 'driver', operator: 'operator' };
    if (plan.plan_type !== roleMap[req.userRole]) {
      return res.status(400).json({ success: false, message: `This plan is for ${plan.plan_type}s only` });
    }

    // Cancel any existing active subscription
    await dbRun(
      `UPDATE subscriptions SET status = 'cancelled'
       WHERE user_id = $1 AND user_type = $2 AND status = 'active'`,
      [req.userId, req.userRole]
    );

    // Create new subscription
    const subId = uuidv4();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + plan.duration_days);

    await dbRun(
      `INSERT INTO subscriptions
        (subscription_id, user_id, user_type, plan_id, status, expires_at, payment_method, amount_paid)
       VALUES ($1,$2,$3,$4,'active',$5,$6,$7)`,
      [subId, req.userId, req.userRole, planId, expiresAt,
       paymentMethod || 'gcash', plan.price]
    );

    const sub = await dbGet(`SELECT * FROM subscriptions WHERE subscription_id = $1`, [subId]);
    return res.status(201).json({
      success: true,
      message: `Subscribed to ${plan.plan_name} successfully!`,
      subscription: sub,
      plan,
    });
  } catch (err) {
    console.error('[Subscription] Error:', err.message);
    return res.status(500).json({ success: false, message: 'Subscription failed' });
  }
});

// ─── GET /api/subscriptions/my ────────────────────────────────────────────────
router.get('/my', requireAuth, async (req, res) => {
  try {
    const sub = await dbGet(
      `SELECT s.*, p.plan_name, p.price, p.duration_days, p.features, p.plan_type
       FROM subscriptions s
       JOIN subscription_plans p ON p.plan_id = s.plan_id
       WHERE s.user_id = $1 AND s.user_type = $2 AND s.status = 'active'
         AND s.expires_at > NOW()
       ORDER BY s.started_at DESC LIMIT 1`,
      [req.userId, req.userRole]
    );
    return res.json({ success: true, subscription: sub || null, hasSubscription: !!sub });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─── GET /api/subscriptions/commission ───────────────────────────────────────
router.get('/commission', requireAuth, async (req, res) => {
  try {
    // Check if user has active Pro subscription
    const sub = await dbGet(
      `SELECT p.plan_name FROM subscriptions s
       JOIN subscription_plans p ON p.plan_id = s.plan_id
       WHERE s.user_id = $1 AND s.user_type = $2 AND s.status = 'active'
         AND s.expires_at > NOW()`,
      [req.userId, req.userRole]
    );

    const planType = sub
      ? (sub.plan_name.toLowerCase().includes('pro') ? 'pro' : 'basic')
      : 'none';

    const rate = await dbGet(
      `SELECT * FROM commission_rates
       WHERE user_type = $1 AND plan_type = $2 AND is_active = true`,
      [req.userRole, planType]
    );

    return res.json({
      success: true,
      commission: {
        rate_percent: rate?.rate_percent || 10.00,
        plan_type: planType,
        description: rate?.description || 'Standard commission',
        subscription: sub || null,
      },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─── GET /api/subscriptions/ledger ───────────────────────────────────────────
router.get('/ledger', requireAuth, async (req, res) => {
  try {
    let sql, params;
    if (req.userRole === 'driver') {
      sql = `SELECT * FROM commission_ledger WHERE driver_id = $1 ORDER BY created_at DESC LIMIT 50`;
      params = [req.userId];
    } else if (req.userRole === 'operator') {
      const op = await dbGet(`SELECT toda_id FROM operators WHERE operator_id = $1`, [req.userId]);
      sql = `SELECT * FROM commission_ledger WHERE toda_id = $1 ORDER BY created_at DESC LIMIT 50`;
      params = [op?.toda_id];
    } else {
      return res.status(403).json({ success: false, message: 'Access denied' });
    }

    const ledger = await dbAll(sql, params);
    const totals = ledger.reduce((acc, row) => ({
      gross: acc.gross + parseFloat(row.gross_fare),
      commission: acc.commission + parseFloat(row.commission_amt),
      payout: acc.payout + parseFloat(row.driver_payout),
      pending: acc.pending + (row.status === 'pending' ? parseFloat(row.commission_amt) : 0),
    }), { gross: 0, commission: 0, payout: 0, pending: 0 });

    return res.json({ success: true, ledger, totals });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─── POST /api/subscriptions/pay-commission ───────────────────────────────────
router.post('/pay-commission', requireAuth, async (req, res) => {
  if (!['driver', 'operator'].includes(req.userRole)) {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }
  try {
    let whereClause, params;
    if (req.userRole === 'driver') {
      whereClause = `driver_id = $1`;
      params = [req.userId];
    } else {
      const op = await dbGet(`SELECT toda_id FROM operators WHERE operator_id = $1`, [req.userId]);
      whereClause = `toda_id = $1`;
      params = [op?.toda_id];
    }

    const result = await dbRun(
      `UPDATE commission_ledger
       SET status = 'paid', paid_at = NOW()
       WHERE ${whereClause} AND status = 'pending'
       RETURNING commission_amt`,
      params
    );

    const totalPaid = result.rows.reduce((sum, r) => sum + parseFloat(r.commission_amt), 0);

    return res.json({
      success: true,
      message: `Commission of ₱${totalPaid.toFixed(2)} paid successfully!`,
      total_paid: totalPaid,
      records_updated: result.rowCount,
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Payment failed' });
  }
});

module.exports = router;