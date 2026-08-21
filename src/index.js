require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const { initializeDatabase } = require('./db/database');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({
  limit: '2mb',
  verify: (req, res, buf, encoding) => {
    if (
      req.originalUrl?.startsWith('/api/trips/paymongo/webhook')
      || req.originalUrl?.startsWith('/api/wallet/paymongo/webhook')
      || req.originalUrl?.startsWith('/api/kyc/persona/webhook')
    ) {
      req.rawBody = Buffer.from(buf || '', encoding || 'utf8');
    }
  },
}));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// ── Routes ────────────────────────────────────────────────────────────────────
// FIX: auth exports both router and requireAuth, so we import only the router here
const authRouter         = require('./routes/auth');          // the Express router
const driverAuthRouter   = require('./routes/driver_auth');
const operatorAuthRouter = require('./routes/operator_auth');
const adminAuthRouter    = require('./routes/admin_auth');
const tripsRouter        = require('./routes/trips');
const walletRouter       = require('./routes/wallet');
const subscriptionsRouter = require('./routes/subscriptions');
const aiRouter = require('./routes/ai');
const migrateRouter = require('./db/migrate');
const faresRouter = require('./routes/fares');
const reportsRouter = require('./routes/reports');
const { router: kycRouter } = require('./routes/kyc');

app.use('/api/migrate',       migrateRouter);
app.use('/api/auth',          authRouter);
app.use('/api/driver',        driverAuthRouter);
app.use('/api/operator',      operatorAuthRouter);
app.use('/api/admin',         adminAuthRouter);
app.use('/api/trips',         tripsRouter);
app.use('/api/wallet',        walletRouter);
app.use('/api/subscriptions', subscriptionsRouter);
app.use('/api/ai',            aiRouter);
app.use('/api/fares',         faresRouter);
app.use('/api/reports',       reportsRouter);
app.use('/api/kyc',           kycRouter);

app.get('/', (req, res) => {
  res.json({
    success: true,
    status: 'ok',
    message: 'TODAGO backend is online',
    health: '/health',
    apiBase: '/api',
    timestamp: new Date().toISOString(),
  });
});

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ── 404 handler ───────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[App] Unhandled error:', err.message);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// ── Start ─────────────────────────────────────────────────────────────────────
async function start() {
  try {
    await initializeDatabase();
    app.listen(PORT, () => {
      console.log(`[App] Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error('[App] Failed to start:', err.message);
    process.exit(1);
  }
}

start();
