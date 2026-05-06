require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const { initializeDatabase } = require('./db/database');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Routes ────────────────────────────────────────────────────────────────────
// FIX: auth exports both router and requireAuth, so we import only the router here
const authRouter         = require('./routes/auth');          // the Express router
const driverAuthRouter   = require('./routes/driver_auth');
const operatorAuthRouter = require('./routes/operator_auth');
const tripsRouter        = require('./routes/trips');
const subscriptionsRouter = require('./routes/subscriptions');

app.use('/api/auth',          authRouter);
app.use('/api/driver',        driverAuthRouter);
app.use('/api/operator',      operatorAuthRouter);
app.use('/api/trips',         tripsRouter);
app.use('/api/subscriptions', subscriptionsRouter);

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