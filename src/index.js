require('dotenv').config();

const express   = require('express');
const helmet    = require('helmet');
const cors      = require('cors');
const morgan    = require('morgan');
const rateLimit = require('express-rate-limit');

const { initializeDatabase } = require('./db/database');
const authRoutes         = require('./routes/auth');
const driverAuthRoutes   = require('./routes/driver_auth');
const operatorAuthRoutes = require('./routes/operator_auth');
const subscriptionRoutes = require('./routes/subscription');
const tripRoutes          = require('./routes/trips');

const app  = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);
app.use(helmet());
app.use(cors({
  origin: '*',
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
}));

// Rate limiting
const authLimit = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  message: { success: false, message: 'Too many attempts. Try again in 15 minutes.' },
});
app.use('/api/auth/login',        authLimit);
app.use('/api/auth/register',     authLimit);
app.use('/api/driver/login',      authLimit);
app.use('/api/driver/register',   authLimit);
app.use('/api/operator/login',    authLimit);
app.use('/api/operator/register', authLimit);

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false }));
if (process.env.NODE_ENV !== 'test') app.use(morgan('combined'));

// ── Health ──────────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({
  service: 'TodaGo API', version: '1.0.0', status: 'running',
  timestamp: new Date().toISOString(),
  routes: {
    commuter: ['/api/auth/register', '/api/auth/login', '/api/auth/me'],
    driver:   ['/api/driver/register', '/api/driver/login', '/api/driver/me', '/api/driver/status'],
    operator: ['/api/operator/register', '/api/operator/login', '/api/operator/me', '/api/operator/drivers', '/api/operator/stats'],
    subscription: ['/api/subscriptions/plans', '/api/subscriptions/subscribe', '/api/subscriptions/my', '/api/subscriptions/commission', '/api/subscriptions/ledger', '/api/subscriptions/pay-commission'],
  },
}));
app.get('/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));

// ── Routes ───────────────────────────────────────────────────────────────────
app.use('/api/auth',          authRoutes);
app.use('/api/driver',        driverAuthRoutes);
app.use('/api/operator',      operatorAuthRoutes);
app.use('/api/subscriptions', subscriptionRoutes);
app.use('/api/trips',         tripRoutes);

// ── 404 ──────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Route not found: ${req.method} ${req.originalUrl}`,
    available_routes: [
      'POST /api/auth/register',
      'POST /api/auth/login',
      'POST /api/driver/register',
      'POST /api/driver/login',
      'POST /api/operator/register',
      'POST /api/operator/login',
      'GET  /api/subscriptions/plans',
      'GET  /api/trips/drivers/online',
      'POST /api/trips/request',
    ],
  });
});

// ── Error handler ─────────────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('[Server Error]', err.message);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// ── Start ────────────────────────────────────────────────────────────────────
async function start() {
  try {
    await initializeDatabase();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`\n🚀 TodaGo API LIVE on port ${PORT}`);
      console.log(`   POST /api/auth/register       ← Commuter sign up`);
      console.log(`   POST /api/auth/login          ← Commuter login`);
      console.log(`   POST /api/driver/register     ← Driver sign up`);
      console.log(`   POST /api/driver/login        ← Driver login`);
      console.log(`   POST /api/operator/register   ← Operator sign up`);
      console.log(`   POST /api/operator/login      ← Operator login`);
      console.log(`   GET  /api/subscriptions/plans ← View plans\n`);
    });
  } catch (error) {
    console.error('[Startup] Failed:', error.message);
    process.exit(1);
  }
}

start();