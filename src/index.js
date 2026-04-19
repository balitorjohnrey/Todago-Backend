require('dotenv').config();

const express   = require('express');
const helmet    = require('helmet');
const cors      = require('cors');
const morgan    = require('morgan');
const rateLimit = require('express-rate-limit');

const { initializeDatabase } = require('./db/database');
const authRoutes             = require('./routes/auth');          // Commuter/passenger
const driverAuthRoutes       = require('./routes/driver_auth');   // Driver
const operatorAuthRoutes     = require('./routes/operator_auth'); // Operator

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Trust proxy (Railway/Render) ──────────────────────────────────────────────
app.set('trust proxy', 1);

// ── Security ──────────────────────────────────────────────────────────────────
app.use(helmet());
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS'],
               allowedHeaders: ['Content-Type','Authorization'] }));

// ── Rate limiting ─────────────────────────────────────────────────────────────
const apiLimit = rateLimit({ windowMs: 15*60*1000, max: 200, standardHeaders: true, legacyHeaders: false,
  message: { success: false, message: 'Too many requests. Try again later.' } });

const authLimit = rateLimit({ windowMs: 15*60*1000, max: 20,
  message: { success: false, message: 'Too many attempts. Try again in 15 minutes.' } });

app.use('/api', apiLimit);
app.use('/api/auth/login',          authLimit);
app.use('/api/auth/register',       authLimit);
app.use('/api/driver/login',        authLimit);
app.use('/api/driver/register',     authLimit);
app.use('/api/operator/login',      authLimit);
app.use('/api/operator/register',   authLimit);

// ── Body parsing ──────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false }));

// ── Logging ───────────────────────────────────────────────────────────────────
if (process.env.NODE_ENV !== 'test') app.use(morgan('combined'));

// ── Routes ────────────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({
  service: 'TodaGo API', version: '1.0.0', status: 'running',
  timestamp: new Date().toISOString(),
}));
app.get('/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));

// Auth routes per role
app.use('/api/auth',     authRoutes);         // Commuter: /api/auth/register, /login
app.use('/api/driver',   driverAuthRoutes);   // Driver:   /api/driver/register, /login
app.use('/api/operator', operatorAuthRoutes); // Operator: /api/operator/register, /login

// ── 404 ───────────────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ success: false, message: 'Route not found' }));

// ── Error handler ─────────────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('[Server Error]', err.message);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// ── Start ─────────────────────────────────────────────────────────────────────
async function start() {
  try {
    await initializeDatabase();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`\n🚀 TodaGo API is LIVE on port ${PORT}`);
      console.log(`   Env: ${process.env.NODE_ENV || 'development'}\n`);
      console.log('   Routes:');
      console.log('   POST /api/auth/register     ← Commuter sign up');
      console.log('   POST /api/auth/login        ← Commuter login');
      console.log('   POST /api/driver/register   ← Driver sign up');
      console.log('   POST /api/driver/login      ← Driver login (TODA # + plate + password)');
      console.log('   POST /api/operator/register ← Operator sign up');
      console.log('   POST /api/operator/login    ← Operator login (TODA ID + email + password)\n');
    });
  } catch (error) {
    console.error('[Startup] Failed:', error.message);
    process.exit(1);
  }
}

start();