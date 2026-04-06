require('dotenv').config();

const express    = require('express');
const helmet     = require('helmet');
const cors       = require('cors');
const morgan     = require('morgan');
const rateLimit  = require('express-rate-limit');

const { initializeDatabase } = require('./db/database');
const authRoutes             = require('./routes/auth');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Trust proxy (required for Railway / Render / Heroku) ─────────────────────
app.set('trust proxy', 1);

// ─── Security Headers ─────────────────────────────────────────────────────────
app.use(helmet());

// ─── CORS — allow any device / any network ────────────────────────────────────
app.use(cors({
  origin      : '*',       // Allow all origins (Flutter app on any network)
  methods     : ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ─── Rate Limiting ────────────────────────────────────────────────────────────
// General API: 200 requests per 15 min
app.use('/api', rateLimit({
  windowMs       : 15 * 60 * 1000,
  max            : 200,
  standardHeaders: true,
  legacyHeaders  : false,
  message        : { success: false, message: 'Too many requests. Please try again later.' },
}));

// Auth endpoints: strict — 20 attempts per 15 min (brute force protection)
app.use('/api/auth/login', rateLimit({
  windowMs: 15 * 60 * 1000,
  max     : 20,
  message : { success: false, message: 'Too many login attempts. Try again in 15 minutes.' },
}));

app.use('/api/auth/register', rateLimit({
  windowMs: 60 * 60 * 1000,  // 1 hour
  max     : 10,
  message : { success: false, message: 'Too many registration attempts. Try again later.' },
}));

// ─── Body Parsing ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false }));

// ─── Logging ──────────────────────────────────────────────────────────────────
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('combined'));
}

// ─── Routes ───────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    service  : 'TodaGo API',
    version  : '1.0.0',
    status   : 'running',
    timestamp: new Date().toISOString(),
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

app.use('/api/auth', authRoutes);

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

// ─── Global Error Handler ─────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('[Server Error]', err.message);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// ─── Start ────────────────────────────────────────────────────────────────────
async function start() {
  try {
    await initializeDatabase();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`\n🚀 TodaGo API is LIVE`);
      console.log(`   Port      : ${PORT}`);
      console.log(`   Env       : ${process.env.NODE_ENV || 'development'}`);
      console.log(`   Health    : /health\n`);
    });
  } catch (error) {
    console.error('[Startup] Failed:', error.message);
    process.exit(1);
  }
}

start();