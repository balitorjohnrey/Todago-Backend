const express = require('express');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const { dbRun, dbGet } = require('../db/database');

const router = express.Router();

const FARE_BANDS = [
  { min_fuel_price: 20, max_fuel_price: 29.99, regular_fare: 10, discounted_fare: 8 },
  { min_fuel_price: 30, max_fuel_price: 39.99, regular_fare: 12, discounted_fare: 10 },
  { min_fuel_price: 40, max_fuel_price: 49.99, regular_fare: 13, discounted_fare: 11 },
  { min_fuel_price: 50, max_fuel_price: 59.99, regular_fare: 14, discounted_fare: 12 },
  { min_fuel_price: 60, max_fuel_price: 69.99, regular_fare: 15, discounted_fare: 13 },
  { min_fuel_price: 70, max_fuel_price: 79.99, regular_fare: 16, discounted_fare: 14 },
  { min_fuel_price: 80, max_fuel_price: 89.99, regular_fare: 17, discounted_fare: 15 },
  { min_fuel_price: 90, max_fuel_price: 99.99, regular_fare: 18, discounted_fare: 16 },
  { min_fuel_price: 100, max_fuel_price: null, regular_fare: 20, discounted_fare: 18 },
];

const DEFAULT_FUEL_PRICE = 80.0;
const DEFAULT_PREMIUM_MULTIPLIER = 1.3;

function requireAdminAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Admin authorization required' });
  }

  try {
    const payload = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET, {
      issuer: 'todago-api',
      audience: 'todago-app',
    });
    if (payload.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Admin access only' });
    }
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired admin token' });
  }
}

function bandForFuelPrice(fuelPrice) {
  return FARE_BANDS.find((band) =>
    fuelPrice >= band.min_fuel_price &&
    (band.max_fuel_price == null || fuelPrice <= band.max_fuel_price)
  ) || FARE_BANDS[0];
}

async function readNumericSetting(key, fallback) {
  const row = await dbGet('SELECT value FROM app_settings WHERE key = $1', [key]);
  const value = Number.parseFloat(row?.value);
  return Number.isFinite(value) ? value : fallback;
}

async function readFareSettings() {
  const fuelPrice = await readNumericSetting(
    'fare_fuel_price_per_liter',
    DEFAULT_FUEL_PRICE
  );
  const premiumMultiplier = await readNumericSetting(
    'fare_premium_multiplier',
    DEFAULT_PREMIUM_MULTIPLIER
  );
  const band = bandForFuelPrice(fuelPrice);

  return {
    fuel_price_per_liter: Number(fuelPrice.toFixed(2)),
    premium_multiplier: Number(premiumMultiplier.toFixed(2)),
    regular_fare: band.regular_fare,
    discounted_fare: band.discounted_fare,
    band,
    fare_bands: FARE_BANDS,
  };
}

router.get('/settings', async (_req, res) => {
  try {
    return res.json({ success: true, settings: await readFareSettings() });
  } catch (error) {
    console.error('[Fares] Settings read error:', error.message);
    return res.status(500).json({ success: false, message: 'Unable to load fare settings' });
  }
});

router.patch('/settings', requireAdminAuth, [
  body('fuelPricePerLiter')
    .isFloat({ min: 20 })
    .withMessage('Fuel price must be at least PHP 20.00'),
  body('premiumMultiplier')
    .optional({ nullable: true })
    .isFloat({ min: 1, max: 3 })
    .withMessage('Premium multiplier must be between 1.00 and 3.00'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  const fuelPrice = Number.parseFloat(req.body.fuelPricePerLiter);
  const premiumMultiplier = req.body.premiumMultiplier == null
    ? DEFAULT_PREMIUM_MULTIPLIER
    : Number.parseFloat(req.body.premiumMultiplier);

  try {
    await dbRun(
      `INSERT INTO app_settings (key, value, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (key)
       DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
      ['fare_fuel_price_per_liter', fuelPrice.toFixed(2)]
    );
    await dbRun(
      `INSERT INTO app_settings (key, value, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (key)
       DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
      ['fare_premium_multiplier', premiumMultiplier.toFixed(2)]
    );

    return res.json({
      success: true,
      message: 'Fare settings updated.',
      settings: await readFareSettings(),
    });
  } catch (error) {
    console.error('[Fares] Settings update error:', error.message);
    return res.status(500).json({ success: false, message: 'Unable to update fare settings' });
  }
});

module.exports = router;
