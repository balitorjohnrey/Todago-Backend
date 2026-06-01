const express = require('express');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const { dbGet, dbAll, pool } = require('../db/database');

const router = express.Router();

const DEFAULT_FUEL_PRICE = 80.0;
const DEFAULT_PREMIUM_MULTIPLIER = 1.3;
const DEFAULT_FARE_BANDS = [
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

function numberOrNull(value) {
  if (value === null || value === undefined || value === '') return null;
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function toFareBand(row) {
  return {
    min_fuel_price: Number.parseFloat(row.min_fuel_price),
    max_fuel_price: row.max_fuel_price == null
      ? null
      : Number.parseFloat(row.max_fuel_price),
    regular_fare: Number.parseFloat(row.regular_fare),
    discounted_fare: Number.parseFloat(row.discounted_fare),
  };
}

async function readNumericSetting(key, fallback) {
  const row = await dbGet('SELECT value FROM app_settings WHERE key = $1', [key]);
  const value = Number.parseFloat(row?.value);
  return Number.isFinite(value) ? value : fallback;
}

async function readFareBands() {
  const rows = await dbAll(
    `SELECT min_fuel_price, max_fuel_price, regular_fare, discounted_fare
     FROM fare_rate_bands
     ORDER BY sort_order ASC`
  ).catch(() => []);

  if (!rows.length) return DEFAULT_FARE_BANDS;
  return rows.map(toFareBand);
}

function bandForFuelPrice(fuelPrice, bands) {
  return bands.find((band) =>
    fuelPrice >= band.min_fuel_price &&
    (band.max_fuel_price == null || fuelPrice <= band.max_fuel_price)
  ) || bands[0] || DEFAULT_FARE_BANDS[0];
}

async function readFareSettings() {
  const [fuelPrice, premiumMultiplier, fareBands] = await Promise.all([
    readNumericSetting('fare_fuel_price_per_liter', DEFAULT_FUEL_PRICE),
    readNumericSetting('fare_premium_multiplier', DEFAULT_PREMIUM_MULTIPLIER),
    readFareBands(),
  ]);
  const band = bandForFuelPrice(fuelPrice, fareBands);

  return {
    fuel_price_per_liter: Number(fuelPrice.toFixed(2)),
    premium_multiplier: Number(premiumMultiplier.toFixed(2)),
    regular_fare: band.regular_fare,
    discounted_fare: band.discounted_fare,
    band,
    fare_bands: fareBands,
  };
}

function parseIncomingBand(raw) {
  const minFuelPrice = numberOrNull(raw.minFuelPrice ?? raw.min_fuel_price);
  const maxFuelPrice = numberOrNull(raw.maxFuelPrice ?? raw.max_fuel_price);
  const regularFare = numberOrNull(raw.regularFare ?? raw.regular_fare);
  const discountedFare = numberOrNull(raw.discountedFare ?? raw.discounted_fare);

  return {
    min_fuel_price: minFuelPrice,
    max_fuel_price: maxFuelPrice,
    regular_fare: regularFare,
    discounted_fare: discountedFare,
  };
}

function validateFareBands(rawBands) {
  if (!Array.isArray(rawBands) || rawBands.length === 0) {
    return { message: 'Fare bands are required' };
  }

  const bands = rawBands.map(parseIncomingBand);
  for (const band of bands) {
    if (band.min_fuel_price == null || band.regular_fare == null || band.discounted_fare == null) {
      return { message: 'Each fare band needs fuel price, regular fare, and discounted fare' };
    }
    if (band.min_fuel_price < 0 || band.regular_fare < 0 || band.discounted_fare < 0) {
      return { message: 'Fare bands cannot contain negative values' };
    }
    if (band.max_fuel_price != null && band.max_fuel_price < band.min_fuel_price) {
      return { message: 'Maximum fuel price cannot be lower than minimum fuel price' };
    }
  }

  bands.sort((a, b) => a.min_fuel_price - b.min_fuel_price);
  return { bands };
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
    .isFloat({ min: 0 })
    .withMessage('Fuel price must be a valid number'),
  body('premiumMultiplier')
    .optional({ nullable: true })
    .isFloat({ min: 1, max: 3 })
    .withMessage('Premium multiplier must be between 1.00 and 3.00'),
  body('fareBands')
    .optional({ nullable: true })
    .isArray({ min: 1 })
    .withMessage('Fare bands must be a list'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, message: errors.array()[0].msg });
  }

  const fuelPrice = Number.parseFloat(req.body.fuelPricePerLiter);
  const premiumMultiplier = req.body.premiumMultiplier == null
    ? DEFAULT_PREMIUM_MULTIPLIER
    : Number.parseFloat(req.body.premiumMultiplier);
  const fareBandValidation = req.body.fareBands == null
    ? null
    : validateFareBands(req.body.fareBands);

  if (fareBandValidation?.message) {
    return res.status(422).json({ success: false, message: fareBandValidation.message });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `INSERT INTO app_settings (key, value, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (key)
       DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
      ['fare_fuel_price_per_liter', fuelPrice.toFixed(2)]
    );
    await client.query(
      `INSERT INTO app_settings (key, value, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (key)
       DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
      ['fare_premium_multiplier', premiumMultiplier.toFixed(2)]
    );

    if (fareBandValidation?.bands) {
      await client.query('DELETE FROM fare_rate_bands');
      for (const [index, band] of fareBandValidation.bands.entries()) {
        await client.query(
          `INSERT INTO fare_rate_bands
             (sort_order, min_fuel_price, max_fuel_price, regular_fare, discounted_fare, updated_at)
           VALUES ($1,$2,$3,$4,$5,NOW())`,
          [
            index + 1,
            band.min_fuel_price.toFixed(2),
            band.max_fuel_price == null ? null : band.max_fuel_price.toFixed(2),
            band.regular_fare.toFixed(2),
            band.discounted_fare.toFixed(2),
          ]
        );
      }
    }

    await client.query('COMMIT');
    return res.json({
      success: true,
      message: 'Fare settings updated.',
      settings: await readFareSettings(),
    });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('[Fares] Settings update error:', error.message);
    return res.status(500).json({ success: false, message: 'Unable to update fare settings' });
  } finally {
    client.release();
  }
});

module.exports = router;
