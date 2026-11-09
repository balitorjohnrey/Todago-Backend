const express = require('express');
const rateLimit = require('express-rate-limit');
const { requireAuth } = require('./auth');
const service = require('../services/merchantQrWallet');
const qrPool = require('../services/passengerQrPool');

const router = express.Router();
const referenceLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 20,
  keyGenerator: req => req.userId, standardHeaders: true, legacyHeaders: false,
  message: { success: false, message: 'Please wait before submitting another reference.' } });

function passenger(req, res, next) {
  if (!['passenger', 'commuter'].includes(req.userRole)) return res.status(403).json({ success: false, message: 'Passenger access only' });
  next();
}

function endpoint(action) {
  return async (req, res) => {
    try {
      const result = await action(req);
      return res.json({ success: true, ...result });
    } catch (error) {
      return res.status(error.statusCode || 500).json({ success: false,
        message: error.statusCode ? error.message : 'Unable to process this top-up. Please try again.' });
    }
  };
}

router.get('/configuration', requireAuth, passenger, endpoint(async () => {
  if (qrPool.enabled()) return { available: qrPool.ready(), qrMode: 'passenger_pool', testMode: false };
  const ready = service.configuration().ready;
  return { available: ready, minimumTopUp: 20, qrPageUrl: ready ? service.QR_PAGE_URL : null };
}));

router.get('/passenger-qr', requireAuth, passenger, endpoint(req => qrPool.getPassengerQr(req.userId)));
router.post('/top-ups', requireAuth, passenger, endpoint(req => {
  if (qrPool.enabled()) throw Object.assign(new Error('Update TodaGo to use your passenger QR.'), { statusCode: 409 });
  return service.createTopUp(req.userId, req.body.amount);
}));
router.get('/top-ups/:transactionId', requireAuth, passenger,
  endpoint(req => service.readTopUp(req.userId, req.params.transactionId)));
router.post('/top-ups/:transactionId/reference', requireAuth, passenger, referenceLimit,
  endpoint(req => service.submitReference(req.userId, req.params.transactionId, req.body.reference)));

router.post('/webhook', async (req, res) => {
  if (!service.verifyLiveSignature(req.rawBody, req.get('Paymongo-Signature'))) {
    return res.status(401).json({ success: false, message: 'Invalid webhook signature' });
  }
  try {
    const handled = qrPool.enabled()
      ? await qrPool.receivePaidEvent(req.body?.data) ||
        (service.configuration().ready && await service.receivePaidEvent(req.body?.data))
      : await service.receivePaidEvent(req.body?.data);
    if (handled) await qrPool.recoverApprovedPayment();
    return res.json({ success: true, ignored: !handled });
  } catch (error) {
    // Database/configuration failures remain retryable; never log receipt data.
    return res.status(error.statusCode || 500).json({ success: false });
  }
});

module.exports = router;
