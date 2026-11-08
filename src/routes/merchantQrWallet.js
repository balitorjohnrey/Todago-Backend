const express = require('express');
const rateLimit = require('express-rate-limit');
const { requireAuth } = require('./auth');
const service = require('../services/merchantQrWallet');

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
  const ready = service.configuration().ready;
  return { available: ready, minimumTopUp: 20, qrPageUrl: ready ? service.QR_PAGE_URL : null };
}));

router.post('/top-ups', requireAuth, passenger, endpoint(req => service.createTopUp(req.userId, req.body.amount)));
router.get('/top-ups/:transactionId', requireAuth, passenger,
  endpoint(req => service.readTopUp(req.userId, req.params.transactionId)));
router.post('/top-ups/:transactionId/reference', requireAuth, passenger, referenceLimit,
  endpoint(req => service.submitReference(req.userId, req.params.transactionId, req.body.reference)));

router.post('/webhook', async (req, res) => {
  if (!service.verifyLiveSignature(req.rawBody, req.get('Paymongo-Signature'))) {
    return res.status(401).json({ success: false, message: 'Invalid webhook signature' });
  }
  try {
    const handled = await service.receivePaidEvent(req.body?.data);
    return res.json({ success: true, ignored: !handled });
  } catch (error) {
    // Database/configuration failures remain retryable; never log receipt data.
    return res.status(error.statusCode || 500).json({ success: false });
  }
});

module.exports = router;
