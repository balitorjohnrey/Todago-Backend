/**
 * TodaGo Chatbot FAQ route.
 *
 * Endpoint: POST /api/ai/chat
 * Auth:     Bearer token (passenger or driver JWT)
 *
 * This route is intentionally FAQ-only. It does not call an external model.
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const { parseRideIntent } = require('../services/gemini');
const { dataset, matchFaq, fallbackAnswer, normalizeRole, referencesFor } = require('../services/faq');

const router = express.Router();

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Authorization required' });
  }

  try {
    const payload = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET, {
      issuer: 'todago-api',
      audience: 'todago-app',
    });
    req.userId = payload.sub;
    req.userRole = payload.role;
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
}

function extractMessage(body) {
  if (typeof body?.message === 'string') return body.message;
  if (typeof body?.prompt === 'string') return body.prompt;

  const messages = Array.isArray(body?.messages) ? body.messages : [];
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    const msg = messages[i];
    if (msg?.role === 'user' && typeof msg.content === 'string') return msg.content;
  }

  return '';
}

router.post('/chat', requireAuth, (req, res) => {
  const message = extractMessage(req.body);
  const role = normalizeRole(req.userRole);
  const match = matchFaq(message, role);
  const text = match ? match.answer : fallbackAnswer(role);

  return res.json({
    success: true,
    role,
    content: [{ type: 'text', text }],
    text,
    datasetVersion: dataset.version,
    faq: match ? {
      id: match.id, category: match.category,
      reviewedAt: match.reviewedAt, sources: match.sources,
      onlineReferences: referencesFor(match),
    } : null,
  });
});

router.post('/ride-intent', requireAuth, async (req, res) => {
  const message = extractMessage(req.body);
  if (!message.trim()) {
    return res.status(400).json({
      success: false,
      message: 'Message is required',
    });
  }

  if (req.userRole === 'driver' || req.userRole === 'operator' || req.userRole === 'admin') {
    return res.status(403).json({
      success: false,
      message: 'Smart ride booking is available for passengers only',
    });
  }

  try {
    const intent = await parseRideIntent(message, {
      role: req.userRole || 'passenger',
    });

    return res.json({
      success: true,
      intent,
    });
  } catch (err) {
    console.error('[AI] Ride intent error:', err.message);
    return res.status(500).json({
      success: false,
      message: 'Could not understand ride request',
    });
  }
});

module.exports = router;
