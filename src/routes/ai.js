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

const FAQS = [
  {
    question: 'How do I book a ride?',
    answer:
      'Tap Book Now, choose your destination, confirm the route and fare, choose a service type, then select a driver. You can track the trip after the request is accepted.',
    keywords: ['book', 'ride', 'request', 'destination', 'driver'],
    roles: ['passenger'],
  },
  {
    question: 'How do I cancel a trip?',
    answer:
      'Open the active trip or waiting screen and tap Cancel Trip. If a driver was already assigned, TodaGo notifies the driver and releases them for other rides.',
    keywords: ['cancel', 'cancellation', 'trip', 'ride'],
    roles: ['passenger'],
  },
  {
    question: 'How do fares work?',
    answer:
      'TodaGo shows the estimated fare before confirmation. The fare is based on route distance, service type, and the minimum base fare. Cash is currently the default payment flow in the app.',
    keywords: ['fare', 'price', 'pricing', 'cost', 'payment'],
    roles: ['passenger', 'driver'],
  },
  {
    question: 'How do I rate my driver?',
    answer:
      'After a completed trip, the rating screen appears. Choose 1 to 5 stars, select quick feedback tags, and submit. You can also rate completed trips from Past Trips if you skipped it.',
    keywords: ['rate', 'rating', 'stars', 'feedback', 'review'],
    roles: ['passenger'],
  },
  {
    question: 'Where can I see my past trips?',
    answer:
      'Go to Bookings, then open the Past tab. Pull down to refresh if your latest completed or cancelled trip is not visible yet.',
    keywords: ['past', 'history', 'bookings', 'completed', 'cancelled'],
    roles: ['passenger'],
  },
  {
    question: 'How do I upload a profile picture?',
    answer:
      'Open Profile and tap your avatar or Upload Photo. Choose an image from your gallery. The app syncs it to your account so it stays after login.',
    keywords: ['profile', 'picture', 'photo', 'avatar', 'upload'],
    roles: ['passenger', 'driver'],
  },
  {
    question: 'How do I go online as a driver?',
    answer:
      'On the driver dashboard, tap the large GO ONLINE button. When it turns green, you are available and TodaGo checks for incoming ride requests.',
    keywords: ['online', 'offline', 'available', 'driver', 'go online'],
    roles: ['driver'],
  },
  {
    question: 'How do I accept a ride request?',
    answer:
      'When a ride request popup appears, review the pickup, destination, fare, and service type. Tap ACCEPT to take the ride or DECLINE if you cannot take it.',
    keywords: ['accept', 'request', 'decline', 'popup', 'ride'],
    roles: ['driver'],
  },
  {
    question: 'How do driver earnings work?',
      answer:
      'Driver earnings are shown after completing a trip. The payout summary uses the passenger fare for that completed ride.',
    keywords: ['earnings', 'income', 'payout', 'fare'],
    roles: ['driver'],
  },
  {
    question: 'How do I complete a trip?',
    answer:
      'After pickup, follow the active trip screen. When the passenger reaches the destination, tap Complete Trip. The app then records the completed status and shows earnings.',
    keywords: ['complete', 'finish', 'end', 'trip', 'destination'],
    roles: ['driver'],
  },
  {
    question: 'How can I improve my driver rating?',
    answer:
      'Arrive on time, confirm the passenger name, drive safely, keep the vehicle clean, and politely remind passengers they can rate the trip after completion.',
    keywords: ['improve', 'rating', 'low', 'stars', 'feedback'],
    roles: ['driver'],
  },
  {
    question: 'What should I do if something goes wrong?',
    answer:
      'For app issues, check your internet connection, refresh the current screen, and try again. For trip safety or account problems, contact TodaGo support or your operator.',
    keywords: ['problem', 'issue', 'error', 'support', 'help', 'wrong'],
    roles: ['passenger', 'driver'],
  },
];

function normalize(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function roleFaqs(role) {
  const normalizedRole = role === 'driver' ? 'driver' : 'passenger';
  return FAQS.filter((faq) => faq.roles.includes(normalizedRole));
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

function fallbackAnswer(faqs) {
  const topics = faqs.slice(0, 4).map((faq) => faq.question).join(', ');
  return `I can only answer TodaGo FAQs. Try asking about: ${topics}.`;
}

function answerFaq(message, role) {
  const normalized = normalize(message);
  const faqs = roleFaqs(role);

  if (!normalized) return fallbackAnswer(faqs);

  let best = null;
  let bestScore = 0;

  for (const faq of faqs) {
    let score = 0;
    const faqQuestion = normalize(faq.question);

    if (faqQuestion === normalized) score += 8;
    if (faqQuestion.includes(normalized) || normalized.includes(faqQuestion)) score += 4;

    for (const keyword of faq.keywords) {
      if (normalized.includes(normalize(keyword))) score += 2;
    }

    if (score > bestScore) {
      best = faq;
      bestScore = score;
    }
  }

  return best && bestScore >= 2 ? best.answer : fallbackAnswer(faqs);
}

router.post('/chat', requireAuth, (req, res) => {
  const message = extractMessage(req.body);
  const role = req.userRole === 'driver' ? 'driver' : 'passenger';
  const text = answerFaq(message, role);

  return res.json({
    success: true,
    role,
    content: [{ type: 'text', text }],
    text,
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
