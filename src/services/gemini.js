const DEFAULT_MODEL = 'gemini-2.5-flash';

const rideIntentSchema = {
  type: 'object',
  properties: {
    intent: {
      type: 'string',
      enum: ['book_ride', 'schedule_ride', 'faq', 'other'],
      description: 'The user intent. Use book_ride only when the user wants to start a ride booking.',
    },
    confidence: {
      type: 'number',
      minimum: 0,
      maximum: 1,
      description: 'Confidence that the detected intent and fields are correct.',
    },
    pickupMode: {
      type: 'string',
      enum: ['current_location', 'specified_location', 'unknown'],
      description: 'How the pickup location was expressed by the user.',
    },
    pickupQuery: {
      type: 'string',
      description: 'Pickup place search text when specified, otherwise an empty string.',
    },
    destinationQuery: {
      type: 'string',
      description: 'Short place search text for the destination, otherwise an empty string.',
    },
    serviceType: {
      type: 'string',
      enum: ['solo', 'shared', 'express', 'unknown'],
      description: 'Requested service type, or unknown if not provided.',
    },
    scheduledForText: {
      type: 'string',
      description: 'Natural language schedule text if this is a scheduled ride, otherwise an empty string.',
    },
    needsConfirmation: {
      type: 'boolean',
      description: 'True when the app should ask the user to confirm before continuing.',
    },
    reply: {
      type: 'string',
      description: 'A short, user-facing confirmation or clarification message.',
    },
  },
  required: [
    'intent',
    'confidence',
    'pickupMode',
    'pickupQuery',
    'destinationQuery',
    'serviceType',
    'scheduledForText',
    'needsConfirmation',
    'reply',
  ],
};

function normalizeServiceType(value) {
  const s = String(value || '').toLowerCase().replace(/[-_\s]/g, '');
  if (s.includes('express') || s.includes('priority') || s.includes('fast')) return 'express';
  if (s.includes('shared') || s.includes('share')) return 'shared';
  if (s.includes('solo') || s.includes('private') || s.includes('alone')) return 'solo';
  return 'unknown';
}

function sanitizeIntent(value) {
  const intent = value && typeof value === 'object' ? value : {};
  const rawIntent = ['book_ride', 'schedule_ride', 'faq', 'other'].includes(intent.intent)
    ? intent.intent
    : 'other';
  const destinationQuery = String(intent.destinationQuery || '').trim();
  const pickupMode = ['current_location', 'specified_location', 'unknown'].includes(intent.pickupMode)
    ? intent.pickupMode
    : 'unknown';
  const serviceType = normalizeServiceType(intent.serviceType);
  const confidence = Number(intent.confidence);

  let reply = String(intent.reply || '').trim();
  if (!reply) {
    reply = destinationQuery
      ? `I can help book a ride to ${destinationQuery}. Please confirm before I continue.`
      : 'Where would you like to go?';
  }

  return {
    intent: rawIntent,
    confidence: Number.isFinite(confidence) ? Math.max(0, Math.min(1, confidence)) : 0,
    pickupMode,
    pickupQuery: String(intent.pickupQuery || '').trim(),
    destinationQuery,
    serviceType,
    scheduledForText: String(intent.scheduledForText || '').trim(),
    needsConfirmation: intent.needsConfirmation !== false,
    reply,
  };
}

function parseFallbackRideIntent(message) {
  const text = String(message || '').trim();
  const bookingWords = /(book|ride|trip|take me|bring me|go to|going to|to\s+)/i;
  const hasBookingIntent = bookingWords.test(text);

  if (!hasBookingIntent) {
    return sanitizeIntent({
      intent: 'other',
      confidence: 0.25,
      reply: '',
    });
  }

  const patterns = [
    /(?:book|request|find|get)\s+(?:me\s+)?(?:a\s+)?(?:solo|shared|express|toda-express)?\s*(?:ride|trip)?\s*(?:to|going to|for)\s+(.+)/i,
    /(?:take me|bring me|go|going|ride|trip)\s+to\s+(.+)/i,
    /\bto\s+(.+)/i,
  ];

  let destination = '';
  for (const pattern of patterns) {
    const match = pattern.exec(text);
    if (match?.[1]) {
      destination = match[1];
      break;
    }
  }

  destination = destination
    .replace(/\b(from|using|with|please|now|today|current location|my location)\b.*$/i, '')
    .replace(/[?.!]+$/g, '')
    .trim();

  const serviceType = normalizeServiceType(text);
  const pickupMode = /(current location|my location|here|where i am)/i.test(text)
    ? 'current_location'
    : 'unknown';

  return sanitizeIntent({
    intent: destination ? 'book_ride' : 'other',
    confidence: destination ? 0.62 : 0.35,
    pickupMode,
    destinationQuery: destination,
    serviceType,
    needsConfirmation: true,
    reply: destination
      ? `I can help book a ride to ${destination}. Tap Continue booking to confirm.`
      : 'Where would you like to go?',
  });
}

function buildPrompt(message, context = {}) {
  return [
    'You are TodaGo ride intent parser for a tricycle hailing app in Panabo City, Philippines.',
    'Extract ride booking details from the user message.',
    'Rules:',
    '- Use book_ride only when the user is asking to start a ride now.',
    '- Use schedule_ride only when the user clearly asks to book for a later date or time.',
    '- If the pickup is "my current location", "here", or implied by "from my current location", set pickupMode to current_location.',
    '- If destination is missing or vague, leave destinationQuery empty and ask a short clarification.',
    '- Do not invent place names. Keep destinationQuery short and searchable.',
    '- serviceType must be solo, shared, express, or unknown.',
    '- The app will ask confirmation before any booking action.',
    '',
    `User role: ${context.role || 'passenger'}`,
    `User message: ${message}`,
  ].join('\n');
}

function buildGeminiPayload(message, context, legacyFormat = false) {
  const generationConfig = legacyFormat
    ? {
        temperature: 0.1,
        maxOutputTokens: 512,
        responseMimeType: 'application/json',
        responseSchema: rideIntentSchema,
      }
    : {
        temperature: 0.1,
        maxOutputTokens: 512,
        responseFormat: {
          text: {
            mimeType: 'application/json',
            schema: rideIntentSchema,
          },
        },
      };

  return {
    contents: [
      {
        parts: [{ text: buildPrompt(message, context) }],
      },
    ],
    generationConfig,
  };
}

async function callGemini(message, context) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return null;

  const model = process.env.GEMINI_MODEL || DEFAULT_MODEL;
  const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const postPayload = (payload) => fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-goog-api-key': apiKey,
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    let res = await postPayload(buildGeminiPayload(message, context));
    if (res.status === 400) {
      res = await postPayload(buildGeminiPayload(message, context, true));
    }

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`Gemini request failed (${res.status}): ${body.slice(0, 200)}`);
    }

    const data = await res.json();
    const text = data?.candidates?.[0]?.content?.parts
      ?.map((part) => part.text || '')
      .join('')
      .trim();

    if (!text) return null;
    return JSON.parse(text);
  } finally {
    clearTimeout(timeout);
  }
}

async function parseRideIntent(message, context = {}) {
  try {
    const geminiResult = await callGemini(message, context);
    if (geminiResult) return sanitizeIntent(geminiResult);
  } catch (err) {
    console.error('[Gemini] Ride intent fallback:', err.message);
  }

  return parseFallbackRideIntent(message);
}

module.exports = {
  parseRideIntent,
};
