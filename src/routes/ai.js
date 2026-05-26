/**
 * AI Chat Proxy — routes/ai.js
 *
 * Uses Google Gemini 1.5 Flash — completely FREE, no credit card needed.
 * Free tier: 1,500 requests/day · 15 requests/minute
 *
 * SETUP:
 * 1. Get free API key at https://aistudio.google.com/app/apikey
 * 2. Add to Railway environment variables:
 *       GEMINI_API_KEY = AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXX
 *
 * Endpoint: POST /api/ai/chat
 * Auth:     Bearer token (passenger or driver JWT)
 */

const express = require('express');
const jwt     = require('jsonwebtoken');

const router = express.Router();

// ── Gemini model + base URL ───────────────────────────────────────────────────
const GEMINI_MODEL = 'gemini-1.5-flash';
const GEMINI_URL   = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;

// ── Auth middleware (supports both passenger and driver tokens) ───────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Authorization required' });
  }
  try {
    const payload = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET, {
      issuer: 'todago-api', audience: 'todago-app',
    });
    req.userId   = payload.sub;
    req.userRole = payload.role;
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
}

// ── Convert Anthropic-style messages → Gemini format ─────────────────────────
// Anthropic: [{ role: 'user'|'assistant', content: 'text' }]
// Gemini:    [{ role: 'user'|'model',     parts: [{ text: 'text' }] }]
function toGeminiMessages(messages) {
  return messages.map((m) => ({
    role:  m.role === 'assistant' ? 'model' : 'user',
    parts: [{ text: m.content }],
  }));
}

// ── POST /api/ai/chat ─────────────────────────────────────────────────────────
router.post('/chat', requireAuth, async (req, res) => {
  try {
    const { messages, system, max_tokens } = req.body;

    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'messages array is required and must not be empty',
      });
    }

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      console.error('[AI] GEMINI_API_KEY is not set in environment variables');
      return res.status(500).json({
        success: false,
        message: 'AI service is not configured. Contact support.',
      });
    }

    console.log(
      `[AI] Gemini request from user=${req.userId} role=${req.userRole} msgs=${messages.length}`
    );

    // ── Build Gemini request body ─────────────────────────────────────────────
    const geminiBody = {
      // System instruction (replaces Anthropic's top-level "system" field)
      system_instruction: system
        ? { parts: [{ text: system }] }
        : undefined,

      // Conversation history in Gemini format
      contents: toGeminiMessages(messages),

      generationConfig: {
        maxOutputTokens: max_tokens || 400,
        temperature:     0.7,
        topP:            0.9,
      },

      // Safety settings — keep relaxed so app support answers aren't blocked
      safetySettings: [
        { category: 'HARM_CATEGORY_HARASSMENT',        threshold: 'BLOCK_ONLY_HIGH' },
        { category: 'HARM_CATEGORY_HATE_SPEECH',       threshold: 'BLOCK_ONLY_HIGH' },
        { category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold: 'BLOCK_ONLY_HIGH' },
        { category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_ONLY_HIGH' },
      ],
    };

    // ── Call Gemini API ───────────────────────────────────────────────────────
    const geminiRes = await fetch(`${GEMINI_URL}?key=${apiKey}`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(geminiBody),
      signal:  AbortSignal.timeout(25000),
    });

    const data = await geminiRes.json();

    if (!geminiRes.ok) {
      const errMsg = data?.error?.message || 'Gemini API returned an error';
      console.error('[AI] Gemini error:', geminiRes.status, errMsg);
      return res.status(geminiRes.status).json({ success: false, message: errMsg });
    }

    // ── Extract text from Gemini response ─────────────────────────────────────
    // Gemini format: { candidates: [{ content: { parts: [{ text: '...' }] } }] }
    const text =
      data?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() ||
      'I could not generate a response. Please try again.';

    // ── Return in Anthropic-compatible format so Flutter needs no changes ─────
    return res.json({
      content: [{ type: 'text', text }],
    });

  } catch (err) {
    if (err.name === 'TimeoutError' || err.name === 'AbortError') {
      console.error('[AI] Gemini request timed out');
      return res.status(504).json({
        success: false,
        message: 'AI response timed out. Please try again.',
      });
    }
    console.error('[AI] Unexpected error:', err.message);
    return res.status(500).json({
      success: false,
      message: 'AI service temporarily unavailable. Please try again.',
    });
  }
});

module.exports = router;