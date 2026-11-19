const dataset = require('../data/faqs.json');
const { referencesFor } = require('./faqReferences');

function normalize(value) {
  return String(value || '').toLowerCase()
    .replace(/['\u2019]/g, '')
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ').trim();
}

function normalizeRole(role) {
  const value = String(role || '').toLowerCase().trim();
  if (value === 'commuter') return 'passenger';
  return ['passenger', 'driver'].includes(value) ? value : 'guest';
}

function roleFaqs(role) {
  return dataset.entries.filter(entry => entry.roles.includes(normalizeRole(role)));
}

function quickQuestions(role) {
  const ids = dataset.quickQuestions[normalizeRole(role)];
  return ids.map(id => dataset.entries.find(entry => entry.id === id));
}

// Match complete words/phrases so "rate" cannot match "accurate". Exact
// questions and aliases win; equally plausible topics ask for clarification.
function matchFaq(message, role, { minKeywordWords = 1 } = {}) {
  const query = normalize(message);
  if (!query) return null;
  const candidates = roleFaqs(role);
  const exact = candidates.find(entry => [entry.question, ...entry.aliases]
    .some(question => normalize(question) === query));
  if (exact) return exact;
  // A known question for another role must not fall through to a broad term
  // in this role's dataset (for example, cash-out matching cash payment).
  if (dataset.entries.some(entry => [entry.question, ...entry.aliases]
    .some(question => normalize(question) === query))) return null;

  let best = null, bestScore = 0, tied = false;
  for (const entry of candidates) {
    const phrases = new Set(entry.keywords.map(normalize).filter(Boolean));
    let score = 0;
    for (const phrase of phrases) {
      const words = phrase.split(' ').length;
      if (words >= minKeywordWords && ` ${query} `.includes(` ${phrase} `)) score += words * 2;
    }
    // Groups describe a specific issue even when filler words separate its
    // concepts, e.g. "my top-up money is missing" or "cancel my cash-out".
    // Explicit place searches continue to require a contiguous FAQ phrase.
    if (minKeywordWords === 1 && entry.intentGroups?.length) {
      const groups = entry.intentGroups.map(group => group.map(normalize)
        .filter(phrase => ` ${query} `.includes(` ${phrase} `)));
      if (groups.every(group => group.length)) {
        score += 12 + groups.reduce((sum, group) => sum
          + Math.max(...group.map(phrase => phrase.split(' ').length)) * 2, 0);
      }
    }
    if (score > bestScore) {
      best = entry;
      bestScore = score;
      tied = false;
    } else if (score > 0 && score === bestScore) {
      tied = true;
    }
  }
  return bestScore >= 2 && !tied ? best : null;
}

function fallbackAnswer(role) {
  const topics = quickQuestions(role).slice(0, 4).map(entry => entry.question).join(' ');
  return `I could not confidently match that to a TodaGo FAQ. Please ask one specific question. Try: ${topics}`;
}

module.exports = { dataset, normalize, normalizeRole, roleFaqs, quickQuestions, matchFaq, fallbackAnswer, referencesFor };
