const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const jwt = require('jsonwebtoken');
const { dataset, normalize, normalizeRole, roleFaqs, quickQuestions, matchFaq, fallbackAnswer, referencesFor } = require('../src/services/faq');
const { sources: onlineSources } = require('../src/services/faqReferences');
const { sync } = require('../scripts/sync-faqs');

test('FAQ entries have unique IDs, attributable sources, and review dates', () => {
  assert.equal(dataset.schemaVersion, 2);
  assert.equal(dataset.entries.length, 100);
  assert.equal(new Set(dataset.entries.map(entry => entry.id)).size, dataset.entries.length);
  const workspace = path.resolve(__dirname, '../..');
  const exactQueries = new Set();
  for (const entry of dataset.entries) {
    assert.ok(entry.category && entry.question && entry.answer && entry.keywords.length);
    assert.ok(entry.aliases.length && entry.sources.length && entry.roles.length);
    assert.match(entry.reviewedAt, /^\d{4}-\d{2}-\d{2}$/);
    assert.ok(entry.reviewedAt <= dataset.version);
    for (const role of entry.roles) {
      assert.ok(['passenger', 'driver', 'guest'].includes(role));
      for (const query of [entry.question, ...entry.aliases]) {
        const key = `${role}:${normalize(query)}`;
        assert.ok(!exactQueries.has(key), `Duplicate ${key}`);
        exactQueries.add(key);
      }
    }
    for (const source of entry.sources) {
      assert.match(source.path, /^todago_(backend|flutter)\/[a-zA-Z0-9_./-]+$/);
      assert.ok(!source.path.includes('..'));
      assert.ok(source.locator);
      // A backend-only checkout can validate its own references. A combined
      // workspace validates the Flutter references too.
      const project = source.path.split('/')[0];
      if (!fs.existsSync(path.join(workspace, project))) continue;
      const file = path.join(workspace, source.path);
      assert.ok(fs.existsSync(file), `Missing ${source.path}`);
      assert.ok(fs.readFileSync(file, 'utf8').includes(source.locator),
        `Missing ${source.locator} in ${source.path}`);
    }
  }
});

test('all 100 FAQs resolve to attributed online references and distinguish methodology', () => {
  const ids = new Set(onlineSources.map(item => item.id));
  assert.equal(ids.size, onlineSources.length);
  const allowedHosts = new Set(['www.angkas.com', 'help.grab.com', 'help.uber.com',
    'www.bsp.gov.ph', 'help.gcash.com', 'docs.paymongo.com', 'support.google.com', 'aclanthology.org', 'doi.org']);
  let operational = 0;
  for (const entry of dataset.entries) {
    assert.ok(entry.onlineReferences.length, entry.id);
    for (const ref of entry.onlineReferences) {
      assert.ok(ids.has(ref.sourceId), `${entry.id}: ${ref.sourceId}`);
      assert.ok(ref.topic.trim().length > 8);
      assert.ok(['topic_adaptation', 'general_guidance', 'methodology'].includes(ref.usage));
    }
    const references = referencesFor(entry);
    for (const source of references) {
      const url = new URL(source.url);
      assert.equal(url.protocol, 'https:');
      assert.ok(allowedHosts.has(url.hostname), source.url);
      assert.equal(source.retrievedAt, '2026-11-19');
      assert.ok(source.apaCitation.includes(source.url));
      assert.ok(source.apaCitation.includes(`(${source.dateLabel})`));
      if (source.kind === 'research_paper') assert.equal(source.usage, 'methodology');
    }
    if (references.some(ref => ref.usage !== 'methodology')) operational++;
  }
  assert.equal(operational, 99);
});

test('every supported question and alias retrieves its own answer for each allowed role', () => {
  for (const entry of dataset.entries) {
    for (const role of entry.roles) {
      for (const query of [entry.question, ...entry.aliases]) {
        assert.equal(matchFaq(query, role)?.id, entry.id, `${role}: ${query}`);
      }
    }
  }
});

test('role suggestions exist and respect audience boundaries', () => {
  for (const role of ['passenger', 'driver', 'guest']) {
    const suggestions = quickQuestions(role);
    assert.equal(suggestions.length, 7);
    assert.equal(new Set(suggestions.map(entry => entry.id)).size, suggestions.length);
    for (const entry of suggestions) assert.ok(entry.roles.includes(role));
    assert.ok(suggestions.some(entry => entry.id === 'faq_sources'));
  }
  assert.equal(normalizeRole(' Commuter '), 'passenger');
  assert.equal(normalizeRole('DRIVER'), 'driver');
  assert.equal(normalizeRole('operator'), 'guest');
  assert.ok(!roleFaqs('guest').some(entry => entry.id === 'driver_cash_out'));
  assert.equal(matchFaq('How do I request a driver cash-out?', 'passenger'), null);
});

test('paraphrases, local-language queries, and specific topics beat broad terms', () => {
  const examples = [
    ['passenger', 'please cancel my ride', 'cancel_trip'],
    ['passenger', 'How much is my fare', 'fares'],
    ['passenger', 'my top-up is not received', 'missing_top_up'],
    ['passenger', 'add money using gcash', 'wallet_top_up'],
    ['passenger', 'Where can I find my past trips?', 'passenger_history'],
    ['passenger', 'my driver location is stuck', 'track_driver'],
    ['passenger', 'Can I use the student fare?', 'discounted_fares'],
    ['passenger', 'Paano mag book ng ride?', 'book_ride'],
    ['guest', 'Pila ang plete?', 'fares'],
    ['driver', 'Unsaon pag online?', 'driver_online'],
    ['driver', 'how can I collect payment now', 'complete_trip'],
    ['driver', 'how can I rate a passenger', 'rate_passenger'],
    ['driver', 'I am not receiving ride requests', 'no_requests'],
    ['driver', 'withdraw my earnings', 'driver_cash_out'],
    ['guest', 'Where is FAQ data from?', 'faq_sources'],
    ['guest', 'Asa gikan ang data?', 'faq_sources'],
  ];
  for (const [role, query, id] of examples) {
    assert.equal(matchFaq(query, role)?.id, id, query);
  }
});

test('partial words, generic words, ambiguous topics, and unrelated queries fall back', () => {
  for (const query of ['', 'driver', 'ride', 'accurate', 'corporate', 'climate',
    'write a poem', 'book cancel', 'tell me my exact current balance']) {
    assert.equal(matchFaq(query, 'passenger'), null, query);
  }
  assert.match(fallbackAnswer('driver'), /one specific question/);
  assert.match(fallbackAnswer('driver'), /go online/);
});

test('explicit place queries need a specific FAQ phrase to override directions', () => {
  assert.equal(matchFaq('Where is Maya Hotel?', 'passenger', { minKeywordWords: 2 }), null);
  assert.equal(matchFaq('Where can I find my past trips?', 'passenger', { minKeywordWords: 2 })?.id, 'passenger_history');
});

test('expanded FAQ topics distinguish issues from the general instructions', () => {
  const examples = [
    ['passenger', 'show my wallet transactions', 'wallet_history'],
    ['passenger', 'my top up money is missing', 'missing_top_up'],
    ['passenger', 'change my rating', 'ratings_once'],
    ['passenger', 'how can i split the group fare', 'shared_fare'],
    ['passenger', 'add a landmark for pickup', 'booking_notes'],
    ['passenger', 'my destination search has no results', 'destination_search'],
    ['passenger', 'no drivers online near me', 'no_drivers_passenger'],
    ['passenger', 'why am i being charged twice', 'duplicate_charge'],
    ['passenger', 'i already pressed done', 'topup_done'],
    ['driver', 'cashout is pending', 'cashout_status'],
    ['driver', 'why can i not cancel my cash out', 'cashout_cancel'],
    ['driver', 'the passenger never appeared', 'driver_no_show'],
    ['driver', 'i want to stop requests for a break', 'driver_stop_requests'],
    ['passenger', 'can i change payment method', 'payment_change'],
    ['passenger', 'i forgot to leave a rating', 'rate_later'],
    ['passenger', 'my payment is not confirmed', 'payment_pending'],
    ['passenger', 'can i reuse the same qr again', 'qr_reuse'],
    ['passenger', 'how do i report the wrong vehicle', 'wrong_vehicle'],
    ['passenger', 'my verification camera failed', 'identity_retry'],
    ['guest', 'how do i register a passenger account', 'register_passenger'],
  ];
  for (const [role, query, id] of examples) assert.equal(matchFaq(query, role)?.id, id, query);
});

test('the generated Flutter dataset matches the canonical dataset', {
  skip: !fs.existsSync(path.resolve(__dirname, '../../todago_flutter')),
}, () => sync({ check: true }));

function chat(t, body, role = 'commuter', authenticated = true) {
  const previous = process.env.JWT_SECRET;
  process.env.JWT_SECRET = 'faq-test-only-secret';
  t.after(() => {
    if (previous === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = previous;
  });
  const token = jwt.sign({ role }, process.env.JWT_SECRET,
    { subject: 'faq-test-user', issuer: 'todago-api', audience: 'todago-app' });
  const router = require('../src/routes/ai');
  return new Promise((resolve, reject) => {
    const res = { statusCode: 200, status(code) { this.statusCode = code; return this; },
      json(data) { resolve({ status: this.statusCode, data }); } };
    router.handle({ method: 'POST', url: '/chat', body,
      headers: authenticated ? { authorization: `Bearer ${token}` } : {} }, res, reject);
  });
}

test('FAQ API preserves text fields and returns the matched answer provenance', async t => {
  const result = await chat(t, { message: 'How do I cancel a trip?' });
  assert.equal(result.status, 200);
  assert.equal(result.data.role, 'passenger');
  assert.equal(result.data.faq.id, 'cancel_trip');
  assert.deepEqual(result.data.content, [{ type: 'text', text: result.data.text }]);
  assert.equal(result.data.datasetVersion, dataset.version);
  assert.equal(result.data.faq.reviewedAt, '2026-11-19');
  assert.ok(result.data.faq.sources.length);
  assert.ok(result.data.faq.onlineReferences.every(source => source.url && source.apaCitation));
});

test('FAQ API accepts history and prompt formats and keeps auth required', async t => {
  const prompt = await chat(t, { prompt: 'How do I complete a trip?' }, 'driver');
  assert.equal(prompt.data.faq.id, 'complete_trip');
  const history = await chat(t, { messages: [
    { role: 'assistant', content: 'How do fares work?' },
    { role: 'user', content: 'Where do the FAQ answers come from?' },
  ] });
  assert.equal(history.data.faq.id, 'faq_sources');
  const fallback = await chat(t, { message: 'write a poem' });
  assert.equal(fallback.data.faq, null);
  const denied = await chat(t, { message: 'How do fares work?' }, 'passenger', false);
  assert.equal(denied.status, 401);
});
