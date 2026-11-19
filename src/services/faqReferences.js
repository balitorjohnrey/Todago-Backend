const registry = require('../data/faq_online_sources.json');

// APA 7: disambiguate works by the same author with the same date by title.
const groups = new Map();
for (const source of registry.sources) {
  const key = `${source.author}|${source.date}`;
  if (!groups.has(key)) groups.set(key, []);
  groups.get(key).push(source);
}
const sources = registry.sources.map(source => {
  const group = [...groups.get(`${source.author}|${source.date}`)]
    .sort((a, b) => a.title.localeCompare(b.title, 'en'));
  const suffix = group.length > 1 ? `-${String.fromCharCode(97 + group.indexOf(source))}` : '';
  const dateLabel = `${source.date}${suffix}`;
  let details;
  if (source.kind === 'research_paper') {
    const publication = source.issue
      ? `*${source.publication}, ${source.volume}*(${source.issue}), ${source.pages}.`
      : source.volume
        ? `*${source.publication}, ${source.volume}*, ${source.pages}.`
        : `In *${source.publication}* (pp. ${source.pages}). ${source.publisher}.`;
    details = `${source.title}. ${publication}`;
  } else {
    // Sentence case for titles, retaining product names and acronyms as stored.
    const title = source.title === 'About Advance Bookings' ? 'About advance bookings'
      : source.title === 'About Group Rides' ? 'About group rides' : source.title;
    details = `*${title}*${/[.!?]$/.test(title) ? '' : '.'}${source.url.endsWith('.pdf') ? '' : ' Retrieved November 19, 2026, from'}`;
  }
  return {
    ...source, dateLabel, retrievedAt: registry.retrievedAt,
    apaCitation: `${source.author}${source.author.endsWith('.') ? '' : '.'} (${dateLabel}). ${details} [${source.url}](${source.url})`,
  };
});
const byId = new Map(sources.map(source => [source.id, source]));

function referencesFor(entry) {
  return (entry.onlineReferences || []).map(reference => ({
    ...byId.get(reference.sourceId), topic: reference.topic, usage: reference.usage,
  }));
}

module.exports = { sources, referencesFor, registry };
