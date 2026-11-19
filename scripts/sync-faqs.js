#!/usr/bin/env node
// Run from either project directory. The backend JSON is the only edited copy.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { sources: onlineSources, registry } = require('../src/services/faqReferences');

const source = path.resolve(__dirname, '../src/data/faqs.json');
const defaultTarget = path.resolve(__dirname, '../../todago_flutter/lib/data/faq_dataset.g.dart');

function renderDataset() {
  const json = JSON.stringify(JSON.parse(fs.readFileSync(source, 'utf8')));
  const sha = crypto.createHash('sha256').update(json).digest('hex');
  // JSON becomes one Dart string literal. Escape Dart interpolation as well.
  const literal = JSON.stringify(json).replace(/\$/g, '\\$');
  return '// GENERATED FILE. DO NOT EDIT.\n'
    + '// Source: todago_backend/src/data/faqs.json\n'
    + '// Update: node scripts/sync-faqs.js (from todago_backend)\n'
    + `// SHA-256 of canonical JSON: ${sha}\n`
    + '// ignore_for_file: lines_longer_than_80_chars\n'
    + `const String faqDatasetJson = ${literal};\n`
    + `const String faqOnlineSourcesJson = ${JSON.stringify(JSON.stringify(onlineSources)).replace(/\$/g, '\\$')};\n`;
}

function renderDocumentation() {
  const dataset = JSON.parse(fs.readFileSync(source, 'utf8'));
  const ordered = [...onlineSources].sort((a, b) =>
    a.author.localeCompare(b.author, 'en') || a.title.localeCompare(b.title, 'en'));
  const primary = ordered.filter(item => item.kind !== 'research_paper');
  const research = ordered.filter(item => item.kind === 'research_paper');
  const bibliography = '# TodaGo FAQ online references — APA 7\n\n'
    + `Dataset revision: ${dataset.version}. Retrieved/reviewed: 19 November 2026.\n\n`
    + `The ${dataset.entries.length}-entry collection adapts public FAQ/help topics for TodaGo. `
    + 'The online references below were actually consulted for this revision. The source map records '
    + 'the topic used by each entry; project code separately substantiates the TodaGo instructions. '
    + 'External companies do not endorse TodaGo. Their fees, timelines, insurance, service areas, '
    + 'and other policies have not been imported as TodaGo policy.\n\n'
    + 'No bulk MFAQ or FAQIR records were imported. This is an adapted FAQ collection, not a trained '
    + 'benchmark model or a survey of passenger demand. The previous 33 entries were reviewed against '
    + 'external counterparts and 67 additional entries were added; 99 entries reference operational '
    + 'FAQ/help topics and one entry explains dataset provenance using methodology references.\n\n'
    + `The list contains ${primary.length} FAQ/help or authoritative guidance sources and ${research.length} research papers.\n\n`
    + '## References (APA 7, alphabetized)\n\n'
    + ordered.map(item => item.apaCitation + '\n').join('\n')
    + '\n## Source roles and scope\n\n'
    + ordered.map(item => `- \`${item.id}\` (${item.kind}): ${item.scope}`
      + (item.openAccessUrl ? ` [Open-access version](${item.openAccessUrl}).` : '')).join('\n') + '\n'
    + '\n## Suggested methodology wording\n\n'
    + '> The TodaGo FAQ knowledge base was expanded through a purposive review of publicly available '
    + 'transport-service FAQ collections and payment/device guidance. Relevant question topics were '
    + 'paraphrased, deduplicated, grouped by user role, and adapted to TodaGo. Each answer was checked '
    + 'against the implemented application and backend rules. The resulting collection contains 100 '
    + 'entries, including a provenance explanation. Online source identifiers, adaptation topics, '
    + 'access dates, implementation references, and APA citations were retained for traceability.\n\n'
    + 'Use the research papers to discuss FAQ retrieval, paraphrases, and dataset documentation. '
    + 'The studies use methods and corpora different from TodaGo; their reported performance does '
    + 'not measure this app. The local aliases are authored query variants, not samples from those papers. '
    + 'A faculty/domain review and an independent user-query evaluation have not been performed.\n\n'
    + '## Citation notes\n\n'
    + '- Undated help pages use `n.d.`; no date is inferred from a crawl timestamp or internal PDF code.\n'
    + '- Same-author, same-date works use alphabetic suffixes by title. Use the same suffix in text.\n'
    + '- Retrieval dates are included for help pages whose content can change.\n'
    + '- Some Grab pages require JavaScript; their indexed Help Centre content was reviewed.\n'
    + '- Text is paraphrased. Whole source pages, customer records, and original benchmark records are not redistributed.\n';
  const escapeCell = value => String(value).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
  const map = '# TodaGo FAQ source map\n\n'
    + `Revision ${dataset.version}; ${dataset.entries.length} entries; source access date ${registry.retrievedAt}.\n\n`
    + 'Online links identify the question-topic or general-guidance source. Implementation files identify '
    + 'the checked TodaGo behavior. `methodology` is used only for the provenance explanation.\n\n'
    + '| # | FAQ ID and question | Online source and adaptation topic | Implementation references |\n'
    + '| --- | --- | --- | --- |\n'
    + dataset.entries.map((entry, index) => {
      const refs = entry.onlineReferences.map(ref => {
        const item = onlineSources.find(item => item.id === ref.sourceId);
        return `[${item.author}, ${item.dateLabel}](${item.url}): ${escapeCell(ref.topic)} (${ref.usage})`;
      }).join('<br>');
      return `| ${index + 1} | \`${entry.id}\` — ${escapeCell(entry.question)} | ${refs} | `
        + entry.sources.map(item => `\`${item.path}\` (${escapeCell(item.locator)})`).join('<br>') + ' |';
    }).join('\n') + '\n';
  const csvCell = value => `"${String(value).replace(/"/g, '""')}"`;
  const rows = [['id', 'category', 'roles', 'question', 'answer', 'aliases', 'online_source_urls', 'source_topics', 'apa_citations', 'reviewed_at'],
    ...dataset.entries.map(entry => [entry.id, entry.category, entry.roles.join('; '), entry.question,
      entry.answer, entry.aliases.join('; '),
      entry.onlineReferences.map(ref => onlineSources.find(item => item.id === ref.sourceId).url).join(' | '),
      entry.onlineReferences.map(ref => `${ref.usage}: ${ref.topic}`).join(' | '),
      entry.onlineReferences.map(ref => onlineSources.find(item => item.id === ref.sourceId).apaCitation).join(' | '), entry.reviewedAt])];
  return {
    'FAQ_REFERENCES_APA.md': bibliography,
    'FAQ_SOURCE_MAP.md': map,
    'faq_dataset.csv': rows.map(row => row.map(csvCell).join(',')).join('\n') + '\n',
  };
}

function sync({ check = false, target = defaultTarget } = {}) {
  const outputs = [[target, renderDataset()], ...Object.entries(renderDocumentation())
    .map(([name, content]) => [path.resolve(__dirname, '../docs', name), content])];
  for (const [filename, expected] of outputs) {
    if (check) {
      if (!fs.existsSync(filename) || fs.readFileSync(filename, 'utf8').replace(/\r\n/g, '\n') !== expected) {
        throw new Error(`FAQ artifact is out of date: ${filename}. Run node scripts/sync-faqs.js.`);
      }
    } else {
      fs.mkdirSync(path.dirname(filename), { recursive: true });
      fs.writeFileSync(filename, expected);
    }
  }
}

if (require.main === module) {
  try {
    const args = process.argv.slice(2);
    const targetArg = args.indexOf('--target');
    sync({ check: args.includes('--check'), target: targetArg < 0 ? defaultTarget : path.resolve(args[targetArg + 1]) });
    console.log(args.includes('--check') ? 'FAQ dataset is in sync.' : 'Generated Flutter FAQ dataset.');
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

module.exports = { renderDataset, renderDocumentation, sync };
