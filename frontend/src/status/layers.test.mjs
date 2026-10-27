import assert from 'node:assert/strict';
import { test } from 'node:test';
import { aiSummary, coverageSummary, enrichmentSummary, providerStates } from './layers.js';

const ev = (provider, reputation, error_status = null) => ({ provider, reputation, error_status, indicator: 'x', indicator_type: 't' });
const byId = (states) => Object.fromEntries(states.map((s) => [s.id, s]));

test('disabled enrichment marks every provider as not queried, never as checked', () => {
  const s = byId(providerStates({ status: 'disabled', evidence: [], providers_checked: [] }));
  for (const id of ['virustotal', 'urlhaus', 'abuseipdb']) assert.equal(s[id].state, 'disabled');
});

test('a configured provider with no indicators is "not queried", not a clean check', () => {
  const s = byId(providerStates({ status: 'active', evidence: [], providers_checked: ['urlhaus'] }));
  assert.equal(s.urlhaus.state, 'not_queried');
  assert.equal(s.virustotal.state, 'disabled');
});

test('failed lookups are unavailable, never a no-match', () => {
  const s = byId(providerStates({ status: 'error', evidence: [ev('virustotal', 'unknown', 'timeout')], providers_checked: ['virustotal'] }));
  assert.equal(s.virustotal.state, 'unavailable');
  assert.match(s.virustotal.text, /timeout/);
});

test('a match is reported even if other lookups failed', () => {
  const s = byId(providerStates({
    status: 'degraded',
    evidence: [ev('urlhaus', 'malicious'), ev('urlhaus', 'unknown', 'rate_limited')],
    providers_checked: ['urlhaus'],
  }));
  assert.equal(s.urlhaus.state, 'match');
  assert.equal(s.urlhaus.tone, 'breach');
});

test('benign answers read as "no malicious match", with the caveat', () => {
  const s = byId(providerStates({ status: 'active', evidence: [ev('abuseipdb', 'benign')], providers_checked: ['abuseipdb'] }));
  assert.equal(s.abuseipdb.state, 'no_match');
  assert.match(s.abuseipdb.text, /not proof/);
});

test('a missing report means enrichment did not complete', () => {
  assert.equal(enrichmentSummary(null).word, 'Not completed');
  assert.ok(providerStates(null).every((p) => p.state === 'not_run'));
  assert.equal(enrichmentSummary({ status: 'degraded' }).word, 'Partial');
});

test('newer reports: result_state decides, and NO_MATCH with reputation unknown is still a no-match', () => {
  const s = byId(providerStates({
    status: 'degraded',
    enrichment_status: 'PARTIAL',
    providers_checked: ['urlhaus', 'virustotal'],
    evidence: [
      { provider: 'urlhaus', reputation: 'unknown', result_state: 'NO_MATCH' },
      { provider: 'virustotal', reputation: 'unknown', result_state: 'RATE_LIMITED', error_status: 'rate_limited' },
    ],
  }));
  assert.equal(s.urlhaus.state, 'no_match');
  assert.equal(s.virustotal.state, 'unavailable');
  assert.match(s.virustotal.text, /rate limited/);
  assert.equal(enrichmentSummary({ status: 'degraded', enrichment_status: 'PARTIAL' }).word, 'Partial');
  assert.equal(enrichmentSummary({ status: 'error', enrichment_status: 'UNAVAILABLE' }).word, 'Unavailable');
});

test('NOT_QUERIED lookups do not count as checks', () => {
  const s = byId(providerStates({ status: 'active', providers_checked: ['abuseipdb'], evidence: [{ provider: 'abuseipdb', result_state: 'NOT_QUERIED' }] }));
  assert.equal(s.abuseipdb.state, 'not_queried');
});

const catalog = [
  { name: 'clamav', layer: 'L1', enabled: true },
  { name: 'virustotal', layer: 'L4', enabled: true, lookup: 'sha256 only' },
  { name: 'urlhaus', layer: 'L4', enabled: false, lookup: 'URLs only' },
  { name: 'abuseipdb', layer: 'L4', enabled: false, lookup: 'public IPs only' },
  { name: 'malwarebazaar', layer: 'L4', enabled: false, lookup: 'sha256 only' },
  { name: 'threatfox', layer: 'L4', enabled: false, lookup: 'sha256 and extracted URLs' },
  { name: 'circl_hashlookup', layer: 'L4', enabled: true, lookup: 'sha256 only; known-good annotation' },
  { name: 'newfeed', layer: 'L4', enabled: false, lookup: 'domains only' },
];

test('providers come from the server catalogue, not a fixed three', () => {
  const ids = providerStates({ status: 'active', providers_checked: ['virustotal'], evidence: [] }, catalog).map((p) => p.id);
  assert.deepEqual(ids, ['virustotal', 'urlhaus', 'abuseipdb', 'malwarebazaar', 'threatfox', 'circl_hashlookup', 'newfeed']);
  const s = byId(providerStates({ status: 'active', providers_checked: [], evidence: [] }, catalog));
  assert.equal(s.newfeed.name, 'newfeed');
  assert.equal(s.newfeed.sends, 'domains only');
  assert.equal(s.malwarebazaar.name, 'MalwareBazaar');
});

test('without a catalogue, providers named in the report are still listed', () => {
  const ids = providerStates({ status: 'active', providers_checked: ['threatfox'], evidence: [] }).map((p) => p.id);
  assert.ok(ids.includes('threatfox'));
  assert.ok(ids.includes('virustotal'));
});

test('a CIRCL known-file match is an annotation, never a malicious match or a clean verdict', () => {
  const s = byId(providerStates({
    status: 'active',
    providers_checked: ['circl_hashlookup'],
    evidence: [{ provider: 'circl_hashlookup', reputation: 'known_good', result_state: 'MATCH' }],
  }, catalog));
  assert.equal(s.circl_hashlookup.state, 'known');
  assert.equal(s.circl_hashlookup.tone, 'neutral');
  assert.match(s.circl_hashlookup.text, /Known file \(annotation\)/);
  assert.match(s.circl_hashlookup.text, /not a verdict/);
});

test('AI layer distinguishes not run, blocked, completed and failed', () => {
  assert.equal(aiSummary(null).word, 'Not run');
  assert.equal(aiSummary({ status: 'failed', guardrail_status: 'BLOCK' }).word, 'Blocked');
  assert.equal(aiSummary({ status: 'completed', final_provider: 'groq' }).word, 'Completed');
  assert.equal(aiSummary({ status: 'unavailable' }).word, 'Unavailable');
});

test('partial coverage is never described as full', () => {
  const c = coverageSummary({ coverage_status: 'PARTIAL', coverage_percentage: 41.2, rows_inspected: 10000, rows_total: 24300 });
  assert.equal(c.full, false);
  assert.match(c.text, /Partial coverage: 41.2%/);
  assert.equal(coverageSummary({ coverage_status: 'FULL', coverage_percentage: 100, rows_inspected: 15, rows_total: 15 }).full, true);
});

test('antivirus line names the provider and never calls a hash miss "clean"', async () => {
  const { antivirusSummary } = await import('./layers.js');
  const miss = antivirusSummary({ clamav_status: 'skipped', av_provider: 'metadefender', av_reason: 'METADEFENDER_HASH_NOT_FOUND' });
  assert.equal(miss.text, 'Antivirus, MetaDefender (hash lookup): no record of this file, so no signature result.');
  assert.equal(miss.tone, 'risk');
  const known = antivirusSummary({ clamav_status: 'clean', av_provider: 'metadefender' });
  assert.match(known.text, /clean \(known-clean hash\)/);
  const older = antivirusSummary({ clamav_status: 'skipped' }, 'metadefender');
  assert.match(older.text, /MetaDefender/);
  const clam = antivirusSummary({ clamav_status: 'infected', av_provider: 'clamav_rest', clamav_virus_name: 'Eicar-Test-Signature' });
  assert.equal(clam.tone, 'breach');
  assert.match(clam.text, /ClamAV: infected \(Eicar-Test-Signature\)/);
});
