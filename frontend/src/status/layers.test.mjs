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
