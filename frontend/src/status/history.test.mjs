import assert from 'node:assert/strict';
import { test } from 'node:test';
import { describeEvent, historyMissing, notRecorded, persistenceNote, scanQuery } from './history.js';

test('the query keeps only chosen filters and turns the day range into an exclusive ISO range', () => {
  const q = scanQuery({ verdict: 'malicious', dataset_status: 'all', file_format: '', target: 'all', from: '2026-10-01', to: '2026-10-17' }, 2, 20);
  assert.equal(q.get('page'), '2');
  assert.equal(q.get('page_size'), '20');
  assert.equal(q.get('verdict'), 'malicious');
  assert.equal(q.get('dataset_status'), null);
  assert.equal(q.get('file_format'), null);
  assert.equal(q.get('target'), 'all');
  assert.equal(q.get('since'), new Date('2026-10-01T00:00:00').toISOString());
  // "to 17 Oct" includes the whole day, so the exclusive bound is 18 Oct local midnight
  assert.equal(q.get('until'), new Date('2026-10-18T00:00:00').toISOString());
});

test('only a bare 404 from an unknown route means the server has no history API', () => {
  assert.equal(historyMissing({ status: 404, detail: 'Not Found' }), true);
  assert.equal(historyMissing({ status: 404, detail: 'Not found' }), true);
  assert.equal(historyMissing({ status: 404, detail: 'Resource not found.' }), false);
  assert.equal(historyMissing({ status: 500, detail: 'Not Found' }), false);
  assert.equal(historyMissing(new Error('Network error')), false);
});

test('non-durable storage gets a warning; durable or unknown does not', () => {
  assert.match(persistenceNote({ durable: false, database: 'sqlite', note: 'x' }), /will be lost when the server restarts/);
  assert.equal(persistenceNote({ durable: true, database: 'sqlite', note: '' }), null);
  assert.equal(persistenceNote(undefined), null);
});

test('missing values read "Not recorded", never a guess', () => {
  assert.equal(notRecorded(null), 'Not recorded');
  assert.equal(notRecorded('clamav_rest'), 'clamav_rest');
});

test('events describe what ran, and failures stay failures', () => {
  const det = describeEvent({ event_type: 'DETECTOR_COMPLETED', outcome: 'ok', detail: { detector: 'clamav', state: 'unavailable' } });
  assert.equal(det.title, 'Antivirus (ClamAV): unavailable');
  assert.equal(det.tone, 'risk');

  const md = describeEvent({ event_type: 'DETECTOR_COMPLETED', outcome: 'ok', detail: { detector: 'clamav', state: 'unavailable', provider: 'metadefender', reason: 'METADEFENDER_HASH_NOT_FOUND' } });
  assert.equal(md.title, 'Antivirus (MetaDefender): no record of this file');
  assert.equal(md.tone, 'risk');
  const rest = describeEvent({ event_type: 'DETECTOR_COMPLETED', outcome: 'ok', detail: { detector: 'clamav', state: 'ran', provider: 'clamav_rest' } });
  assert.equal(rest.title, 'Antivirus (ClamAV): ran');

  const ti = describeEvent({ event_type: 'THREAT_INTEL_LOOKUP_FAILED', outcome: 'failed', detail: { provider: 'virustotal', lookups: 1, result_states: { TIMEOUT: 1 } } });
  assert.equal(ti.title, 'VirusTotal lookup failed');
  assert.equal(ti.text, '1 lookup: 1 timeout');
  assert.equal(ti.tone, 'breach');

  const done = describeEvent({ event_type: 'SCAN_COMPLETED', outcome: 'ok', detail: { verdict: 'clean_with_limitations', coverage_status: 'FULL', enrichment_status: 'PARTIAL', limitations: ['CLAMAV_UNAVAILABLE'], duration_ms: 42 } });
  assert.match(done.text, /Clean, limited scan/);
  assert.match(done.text, /threat intelligence partial/);
  assert.match(done.text, /1 limitation/);

  const ai = describeEvent({ event_type: 'AI_ANALYSIS_COMPLETED', outcome: 'failed', detail: { status: 'failed', guardrail_status: 'BLOCK' } });
  assert.match(ai.text, /guardrail blocked/i);
  assert.equal(ai.tone, 'breach');

  const unknown = describeEvent({ event_type: 'SOMETHING_NEW', outcome: 'ok', detail: {} });
  assert.equal(unknown.title, 'Something new');
});
