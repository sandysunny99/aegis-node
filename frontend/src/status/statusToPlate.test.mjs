// Run with: npm test  (Node's built-in test runner, no extra dependency)
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  DATASET_STATUSES,
  STATUS_TO_PLATE,
  VERDICT_TO_STATUS,
  byUrgency,
  effectiveStatus,
  statusToPlate,
} from './statusToPlate.js';

const modelsPy = readFileSync(new URL('../../../backend/models.py', import.meta.url), 'utf8');

/** Statuses documented on DatasetRecord.status in backend/models.py. */
function backendStatuses() {
  const block = modelsPy.match(/# status: ([^\n]+)\n\s+#\s+([^\n]+)/);
  assert.ok(block, 'could not find the "# status:" comment in backend/models.py');
  return `${block[1]} ${block[2]}`
    .split('|')
    .map((s) => s.trim())
    .filter(Boolean);
}

test('every backend dataset status has a plate entry', () => {
  const backend = backendStatuses();
  assert.ok(backend.length >= 11, `expected at least 11 statuses, got ${backend.length}`);
  for (const status of backend) {
    assert.ok(STATUS_TO_PLATE[status], `missing statusToPlate entry for "${status}"`);
  }
});

test('the map has no statuses the backend does not know', () => {
  assert.deepEqual([...DATASET_STATUSES].sort(), [...backendStatuses()].sort());
});

test('unknown statuses fail loudly outside production builds', () => {
  assert.throws(() => statusToPlate('totally_new_status'), /Unknown dataset status/);
});

test('every entry shows a word and an icon, never colour alone', () => {
  for (const [status, entry] of Object.entries(STATUS_TO_PLATE)) {
    assert.ok(entry.label && entry.label.length > 2, `${status} has no label`);
    assert.ok(entry.icon, `${status} has no icon`);
  }
});

test('limited, incomplete and unverified results never look healthy', () => {
  for (const status of ['clean_limited', 'incomplete', 'remediated_unverified', 'error', 'suspicious']) {
    assert.notEqual(statusToPlate(status).plate, 'healthy', status);
  }
  assert.equal(statusToPlate('quarantined').plate, 'breached');
  assert.equal(statusToPlate('uploaded').plate, 'unscanned');
});

test('every scan verdict maps to a known status', () => {
  for (const status of Object.values(VERDICT_TO_STATUS)) {
    assert.ok(STATUS_TO_PLATE[status], status);
  }
});

test('the report verdict overrides a legacy "clean" row', () => {
  assert.equal(effectiveStatus('clean', 'clean_with_limitations'), 'clean_limited');
  assert.equal(effectiveStatus('clean', 'clean_verified'), 'clean');
  assert.equal(effectiveStatus('remediated', 'malicious'), 'remediated');
});

test('default sort puts the most urgent first (brief 4a order)', () => {
  const sorted = ['clean', 'uploaded', 'error', 'quarantined', 'remediated', 'scanning', 'suspicious', 'partial_remediated']
    .sort(byUrgency);
  assert.deepEqual(sorted, ['quarantined', 'suspicious', 'partial_remediated', 'error', 'scanning', 'uploaded', 'remediated', 'clean']);
});
