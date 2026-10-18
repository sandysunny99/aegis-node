import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildPlates, hexSpiral, slotCount } from './layout.js';

test('slot count rounds up to whole rings with a minimum of 7', () => {
  assert.equal(slotCount(0), 7);
  assert.equal(slotCount(3), 7);
  assert.equal(slotCount(7), 7);
  assert.equal(slotCount(8), 19);
  assert.equal(slotCount(19), 19);
  assert.equal(slotCount(20), 37);
});

test('hex spiral produces unique coordinates', () => {
  const coords = hexSpiral(37).map(([q, r]) => `${q},${r}`);
  assert.equal(new Set(coords).size, 37);
});

test('real datasets come first and the rest are inert filler, never fake datasets', () => {
  const datasets = [{ dataset_id: 'a' }, { dataset_id: 'b' }];
  const plates = buildPlates(datasets);
  assert.equal(plates.length, 7);
  assert.deepEqual(plates.slice(0, 2).map((p) => p.dataset.dataset_id), ['a', 'b']);
  assert.ok(plates.slice(2).every((p) => p.dataset === null));
});
