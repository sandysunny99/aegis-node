import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { test } from 'node:test';
import { describeLimitation, detectorGaps } from './limitations.js';

/** Every literal limitation code the scanner appends must get plain-language text. */
function literalCodes() {
  const roots = ['../../../scanner/', '../../../backend/routers/', '../../../backend/services/threat_intelligence/'];
  const codes = new Set();
  for (const root of roots) {
    const dir = new URL(root, import.meta.url);
    for (const name of readdirSync(dir).filter((n) => n.endsWith('.py'))) {
      const src = readFileSync(new URL(name, dir), 'utf8');
      // Limitation codes are UPPER_SNAKE, optionally ":detector"
      for (const m of src.matchAll(/append\("([A-Z][A-Z_]+(?::[a-z_]+)?)"\)/g)) codes.add(m[1]);
    }
  }
  return [...codes];
}

test('every literal limitation code has a description, not the raw code', () => {
  const codes = literalCodes();
  assert.ok(codes.length >= 5, `found only ${codes.length} codes`);
  for (const code of codes) assert.notEqual(describeLimitation(code), code, code);
});

test('detector codes name the detector and its state', () => {
  assert.match(describeLimitation('DETECTOR_UNAVAILABLE:yara'), /YARA/);
  assert.deepEqual(detectorGaps(['DETECTOR_DISABLED:heuristics', 'CLAMAV_UNAVAILABLE']), [
    { name: 'Heuristic checks', state: 'switched off' },
  ]);
});

test('provider outages are described generically', () => {
  assert.match(describeLimitation('URLHAUS_UNAVAILABLE_TIMEOUT'), /Urlhaus was unavailable \(timeout\)/);
});
