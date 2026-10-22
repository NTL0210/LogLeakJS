import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import test from 'node:test';
import { createCanarySecret, createLogLeakDetector } from '../src/index.js';

test('a canary has a high-entropy default format', () => {
  const canary = createCanarySecret();
  assert.match(canary.value, /^LLT_CANARY_[0-9a-f]{32}$/u);
  assert.equal(Object.isFrozen(canary), true);
  assert.notEqual(createCanarySecret().value, canary.value);
});

test('a canary prefix can be customized and is validated', () => {
  assert.match(createCanarySecret({ prefix: 'MY_TEST' }).value, /^MY_TEST_[0-9a-f]{32}$/u);

  assert.throws(() => createCanarySecret({ prefix: 'x' }), /at least 3/u);
  assert.throws(() => createCanarySecret({ prefix: '1BAD' }), /unsupported characters/u);
  assert.throws(() => createCanarySecret({ prefix: 'bad-prefix' }), /unsupported characters/u);
  assert.throws(() => createCanarySecret({ unknown: true }), /Unknown option/u);
});

test('a canary value is hidden from accidental serialization and inspection', () => {
  const canary = createCanarySecret();
  assert.deepEqual(Object.keys(canary), []);
  assert.equal(JSON.stringify(canary), '"[LogLeakCanary]"');
  assert.equal(inspect(canary), '[LogLeakCanary]');
  assert.equal(String(canary).includes(canary.value), false);
});

test('a canary can be registered and detected end-to-end without appearing in the result', () => {
  const canary = createCanarySecret();
  const detector = createLogLeakDetector({ knownSecrets: [canary.value] });

  const result = detector.analyze({ note: `value=${canary.value}` });
  assert.equal(result.status, 'leaks');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].detector, 'known-secret');
  assert.equal(JSON.stringify(result).includes(canary.value), false);
});
