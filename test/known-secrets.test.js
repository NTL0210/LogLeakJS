import assert from 'node:assert/strict';
import test from 'node:test';
import { createLogLeakDetector } from '../src/index.js';
import { findingsFor } from '../test-support/helpers.js';
import { SYNTHETIC } from '../test-support/synthetic.js';

test('a registered secret in a raw string is reported without its value', () => {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  const result = detector.analyze(`prefix ${SYNTHETIC.canary} suffix`);

  assert.equal(result.status, 'leaks');
  assert.equal(result.coverage, 'complete');
  assert.equal(result.findings.length, 1);

  const [finding] = result.findings;
  assert.equal(finding.detector, 'known-secret');
  assert.equal(finding.ruleId, 'known-secret');
  assert.equal(finding.evidence, 'known-secret');
  assert.equal(finding.severity, 'critical');
  assert.equal(finding.confidence, 'high');
  assert.equal(finding.path, '$');
  assert.equal(finding.scope, 'record-text');
  assert.equal(finding.source, 'memory');
  assert.equal(finding.reference, 'secret-1');
  assert.equal(finding.redacted, false);
  assert.match(finding.id, /^LL-[0-9a-f]{12}$/);

  assert.equal(JSON.stringify(result).includes(SYNTHETIC.canary), false);
});

test('a registered secret in a structured field and nested array is found', () => {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  const result = detector.analyze({
    request: {
      headers: ['accept', SYNTHETIC.canary],
    },
  });

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].path, '$.request.headers[1]');
  assert.equal(result.findings[0].scope, 'field');
});

test('matching is exact and case-sensitive', () => {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  const lower = detector.analyze(SYNTHETIC.canary.toLowerCase());
  const partial = detector.analyze(SYNTHETIC.canary.slice(0, 12));

  assert.equal(lower.findings.length, 0);
  assert.equal(partial.findings.length, 0);
});

test('multiple registered secrets produce distinct, value-free references', () => {
  const detector = createLogLeakDetector({
    knownSecrets: [SYNTHETIC.canary, SYNTHETIC.password],
  });
  const result = detector.analyze(`${SYNTHETIC.canary} and ${SYNTHETIC.password}`);

  const findings = findingsFor(result, 'known-secret');
  assert.equal(findings.length, 2);
  assert.deepEqual(
    findings.map((finding) => finding.reference).sort(),
    ['secret-1', 'secret-2'],
  );
  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes(SYNTHETIC.canary), false);
  assert.equal(serialized.includes(SYNTHETIC.password), false);
});

test('registerSecret affects later analyses and counts unique values', () => {
  const detector = createLogLeakDetector();
  assert.equal(detector.analyze(SYNTHETIC.canary).findings.length, 0);

  assert.equal(detector.registerSecret(SYNTHETIC.canary), 1);
  assert.equal(detector.registerSecret(SYNTHETIC.canary), 1);
  assert.equal(detector.secretCount, 1);
  assert.equal(detector.analyze(SYNTHETIC.canary).findings.length, 1);
});

test('secrets are never echoed by length or limit validation errors', () => {
  const attempts = [
    () => createLogLeakDetector({ knownSecrets: ['SHORT'] }),
    () =>
      createLogLeakDetector({
        limits: { maxSecretBytes: 8 },
        knownSecrets: [SYNTHETIC.canary],
      }),
    () =>
      createLogLeakDetector({
        knownSecrets: Array.from({ length: 33 }, (_, index) => `${SYNTHETIC.canary}_${index}`),
      }),
  ];

  for (const attempt of attempts) {
    assert.throws(attempt, (error) => {
      assert.equal(error.message.includes(SYNTHETIC.canary), false);
      assert.equal(error.message.includes('SHORT'), false);
      return true;
    });
  }
});

test('known-secret detection can be disabled but never suppressed by exceptions', () => {
  const disabled = createLogLeakDetector({
    detectors: { knownSecrets: false },
    knownSecrets: [SYNTHETIC.canary],
  });
  assert.equal(disabled.analyze(SYNTHETIC.canary).findings.length, 0);

  assert.throws(
    () =>
      createLogLeakDetector({
        knownSecrets: [SYNTHETIC.canary],
        exceptions: [
          {
            detector: 'known-secret',
            ruleId: 'known-secret',
            path: '$',
            reason: 'Attempt to suppress a known secret',
          },
        ],
      }),
    /cannot be suppressed/,
  );
});

test('the configured severity for known secrets is honoured', () => {
  const detector = createLogLeakDetector({
    knownSecrets: [SYNTHETIC.canary],
    severity: { knownSecret: 'medium' },
  });
  assert.equal(detector.analyze(SYNTHETIC.canary).findings[0].severity, 'medium');
});

test('the capture source is sanitized before it reaches a finding', () => {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  const result = detector.analyze([
    { source: 'integration test / auth flow!', value: SYNTHETIC.canary },
  ]);

  assert.equal(result.findings[0].source, 'integrationtestauthflow');
});
