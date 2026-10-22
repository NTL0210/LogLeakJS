import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ConfigurationError,
  createLogLeakDetector,
} from '../src/index.js';
import { SYNTHETIC } from '../test-support/synthetic.js';

test('default policy is conservative and complete-analysis-strict', () => {
  const detector = createLogLeakDetector();
  const config = detector.getConfig();

  assert.equal(config.policy, 'default');
  assert.equal(config.failOnIncomplete, true);
  assert.equal(config.detectors.fieldNames.enabled, true);
  assert.equal(config.detectors.fieldNames.allowRedactedValues, true);
  assert.equal(config.detectors.knownSecrets.enabled, true);
  assert.equal(config.detectors.knownSecrets.minLength, 8);
  assert.equal(config.detectors.credentialPatterns.enabled, true);
  assert.equal(config.detectors.personalData.enabled, false);
  assert.equal(config.detectors.personalData.email, false);
  assert.equal(config.detectors.personalData.phone, false);
  assert.equal(config.detectors.logInjection.enabled, true);
  assert.equal(config.limits.maxRecords, 500);
  assert.equal(config.limits.maxRecordBytes, 16384);
  assert.equal(config.knownSecretCount, 0);
  assert.equal(Object.isFrozen(config), true);
  assert.equal(Object.isFrozen(config.detectors), true);
});

test('strict policy reports redacted sensitive field names', () => {
  const detector = createLogLeakDetector({ policy: 'strict' });
  assert.equal(detector.getConfig().detectors.fieldNames.allowRedactedValues, false);
  const result = detector.analyze([{ password: '[REDACTED]' }]);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].ruleId, 'password-field');
  assert.equal(result.findings[0].redacted, true);
  assert.equal(result.findings[0].severity, 'low');
});

test('audit policy enables all optional personal-data detectors', () => {
  const detector = createLogLeakDetector({ policy: 'audit' });
  const config = detector.getConfig();
  assert.equal(config.detectors.personalData.enabled, true);
  assert.equal(config.detectors.personalData.email, true);
  assert.equal(config.detectors.personalData.phone, true);
});

test('unknown top-level and nested options are rejected', () => {
  assert.throws(
    () => createLogLeakDetector({ polciy: 'strict' }),
    ConfigurationError,
  );
  assert.throws(
    () => createLogLeakDetector({ detectors: { fieldNames: { typo: true } } }),
    /Unknown option "typo"/,
  );
  assert.throws(
    () => createLogLeakDetector({ limits: { maxReocrds: 5 } }),
    /Unknown option "maxReocrds"/,
  );
});

test('invalid values are rejected with actionable messages', () => {
  assert.throws(() => createLogLeakDetector({ policy: 'loose' }), /policy must be one of/);
  assert.throws(() => createLogLeakDetector('strict'), /options must be a plain object/);
  assert.throws(
    () => createLogLeakDetector({ detectors: { fieldNames: { enabled: 'yes' } } }),
    /must be a boolean/,
  );
  assert.throws(
    () => createLogLeakDetector({ severity: { knownSecret: 'apocalyptic' } }),
    /severity.knownSecret must be one of/,
  );
  assert.throws(
    () => createLogLeakDetector({ limits: { maxRecords: 0 } }),
    /maxRecords must be >= 1/,
  );
  assert.throws(
    () => createLogLeakDetector({ limits: { maxRecords: 1.5 } }),
    /must be an integer/,
  );
  assert.throws(
    () => createLogLeakDetector({ limits: { maxRecordBytes: 4096, maxTotalBytes: 2048 } }),
    /must be >=/,
  );
  assert.throws(
    () => createLogLeakDetector({ failOnIncomplete: 'no' }),
    /must be a boolean/,
  );
});

test('disabledRules must reference known rule ids', () => {
  assert.throws(
    () => createLogLeakDetector({ disabledRules: ['not-a-rule'] }),
    /not a known rule id/,
  );
  const detector = createLogLeakDetector({ disabledRules: ['password-field'] });
  const result = detector.analyze([{ password: SYNTHETIC.password }]);
  assert.equal(result.findings.length, 0);
});

test('known-secret exceptions are rejected; other exceptions need a narrow scope', () => {
  assert.throws(
    () =>
      createLogLeakDetector({
        exceptions: [{ detector: 'known-secret', reason: 'because' }],
      }),
    /cannot be suppressed/,
  );
  assert.throws(
    () =>
      createLogLeakDetector({
        exceptions: [{ detector: 'sensitive-field', reason: 'because' }],
      }),
    /must target a ruleId, a path, or both/,
  );
  assert.throws(
    () =>
      createLogLeakDetector({
        exceptions: [
          { detector: 'sensitive-field', path: '$.request.*', reason: 'wildcard' },
        ],
      }),
    /unsupported characters/,
  );
  assert.throws(
    () =>
      createLogLeakDetector({
        exceptions: [{ detector: 'nope', path: '$.x', reason: 'x' }],
      }),
    /detector must be one of/,
  );
  assert.throws(
    () =>
      createLogLeakDetector({
        exceptions: [{ detector: 'sensitive-field', path: '$.x' }],
      }),
    /reason must be/,
  );

  const detector = createLogLeakDetector({
    exceptions: [
      {
        detector: 'sensitive-field',
        ruleId: 'password-field',
        path: '$.password',
        recordIndex: 0,
        reason: 'Known synthetic fixture documented in the test',
      },
    ],
  });
  assert.equal(detector.getConfig().exceptions.length, 1);
  assert.equal('reason' in detector.getConfig().exceptions[0], false);
});

test('configuration never includes registered secret values', () => {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  const serialized = JSON.stringify(detector.getConfig());
  assert.equal(serialized.includes(SYNTHETIC.canary), false);
  assert.equal(detector.getConfig().knownSecretCount, 1);
  assert.equal(detector.secretCount, 1);
});

test('known secret bounds are enforced without echoing the value', () => {
  assert.throws(
    () => createLogLeakDetector({ knownSecrets: [123] }),
    /knownSecrets\[0\] must be a string/,
  );
  assert.throws(
    () => createLogLeakDetector({ knownSecrets: ['abc'] }),
    /shorter than the configured minimum/,
  );
  assert.throws(
    () =>
      createLogLeakDetector({
        limits: { maxSecrets: 1 },
        knownSecrets: [SYNTHETIC.canary, SYNTHETIC.password],
      }),
    /At most 1 synthetic secrets/,
  );

  let message = '';
  try {
    createLogLeakDetector({ knownSecrets: ['SHORT'] });
  } catch (error) {
    message = error.message;
  }
  assert.equal(message.includes('SHORT'), false);

  const detector = createLogLeakDetector();
  assert.equal(detector.registerSecret(SYNTHETIC.canary), 1);
  assert.equal(detector.registerSecret(SYNTHETIC.canary), 1);
  assert.equal(detector.secretCount, 1);
  assert.throws(() => detector.registerSecret(42), /must be a string/);
});

test('minLength can be lowered explicitly', () => {
  const detector = createLogLeakDetector({
    detectors: { knownSecrets: { minLength: 4 } },
    knownSecrets: ['PIN7'],
  });
  assert.equal(detector.secretCount, 1);
});

test('safe placeholders are validated', () => {
  assert.throws(
    () => createLogLeakDetector({ safePlaceholders: 'nope' }),
    /must be an array/,
  );
  assert.throws(
    () => createLogLeakDetector({ safePlaceholders: ['ok', 42] }),
    /must be a string/,
  );
  assert.throws(
    () => createLogLeakDetector({ safePlaceholders: ['bad\u0000value'] }),
    /unsupported characters/,
  );
});

test('dispose clears the registry and disables the detector', () => {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  detector.dispose();
  assert.equal(detector.disposed, true);
  assert.equal(detector.secretCount, 0);
  assert.throws(() => detector.analyze([]), /disposed/);
  assert.throws(() => detector.registerSecret(SYNTHETIC.password), /disposed/);
});

test('detector objects are frozen', () => {
  const detector = createLogLeakDetector();
  assert.equal(Object.isFrozen(detector), true);
});
