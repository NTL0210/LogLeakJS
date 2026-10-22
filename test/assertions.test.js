import assert from 'node:assert/strict';
import test from 'node:test';
import {
  assertAnalysisComplete,
  assertNoSensitiveLogLeaks,
  ConfigurationError,
  createLogLeakDetector,
  EXIT_CODES,
  getExitCode,
  LogLeakAssertionError,
} from '../src/index.js';
import { SYNTHETIC } from '../test-support/synthetic.js';

test('a clean, complete result passes both assertions and maps to exit code 0', () => {
  const result = createLogLeakDetector().analyze({ message: 'clean' });
  assert.equal(getExitCode(result), EXIT_CODES.OK);
  assert.equal(assertNoSensitiveLogLeaks(result), result);
  assert.equal(assertAnalysisComplete(result), result);
});

test('findings throw a privacy-safe assertion error with exit code 1', () => {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  const result = detector.analyze({ password: SYNTHETIC.password, note: SYNTHETIC.canary });
  assert.equal(getExitCode(result), EXIT_CODES.LEAKS);

  assert.throws(
    () => assertNoSensitiveLogLeaks(result),
    (error) => {
      assert.equal(error instanceof LogLeakAssertionError, true);
      assert.equal(error.exitCode, EXIT_CODES.LEAKS);
      assert.equal(error.code, 'ERR_LOGLEAK_ASSERTION');
      assert.match(error.message, /detected 2 sensitive-log findings/u);
      assert.match(error.message, /known-secret/u);
      assert.match(error.message, /password-field/u);
      assert.match(error.message, /Analysis coverage: complete/u);
      assert.equal(error.message.includes(SYNTHETIC.password), false);
      assert.equal(error.message.includes(SYNTHETIC.canary), false);
      assert.equal(error.result, result);
      return true;
    },
  );
});

test('minSeverity filters low-severity findings', () => {
  const result = createLogLeakDetector({ policy: 'audit' }).analyze(SYNTHETIC.email);
  assert.equal(result.findings[0].severity, 'low');
  assert.equal(getExitCode(result), EXIT_CODES.LEAKS);

  assert.equal(assertNoSensitiveLogLeaks(result, { minSeverity: 'high' }), result);
  assert.throws(
    () => assertNoSensitiveLogLeaks(result, { minSeverity: 'low' }),
    LogLeakAssertionError,
  );
});

test('an incomplete analysis fails by default and can be explicitly allowed', () => {
  const result = createLogLeakDetector().analyze(new WeakMap());
  assert.equal(result.status, 'incomplete');
  assert.equal(getExitCode(result), EXIT_CODES.INCOMPLETE);

  assert.throws(
    () => assertNoSensitiveLogLeaks(result),
    (error) => {
      assert.equal(error.exitCode, EXIT_CODES.INCOMPLETE);
      assert.match(error.message, /could not complete log analysis/u);
      assert.match(error.message, /incomplete/u);
      assert.match(error.message, /unsupported-container/u);
      return true;
    },
  );

  assert.equal(assertNoSensitiveLogLeaks(result, { allowIncomplete: true }), result);
  assert.throws(() => assertAnalysisComplete(result), LogLeakAssertionError);
});

test('failOnIncomplete=false is honoured by assertions but not by assertAnalysisComplete', () => {
  const detector = createLogLeakDetector({ failOnIncomplete: false });
  const result = detector.analyze(new WeakMap());
  assert.equal(result.coverage, 'incomplete');
  assert.equal(result.failOnIncomplete, false);

  assert.equal(assertNoSensitiveLogLeaks(result), result);
  assert.throws(() => assertAnalysisComplete(result), LogLeakAssertionError);
});

test('findings take precedence over incomplete coverage in exit codes', () => {
  const detector = createLogLeakDetector({
    knownSecrets: [SYNTHETIC.canary],
    limits: { maxRecords: 1 },
  });
  const result = detector.analyze([SYNTHETIC.canary, 'second']);
  assert.equal(result.status, 'leaks');
  assert.equal(result.coverage, 'incomplete');
  assert.equal(getExitCode(result), EXIT_CODES.LEAKS);
});

test('assertion options are validated strictly', () => {
  const result = createLogLeakDetector().analyze('clean');

  assert.throws(() => assertNoSensitiveLogLeaks(result, { minSeverty: 'high' }), ConfigurationError);
  assert.throws(
    () => assertNoSensitiveLogLeaks(result, { minSeverity: 'severe' }),
    /not a valid severity/u,
  );
  assert.throws(
    () => assertNoSensitiveLogLeaks(result, { allowIncomplete: 'yes' }),
    /must be a boolean/u,
  );
  assert.throws(() => assertNoSensitiveLogLeaks(result, null), /plain object/u);
});

test('invalid results are rejected with a configuration error', () => {
  for (const value of [null, {}, { findings: [] }, { findings: [], coverage: 1 }]) {
    assert.throws(() => getExitCode(value), ConfigurationError);
    assert.throws(() => assertNoSensitiveLogLeaks(value), ConfigurationError);
    assert.throws(() => assertAnalysisComplete(value), ConfigurationError);
  }
});

test('the assertion message is truncated for very large findings lists', () => {
  const record = Object.fromEntries(
    Array.from({ length: 30 }, (_, index) => [`field${index}password`, 'synthetic']),
  );
  const result = createLogLeakDetector().analyze(record);
  assert.equal(result.findings.length, 30);

  assert.throws(
    () => assertNoSensitiveLogLeaks(result),
    (error) => {
      assert.match(error.message, /and 10 more/u);
      return true;
    },
  );
});

test('exit code constants are stable and frozen', () => {
  assert.deepEqual(EXIT_CODES, {
    OK: 0,
    LEAKS: 1,
    CONFIGURATION: 2,
    INCOMPLETE: 3,
    INTERNAL: 4,
  });
  assert.equal(Object.isFrozen(EXIT_CODES), true);
});
