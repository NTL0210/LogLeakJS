import assert from 'node:assert/strict';
import test from 'node:test';
import {
  AnalysisError,
  ConfigurationError,
  createLogLeakDetector,
} from '../src/index.js';
import { cloneJson, findingsFor } from '../test-support/helpers.js';
import { SYNTHETIC } from '../test-support/synthetic.js';

test('Error message and stack are inspected and reported safely', () => {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  const error = new Error(`request failed: ${SYNTHETIC.canary}`);
  const result = detector.analyze({ error });

  const paths = new Set(result.findings.map((finding) => finding.path));
  assert.deepEqual(paths, new Set(['$.error.message', '$.error.stack']));
  assert.equal(JSON.stringify(result).includes(SYNTHETIC.canary), false);
});

test('Error cause chains are inspected', () => {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  const inner = new Error(`inner ${SYNTHETIC.canary}`);
  const outer = new Error('outer', { cause: inner });
  const result = detector.analyze(outer);

  const paths = result.findings.map((finding) => finding.path);
  assert.equal(paths.includes('$.cause.message'), true);
  assert.equal(paths.includes('$.cause.stack'), true);
});

test('AggregateError members are inspected', () => {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  const error = new AggregateError([new Error(SYNTHETIC.canary)], 'all failed');
  const result = detector.analyze(error);

  const paths = result.findings.map((finding) => finding.path);
  assert.equal(paths.includes('$.errors[0].message'), true);
  assert.equal(JSON.stringify(result).includes(SYNTHETIC.canary), false);
});

test('custom enumerable Error properties and subclasses are inspected', () => {
  class RequestError extends Error {
    constructor(message) {
      super(message);
      this.token = SYNTHETIC.token;
      this.statusCode = 401;
    }
  }

  const result = createLogLeakDetector().analyze(new RequestError('unauthorized'));
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].ruleId, 'generic-token-field');
  assert.equal(result.findings[0].path, '$.token');
});

test('an explicitly defined stack string is inspected', () => {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  const error = new Error('plain');
  Object.defineProperty(error, 'stack', {
    value: `Error: ${SYNTHETIC.canary}`,
    configurable: true,
    writable: true,
  });
  const result = detector.analyze(error);
  assert.deepEqual(
    result.findings.map((finding) => finding.path),
    ['$.stack'],
  );
});

test('getters are never invoked and make the analysis incomplete', () => {
  let touched = false;
  const record = {
    safe: 'value',
    get password() {
      touched = true;
      return SYNTHETIC.password;
    },
  };

  const result = createLogLeakDetector().analyze(record);
  assert.equal(touched, false);
  assert.equal(result.status, 'incomplete');
  assert.equal(result.coverage, 'incomplete');
  assert.equal(result.summary.incompleteReasons.includes('unsupported-accessor'), true);
  assert.equal(
    result.diagnostics.some((diagnostic) => diagnostic.code === 'unsupported-accessor'),
    true,
  );
});

test('toJSON, toString, and custom inspect hooks are not called', () => {
  let calls = 0;
  const record = {
    toJSON() {
      calls += 1;
      return { password: SYNTHETIC.password };
    },
    toString() {
      calls += 1;
      return SYNTHETIC.password;
    },
    [Symbol.for('nodejs.util.inspect.custom')]() {
      calls += 1;
      return SYNTHETIC.password;
    },
    safe: 'value',
  };

  const result = createLogLeakDetector().analyze({ record });
  assert.equal(calls, 0);
  assert.equal(
    result.diagnostics.some((diagnostic) => diagnostic.code === 'unsupported-value'),
    true,
  );
});

test('circular and repeated references are skipped with a diagnostic, not a crash', () => {
  const shared = { note: 'same object' };
  const record = { first: shared, second: shared };
  record.self = record;

  const result = createLogLeakDetector().analyze(record);
  assert.equal(result.status, 'pass');
  assert.equal(result.coverage, 'complete');
  assert.equal(
    result.diagnostics.filter((diagnostic) => diagnostic.code === 'circular-reference').length,
    2,
  );
});

test('Map and Set entries are inspected', () => {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  const map = new Map([
    ['password', SYNTHETIC.password],
    ['safe', SYNTHETIC.canary],
  ]);
  const result = detector.analyze({ map, set: new Set([SYNTHETIC.canary]) });

  const rules = new Set(result.findings.map((finding) => finding.ruleId));
  assert.equal(rules.has('password-field'), true);
  assert.equal(rules.has('known-secret'), true);
  assert.equal(result.findings.length >= 3, true);
});

test('valid dates and URLs are scanned; invalid dates are diagnosed', () => {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  const url = new URL(`https://user:${SYNTHETIC.password}@example.test/path`);

  const valid = detector.analyze({
    when: new Date('2026-01-02T03:04:05.000Z'),
    url,
    note: SYNTHETIC.canary,
  });
  assert.equal(valid.status, 'leaks');
  assert.equal(
    valid.findings.some((finding) => finding.ruleId === 'connection-string-credentials'),
    true,
  );

  const invalid = detector.analyze({ when: new Date('not a date') });
  assert.equal(invalid.status, 'pass');
  assert.equal(
    invalid.diagnostics.some((diagnostic) => diagnostic.code === 'invalid-date'),
    true,
  );
});

test('buffers are decoded; malformed UTF-8 makes the analysis incomplete', () => {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });

  const valid = detector.analyze({ value: Buffer.from(SYNTHETIC.canary) });
  assert.equal(valid.findings.length, 1);

  const invalid = detector.analyze({ value: Buffer.from([0xff, 0xfe, 0xfd]) });
  assert.equal(invalid.coverage, 'incomplete');
  assert.equal(invalid.summary.incompleteReasons.includes('invalid-utf8'), true);
});

test('unsupported values are diagnosed without failing the analysis', () => {
  const result = createLogLeakDetector().analyze({
    fn() {},
    regex: /password/u,
    promise: Promise.resolve('value'),
    weakMap: new WeakMap(),
  });

  const codes = new Set(result.diagnostics.map((diagnostic) => diagnostic.code));
  assert.equal(codes.has('unsupported-value'), true);
  assert.equal(codes.has('unsupported-container'), true);
  assert.equal(result.coverage, 'incomplete');
});

test('malformed JSON-looking text is analyzed as text and diagnosed', () => {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  const result = detector.analyze(`{"note":"${SYNTHETIC.canary}",`);

  assert.equal(result.status, 'leaks');
  assert.equal(result.coverage, 'complete');
  assert.equal(result.findings[0].path, '$');
  assert.equal(
    result.diagnostics.some((diagnostic) => diagnostic.code === 'invalid-json'),
    true,
  );
});

test('unknown capture issues cannot produce a clean result', () => {
  const result = createLogLeakDetector().analyze({
    coverage: 'incomplete',
    records: [],
    issues: [{ code: 'unexpected-capture-problem', message: 'raw message must be ignored' }],
  });

  assert.equal(result.status, 'incomplete');
  assert.equal(result.coverage, 'incomplete');
  assert.equal(result.summary.incompleteReasons.includes('capture-incomplete'), true);
  assert.equal(
    result.diagnostics.some((diagnostic) => diagnostic.message.includes('raw message')),
    false,
  );
});

test('analysis does not mutate the input record', () => {
  const record = {
    password: SYNTHETIC.password,
    nested: { array: [1, 2, 3], token: SYNTHETIC.token },
  };
  const before = cloneJson(record);
  createLogLeakDetector().analyze(record);
  assert.deepEqual(record, before);
});

test('null-prototype objects and bigints are handled', () => {
  const record = Object.create(null);
  record.password = SYNTHETIC.password;
  record.count = 42n;

  const result = createLogLeakDetector().analyze(record);
  assert.equal(findingsFor(result, 'password-field').length, 1);
});

test('frozen analysis result and error classes have stable metadata', () => {
  const result = createLogLeakDetector().analyze('clean');
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.summary), true);

  const configuration = new ConfigurationError('bad input');
  assert.equal(configuration.name, 'ConfigurationError');
  assert.equal(configuration.code, 'ERR_LOGLEAK_CONFIGURATION');
  assert.equal(configuration.exitCode, 2);

  const analysis = new AnalysisError('internal');
  assert.equal(analysis.code, 'ERR_LOGLEAK_ANALYSIS');
  assert.equal(analysis.exitCode, 4);
  assert.equal(analysis instanceof Error, true);
});
