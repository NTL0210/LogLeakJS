import assert from 'node:assert/strict';
import test from 'node:test';
import {
  CaptureError,
  ConfigurationError,
  createLogLeakDetector,
  createMemoryCapture,
} from '../src/index.js';
import { SYNTHETIC } from '../test-support/synthetic.js';

test('records are captured in order with a sanitized source', () => {
  const capture = createMemoryCapture({ source: 'auth test!' });
  assert.equal(capture.size, 0);
  assert.equal(capture.coverage, 'complete');
  assert.equal(capture.finished, false);

  assert.equal(capture.push('first'), true);
  assert.equal(capture.push({ password: SYNTHETIC.password }), true);
  assert.equal(capture.size, 2);

  const result = capture.finish();
  assert.equal(capture.finished, true);
  assert.equal(result.coverage, 'complete');
  assert.deepEqual(result.issues, []);
  assert.equal(result.records.length, 2);
  assert.equal(result.records[0].value, 'first');
  assert.equal(result.records[0].source, 'authtest');
  assert.equal(result.records[1].source, 'authtest');
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.records), true);
  assert.equal(Object.isFrozen(result.records[0]), true);
});

test('per-record source metadata is validated and sanitized', () => {
  const capture = createMemoryCapture();
  assert.equal(capture.push('value', { source: 'integration / flow' }), true);
  const result = capture.finish();
  assert.equal(result.records[0].source, 'integrationflow');

  assert.throws(() => createMemoryCapture().push('x', { source: 42 }), ConfigurationError);
  assert.throws(() => createMemoryCapture().push('x', { nope: true }), /Unknown option/u);
});

test('buffers and typed arrays are copied, not aliased', () => {
  const capture = createMemoryCapture();
  const buffer = Buffer.from('buffer-value');
  const bytes = new Uint8Array([1, 2, 3]);

  capture.push(buffer);
  capture.push(bytes);
  buffer.fill(0);
  bytes.fill(0);

  const result = capture.finish();
  assert.equal(result.records[0].value.toString('utf8'), 'buffer-value');
  assert.deepEqual([...result.records[1].value], [1, 2, 3]);
});

test('finish is idempotent and closes the capture', async () => {
  const capture = createMemoryCapture();
  capture.push('value');
  const first = capture.finish();
  const second = capture.finish();
  assert.equal(first, second);

  assert.throws(() => capture.push('later'), CaptureError);
  assert.throws(() => capture.push('later'), /already been finished/u);
  await assert.rejects(async () => capture.run(() => 'value'), CaptureError);
});

test('maxRecords marks the capture incomplete and rejects later records', () => {
  const capture = createMemoryCapture({ maxRecords: 2 });
  assert.equal(capture.push('one'), true);
  assert.equal(capture.push('two'), true);
  assert.equal(capture.push('three'), false);

  assert.equal(capture.coverage, 'incomplete');
  const result = capture.finish();
  assert.equal(result.coverage, 'incomplete');
  assert.equal(result.records.length, 2);
  assert.deepEqual(
    result.issues.map((issue) => issue.code),
    ['max-records-exceeded'],
  );
});

test('maxRecordBytes and maxTotalBytes are enforced while pushing', () => {
  const perRecord = createMemoryCapture({ maxRecordBytes: 128, maxTotalBytes: 1024 });
  assert.equal(perRecord.push('a'.repeat(200)), false);
  assert.equal(perRecord.coverage, 'incomplete');
  assert.equal(perRecord.finish().issues[0].code, 'max-record-bytes-exceeded');

  const total = createMemoryCapture({ maxRecordBytes: 1024, maxTotalBytes: 1024 });
  assert.equal(total.push('a'.repeat(600)), true);
  assert.equal(total.push('b'.repeat(600)), false);
  assert.equal(total.finish().issues[0].code, 'max-total-bytes-exceeded');
});

test('custom issues are deduplicated and mark the capture incomplete', () => {
  const capture = createMemoryCapture();
  capture.reportIssue('serialization-failed');
  capture.reportIssue('serialization-failed');
  capture.reportIssue('custom-reason');

  const result = capture.finish();
  assert.equal(result.coverage, 'incomplete');
  assert.deepEqual(
    result.issues.map((issue) => issue.code),
    ['serialization-failed', 'custom-reason'],
  );
  assert.equal(result.issues[1].message, 'The capture reported an unspecified issue.');
  assert.throws(() => createMemoryCapture().reportIssue(''), ConfigurationError);
});

test('run returns a successful outcome without swallowing errors', async () => {
  const capture = createMemoryCapture();
  const outcome = await capture.run(async () => {
    capture.push('inside');
    return 42;
  });

  assert.equal(outcome.ok, true);
  assert.equal(outcome.value, 42);
  assert.equal(outcome.captured.records.length, 1);
  assert.equal(outcome.captured.coverage, 'complete');
  assert.equal(Object.isFrozen(outcome), true);

  const failed = createMemoryCapture();
  const expected = new Error('synthetic failure');
  const failure = await failed.run(() => {
    throw expected;
  });
  assert.equal(failure.ok, false);
  assert.equal(failure.error, expected);
  assert.equal(failure.captured.coverage, 'complete');
});

test('run requires a function', async () => {
  await assert.rejects(async () => createMemoryCapture().run('nope'), ConfigurationError);
});

test('capture options reject unknown keys and invalid sources', () => {
  assert.throws(() => createMemoryCapture({ maxRecords: 0 }), /must be >= 1/u);
  assert.throws(() => createMemoryCapture({ nope: 1 }), /Unknown option/u);
  assert.throws(() => createMemoryCapture({ source: 42 }), ConfigurationError);
  assert.throws(
    () => createMemoryCapture({ maxTotalBytes: 1024, maxRecordBytes: 2048 }),
    /must be >=/u,
  );
});

test('a finished capture can be analyzed directly', () => {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  const capture = createMemoryCapture({ source: 'unit' });
  capture.push({ password: SYNTHETIC.password });
  capture.push(SYNTHETIC.canary);

  const result = detector.analyze(capture.finish());
  assert.deepEqual(
    new Set(result.findings.map((finding) => finding.ruleId)),
    new Set(['password-field', 'known-secret']),
  );
  assert.equal(result.findings[1].source, 'unit');
});

test('analyze rejects malformed capture results', () => {
  const detector = createLogLeakDetector();
  assert.throws(() => detector.analyze({ coverage: 'complete', records: 'nope' }), /records/u);
  assert.throws(() => detector.analyze({ coverage: 'partial', records: [] }), /coverage/u);
  assert.throws(() => detector.analyze(undefined), ConfigurationError);
});
