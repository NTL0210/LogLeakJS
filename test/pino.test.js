import assert from 'node:assert/strict';
import test from 'node:test';
import pino from 'pino';
import { createPinoCapture } from '../src/capture/pino.js';
import { createLogLeakDetector } from '../src/index.js';
import { SYNTHETIC } from '../test-support/synthetic.js';

test('Pino output is analyzed after serialization', () => {
  const capture = createPinoCapture({ source: 'pino-test' });
  const logger = pino({}, capture.stream);

  logger.info({ password: SYNTHETIC.password, requestId: 'req-1' }, 'login');

  const detector = createLogLeakDetector();
  const result = detector.analyze(capture.finish());

  assert.equal(result.status, 'leaks');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].ruleId, 'password-field');
  assert.equal(result.findings[0].path, '$.password');
  assert.equal(result.findings[0].source, 'pino-test');
  assert.equal(JSON.stringify(result).includes(SYNTHETIC.password), false);
});

test('Pino redaction is respected by default and visible under strict policy', () => {
  const capture = createPinoCapture();
  const logger = pino({ redact: ['password', 'req.headers.authorization'] }, capture.stream);
  logger.info({
    password: SYNTHETIC.password,
    req: { headers: { authorization: SYNTHETIC.bearer } },
  });

  const captured = capture.finish();
  const relaxed = createLogLeakDetector().analyze(captured);
  assert.equal(relaxed.status, 'pass');
  assert.equal(relaxed.summary.redactedFields, 2);

  const strict = createLogLeakDetector({ policy: 'strict' }).analyze(captured);
  assert.equal(strict.findings.length, 2);
  assert.equal(strict.findings.every((finding) => finding.redacted), true);
});

test('a serializer that removes a secret prevents a finding', () => {
  const capture = createPinoCapture();
  const logger = pino(
    {
      serializers: {
        user(user) {
          return { id: user.id };
        },
      },
    },
    capture.stream,
  );

  logger.info({ user: { id: 7, password: SYNTHETIC.password } });
  const result = createLogLeakDetector().analyze(capture.finish());

  assert.equal(result.status, 'pass');
  assert.equal(result.findings.length, 0);
});

test('Pino child loggers and raw string messages are captured', () => {
  const capture = createPinoCapture();
  const logger = pino({}, capture.stream);
  const child = logger.child({ component: 'auth' });

  child.info(`token=${SYNTHETIC.githubToken}`);

  const result = createLogLeakDetector().analyze(capture.finish());
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].ruleId, 'github-token');
});

test('run() captures synchronously rendered records and finishes once', async () => {
  const capture = createPinoCapture();
  const logger = pino({}, capture.stream);

  const outcome = await capture.run(() => {
    logger.info({ apiKey: SYNTHETIC.googleKey });
    return 'done';
  });

  assert.equal(outcome.ok, true);
  assert.equal(outcome.value, 'done');
  assert.equal(capture.finished, true);
  assert.equal(outcome.captured.records.length, 1);

  const result = createLogLeakDetector().analyze(outcome.captured);
  assert.equal(result.findings[0].ruleId, 'api-key-field');
});

test('the destination stream accepts strings and byte buffers only', () => {
  const capture = createPinoCapture();
  assert.equal(capture.stream.write('{"message":"one"}\n'), true);
  assert.equal(capture.stream.write(Buffer.from('{"message":"two"}\n')), true);
  assert.equal(capture.stream.write({ message: 'object' }), false);
  assert.equal(capture.coverage, 'incomplete');

  const result = capture.finish();
  assert.equal(result.records.length, 2);
  assert.deepEqual(
    result.issues.map((issue) => issue.code),
    ['serialization-failed'],
  );
});

test('Pino capture limits are enforced and reported as incomplete', () => {
  const capture = createPinoCapture({ maxRecords: 1 });
  const logger = pino({}, capture.stream);
  logger.info('one');
  logger.info('two');

  const captured = capture.finish();
  assert.equal(captured.coverage, 'incomplete');
  assert.equal(captured.records.length, 1);

  const result = createLogLeakDetector().analyze(captured);
  assert.equal(result.status, 'incomplete');
  assert.equal(result.summary.incompleteReasons.includes('max-records-exceeded'), true);
});

test('Pino capture options are validated', () => {
  assert.throws(() => createPinoCapture({ maxRecords: 0 }), /must be >= 1/u);
  assert.throws(() => createPinoCapture({ unknown: true }), /Unknown option/u);
  assert.throws(() => createPinoCapture({ source: 42 }), /must be a string/u);
});

test('an oversized rendered Pino line is rejected safely', () => {
  const capture = createPinoCapture({ maxRecordBytes: 128, maxTotalBytes: 1024 });
  const logger = pino({}, capture.stream);
  logger.info({ note: 'x'.repeat(200) });

  const captured = capture.finish();
  assert.equal(captured.coverage, 'incomplete');
  assert.equal(captured.issues[0].code, 'max-record-bytes-exceeded');
});
