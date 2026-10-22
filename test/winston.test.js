import assert from 'node:assert/strict';
import test from 'node:test';
import winston from 'winston';
import { createWinstonCapture } from '../src/capture/winston.js';
import { CaptureError, ConfigurationError, createLogLeakDetector } from '../src/index.js';
import { SYNTHETIC } from '../test-support/synthetic.js';

/**
 * @param {object} [options]
 * @returns {import('winston').Logger}
 */
function createLogger(options = {}) {
  return winston.createLogger({ transports: [], ...options });
}

test('Winston JSON output is captured after formatting', () => {
  const capture = createWinstonCapture({ source: 'winston-test' });
  const logger = createLogger();
  capture.attach(logger);

  logger.info('login', { password: SYNTHETIC.password, requestId: 'req-1' });

  const result = createLogLeakDetector().analyze(capture.finish());
  assert.equal(result.status, 'leaks');
  assert.equal(result.findings[0].ruleId, 'password-field');
  assert.equal(result.findings[0].path, '$.password');
  assert.equal(result.findings[0].source, 'winston-test');
  assert.equal(JSON.stringify(result).includes(SYNTHETIC.password), false);
});

test('an object passed as the Winston message is inspected', () => {
  const capture = createWinstonCapture();
  const logger = createLogger();
  capture.attach(logger);
  logger.info({ apiKey: SYNTHETIC.googleKey });

  const result = createLogLeakDetector().analyze(capture.finish());
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].ruleId, 'api-key-field');
  assert.equal(result.findings[0].path, '$.message.apiKey');
});

test('Winston error formatting includes message and stack for inspection', () => {
  const capture = createWinstonCapture();
  const logger = createLogger({
    format: winston.format.combine(
      winston.format.errors({ stack: true }),
      winston.format.json(),
    ),
  });
  capture.attach(logger);

  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  logger.error(new Error(`boom ${SYNTHETIC.canary}`));

  const result = detector.analyze(capture.finish());
  const paths = new Set(result.findings.map((finding) => finding.path));
  assert.equal(paths.has('$.message'), true);
  assert.equal(paths.has('$.stack'), true);
  assert.equal(JSON.stringify(result).includes(SYNTHETIC.canary), false);
});

test('a Winston format that removes a secret prevents a finding', () => {
  const capture = createWinstonCapture();
  const logger = createLogger({
    format: winston.format.combine(
      winston.format((info) => {
        delete info.password;
        return info;
      })(),
      winston.format.json(),
    ),
  });
  capture.attach(logger);
  logger.info('safe message', { password: SYNTHETIC.password, userId: 12 });

  const result = createLogLeakDetector().analyze(capture.finish());
  assert.equal(result.status, 'pass');
  assert.equal(result.findings.length, 0);
});

test('attaching twice does not duplicate the transport, and finish detaches it', () => {
  const capture = createWinstonCapture();
  const logger = createLogger();
  const before = logger.transports.length;

  assert.equal(capture.attach(logger), capture);
  assert.equal(capture.attach(logger), capture);
  assert.equal(logger.transports.length, before + 1);

  capture.finish();
  assert.equal(logger.transports.length, before);
});

test('detach does not remove a transport the adapter did not attach', () => {
  const capture = createWinstonCapture();
  const logger = createLogger();
  logger.add(capture.transport);

  capture.attach(logger);
  capture.finish();

  assert.equal(logger.transports.includes(capture.transport), true);
  logger.remove(capture.transport);
});

test('run attaches, captures, and always detaches even when the body throws', async () => {
  const capture = createWinstonCapture();
  const logger = createLogger();
  const before = logger.transports.length;
  const expected = new Error('synthetic failure');

  const outcome = await capture.run(logger, () => {
    logger.info('before failure', { token: SYNTHETIC.token });
    throw expected;
  });

  assert.equal(outcome.ok, false);
  assert.equal(outcome.error, expected);
  assert.equal(capture.finished, true);
  assert.equal(logger.transports.length, before);
  assert.equal(outcome.captured.records.length, 1);

  const result = createLogLeakDetector().analyze(outcome.captured);
  assert.equal(result.findings[0].ruleId, 'generic-token-field');
});

test('a directly invoked transport without a rendered message uses a shallow snapshot', () => {
  const capture = createWinstonCapture();
  capture.transport.log({ password: SYNTHETIC.password }, () => {});

  const result = createLogLeakDetector().analyze(capture.finish());
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].path, '$.password');
});

test('a transport write after finish reports a safe failure through the callback', () => {
  const capture = createWinstonCapture();
  capture.finish();

  let failure;
  capture.transport.log({ message: 'too late' }, (error) => {
    failure = error;
  });

  assert.equal(failure instanceof CaptureError, true);
});

test('invalid loggers and options are rejected', async () => {
  const capture = createWinstonCapture();
  assert.throws(() => capture.attach({}), ConfigurationError);
  assert.throws(() => capture.attach(null), ConfigurationError);
  await assert.rejects(async () => capture.run({}, () => {}), ConfigurationError);

  assert.throws(() => createWinstonCapture({ maxRecords: 0 }), /must be >= 1/u);
  assert.throws(() => createWinstonCapture({ unknown: true }), /Unknown option/u);
  assert.throws(() => createWinstonCapture({ source: 42 }), /must be a string/u);
});

test('Winston capture limits are enforced and surface as incomplete', () => {
  const capture = createWinstonCapture({ maxRecords: 1 });
  const logger = createLogger();
  capture.attach(logger);
  logger.info('one');
  logger.info('two');

  const captured = capture.finish();
  assert.equal(captured.coverage, 'incomplete');
  assert.equal(captured.records.length, 1);

  const result = createLogLeakDetector().analyze(captured);
  assert.equal(result.status, 'incomplete');
  assert.equal(result.summary.incompleteReasons.includes('max-records-exceeded'), true);
});

test('an oversized rendered Winston line is rejected safely', () => {
  const capture = createWinstonCapture({ maxRecordBytes: 128, maxTotalBytes: 1024 });
  const logger = createLogger();
  capture.attach(logger);
  logger.info({ note: 'x'.repeat(200) });

  const captured = capture.finish();
  assert.equal(captured.coverage, 'incomplete');
  assert.equal(captured.issues[0].code, 'max-record-bytes-exceeded');
});
