import assert from 'node:assert/strict';
import test from 'node:test';
import {
  assertNoSensitiveLogLeaks,
  createLogLeakDetector,
  createMemoryCapture,
} from 'logleak-test';
import { login } from './app.js';

test('the redacted example passes the default policy', () => {
  const capture = createMemoryCapture({ source: 'redacted-example' });
  const logger = {
    info(record) {
      capture.push(record);
    },
  };

  login(logger, { userId: 'user-1' });
  const result = createLogLeakDetector().analyze(capture.finish());

  assert.equal(result.status, 'pass');
  assert.equal(result.summary.redactedFields, 1);
  assert.equal(assertNoSensitiveLogLeaks(result), result);
});

test('the strict policy surfaces the redacted field at low severity', () => {
  const capture = createMemoryCapture();
  const logger = {
    info(record) {
      capture.push(record);
    },
  };

  login(logger, { userId: 'user-1' });
  const result = createLogLeakDetector({ policy: 'strict' }).analyze(capture.finish());

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].ruleId, 'password-field');
  assert.equal(result.findings[0].redacted, true);
  assert.equal(result.findings[0].severity, 'low');
});
