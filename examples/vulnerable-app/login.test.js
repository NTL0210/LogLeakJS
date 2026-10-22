import assert from 'node:assert/strict';
import test from 'node:test';
import {
  assertNoSensitiveLogLeaks,
  createLogLeakDetector,
  createMemoryCapture,
  formatJsonReport,
  LogLeakAssertionError,
} from 'logleak-test';
import { login } from './app.js';

const PASSWORD = 'demo-password-value';
const TOKEN = 'demo-token-value';

test('the vulnerable example is caught without printing the values', () => {
  const capture = createMemoryCapture({ source: 'vulnerable-example' });
  const logger = {
    info(record) {
      capture.push(record);
    },
  };

  login(logger, { userId: 'user-1', password: PASSWORD, token: TOKEN });

  const result = createLogLeakDetector().analyze(capture.finish());
  assert.equal(result.status, 'leaks');

  const rules = new Set(result.findings.map((finding) => finding.ruleId));
  assert.equal(rules.has('password-field'), true);
  assert.equal(rules.has('generic-token-field'), true);

  const report = formatJsonReport(result);
  assert.equal(report.includes(PASSWORD), false);
  assert.equal(report.includes(TOKEN), false);

  assert.throws(
    () => assertNoSensitiveLogLeaks(result),
    (error) => error instanceof LogLeakAssertionError && error.exitCode === 1,
  );
});
