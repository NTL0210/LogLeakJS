import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ConfigurationError,
  createLogLeakDetector,
  formatJsonReport,
  formatTerminalReport,
} from '../src/index.js';
import { SYNTHETIC } from '../test-support/synthetic.js';

/**
 * @param {{color?: boolean, maxFindings?: number, includeRemediation?: boolean}} [options]
 * @returns {string}
 */
function leakResult(options) {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  return formatTerminalReport(
    detector.analyze({ password: SYNTHETIC.password, note: SYNTHETIC.canary }),
    options,
  );
}

test('a clean report states that no findings were present', () => {
  const result = createLogLeakDetector().analyze({ message: 'clean' });
  const report = formatTerminalReport(result);

  assert.match(report, /Status: PASS/u);
  assert.match(report, /coverage: complete/u);
  assert.match(report, /No findings in the captured log output\./u);
  assert.match(report, /Summary: 1 record\(s\)/u);
  assert.match(report, /No sensitive values are included in this report\./u);
  assert.equal(report.includes('\u001B['), false);
});

test('an incomplete clean report refuses to claim a clean result', () => {
  const result = createLogLeakDetector().analyze(new WeakMap());
  const report = formatTerminalReport(result);

  assert.match(report, /Status: INCOMPLETE/u);
  assert.match(report, /No findings, but the analysis was incomplete/u);
  assert.match(report, /Incomplete analysis: unsupported-container/u);
  assert.match(report, /must not be reported as clean/u);
});

test('leak reports include metadata, remediation, and diagnostics only', () => {
  const report = leakResult();

  assert.match(report, /Status: LEAKS/u);
  assert.match(report, /CRITICAL +known-secret · known-secret/u);
  assert.match(report, /HIGH +sensitive-field · password-field/u);
  assert.match(report, /record 0 · \$\.password/u);
  assert.match(report, /fix: /u);
  assert.equal(report.includes(SYNTHETIC.password), false);
  assert.equal(report.includes(SYNTHETIC.canary), false);
});

test('maxFindings truncates a terminal report with an explicit notice', () => {
  const report = leakResult({ maxFindings: 1 });
  assert.match(report, /and 1 more finding\(s\)/u);
  assert.match(report, /Raise report options\.maxFindings/u);
});

test('remediation can be omitted and color can be enabled', () => {
  const plain = leakResult({ includeRemediation: false });
  assert.equal(plain.includes('fix: '), false);

  const colored = leakResult({ color: true });
  assert.equal(colored.includes('\u001B['), true);
  assert.equal(colored.includes('\u001B[0m'), true);
});

test('the JSON report has a stable schema and optional timestamp', () => {
  const result = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] }).analyze(
    SYNTHETIC.canary,
  );
  const json = formatJsonReport(result);
  const parsed = JSON.parse(json);

  assert.deepEqual(Object.keys(parsed), [
    'tool',
    'version',
    'schemaVersion',
    'status',
    'exitCode',
    'policy',
    'coverage',
    'failOnIncomplete',
    'findings',
    'diagnostics',
    'summary',
  ]);
  assert.equal(parsed.tool, 'logleak-test');
  assert.equal(parsed.status, 'leaks');
  assert.equal(parsed.exitCode, 1);
  assert.equal(json.includes(SYNTHETIC.canary), false);

  const compact = formatJsonReport(result, { pretty: false });
  assert.equal(compact.includes('\n'), false);
  assert.deepEqual(JSON.parse(compact).findings, parsed.findings);

  const timestamped = JSON.parse(formatJsonReport(result, { includeTimestamp: true }));
  assert.equal(typeof timestamped.generatedAt, 'string');
  assert.equal(Number.isNaN(Date.parse(timestamped.generatedAt)), false);
});

test('report options are validated strictly', () => {
  const result = createLogLeakDetector().analyze('clean');

  assert.throws(() => formatTerminalReport(result, { colour: true }), ConfigurationError);
  assert.throws(() => formatTerminalReport(result, { maxFindings: 0 }), /must be >= 1/u);
  assert.throws(() => formatTerminalReport(result, { maxFindings: 1.5 }), /integer/u);
  assert.throws(() => formatJsonReport(result, { pretty: 'yes' }), ConfigurationError);
  assert.throws(() => formatJsonReport(result, { nope: true }), /Unknown option/u);
  assert.throws(() => formatTerminalReport(result, null), /plain object/u);
});

test('invalid analysis results are rejected by both formatters', () => {
  for (const value of [null, {}, { findings: 'nope' }]) {
    assert.throws(() => formatTerminalReport(value), ConfigurationError);
    assert.throws(() => formatJsonReport(value), ConfigurationError);
  }
});
