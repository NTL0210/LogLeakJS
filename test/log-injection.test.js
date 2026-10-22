import assert from 'node:assert/strict';
import test from 'node:test';
import { createLogLeakDetector } from '../src/index.js';
import { analyze, findingsFor } from '../test-support/helpers.js';
import { SYNTHETIC } from '../test-support/synthetic.js';

test('NUL and ANSI escape characters are reported as control characters', () => {
  const nul = findingsFor(analyze({ message: SYNTHETIC.controlCharacters }), 'control-character');
  assert.equal(nul.length, 1);
  assert.equal(nul[0].detector, 'log-injection');
  assert.equal(nul[0].evidence, 'log-injection');
  assert.equal(nul[0].severity, 'medium');
  assert.equal(nul[0].path, '$.message');

  const ansi = findingsFor(analyze({ message: SYNTHETIC.ansiEscape }), 'control-character');
  assert.equal(ansi.length, 1);
});

test('a lone carriage return is reported but CRLF is not', () => {
  const lone = findingsFor(analyze(SYNTHETIC.loneCarriageReturn), 'lone-carriage-return');
  assert.equal(lone.length, 1);
  assert.equal(lone[0].scope, 'record-text');

  assert.equal(analyze('line1\r\nline2').findings.length, 0);
});

test('Unicode line separators are reported at low severity', () => {
  const result = analyze(SYNTHETIC.unicodeLineSeparator);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].ruleId, 'unicode-line-separator');
  assert.equal(result.findings[0].severity, 'low');
});

test('log-injection rules can be disabled individually or as a family', () => {
  const one = analyze(SYNTHETIC.controlCharacters, {
    disabledRules: ['control-character'],
  });
  assert.equal(one.findings.length, 0);

  const family = analyze(SYNTHETIC.controlCharacters, {
    detectors: { logInjection: false },
  });
  assert.equal(family.findings.length, 0);
});

test('a rendered, line-prefixed injection attempt is reported without its content', () => {
  const detector = createLogLeakDetector();
  const result = detector.analyze({
    message: 'GET /login\nINFO forged admin=true\rnext',
  });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].ruleId, 'lone-carriage-return');
  assert.equal(JSON.stringify(result).includes('forged admin'), false);
});

test('the log-injection severity is configurable', () => {
  const result = analyze(SYNTHETIC.controlCharacters, {
    severity: { logInjection: 'critical' },
  });
  assert.equal(result.findings[0].severity, 'critical');
});
