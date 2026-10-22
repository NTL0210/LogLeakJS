import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import {
  assertNoSensitiveLogLeaks,
  createLogLeakDetector,
  formatJsonReport,
  formatTerminalReport,
} from '../src/index.js';
import { SYNTHETIC, SYNTHETIC_VALUES } from '../test-support/synthetic.js';

const EXTRA_SENSITIVE = Object.freeze([
  SYNTHETIC.secretKeyName,
  SYNTHETIC.controlCharacters,
  SYNTHETIC.ansiEscape,
  SYNTHETIC.loneCarriageReturn,
  SYNTHETIC.unicodeLineSeparator,
]);

/**
 * Inputs whose exact text must never appear in any report.
 *
 * @returns {string[]}
 */
function forbiddenStrings() {
  return [...SYNTHETIC_VALUES, ...EXTRA_SENSITIVE];
}

/**
 * @param {string} report
 */
function assertNoForbiddenValues(report) {
  for (const value of forbiddenStrings()) {
    assert.equal(
      report.includes(value),
      false,
      `report contained a captured value of length ${value.length}`,
    );
    const digest = createHash('sha256').update(value, 'utf8').digest('hex');
    assert.equal(report.includes(digest), false, 'report contained a hash of a captured value');
  }
  assert.equal(report.includes('forged admin'), false);
  assert.equal(report.includes('boom SYNTHETIC'), false);
}

test('terminal and JSON reports never include detected values, raw lines, or hashes', () => {
  const detector = createLogLeakDetector({
    policy: 'audit',
    knownSecrets: [SYNTHETIC.canary],
  });

  const record = {
    password: SYNTHETIC.password,
    token: SYNTHETIC.token,
    authorization: SYNTHETIC.bearer,
    basic: SYNTHETIC.basic,
    jwt: SYNTHETIC.jwt,
    privateKeyPem: SYNTHETIC.pem,
    awsKey: SYNTHETIC.awsKey,
    githubToken: SYNTHETIC.githubToken,
    npmToken: SYNTHETIC.npmToken,
    slackToken: SYNTHETIC.slackToken,
    stripeKey: SYNTHETIC.stripeKey,
    googleKey: SYNTHETIC.googleKey,
    databaseUrl: SYNTHETIC.databaseUrl,
    canary: SYNTHETIC.canary,
    email: SYNTHETIC.email,
    phone: SYNTHETIC.phone,
    note: [
      SYNTHETIC.nanpPhone,
      SYNTHETIC.controlCharacters,
      SYNTHETIC.ansiEscape,
      SYNTHETIC.loneCarriageReturn,
      SYNTHETIC.unicodeLineSeparator,
      'forged admin=true',
    ].join(' '),
    [SYNTHETIC.secretKeyName]: 'synthetic',
    error: new Error(`boom ${SYNTHETIC.canary}`),
  };

  const result = detector.analyze(record);
  assert.equal(result.status, 'leaks');
  assert.equal(result.coverage, 'complete');

  const json = formatJsonReport(result);
  const terminal = formatTerminalReport(result, { color: false });
  const coloredTerminal = formatTerminalReport(result, { color: true });

  assertNoForbiddenValues(json);
  assertNoForbiddenValues(terminal);
  assertNoForbiddenValues(coloredTerminal);

  const parsed = JSON.parse(json);
  assert.equal(parsed.status, 'leaks');
  assert.equal(Array.isArray(parsed.findings), true);
  for (const finding of parsed.findings) {
    assertNoForbiddenValues(JSON.stringify(finding));
  }
});

test('assertion errors and the embedded result are privacy-safe', () => {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  const result = detector.analyze({
    password: SYNTHETIC.password,
    note: SYNTHETIC.canary,
    error: new Error(`boom ${SYNTHETIC.canary}`),
  });

  assert.throws(
    () => assertNoSensitiveLogLeaks(result),
    (error) => {
      assert.equal(error.name, 'LogLeakAssertionError');
      assertNoForbiddenValues(error.message);
      assertNoForbiddenValues(JSON.stringify(error.result));
      assertNoForbiddenValues(formatTerminalReport(error.result));
      return true;
    },
  );
});

test('privacy-safe configuration does not expose registered secrets', () => {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  const serialized = JSON.stringify(detector.getConfig());
  assert.equal(serialized.includes(SYNTHETIC.canary), false);
  assert.equal(serialized.includes('secret-1'), false);
});

test('a secret embedded in a field name is redacted from the path', () => {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  const result = detector.analyze({ [SYNTHETIC.secretKeyName]: 'synthetic' });

  assert.equal(result.findings.length >= 1, true);
  for (const finding of result.findings) {
    assert.equal(finding.path.includes(SYNTHETIC.canary), false);
    assert.equal(finding.path.includes('[redacted-key]'), true);
  }
  assertNoForbiddenValues(formatTerminalReport(result));
});

test('diagnostics for unsafe data do not echo the data', () => {
  const detector = createLogLeakDetector({ knownSecrets: [SYNTHETIC.canary] });
  const record = {};
  Object.defineProperty(record, SYNTHETIC.secretKeyName, {
    enumerable: true,
    get() {
      return SYNTHETIC.password;
    },
  });

  const result = detector.analyze(record);
  assertNoForbiddenValues(formatJsonReport(result));
  assertNoForbiddenValues(formatTerminalReport(result));
});

test('finding ids depend only on rule metadata, not on the detected value', () => {
  const detector = createLogLeakDetector();
  const first = detector.analyze({ password: 'first-synthetic-value' });
  const second = detector.analyze({ password: 'second-synthetic-value' });
  assert.equal(first.findings[0].id, second.findings[0].id);
});
