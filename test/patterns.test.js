import assert from 'node:assert/strict';
import test from 'node:test';
import { createLogLeakDetector } from '../src/index.js';
import { analyze, findingsFor } from '../test-support/helpers.js';
import { SYNTHETIC } from '../test-support/synthetic.js';

const FIXTURES = [
  ['bearer-token', SYNTHETIC.bearer],
  ['basic-auth-credential', SYNTHETIC.basic],
  ['jwt', SYNTHETIC.jwt],
  ['pem-private-key', SYNTHETIC.pem],
  ['aws-access-key-id', SYNTHETIC.awsKey],
  ['github-token', SYNTHETIC.githubToken],
  ['npm-token', SYNTHETIC.npmToken],
  ['slack-token', SYNTHETIC.slackToken],
  ['stripe-secret-key', SYNTHETIC.stripeKey],
  ['google-api-key', SYNTHETIC.googleKey],
  ['connection-string-credentials', SYNTHETIC.databaseUrl],
];

for (const [ruleId, value] of FIXTURES) {
  test(`credential pattern ${ruleId} is detected`, () => {
    const result = analyze(`log line: ${value}`);

    assert.equal(result.status, 'leaks');
    assert.equal(result.coverage, 'complete');
    const findings = findingsFor(result, ruleId);
    assert.equal(findings.length, 1);

    const [finding] = findings;
    assert.equal(finding.detector, 'credential-pattern');
    assert.equal(finding.evidence, 'credential-pattern');
    assert.equal(finding.path, '$');
    assert.equal(finding.scope, 'record-text');
    assert.equal(finding.redacted, false);
    assert.equal(JSON.stringify(finding).includes(value), false);
  });
}

test('PEM private keys are critical by default', () => {
  const result = analyze(SYNTHETIC.pem);
  const [finding] = findingsFor(result, 'pem-private-key');
  assert.equal(finding.severity, 'critical');
});

test('a pattern severity override applies unless a rule-specific severity exists', () => {
  const result = analyze(SYNTHETIC.pem, { severity: { credentialPattern: 'medium' } });
  assert.equal(result.findings[0].severity, 'medium');
});

test('a credential value inside a structured field is found at its path', () => {
  const result = analyze({ nested: { note: SYNTHETIC.githubToken } });
  const [finding] = findingsFor(result, 'github-token');
  assert.equal(finding.path, '$.nested.note');
  assert.equal(finding.scope, 'field');
});

test('multiple patterns in one record are reported independently', () => {
  const result = analyze(`one ${SYNTHETIC.bearer} two ${SYNTHETIC.googleKey}`);
  assert.deepEqual(
    new Set(result.findings.map((finding) => finding.ruleId)),
    new Set(['bearer-token', 'google-api-key']),
  );
});

test('pattern ids in a field name are redacted from the path', () => {
  const result = analyze({ [SYNTHETIC.githubToken]: 'synthetic' });
  const findings = findingsFor(result, 'github-token');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].path, '$["[redacted-key]"]');
  assert.equal(JSON.stringify(result).includes(SYNTHETIC.githubToken), false);
});

test('patterns can be disabled individually with disabledRules', () => {
  const detector = createLogLeakDetector({ disabledRules: ['jwt'] });
  assert.equal(detector.analyze(SYNTHETIC.jwt).findings.length, 0);
  assert.equal(detector.analyze(SYNTHETIC.bearer).findings.length, 1);
});

test('the credential-pattern detector can be disabled as a family', () => {
  const result = analyze(`Bearer ${SYNTHETIC.bearer}`, {
    detectors: { credentialPatterns: false },
  });
  assert.equal(result.findings.length, 0);
});

test('ordinary text does not trigger credential patterns', () => {
  const result = analyze({
    message: 'Basic plan renewed. Token count: 4. Connection to db.internal established.',
    url: 'https://example.test/docs',
  });
  assert.equal(result.status, 'pass');
  assert.equal(result.findings.length, 0);
});

test('a published rule catalog lists every shipped credential pattern', () => {
  const detector = createLogLeakDetector();
  const rules = detector.getConfig();
  assert.equal(rules.detectors.credentialPatterns.enabled, true);
  for (const [ruleId] of FIXTURES) {
    assert.doesNotThrow(() => createLogLeakDetector({ disabledRules: [ruleId] }));
  }
});
