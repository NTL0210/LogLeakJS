import assert from 'node:assert/strict';
import test from 'node:test';
import { createLogLeakDetector } from '../src/index.js';
import { analyze } from '../test-support/helpers.js';
import { SYNTHETIC } from '../test-support/synthetic.js';

test('a password-like field is reported with a value-free finding', () => {
  const result = analyze({ password: SYNTHETIC.password });

  assert.equal(result.status, 'leaks');
  assert.equal(result.findings.length, 1);
  const [finding] = result.findings;
  assert.equal(finding.detector, 'sensitive-field');
  assert.equal(finding.ruleId, 'password-field');
  assert.equal(finding.evidence, 'sensitive-field');
  assert.equal(finding.category, 'credentials');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.path, '$.password');
  assert.equal(finding.scope, 'field');
  assert.equal(finding.redacted, false);
});

test('field names are matched after case folding and separator removal', () => {
  const names = [
    'Password',
    'PASSWORD',
    'pass_word',
    'user-password',
    'refreshToken',
    'refresh_token',
    'REFRESH-TOKEN',
    'API Key',
    'x-api-key',
    'client.secret',
    'ｐａｓｓｗｏｒｄ',
  ];

  for (const name of names) {
    const result = analyze({ [name]: 'synthetic-value' });
    assert.equal(
      result.findings.length,
      1,
      `expected exactly one finding for field name ${JSON.stringify(name)}`,
    );
  }
});

test('curated suffix rules match compound names but generic tokens do not', () => {
  const positive = analyze({
    accountPassword: 'x',
    my_refresh_token: 'x',
    databaseConnectionString: 'x',
    awsSecretAccessKey: 'x',
  });
  assert.deepEqual(
    new Set(positive.findings.map((finding) => finding.ruleId)),
    new Set([
      'password-field',
      'refresh-token-field',
      'connection-string-field',
      'private-key-field',
    ]),
  );

  const negative = analyze({
    nextToken: 'x',
    tokenCount: 1,
    passwordPolicy: 'strict',
    secretSanta: 'x',
    author: 'x',
    sessionDuration: 60,
  });
  assert.equal(negative.status, 'pass');
  assert.equal(negative.findings.length, 0);
});

test('generic token names are reported at medium severity', () => {
  const result = analyze({ token: 'synthetic' });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].ruleId, 'generic-token-field');
  assert.equal(result.findings[0].severity, 'medium');
});

test('blank, null, boolean, and empty-container values are not findings', () => {
  const result = analyze({
    password: '',
    secretKey: '   ',
    token: null,
    apiKey: undefined,
    authorization: false,
    credentials: {},
    cookie: [],
  });

  assert.equal(result.status, 'pass');
  assert.equal(result.findings.length, 0);
});

test('non-string scalar values in sensitive fields are findings', () => {
  const result = analyze({ password: 1234, apiKey: 0, otp: 987654n });
  assert.equal(result.findings.length, 3);
});

test('nested sensitive containers are reported once at the container path', () => {
  const result = analyze({ password: { value: 'synthetic', nested: { again: true } } });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].ruleId, 'password-field');
  assert.equal(result.findings[0].path, '$.password');
});

test('a more specific nested field finding replaces its sensitive ancestor', () => {
  const result = analyze({ password: { secretKey: 'synthetic' } });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].ruleId, 'private-key-field');
  assert.equal(result.findings[0].path, '$.password.secretKey');
});

test('default policy accepts redacted values; strict policy reports them at low severity', () => {
  const record = { password: '[REDACTED]' };

  const relaxed = analyze(record);
  assert.equal(relaxed.status, 'pass');
  assert.equal(relaxed.summary.redactedFields, 1);

  const strict = analyze(record, { policy: 'strict' });
  assert.equal(strict.findings.length, 1);
  assert.equal(strict.findings[0].redacted, true);
  assert.equal(strict.findings[0].severity, 'low');
  assert.equal(strict.findings[0].path, '$.password');
});

test('an all-placeholder sensitive container is treated as redacted', () => {
  const record = { authorization: { scheme: '***', value: '<redacted>' } };
  const relaxed = analyze(record);
  assert.equal(relaxed.status, 'pass');
  assert.equal(relaxed.summary.redactedFields, 1);

  const strict = analyze(record, { policy: 'strict' });
  assert.equal(strict.findings.length, 1);
  assert.equal(strict.findings[0].path, '$.authorization');
  assert.equal(strict.findings[0].redacted, true);
});

test('explicit safe placeholders and asterisk runs are accepted', () => {
  const detector = createLogLeakDetector({ safePlaceholders: ['scrubbed-value'] });
  assert.equal(detector.analyze({ password: 'scrubbed-value' }).findings.length, 0);
  assert.equal(detector.analyze({ password: '*****' }).findings.length, 0);
  assert.equal(detector.analyze({ password: '***abc***' }).findings.length, 1);
});

test('structured header name/value pairs are reported', () => {
  const result = analyze({
    headers: [
      { name: 'authorization', value: SYNTHETIC.bearer },
      { name: 'x-api-key', value: 'synthetic-key' },
      { name: 'accept', value: 'application/json' },
    ],
  });

  const rules = result.findings.map((finding) => finding.ruleId).sort();
  assert.deepEqual(rules, ['api-key-field', 'authorization-header']);
  assert.deepEqual(
    result.findings.map((finding) => finding.path).sort(),
    ['$.headers[0].value', '$.headers[1].value'],
  );
  assert.equal(
    result.findings.every((finding) => finding.confidence === 'medium'),
    true,
  );
});

test('a redacted structured header is only reported in strict policy', () => {
  const record = { headers: [{ name: 'authorization', value: '[REDACTED]' }] };

  assert.equal(analyze(record).findings.length, 0);

  const strict = analyze(record, { policy: 'strict' });
  assert.equal(strict.findings.length, 1);
  assert.equal(strict.findings[0].path, '$.headers[0].value');
  assert.equal(strict.findings[0].redacted, true);
});

test('personal-data field names are gated behind the audit policy', () => {
  const record = { email: SYNTHETIC.email, cardNumber: '4111111111111111' };

  assert.equal(analyze(record).findings.length, 0);

  const audit = analyze(record, { policy: 'audit' });
  assert.deepEqual(
    new Set(audit.findings.map((finding) => finding.ruleId)),
    new Set(['contact-field', 'financial-field']),
  );
});

test('the header container heuristic does not invent findings for arbitrary pairs', () => {
  const result = analyze({
    entries: [
      { label: 'authorization', value: 'synthetic' },
      { name: 'accept', value: 'text/plain' },
      { name: 'authorization', value: '' },
      { name: 'authorization', value: null },
    ],
  });
  assert.equal(result.findings.length, 0);
});
