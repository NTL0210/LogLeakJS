import assert from 'node:assert/strict';
import test from 'node:test';
import { createLogLeakDetector } from '../src/index.js';
import { analyze, findingsFor } from '../test-support/helpers.js';
import { SYNTHETIC } from '../test-support/synthetic.js';

test('personal-data detection is disabled by default', () => {
  const result = analyze(`contact ${SYNTHETIC.email} or ${SYNTHETIC.phone}`);
  assert.equal(result.status, 'pass');
  assert.equal(result.findings.length, 0);
  assert.equal(result.summary.findings.byDetector['personal-data'], 0);
});

test('the audit policy enables email and phone detection', () => {
  const email = findingsFor(analyze(SYNTHETIC.email, { policy: 'audit' }), 'email-address');
  assert.equal(email.length, 1);
  assert.equal(email[0].detector, 'personal-data');
  assert.equal(email[0].evidence, 'personal-data');
  assert.equal(email[0].category, 'personal-data');
  assert.equal(email[0].severity, 'low');
  assert.equal(email[0].confidence, 'medium');

  const e164 = findingsFor(analyze(SYNTHETIC.phone, { policy: 'audit' }), 'phone-e164');
  assert.equal(e164.length, 1);
  assert.equal(e164[0].confidence, 'medium');

  const nanp = findingsFor(analyze(SYNTHETIC.nanpPhone, { policy: 'audit' }), 'phone-nanp');
  assert.equal(nanp.length, 1);
  assert.equal(nanp[0].confidence, 'low');
});

test('personal-data kinds can be enabled individually', () => {
  const emailOnly = createLogLeakDetector({
    detectors: { personalData: { enabled: true, phone: false } },
  });
  assert.equal(emailOnly.analyze(SYNTHETIC.email).findings.length, 1);
  assert.equal(emailOnly.analyze(SYNTHETIC.phone).findings.length, 0);

  const phoneOnly = createLogLeakDetector({
    detectors: { personalData: { enabled: true, email: false, phone: true } },
  });
  assert.equal(phoneOnly.analyze(SYNTHETIC.email).findings.length, 0);
  assert.equal(phoneOnly.analyze(SYNTHETIC.phone).findings.length, 1);
});

test('a personal-data field name wins over a duplicate value finding', () => {
  const result = analyze({ email: SYNTHETIC.email }, { policy: 'audit' });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].ruleId, 'contact-field');
  assert.equal(result.findings[0].path, '$.email');
});

test('personal-data rules can be disabled individually', () => {
  const result = analyze(SYNTHETIC.phone, {
    policy: 'audit',
    disabledRules: ['phone-e164'],
  });
  assert.equal(result.findings.length, 0);
});

test('personal-data severity can be overridden', () => {
  const result = analyze(SYNTHETIC.email, {
    policy: 'audit',
    severity: { personalData: 'high' },
  });
  assert.equal(result.findings[0].severity, 'high');
});

test('email-like text without an address shape is ignored', () => {
  const result = analyze('user@host (no dot) and @example.test', { policy: 'audit' });
  assert.equal(result.findings.length, 0);
});

test('personal data never appears in a report or a finding', () => {
  const result = analyze(
    { note: `${SYNTHETIC.email} ${SYNTHETIC.phone} ${SYNTHETIC.nanpPhone}` },
    { policy: 'audit' },
  );
  assert.equal(result.findings.length, 3);
  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes(SYNTHETIC.email), false);
  assert.equal(serialized.includes(SYNTHETIC.phone), false);
  assert.equal(serialized.includes(SYNTHETIC.nanpPhone), false);
});
