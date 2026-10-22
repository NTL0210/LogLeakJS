import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ConfigurationError,
  createLogLeakDetector,
  listDetectorRules,
} from '../src/index.js';
import {
  buildFieldIndex,
  normalizeFieldName,
} from '../src/detectors/field-names.js';
import {
  highestSeverity,
  isAtLeast,
  isSeverity,
  SEVERITIES,
} from '../src/severity.js';

test('the rule catalog is frozen, grouped, and unique', () => {
  const rules = listDetectorRules();
  assert.deepEqual(Object.keys(rules), [
    'fieldNames',
    'credentialPatterns',
    'personalData',
    'logInjection',
  ]);
  assert.equal(Object.isFrozen(rules), true);

  const all = [];
  for (const family of Object.values(rules)) {
    assert.equal(Object.isFrozen(family), true);
    assert.equal(family.length > 0, true);
    all.push(...family);
  }
  assert.equal(new Set(all).size, all.length);
  assert.equal(all.length, 33);
  assert.equal(rules.fieldNames.length, 16);
  assert.equal(rules.credentialPatterns.length, 11);
  assert.equal(rules.personalData.length, 3);
  assert.equal(rules.logInjection.length, 3);
});

test('every published rule id is accepted by disabledRules', () => {
  for (const family of Object.values(listDetectorRules())) {
    for (const ruleId of family) {
      assert.doesNotThrow(() => createLogLeakDetector({ disabledRules: [ruleId] }));
    }
  }
});

test('the catalog contains the documented stable ids', () => {
  const rules = listDetectorRules();
  assert.equal(rules.fieldNames.includes('password-field'), true);
  assert.equal(rules.fieldNames.includes('private-key-field'), true);
  assert.equal(rules.credentialPatterns.includes('pem-private-key'), true);
  assert.equal(rules.personalData.includes('email-address'), true);
  assert.equal(rules.logInjection.includes('control-character'), true);
});

test('field names normalize across case, separators, and Unicode forms', () => {
  assert.equal(normalizeFieldName('  Refresh__Token '), 'refreshtoken');
  assert.equal(normalizeFieldName('REFRESH-TOKEN'), 'refreshtoken');
  assert.equal(normalizeFieldName('refresh.token'), 'refreshtoken');
  assert.equal(normalizeFieldName('ｐａｓｓｗｏｒｄ'), 'password');
  assert.equal(normalizeFieldName(''), '');
});

test('conflicting field rules are rejected at index build time', () => {
  const base = { category: 'credentials', severity: 'high', confidence: 'high', message: 'm', remediation: 'r' };
  assert.throws(
    () =>
      buildFieldIndex([
        { ...base, id: 'one', names: ['shared'], suffixes: [] },
        { ...base, id: 'two', names: ['shared'], suffixes: [] },
      ]),
    ConfigurationError,
  );
});

test('the longest matching compound suffix wins', () => {
  const base = { category: 'credentials', severity: 'high', confidence: 'high', message: 'm', remediation: 'r' };
  const index = buildFieldIndex([
    { ...base, id: 'short', names: [], suffixes: ['token'] },
    { ...base, id: 'long', names: [], suffixes: ['sessiontoken'] },
  ]);

  assert.equal(index.lookup('mysessiontoken')?.id, 'long');
  assert.equal(index.lookup('mytoken')?.id, 'short');
  assert.equal(index.lookup('token')?.id, undefined);
});

test('severity helpers order and validate values', () => {
  assert.deepEqual(SEVERITIES, ['low', 'medium', 'high', 'critical']);
  assert.equal(isSeverity('critical'), true);
  assert.equal(isSeverity('CRITICAL'), false);
  assert.equal(isSeverity(undefined), false);
  assert.equal(isAtLeast('critical', 'high'), true);
  assert.equal(isAtLeast('medium', 'high'), false);
  assert.equal(highestSeverity(['low', 'critical', 'medium']), 'critical');
  assert.equal(highestSeverity([]), 'low');
});
