/**
 * Configuration validation and policy presets.
 *
 * Configuration is validated once, up front, and deep-frozen. Unknown options,
 * wrong types, and invalid rule ids are rejected with a
 * {@link import('./errors.js').ConfigurationError} so a typo cannot silently
 * disable a detector.
 *
 * @module config
 */

import { ALL_RULE_IDS } from './detectors/catalog.js';
import { ConfigurationError } from './errors.js';
import { DEFAULT_LIMITS, resolveLimits } from './limits.js';
import { isSeverity, SEVERITIES } from './severity.js';
import {
  assertPlainObject,
  deepFreeze,
  optionalBoolean,
  rejectUnknownKeys,
  requiredInteger,
  requiredString,
} from './validation.js';

/** @typedef {{enabled: boolean, allowRedactedValues: boolean}} FieldNamesConfig */
/** @typedef {{enabled: boolean, minLength: number}} KnownSecretsConfig */
/** @typedef {{enabled: boolean, email: boolean, phone: boolean}} PersonalDataConfig */

/**
 * @typedef {object} DetectorConfig
 * @property {FieldNamesConfig} fieldNames
 * @property {KnownSecretsConfig} knownSecrets
 * @property {{enabled: boolean}} credentialPatterns
 * @property {PersonalDataConfig} personalData
 * @property {{enabled: boolean}} logInjection
 */

/**
 * @typedef {object} SeverityConfig
 * @property {import('./severity.js').Severity} knownSecret
 * @property {import('./severity.js').Severity} sensitiveField
 * @property {import('./severity.js').Severity} sensitiveFieldRedacted
 * @property {import('./severity.js').Severity} credentialPattern
 * @property {import('./severity.js').Severity} personalData
 * @property {import('./severity.js').Severity} logInjection
 */

/**
 * @typedef {object} ExceptionRule
 * @property {'sensitive-field'|'credential-pattern'|'personal-data'|'log-injection'} detector
 * @property {string} [ruleId]
 * @property {string} [path]
 * @property {number} [recordIndex]
 */

/**
 * @typedef {object} ResolvedConfig
 * @property {'default'|'strict'|'audit'} policy
 * @property {boolean} failOnIncomplete
 * @property {DetectorConfig} detectors
 * @property {Readonly<Partial<SeverityConfig>>} severity
 * @property {import('./limits.js').Limits} limits
 * @property {readonly string[]} knownSecrets
 * @property {readonly string[]} safePlaceholders
 * @property {readonly ExceptionRule[]} exceptions
 * @property {readonly string[]} disabledRules
 */

/**
 * Defaults applied when no severity override is configured. Rule-specific
 * severities (for example `pem-private-key` is critical) take precedence over
 * `credentialPattern` unless the caller explicitly overrides them.
 */
export const DEFAULT_SEVERITY = Object.freeze({
  knownSecret: 'critical',
  sensitiveField: 'high',
  sensitiveFieldRedacted: 'low',
  credentialPattern: 'high',
  personalData: 'low',
  logInjection: 'medium',
});

const BASE_DETECTORS = Object.freeze({
  fieldNames: Object.freeze({ enabled: true, allowRedactedValues: true }),
  knownSecrets: Object.freeze({ enabled: true, minLength: 8 }),
  credentialPatterns: Object.freeze({ enabled: true }),
  personalData: Object.freeze({ enabled: false, email: false, phone: false }),
  logInjection: Object.freeze({ enabled: true }),
});

/**
 * Named policy presets. `strict` additionally reports sensitive field names
 * whose values are correctly redacted, and `audit` enables the noisy optional
 * personal-data detectors.
 */
export const POLICIES = Object.freeze({
  default: Object.freeze({
    failOnIncomplete: true,
    detectors: BASE_DETECTORS,
    severity: Object.freeze({}),
  }),
  strict: Object.freeze({
    failOnIncomplete: true,
    detectors: Object.freeze({
      ...BASE_DETECTORS,
      fieldNames: Object.freeze({ enabled: true, allowRedactedValues: false }),
    }),
    severity: Object.freeze({}),
  }),
  audit: Object.freeze({
    failOnIncomplete: true,
    detectors: Object.freeze({
      ...BASE_DETECTORS,
      personalData: Object.freeze({ enabled: true, email: true, phone: true }),
    }),
    severity: Object.freeze({}),
  }),
});

/** @type {readonly string[]} */
export const POLICY_NAMES = Object.freeze(Object.keys(POLICIES));

const DETECTOR_NAMES = Object.freeze([
  'fieldNames',
  'knownSecrets',
  'credentialPatterns',
  'personalData',
  'logInjection',
]);

const DETECTOR_KEYS = Object.freeze({
  fieldNames: ['enabled', 'allowRedactedValues'],
  knownSecrets: ['enabled', 'minLength'],
  credentialPatterns: ['enabled'],
  personalData: ['enabled', 'email', 'phone'],
  logInjection: ['enabled'],
});

const CONFIG_KEYS = Object.freeze([
  'policy',
  'failOnIncomplete',
  'detectors',
  'knownSecrets',
  'limits',
  'safePlaceholders',
  'exceptions',
  'severity',
  'disabledRules',
]);

// eslint-disable-next-line no-control-regex -- rejecting control characters is the intent
const CONTROL_CHARACTER_PATTERN = /^[^\u0000-\u001F\u007F]+$/u;

const EXCEPTION_DETECTORS = Object.freeze([
  'sensitive-field',
  'credential-pattern',
  'personal-data',
  'log-injection',
]);

/**
 * @param {unknown} raw
 * @returns {Partial<DetectorConfig> & Record<string, unknown>}
 */
function parseDetectorOverrides(raw) {
  if (raw === undefined) return {};
  assertPlainObject(raw, 'detectors');
  rejectUnknownKeys(raw, DETECTOR_NAMES, 'detectors');

  /** @type {Record<string, unknown>} */
  const result = {};

  for (const name of DETECTOR_NAMES) {
    const value = raw[name];
    if (value === undefined) continue;
    if (typeof value === 'boolean') {
      result[name] = { enabled: value };
      continue;
    }
    const entry = assertPlainObject(value, `detectors.${name}`);
    rejectUnknownKeys(entry, DETECTOR_KEYS[name], `detectors.${name}`);
    result[name] = { ...entry };
  }

  return /** @type {Partial<DetectorConfig>} */ (result);
}

/**
 * @param {Record<string, unknown>} overrides
 * @param {DetectorConfig} base
 * @returns {DetectorConfig}
 */
function resolveDetectors(overrides, base) {
  const fieldNamesRaw = /** @type {Record<string, unknown>} */ (overrides.fieldNames ?? {});
  const knownSecretsRaw = /** @type {Record<string, unknown>} */ (overrides.knownSecrets ?? {});
  const patternsRaw = /** @type {Record<string, unknown>} */ (overrides.credentialPatterns ?? {});
  const personalRaw = /** @type {Record<string, unknown>} */ (overrides.personalData ?? {});
  const injectionRaw = /** @type {Record<string, unknown>} */ (overrides.logInjection ?? {});

  const personalEnabled = optionalBoolean(personalRaw.enabled, 'detectors.personalData.enabled');
  const personalEmail = optionalBoolean(personalRaw.email, 'detectors.personalData.email');
  const personalPhone = optionalBoolean(personalRaw.phone, 'detectors.personalData.phone');

  const fieldEnabled = optionalBoolean(fieldNamesRaw.enabled, 'detectors.fieldNames.enabled');
  const allowRedacted = optionalBoolean(
    fieldNamesRaw.allowRedactedValues,
    'detectors.fieldNames.allowRedactedValues',
  );

  const knownEnabled = optionalBoolean(
    knownSecretsRaw.enabled,
    'detectors.knownSecrets.enabled',
  );
  const minLength =
    knownSecretsRaw.minLength === undefined
      ? base.knownSecrets.minLength
      : requiredInteger(knownSecretsRaw.minLength, 'detectors.knownSecrets.minLength', {
          min: 1,
          max: 64,
        });

  const patternEnabled = optionalBoolean(
    patternsRaw.enabled,
    'detectors.credentialPatterns.enabled',
  );
  const injectionEnabled = optionalBoolean(
    injectionRaw.enabled,
    'detectors.logInjection.enabled',
  );

  const resolvedPersonalEnabled = personalEnabled ?? base.personalData.enabled;

  return Object.freeze({
    fieldNames: Object.freeze({
      enabled: fieldEnabled ?? base.fieldNames.enabled,
      allowRedactedValues: allowRedacted ?? base.fieldNames.allowRedactedValues,
    }),
    knownSecrets: Object.freeze({
      enabled: knownEnabled ?? base.knownSecrets.enabled,
      minLength,
    }),
    credentialPatterns: Object.freeze({
      enabled: patternEnabled ?? base.credentialPatterns.enabled,
    }),
    personalData: Object.freeze({
      enabled: resolvedPersonalEnabled,
      email: personalEmail ?? resolvedPersonalEnabled,
      phone: personalPhone ?? resolvedPersonalEnabled,
    }),
    logInjection: Object.freeze({
      enabled: injectionEnabled ?? base.logInjection.enabled,
    }),
  });
}

/**
 * @param {unknown} raw
 * @returns {Readonly<Partial<SeverityConfig>>}
 */
function resolveSeverity(raw) {
  if (raw === undefined) return Object.freeze({});
  const value = assertPlainObject(raw, 'severity');
  rejectUnknownKeys(value, Object.keys(DEFAULT_SEVERITY), 'severity');
  /** @type {Record<string, import('./severity.js').Severity>} */
  const resolved = {};
  for (const [key, severity] of Object.entries(value)) {
    if (severity === undefined) continue;
    if (!isSeverity(severity)) {
      throw new ConfigurationError(`severity.${key} must be one of: ${SEVERITIES.join(', ')}.`);
    }
    resolved[key] = severity;
  }
  return Object.freeze(/** @type {Partial<SeverityConfig>} */ (resolved));
}

/**
 * @param {unknown} raw
 * @returns {readonly string[]}
 */
function resolveKnownSecrets(raw) {
  if (raw === undefined) return Object.freeze([]);
  if (!Array.isArray(raw)) {
    throw new ConfigurationError('knownSecrets must be an array of strings.');
  }
  const seen = new Set();
  /** @type {string[]} */
  const values = [];
  raw.forEach((value, index) => {
    if (typeof value !== 'string') {
      throw new ConfigurationError(`knownSecrets[${index}] must be a string.`);
    }
    if (!seen.has(value)) {
      seen.add(value);
      values.push(value);
    }
  });
  return Object.freeze(values);
}

/**
 * @param {unknown} raw
 * @returns {readonly string[]}
 */
function resolveSafePlaceholders(raw) {
  if (raw === undefined) return Object.freeze([]);
  if (!Array.isArray(raw)) {
    throw new ConfigurationError('safePlaceholders must be an array of strings.');
  }
  if (raw.length > 20) {
    throw new ConfigurationError('safePlaceholders supports at most 20 entries.');
  }
  const seen = new Set();
  /** @type {string[]} */
  const values = [];
  raw.forEach((value, index) => {
    const placeholder = requiredString(value, `safePlaceholders[${index}]`, {
      minLength: 1,
      maxLength: 64,
      pattern: CONTROL_CHARACTER_PATTERN,
    });
    if (!seen.has(placeholder)) {
      seen.add(placeholder);
      values.push(placeholder);
    }
  });
  return Object.freeze(values);
}

/**
 * @param {unknown} raw
 * @returns {readonly ExceptionRule[]}
 */
function resolveExceptions(raw) {
  if (raw === undefined) return Object.freeze([]);
  if (!Array.isArray(raw)) {
    throw new ConfigurationError('exceptions must be an array.');
  }
  if (raw.length > 20) {
    throw new ConfigurationError('exceptions supports at most 20 narrowly scoped entries.');
  }
  return Object.freeze(
    raw.map((entry, index) => {
      const label = `exceptions[${index}]`;
      const value = assertPlainObject(entry, label);
      rejectUnknownKeys(
        value,
        ['detector', 'ruleId', 'path', 'recordIndex', 'reason'],
        label,
      );

      const detector = requiredString(value.detector, `${label}.detector`, {
        maxLength: 32,
      });
      if (detector === 'known-secret') {
        throw new ConfigurationError(
          `${label}: known-secret findings cannot be suppressed. Remove the secret from the emitted log instead.`,
        );
      }
      if (!EXCEPTION_DETECTORS.includes(detector)) {
        throw new ConfigurationError(
          `${label}.detector must be one of: ${EXCEPTION_DETECTORS.join(', ')}.`,
        );
      }

      let ruleId;
      if (value.ruleId !== undefined) {
        ruleId = requiredString(value.ruleId, `${label}.ruleId`, { maxLength: 64 });
        if (!ALL_RULE_IDS.has(ruleId)) {
          throw new ConfigurationError(`${label}.ruleId is not a known rule id.`);
        }
      }

      let path;
      if (value.path !== undefined) {
        path = requiredString(value.path, `${label}.path`, {
          minLength: 1,
          maxLength: 200,
          pattern: /^[$A-Za-z0-9_.\-[\]"]+$/u,
        });
      }

      if (path === undefined && ruleId === undefined) {
        throw new ConfigurationError(
          `${label} must target a ruleId, a path, or both. Broad detector-wide exceptions are not supported.`,
        );
      }

      let recordIndex;
      if (value.recordIndex !== undefined) {
        recordIndex = requiredInteger(value.recordIndex, `${label}.recordIndex`, {
          min: 0,
          max: 1000000,
        });
      }

      requiredString(value.reason, `${label}.reason`, { minLength: 1, maxLength: 200 });

      return Object.freeze({ detector, ruleId, path, recordIndex });
    }),
  );
}

/**
 * @param {unknown} raw
 * @returns {readonly string[]}
 */
function resolveDisabledRules(raw) {
  if (raw === undefined) return Object.freeze([]);
  if (!Array.isArray(raw)) {
    throw new ConfigurationError('disabledRules must be an array of rule ids.');
  }
  const seen = new Set();
  for (const [index, value] of raw.entries()) {
    const ruleId = requiredString(value, `disabledRules[${index}]`, { maxLength: 64 });
    if (!ALL_RULE_IDS.has(ruleId)) {
      throw new ConfigurationError(`disabledRules[${index}] is not a known rule id.`);
    }
    seen.add(ruleId);
  }
  return Object.freeze([...seen]);
}

/**
 * Validates options and produces a frozen internal configuration.
 *
 * @param {object} [options]
 * @returns {ResolvedConfig}
 */
export function resolveConfig(options = {}) {
  const value = assertPlainObject(options, 'options');
  rejectUnknownKeys(value, CONFIG_KEYS, 'options');

  const policyName = value.policy ?? 'default';
  if (typeof policyName !== 'string' || !Object.hasOwn(POLICIES, policyName)) {
    throw new ConfigurationError(`policy must be one of: ${POLICY_NAMES.join(', ')}.`);
  }
  const policy = POLICIES[/** @type {keyof typeof POLICIES} */ (policyName)];

  const detectorOverrides = parseDetectorOverrides(value.detectors);
  const detectors = resolveDetectors(detectorOverrides, policy.detectors);

  const failOnIncomplete =
    optionalBoolean(value.failOnIncomplete, 'failOnIncomplete') ?? policy.failOnIncomplete;

  const limits = resolveLimits(
    value.limits === undefined ? {} : assertPlainObject(value.limits, 'limits'),
    DEFAULT_LIMITS,
    'limits',
  );

  const resolved = {
    policy: /** @type {'default'|'strict'|'audit'} */ (policyName),
    failOnIncomplete,
    detectors,
    severity: resolveSeverity(value.severity),
    limits,
    knownSecrets: resolveKnownSecrets(value.knownSecrets),
    safePlaceholders: resolveSafePlaceholders(value.safePlaceholders),
    exceptions: resolveExceptions(value.exceptions),
    disabledRules: resolveDisabledRules(value.disabledRules),
  };

  return deepFreeze(resolved);
}
