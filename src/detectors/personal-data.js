/**
 * Optional personal-data detectors.
 *
 * These rules are disabled by default and are explicitly documented as noisy:
 * an email address or phone number in a log is often legitimate application
 * data. A match does not establish that a legal or regulatory violation
 * occurred. The application owner must decide the data classification and
 * logging policy.
 *
 * @module detectors/personal-data
 */

import { ConfigurationError } from '../errors.js';

/**
 * @typedef {object} PersonalDataRule
 * @property {string} id
 * @property {'personal-data'} category
 * @property {import('../severity.js').Severity} severity
 * @property {'low'|'medium'} confidence
 * @property {'email'|'phone'} kind
 * @property {string} source
 * @property {string} flags
 * @property {RegExp} regex
 * @property {string} message
 * @property {string} remediation
 */

/**
 * @param {Omit<PersonalDataRule, 'regex'>} definition
 * @returns {PersonalDataRule}
 */
function rule(definition) {
  let regex;
  try {
    regex = new RegExp(definition.source, definition.flags);
  } catch {
    throw new ConfigurationError(`Internal personal-data rule "${definition.id}" is invalid.`);
  }
  return Object.freeze({ ...definition, regex });
}

/** @type {readonly PersonalDataRule[]} */
export const PERSONAL_DATA_RULES = Object.freeze([
  rule({
    id: 'email-address',
    category: 'personal-data',
    severity: 'low',
    confidence: 'medium',
    kind: 'email',
    source: '(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\\.)+[A-Za-z]{2,24}',
    flags: '',
    message: 'An email-address-like value was present in log output.',
    remediation:
      'Log a user id instead of an email address, or confirm that this data is approved for logs under your policy.',
  }),
  rule({
    id: 'phone-e164',
    category: 'personal-data',
    severity: 'low',
    confidence: 'medium',
    kind: 'phone',
    source: '\\+[1-9][0-9]{6,14}(?![0-9A-Za-z])',
    flags: '',
    message: 'An E.164-like phone number was present in log output.',
    remediation:
      'Log a user id instead of a phone number, or confirm that this data is approved for logs under your policy.',
  }),
  rule({
    id: 'phone-nanp',
    category: 'personal-data',
    severity: 'low',
    confidence: 'low',
    kind: 'phone',
    source: '(?<![0-9A-Za-z])[0-9]{3}[-. ][0-9]{3}[-. ][0-9]{4}(?![0-9A-Za-z])',
    flags: '',
    message: 'A North-American-style phone number was present in log output.',
    remediation:
      'Confirm whether this is a phone number. If it is, log a user id instead or confirm the field is approved for logs.',
  }),
]);

/** @type {readonly string[]} */
export const PERSONAL_DATA_RULE_IDS = Object.freeze(PERSONAL_DATA_RULES.map((entry) => entry.id));
