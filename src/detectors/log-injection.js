/**
 * Conservative log-injection indicators.
 *
 * The rules look for characters that can break a single log record into
 * multiple visual records or inject terminal escape sequences. They do not try
 * to decide whether untrusted input was sanitized; they only report the
 * presence of the indicator in captured output.
 *
 * @module detectors/log-injection
 */

/**
 * @typedef {object} LogInjectionRule
 * @property {string} id
 * @property {'log-injection'} category
 * @property {import('../severity.js').Severity} severity
 * @property {'medium'|'low'} confidence
 * @property {RegExp} regex
 * @property {string} message
 * @property {string} remediation
 */

/** @type {readonly LogInjectionRule[]} */
export const LOG_INJECTION_RULES = Object.freeze([
  Object.freeze({
    id: 'control-character',
    category: 'log-injection',
    severity: 'medium',
    confidence: 'medium',
    // eslint-disable-next-line no-control-regex -- detecting control characters is the intent
    regex: /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/,
    message: 'A control character (including possible ANSI escapes) was present in log output.',
    remediation:
      'Encode or strip control characters from untrusted values before logging. Log structured fields instead of concatenated text.',
  }),
  Object.freeze({
    id: 'lone-carriage-return',
    category: 'log-injection',
    severity: 'medium',
    confidence: 'medium',
    regex: /\r(?!\n)/,
    message: 'A carriage return that is not part of a CRLF sequence was present in log output.',
    remediation:
      'Normalize line breaks in untrusted values before logging. A bare carriage return can overwrite a rendered log line.',
  }),
  Object.freeze({
    id: 'unicode-line-separator',
    category: 'log-injection',
    severity: 'low',
    confidence: 'low',
    regex: /[\u2028\u2029]/,
    message: 'A Unicode line separator was present in log output.',
    remediation:
      'Confirm whether the value should contain line separators. Encode untrusted text before logging.',
  }),
]);

/** @type {readonly string[]} */
export const LOG_INJECTION_RULE_IDS = Object.freeze(
  LOG_INJECTION_RULES.map((rule) => rule.id),
);
