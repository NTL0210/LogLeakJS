/**
 * Built-in credential patterns.
 *
 * Every pattern is a fixed, reviewed regular expression shipped with the
 * package. User-supplied regular expressions are intentionally not supported:
 * an arbitrary pattern is an easy way to introduce catastrophic backtracking,
 * and a pattern list is not a reliable secret detector.
 *
 * Each pattern is evaluated with `RegExp.prototype.test` on a regular
 * expression without the global flag, so matching has no shared mutable state
 * and is safe to use concurrently.
 *
 * @module detectors/patterns
 */

import { ConfigurationError } from '../errors.js';

/**
 * @typedef {object} PatternRule
 * @property {string} id Stable rule id.
 * @property {'credentials'} category
 * @property {import('../severity.js').Severity} severity
 * @property {'medium'|'high'} confidence
 * @property {string} source Regular expression source.
 * @property {string} flags Regular expression flags (never includes `g`).
 * @property {RegExp} regex Compiled, stateless matcher.
 * @property {string} message Safe, static description.
 * @property {string} remediation Safe remediation guidance.
 */

/**
 * @param {Omit<PatternRule, 'regex'>} definition
 * @returns {PatternRule}
 */
function pattern(definition) {
  let regex;
  try {
    regex = new RegExp(definition.source, definition.flags);
  } catch (error) {
    throw new ConfigurationError(`Internal credential pattern "${definition.id}" is invalid.`);
  }
  return Object.freeze({ ...definition, regex });
}

/** @type {readonly PatternRule[]} */
export const CREDENTIAL_PATTERNS = Object.freeze([
  pattern({
    id: 'bearer-token',
    category: 'credentials',
    severity: 'high',
    confidence: 'high',
    source: '\\bBearer[ \\t]+[A-Za-z0-9\\-._~+/]{8,}={0,2}',
    flags: 'i',
    message: 'A Bearer authorization value was present in log output.',
    remediation:
      'Remove the Authorization header from logs or redact the header value at the logger boundary.',
  }),
  pattern({
    id: 'basic-auth-credential',
    category: 'credentials',
    severity: 'high',
    confidence: 'medium',
    source: '\\bBasic[ \\t]+[A-Za-z0-9+/]{16,}={0,2}',
    flags: 'i',
    message: 'A Basic authorization value was present in log output.',
    remediation: 'Remove Basic credentials from logs. Redact the Authorization header.',
  }),
  pattern({
    id: 'jwt',
    category: 'credentials',
    severity: 'high',
    confidence: 'high',
    source: '\\beyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{4,}\\.[A-Za-z0-9_-]{0,}',
    flags: '',
    message: 'A JWT-like token was present in log output.',
    remediation:
      'Treat JWTs as credentials. Remove the token from logs or redact the field that carries it.',
  }),
  pattern({
    id: 'pem-private-key',
    category: 'credentials',
    severity: 'critical',
    confidence: 'high',
    source: '-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----',
    flags: '',
    message: 'A PEM private-key header was present in log output.',
    remediation:
      'Never log private key material. Remove the value, rotate the key, and audit how it reached the logger.',
  }),
  pattern({
    id: 'aws-access-key-id',
    category: 'credentials',
    severity: 'high',
    confidence: 'high',
    source: '\\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\\b',
    flags: '',
    message: 'An AWS access key id was present in log output.',
    remediation:
      'Remove access key ids from logs, rotate the associated credentials, and prefer short-lived roles.',
  }),
  pattern({
    id: 'github-token',
    category: 'credentials',
    severity: 'high',
    confidence: 'high',
    source: '\\bgh[pousr]_[A-Za-z0-9]{36,255}\\b',
    flags: '',
    message: 'A GitHub token was present in log output.',
    remediation: 'Remove the token from logs and revoke it. Use a secret manager for CI credentials.',
  }),
  pattern({
    id: 'npm-token',
    category: 'credentials',
    severity: 'high',
    confidence: 'high',
    source: '\\bnpm_[A-Za-z0-9]{36}\\b',
    flags: '',
    message: 'An npm token was present in log output.',
    remediation: 'Remove the token from logs and revoke it in the npm account settings.',
  }),
  pattern({
    id: 'slack-token',
    category: 'credentials',
    severity: 'high',
    confidence: 'high',
    source: '\\bxox[abposr]-[A-Za-z0-9-]{10,}\\b',
    flags: '',
    message: 'A Slack token was present in log output.',
    remediation: 'Remove the token from logs and revoke it in the Slack app configuration.',
  }),
  pattern({
    id: 'stripe-secret-key',
    category: 'credentials',
    severity: 'high',
    confidence: 'high',
    source: '\\bsk_live_[A-Za-z0-9]{16,}\\b',
    flags: '',
    message: 'A Stripe live secret key was present in log output.',
    remediation: 'Remove the key from logs and roll it in the Stripe dashboard.',
  }),
  pattern({
    id: 'google-api-key',
    category: 'credentials',
    severity: 'high',
    confidence: 'high',
    source: '\\bAIza[0-9A-Za-z_-]{35}\\b',
    flags: '',
    message: 'A Google API key was present in log output.',
    remediation: 'Remove the key from logs, restrict it in Google Cloud, and rotate if exposed.',
  }),
  pattern({
    id: 'connection-string-credentials',
    category: 'credentials',
    severity: 'high',
    confidence: 'high',
    source: '\\b[a-z][a-z0-9+.-]{1,15}:\\/\\/[^\\s:/@]{1,64}:[^\\s/@]{1,64}@',
    flags: 'i',
    message: 'A URL containing embedded credentials was present in log output.',
    remediation:
      'Remove credentials from the URL before building the log entry. Redact the userinfo component.',
  }),
]);

/**
 * Compiled pattern list used by the analyzer. Frozen; safe to share between
 * concurrent analyze() calls.
 */
export const COMPILED_PATTERNS = CREDENTIAL_PATTERNS;

/** @type {readonly string[]} */
export const PATTERN_IDS = Object.freeze(CREDENTIAL_PATTERNS.map((rule) => rule.id));
