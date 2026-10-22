/**
 * Curated sensitive field-name rules.
 *
 * Field names are normalized by lowercasing and removing the separators that
 * commonly vary between naming conventions (`-`, `_`, `.`, whitespace). This
 * maps `refreshToken`, `refresh_token`, `REFRESH-TOKEN` and
 * `request.refresh_token` to the same key without stemming, splitting words,
 * or otherwise guessing at meaning.
 *
 * Matching is exact on the normalized name, plus a small, documented set of
 * compound suffixes. Generic suffixes such as `token` are deliberately NOT
 * used, because keys like `nextToken` or `tokenCount` are common and usually
 * harmless.
 *
 * @module detectors/field-names
 */

import { ConfigurationError } from '../errors.js';

/**
 * @typedef {object} FieldRule
 * @property {string} id Stable rule id.
 * @property {'credentials'|'personal-data'} category
 * @property {import('../severity.js').Severity} severity
 * @property {'low'|'medium'|'high'} confidence
 * @property {string[]} names Normalized exact field names.
 * @property {string[]} suffixes Normalized compound suffixes.
 * @property {boolean} [requiresPersonalData] Rule only runs when the optional
 *   personal-data detector is enabled.
 * @property {string} message Safe, static description (never contains values).
 * @property {string} remediation Safe remediation guidance.
 */

/** @type {readonly FieldRule[]} */
export const FIELD_RULES = Object.freeze([
  Object.freeze({
    id: 'password-field',
    category: 'credentials',
    severity: 'high',
    confidence: 'high',
    names: [
      'password',
      'passwords',
      'passwd',
      'passphrase',
      'newpassword',
      'oldpassword',
      'currentpassword',
      'passwordconfirmation',
      'passwordhash',
      'hashedpassword',
      'userpassword',
      'dbpassword',
      'dbpass',
      'secretpassphrase',
    ],
    suffixes: ['password', 'passwd', 'passphrase'],
    message: 'A password-like field name was present in log output.',
    remediation:
      'Remove the field from log output or redact it with a fixed placeholder. Never log the value even at debug level.',
  }),
  Object.freeze({
    id: 'authorization-header',
    category: 'credentials',
    severity: 'high',
    confidence: 'high',
    names: ['authorization', 'proxyauthorization', 'httpauthorization', 'xauthorization'],
    suffixes: [],
    message: 'An authorization header field was present in log output.',
    remediation:
      'Log only a header allowlist that excludes Authorization and Proxy-Authorization, or redact the header value.',
  }),
  Object.freeze({
    id: 'cookie-field',
    category: 'credentials',
    severity: 'high',
    confidence: 'medium',
    names: ['cookie', 'cookies', 'setcookie', 'cookieheader'],
    suffixes: ['cookie'],
    message: 'A cookie field was present in log output.',
    remediation:
      'Log cookie names and counts rather than values. Redact Cookie and Set-Cookie headers at the logger boundary.',
  }),
  Object.freeze({
    id: 'session-identifier-field',
    category: 'credentials',
    severity: 'high',
    confidence: 'high',
    names: [
      'sessionid',
      'sessionidentifier',
      'sessionkey',
      'sessiontoken',
      'jsessionid',
      'phpsessid',
      'connectsid',
      'aspnetsessionid',
      'xsessionid',
    ],
    suffixes: ['sessionid', 'sessiontoken', 'sessionkey'],
    message: 'A session identifier field was present in log output.',
    remediation:
      'Remove session identifiers from log output or redact them with a fixed placeholder.',
  }),
  Object.freeze({
    id: 'access-token-field',
    category: 'credentials',
    severity: 'high',
    confidence: 'high',
    names: ['accesstoken', 'authaccesstoken', 'oauthaccesstoken'],
    suffixes: ['accesstoken'],
    message: 'An access token field was present in log output.',
    remediation: 'Remove access tokens from log output or redact them with a fixed placeholder.',
  }),
  Object.freeze({
    id: 'refresh-token-field',
    category: 'credentials',
    severity: 'high',
    confidence: 'high',
    names: ['refreshtoken', 'oauthrefreshtoken'],
    suffixes: ['refreshtoken'],
    message: 'A refresh token field was present in log output.',
    remediation: 'Remove refresh tokens from log output or redact them with a fixed placeholder.',
  }),
  Object.freeze({
    id: 'id-token-field',
    category: 'credentials',
    severity: 'high',
    confidence: 'high',
    names: ['idtoken', 'openidtoken'],
    suffixes: ['idtoken'],
    message: 'An identity token field was present in log output.',
    remediation: 'Remove identity tokens from log output or redact them with a fixed placeholder.',
  }),
  Object.freeze({
    id: 'api-key-field',
    category: 'credentials',
    severity: 'high',
    confidence: 'high',
    names: [
      'apikey',
      'xapikey',
      'apiaccesskey',
      'appapikey',
      'subscriptionkey',
      'storagekey',
    ],
    suffixes: ['apikey'],
    message: 'An API key field was present in log output.',
    remediation: 'Remove API keys from log output or redact them with a fixed placeholder.',
  }),
  Object.freeze({
    id: 'client-secret-field',
    category: 'credentials',
    severity: 'high',
    confidence: 'high',
    names: ['clientsecret', 'oauthclientsecret', 'appsecret', 'consumersecret'],
    suffixes: ['clientsecret'],
    message: 'A client secret field was present in log output.',
    remediation: 'Remove client secrets from log output or redact them with a fixed placeholder.',
  }),
  Object.freeze({
    id: 'private-key-field',
    category: 'credentials',
    severity: 'critical',
    confidence: 'high',
    names: [
      'privatekey',
      'privatekeypem',
      'secretkey',
      'signingkey',
      'encryptionkey',
      'masterkey',
      'jwtsecret',
      'secretkeybase',
      'accesskey',
      'secretaccesskey',
      'awssecretaccesskey',
    ],
    suffixes: ['privatekey', 'secretkey'],
    message: 'A private-key-like field was present in log output.',
    remediation:
      'Never log key material. Remove the field, rotate the key if it was emitted, and audit where the value came from.',
  }),
  Object.freeze({
    id: 'connection-string-field',
    category: 'credentials',
    severity: 'high',
    confidence: 'high',
    names: [
      'connectionstring',
      'databaseurl',
      'dburl',
      'dburi',
      'databaseuri',
      'mongodburi',
      'mongodburl',
      'mongourl',
      'redisurl',
      'redisuri',
      'amqpurl',
      'amqpuri',
      'jdbcurl',
      'datasourceurl',
      'dsn',
      'postgresurl',
      'mysqlurl',
      'mssqlurl',
    ],
    suffixes: ['connectionstring'],
    message: 'A database or service connection string field was present in log output.',
    remediation:
      'Log host and database name only. Remove the connection string or redact embedded credentials.',
  }),
  Object.freeze({
    id: 'credential-field',
    category: 'credentials',
    severity: 'medium',
    confidence: 'medium',
    names: [
      'credential',
      'credentials',
      'credentialvalue',
      'usercredential',
      'usercredentials',
      'proxycredentials',
    ],
    suffixes: ['credentials'],
    message: 'A field whose name indicates credentials was present in log output.',
    remediation: 'Remove the field from log output or redact it with a fixed placeholder.',
  }),
  Object.freeze({
    id: 'generic-token-field',
    category: 'credentials',
    severity: 'medium',
    confidence: 'medium',
    names: [
      'token',
      'bearertoken',
      'authtoken',
      'securitytoken',
      'apitoken',
      'personalaccesstoken',
      'csrftoken',
      'xsrftoken',
      'xamzsecuritytoken',
    ],
    suffixes: [],
    message: 'A field whose name indicates a token was present in log output.',
    remediation:
      'Confirm whether the token is a credential. If it is, remove it from log output or redact it.',
  }),
  Object.freeze({
    id: 'otp-field',
    category: 'credentials',
    severity: 'high',
    confidence: 'medium',
    names: [
      'otp',
      'totp',
      'hotp',
      'onetimepassword',
      'onetimecode',
      'verificationcode',
      'mfacode',
      'otpcode',
    ],
    suffixes: [],
    message: 'A one-time code field was present in log output.',
    remediation: 'Remove one-time codes from log output. They are short-lived credentials.',
  }),
  Object.freeze({
    id: 'financial-field',
    category: 'personal-data',
    severity: 'high',
    confidence: 'medium',
    requiresPersonalData: true,
    names: [
      'cardnumber',
      'creditcardnumber',
      'ccnumber',
      'cvv',
      'cvc',
      'cvv2',
      'securitycode',
      'iban',
      'bankaccount',
      'accountnumber',
      'routingnumber',
    ],
    suffixes: [],
    message: 'A payment-card or bank-account field was present in log output.',
    remediation: 'Remove financial account data from logs. Store and log only non-sensitive references.',
  }),
  Object.freeze({
    id: 'contact-field',
    category: 'personal-data',
    severity: 'medium',
    confidence: 'medium',
    requiresPersonalData: true,
    names: [
      'email',
      'emailaddress',
      'phone',
      'phonenumber',
      'mobilenumber',
      'ssn',
      'socialsecuritynumber',
      'nationalid',
      'taxid',
      'dateofbirth',
      'dob',
      'address',
      'streetaddress',
      'fullname',
      'firstname',
      'lastname',
      'ipaddress',
    ],
    suffixes: [],
    message: 'A field whose name indicates personal data was present in log output.',
    remediation:
      'Log a stable identifier instead of personal data, or remove the field according to your data policy.',
  }),
]);

/**
 * Normalizes a field name for rule lookup.
 *
 * @param {string} name
 * @returns {string}
 */
export function normalizeFieldName(name) {
  return String(name)
    .normalize('NFKC')
    .toLowerCase()
    .replace(/[\s._-]+/g, '');
}

/**
 * @typedef {object} FieldIndex
 * @property {(name: string) => FieldRule | null} lookup
 * @property {readonly FieldRule[]} rules
 */

/**
 * Builds the lookup table. Duplicate normalized names across rules are a
 * programming error and are rejected at module initialization.
 *
 * @param {readonly FieldRule[]} [rules]
 * @returns {FieldIndex}
 */
export function buildFieldIndex(rules = FIELD_RULES) {
  /** @type {Map<string, FieldRule>} */
  const exact = new Map();
  /** @type {Array<{suffix: string, rule: FieldRule}>} */
  const suffixes = [];

  for (const rule of rules) {
    for (const name of rule.names) {
      const normalized = normalizeFieldName(name);
      const existing = exact.get(normalized);
      if (existing && existing !== rule) {
        throw new ConfigurationError(
          `Internal field rule conflict: "${normalized}" is declared by both "${existing.id}" and "${rule.id}".`,
        );
      }
      exact.set(normalized, rule);
    }
    for (const suffix of rule.suffixes) {
      suffixes.push({ suffix: normalizeFieldName(suffix), rule });
    }
  }

  // Longest suffix wins, so "sessiontoken" is preferred over a shorter
  // overlapping suffix.
  suffixes.sort((a, b) => b.suffix.length - a.suffix.length);

  /** @type {(name: string) => FieldRule | null} */
  function lookup(name) {
    const normalized = normalizeFieldName(name);
    if (normalized.length === 0) return null;
    const direct = exact.get(normalized);
    if (direct) return direct;
    for (const entry of suffixes) {
      if (normalized.length > entry.suffix.length && normalized.endsWith(entry.suffix)) {
        return entry.rule;
      }
    }
    return null;
  }

  return Object.freeze({ lookup, rules });
}

/** Shared field-name index. */
export const fieldIndex = buildFieldIndex();
