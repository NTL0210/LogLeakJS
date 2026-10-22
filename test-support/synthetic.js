/**
 * Synthetic fixtures shared by the test suite.
 *
 * Every value here is fake and was invented for this repository. The test suite
 * asserts that reports never contain these values.
 */

const base64url = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

export const SYNTHETIC = Object.freeze({
  canary: 'SYNTHETIC_TEST_SECRET_71F2',
  password: 'SYNTHETIC_PASSWORD_4F2A',
  token: 'SYNTHETIC_TOKEN_9C1E',
  bearer: 'Bearer SYNTHETIC_BEARER_TOKEN_71F2',
  basic: `Basic ${Buffer.from('demo:SYNTHETIC_PASSWORD_4F2A').toString('base64')}`,
  jwt: `${base64url({ alg: 'HS256', typ: 'JWT' })}.${base64url({ sub: 'synthetic-user', scope: 'test' })}.c2lnbmF0dXJlLXRlc3Q`,
  pem: '-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKfakeTESTONLY\n-----END RSA PRIVATE KEY-----',
  awsKey: 'AKIAZZZZTESTTESTTEST',
  githubToken: `ghp_${'SYNTHETICGITHUBTOKEN'.padEnd(36, 'A')}`,
  npmToken: `npm_${'SYNTHETICNPMTOKEN'.padEnd(36, 'B')}`,
  slackToken: ['xoxb', '123456789012', 'SYNTHETICSECRET'].join('-'),
  stripeKey: `sk_live_${'SYNTHETICSTRIPEKEY'.padEnd(24, 'C')}`,
  googleKey: `AIza${'SYNTHETICGOOGLEAPIKEY'.padEnd(35, 'D')}`,
  databaseUrl: 'postgres://app_test:SYNTHETIC_DB_PASSWORD@db.internal:5432/app',
  email: 'alice.test@example.com',
  phone: '+15550100222',
  nanpPhone: '555-010-0222',
  controlCharacters: 'before\u0000after',
  ansiEscape: 'before\u001b[31mafter',
  loneCarriageReturn: 'line1\rline2',
  unicodeLineSeparator: 'line1\u2028line2',
  redacted: '[REDACTED]',
  secretKeyName: `header-${'SYNTHETIC_TEST_SECRET_71F2'}-end`,
});

/** Every synthetic value that must never appear in a report. */
export const SYNTHETIC_VALUES = Object.freeze([
  SYNTHETIC.canary,
  SYNTHETIC.password,
  SYNTHETIC.token,
  SYNTHETIC.bearer,
  SYNTHETIC.basic,
  SYNTHETIC.jwt,
  SYNTHETIC.pem,
  SYNTHETIC.awsKey,
  SYNTHETIC.githubToken,
  SYNTHETIC.npmToken,
  SYNTHETIC.slackToken,
  SYNTHETIC.stripeKey,
  SYNTHETIC.googleKey,
  SYNTHETIC.databaseUrl,
  SYNTHETIC.email,
  SYNTHETIC.phone,
  SYNTHETIC.nanpPhone,
]);
