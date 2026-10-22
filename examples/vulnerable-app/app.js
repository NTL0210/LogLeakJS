/**
 * Deliberately insecure example: logs a password and token in clear text.
 *
 * This module is documentation only and is not part of the published package.
 *
 * @param {{info: (record: object) => unknown}} logger
 * @param {{userId: string, password: string, token: string}} credentials
 */
export function login(logger, credentials) {
  logger.info({
    event: 'login',
    userId: credentials.userId,
    password: credentials.password,
    token: credentials.token,
  });
  return { ok: true };
}
