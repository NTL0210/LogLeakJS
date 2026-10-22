/**
 * Safe example: the sensitive field is retained but its value is a fixed
 * placeholder. The default policy accepts this; the strict policy reports the
 * field name at low severity without exposing a value.
 *
 * This module is documentation only and is not part of the published package.
 *
 * @param {{info: (record: object) => unknown}} logger
 * @param {{userId: string}} user
 */
export function login(logger, user) {
  logger.info({
    event: 'login',
    userId: user.userId,
    password: '[REDACTED]',
  });
  return { ok: true };
}
