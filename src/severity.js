/**
 * Severity helpers.
 *
 * @module severity
 */

/** @typedef {'low'|'medium'|'high'|'critical'} Severity */

/** All supported severities, ordered from least to most severe. */
export const SEVERITIES = Object.freeze(['low', 'medium', 'high', 'critical']);

/** Numeric rank for each severity. */
export const SEVERITY_RANK = Object.freeze({
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
});

/**
 * @param {unknown} value
 * @returns {value is Severity}
 */
export function isSeverity(value) {
  return typeof value === 'string' && Object.hasOwn(SEVERITY_RANK, value);
}

/**
 * Returns true when `severity` is at least as severe as `minimum`.
 *
 * @param {Severity} severity
 * @param {Severity} minimum
 * @returns {boolean}
 */
export function isAtLeast(severity, minimum) {
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[minimum];
}

/**
 * @param {Severity[]} severities
 * @returns {Severity}
 */
export function highestSeverity(severities) {
  let highest = 'low';
  for (const severity of severities) {
    if (SEVERITY_RANK[severity] > SEVERITY_RANK[highest]) highest = severity;
  }
  return highest;
}
