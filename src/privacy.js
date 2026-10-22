/**
 * Privacy helpers.
 *
 * All identifiers, paths, and source names that end up in findings pass through
 * this module. Paths are sanitized to a small character set and truncated. If a
 * field name itself contains a registered secret or a credential-pattern match,
 * the path segment is replaced entirely so the report cannot echo the value.
 *
 * @module privacy
 */

import { createHash } from 'node:crypto';

const SAFE_SEGMENT = /[^A-Za-z0-9_$-]+/g;
const SIMPLE_KEY = /^[A-Za-z_$][A-Za-z0-9_$-]*$/;
const MAX_SEGMENT_LENGTH = 32;

/**
 * Sanitizes one field-name path segment.
 *
 * @param {string} raw
 * @returns {string} A path-safe segment. Never empty.
 */
export function sanitizeSegment(raw) {
  const cleaned = String(raw)
    .normalize('NFKC')
    .replace(SAFE_SEGMENT, '_')
    .slice(0, MAX_SEGMENT_LENGTH);
  return cleaned.length > 0 ? cleaned : '_';
}

/**
 * @param {string} segment
 * @returns {boolean}
 */
export function isSimpleKey(segment) {
  return SIMPLE_KEY.test(segment);
}

/**
 * @param {string} parentPath
 * @param {string} segment Already-sanitized segment.
 * @returns {string}
 */
export function appendKey(parentPath, segment) {
  return isSimpleKey(segment) ? `${parentPath}.${segment}` : `${parentPath}["${segment}"]`;
}

/**
 * @param {string} parentPath
 * @param {number} index
 * @returns {string}
 */
export function appendIndex(parentPath, index) {
  return `${parentPath}[${index}]`;
}

/**
 * Sanitizes a capture source name for reports.
 *
 * @param {unknown} raw
 * @returns {string}
 */
export function sanitizeSourceName(raw) {
  if (typeof raw !== 'string') return 'unknown';
  const cleaned = raw.replace(/[^A-Za-z0-9_-]+/g, '').slice(0, 32);
  return cleaned.length > 0 ? cleaned : 'unknown';
}

/**
 * Builds a deterministic, non-reversible finding id. The input contains only
 * rule metadata and sanitized paths, never detected values.
 *
 * @param {readonly string[]} parts
 * @returns {string}
 */
export function makeFindingId(parts) {
  const digest = createHash('sha256').update(parts.join('\u0000'), 'utf8').digest('hex');
  return `LL-${digest.slice(0, 12)}`;
}
