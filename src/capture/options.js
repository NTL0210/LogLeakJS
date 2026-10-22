/**
 * Shared capture-option validation.
 *
 * @module capture/options
 */

import { ConfigurationError } from '../errors.js';
import { DEFAULT_LIMITS, resolveLimits } from '../limits.js';
import { sanitizeSourceName } from '../privacy.js';
import { assertPlainObject, rejectUnknownKeys } from '../validation.js';

const CAPTURE_OPTION_KEYS = Object.freeze([
  'source',
  'maxRecords',
  'maxRecordBytes',
  'maxTotalBytes',
]);

/**
 * @typedef {object} CaptureOptions
 * @property {string} source Sanitized source name attached to records.
 * @property {import('../limits.js').Limits} limits
 */

/**
 * @param {unknown} raw
 * @param {string} defaultSource
 * @returns {CaptureOptions}
 */
export function resolveCaptureOptions(raw, defaultSource) {
  const value = assertPlainObject(raw ?? {}, 'capture options');
  rejectUnknownKeys(value, CAPTURE_OPTION_KEYS, 'capture options');
  const limits = resolveLimits(
    {
      ...(value.maxRecords === undefined ? {} : { maxRecords: value.maxRecords }),
      ...(value.maxRecordBytes === undefined ? {} : { maxRecordBytes: value.maxRecordBytes }),
      ...(value.maxTotalBytes === undefined ? {} : { maxTotalBytes: value.maxTotalBytes }),
    },
    DEFAULT_LIMITS,
    'capture options',
  );
  const source =
    value.source === undefined ? defaultSource : sanitizeSourceName(requireSource(value.source));
  return { source, limits };
}

/**
 * @param {unknown} value
 * @returns {string}
 */
function requireSource(value) {
  if (typeof value !== 'string') {
    throw new ConfigurationError('capture options.source must be a string.');
  }
  return value;
}

/**
 * @param {CaptureOptions} options
 * @returns {{maxRecords: number, maxRecordBytes: number, maxTotalBytes: number}}
 */
export function captureLimitSubset(options) {
  return {
    maxRecords: options.limits.maxRecords,
    maxRecordBytes: options.limits.maxRecordBytes,
    maxTotalBytes: options.limits.maxTotalBytes,
  };
}
