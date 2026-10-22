/**
 * Resource limits. Logs are treated as untrusted, potentially large data, so
 * every traversal and capture is bounded. Hitting a bound makes the analysis
 * incomplete; it never silently produces a clean result.
 *
 * @module limits
 */

import { ConfigurationError } from './errors.js';
import { assertPlainObject, rejectUnknownKeys, requiredInteger } from './validation.js';

/**
 * Conservative defaults, sized for ordinary unit/integration tests.
 *
 * @readonly
 */
export const DEFAULT_LIMITS = Object.freeze({
  /** Maximum number of log records analyzed in one run. */
  maxRecords: 500,
  /** Maximum estimated serialized bytes for a single record. */
  maxRecordBytes: 16 * 1024,
  /** Maximum estimated total bytes analyzed in one run. */
  maxTotalBytes: 4 * 1024 * 1024,
  /** Maximum container nesting depth per record. */
  maxDepth: 10,
  /** Maximum properties/leaves visited per record. */
  maxNodesPerRecord: 2000,
  /** Maximum number of registered synthetic secrets. */
  maxSecrets: 32,
  /** Maximum length of a single registered synthetic secret. */
  maxSecretBytes: 512,
  /** Maximum combined length of all registered synthetic secrets. */
  maxTotalSecretBytes: 4096,
  /** Maximum findings kept in the result. */
  maxFindings: 100,
  /** Maximum diagnostics kept in the result. */
  maxDiagnostics: 20,
  /** Soft wall-clock budget for a single analyze() call, in milliseconds. */
  timeLimitMs: 2000,
});

/**
 * Hard safety ranges for user-provided limits. Values outside these ranges are
 * rejected so configuration cannot disable the resource bounds entirely.
 *
 * @readonly
 */
export const LIMIT_RANGES = Object.freeze({
  maxRecords: Object.freeze({ min: 1, max: 100000 }),
  maxRecordBytes: Object.freeze({ min: 128, max: 16 * 1024 * 1024 }),
  maxTotalBytes: Object.freeze({ min: 1024, max: 256 * 1024 * 1024 }),
  maxDepth: Object.freeze({ min: 1, max: 100 }),
  maxNodesPerRecord: Object.freeze({ min: 10, max: 1000000 }),
  maxSecrets: Object.freeze({ min: 1, max: 1000 }),
  maxSecretBytes: Object.freeze({ min: 8, max: 8192 }),
  maxTotalSecretBytes: Object.freeze({ min: 8, max: 1024 * 1024 }),
  maxFindings: Object.freeze({ min: 1, max: 100000 }),
  maxDiagnostics: Object.freeze({ min: 1, max: 10000 }),
  timeLimitMs: Object.freeze({ min: 1, max: 600000 }),
});

/** Limits that are relevant to capture adapters. @readonly */
export const CAPTURE_LIMIT_NAMES = Object.freeze([
  'maxRecords',
  'maxRecordBytes',
  'maxTotalBytes',
]);

/**
 * @typedef {typeof DEFAULT_LIMITS} Limits
 */

/**
 * Validates and merges limit overrides.
 *
 * @param {Record<string, unknown>} [overrides]
 * @param {Limits} [base]
 * @param {string} [label]
 * @returns {Limits}
 */
export function resolveLimits(overrides = {}, base = DEFAULT_LIMITS, label = 'limits') {
  assertPlainObject(overrides, label);
  rejectUnknownKeys(overrides, Object.keys(DEFAULT_LIMITS), label);

  /** @type {Record<string, number>} */
  const resolved = { ...base };
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) continue;
    const range = LIMIT_RANGES[key];
    resolved[key] = requiredInteger(value, `${label}.${key}`, range);
  }

  // Guard against a configuration that makes the total budget smaller than a
  // single record: that combination can never analyze anything successfully.
  if (resolved.maxTotalBytes < resolved.maxRecordBytes) {
    throw new ConfigurationError(
      `${label}.maxTotalBytes (${resolved.maxTotalBytes}) must be >= ${label}.maxRecordBytes (${resolved.maxRecordBytes}).`,
    );
  }

  return Object.freeze(/** @type {Limits} */ (resolved));
}
