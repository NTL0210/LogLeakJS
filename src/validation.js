/**
 * Small validation helpers used to validate configuration before any log data
 * is processed. Invalid or unknown configuration is always rejected rather
 * than silently ignored.
 *
 * @module validation
 */

import { ConfigurationError } from './errors.js';

/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
export function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * @param {unknown} value
 * @param {string} label
 * @returns {Record<string, unknown>}
 */
export function assertPlainObject(value, label) {
  if (!isPlainObject(value)) {
    throw new ConfigurationError(`${label} must be a plain object.`);
  }
  return /** @type {Record<string, unknown>} */ (value);
}

/**
 * Rejects unknown option names so typos cannot silently weaken a policy.
 *
 * @param {Record<string, unknown>} value
 * @param {readonly string[]} allowed
 * @param {string} label
 */
export function rejectUnknownKeys(value, allowed, label) {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(value)) {
    if (!allowedSet.has(key)) {
      throw new ConfigurationError(
        `Unknown option "${key}" in ${label}. Allowed options: ${allowed.join(', ')}.`,
      );
    }
  }
}

/**
 * @param {unknown} value
 * @param {string} label
 * @returns {boolean | undefined}
 */
export function optionalBoolean(value, label) {
  if (value === undefined) return undefined;
  if (typeof value !== 'boolean') {
    throw new ConfigurationError(`${label} must be a boolean.`);
  }
  return value;
}

/**
 * @param {unknown} value
 * @param {string} label
 * @param {{min?: number, max?: number}} [range]
 * @returns {number}
 */
export function requiredInteger(value, label, range = {}) {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new ConfigurationError(`${label} must be an integer.`);
  }
  if (range.min !== undefined && value < range.min) {
    throw new ConfigurationError(`${label} must be >= ${range.min}.`);
  }
  if (range.max !== undefined && value > range.max) {
    throw new ConfigurationError(`${label} must be <= ${range.max}.`);
  }
  return value;
}

/**
 * @param {unknown} value
 * @param {string} label
 * @param {{minLength?: number, maxLength?: number, pattern?: RegExp}} [options]
 * @returns {string}
 */
export function requiredString(value, label, options = {}) {
  if (typeof value !== 'string') {
    throw new ConfigurationError(`${label} must be a string.`);
  }
  const { minLength = 0, maxLength = 1024, pattern } = options;
  if (value.length < minLength) {
    throw new ConfigurationError(`${label} must be at least ${minLength} characters.`);
  }
  if (value.length > maxLength) {
    throw new ConfigurationError(`${label} must be at most ${maxLength} characters.`);
  }
  if (pattern && !pattern.test(value)) {
    throw new ConfigurationError(`${label} contains unsupported characters.`);
  }
  return value;
}

/**
 * Recursively freezes a configuration object so callers cannot mutate policy
 * after validation.
 *
 * @template T
 * @param {T} value
 * @returns {T}
 */
export function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const key of Object.keys(value)) {
    deepFreeze(value[key]);
  }
  return value;
}
