/**
 * Exact synthetic-secret registry.
 *
 * Values are held in memory for the lifetime of a detector instance and are
 * never logged, serialized, hashed into reports, or sent anywhere. The registry
 * exposes only counts and match indexes.
 *
 * @module detectors/known-secrets
 */

import { ConfigurationError } from '../errors.js';

/**
 * @typedef {object} SecretRegistryOptions
 * @property {number} maxSecrets
 * @property {number} maxSecretBytes
 * @property {number} maxTotalSecretBytes
 * @property {number} minLength
 */

/**
 * @typedef {object} SecretRegistry
 * @property {number} count
 * @property {boolean} disposed
 * @property {(text: string) => number[]} findMatches Returns indexes of
 *   registered secrets present in the text. Indexes are stable for the
 *   lifetime of the registry and reveal nothing about the value.
 * @property {(value: string) => void} add
 * @property {() => void} dispose
 */

/**
 * Creates a local, in-memory registry of synthetic secrets.
 *
 * @param {readonly string[]} values
 * @param {SecretRegistryOptions} options
 * @returns {SecretRegistry}
 */
export function createSecretRegistry(values, options) {
  const { maxSecrets, maxSecretBytes, maxTotalSecretBytes, minLength } = options;

  /** @type {string[]} */
  const secrets = [];
  let totalBytes = 0;
  let disposed = false;

  /**
   * @param {unknown} value
   * @param {string} label
   */
  function add(value, label) {
    if (disposed) {
      throw new ConfigurationError(
        'The detector has been disposed. Create a new detector before registering secrets.',
      );
    }
    if (typeof value !== 'string') {
      throw new ConfigurationError(`${label} must be a string.`);
    }
    if (value.length < minLength) {
      throw new ConfigurationError(
        `${label} is shorter than the configured minimum of ${minLength} characters. Short values produce unreliable matches.`,
      );
    }
    const bytes = Buffer.byteLength(value, 'utf8');
    if (bytes > maxSecretBytes) {
      throw new ConfigurationError(
        `${label} exceeds the maximum secret length of ${maxSecretBytes} bytes.`,
      );
    }
    if (secrets.length >= maxSecrets) {
      throw new ConfigurationError(
        `At most ${maxSecrets} synthetic secrets can be registered per detector.`,
      );
    }
    if (totalBytes + bytes > maxTotalSecretBytes) {
      throw new ConfigurationError(
        `Registered synthetic secrets exceed the maximum combined length of ${maxTotalSecretBytes} bytes.`,
      );
    }
    if (secrets.includes(value)) return;
    secrets.push(value);
    totalBytes += bytes;
  }

  values.forEach((value, index) => add(value, `knownSecrets[${index}]`));

  return {
    get count() {
      return secrets.length;
    },
    get disposed() {
      return disposed;
    },
    findMatches(text) {
      if (disposed) {
        throw new ConfigurationError(
          'The detector has been disposed. Create a new detector before analyzing logs.',
        );
      }
      if (secrets.length === 0) return [];
      /** @type {number[]} */
      const matches = [];
      for (let index = 0; index < secrets.length; index += 1) {
        if (text.includes(secrets[index])) matches.push(index);
      }
      return matches;
    },
    add(value) {
      add(value, 'registerSecret(value)');
    },
    dispose() {
      // JavaScript strings cannot be reliably wiped from memory. Dropping the
      // references is the best available cleanup and is documented as such.
      secrets.length = 0;
      totalBytes = 0;
      disposed = true;
    },
  };
}
