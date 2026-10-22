/**
 * Canary secret generation.
 *
 * @module canary
 */

import { randomBytes } from 'node:crypto';
import { assertPlainObject, rejectUnknownKeys, requiredString } from './validation.js';

/**
 * Creates a unique, high-entropy synthetic secret that can be passed through an
 * application and then registered with a detector.
 *
 * The value is stored in a non-enumerable property so accidental
 * `JSON.stringify(canary)` or `console.log(canary)` calls do not reveal it.
 * Pass `canary.value` to the application and `canary.value` to
 * `knownSecrets` or `detector.registerSecret()`.
 *
 * @param {{prefix?: string}} [options]
 * @returns {{readonly value: string}}
 */
export function createCanarySecret(options = {}) {
  const value = assertPlainObject(options, 'canary options');
  rejectUnknownKeys(value, ['prefix'], 'canary options');
  const prefix =
    value.prefix === undefined
      ? 'LLT_CANARY'
      : requiredString(value.prefix, 'canary options.prefix', {
          minLength: 3,
          maxLength: 32,
          pattern: /^[A-Za-z][A-Za-z0-9_]*$/u,
        });

  const secret = `${prefix}_${randomBytes(16).toString('hex')}`;
  const canary = {};
  Object.defineProperty(canary, 'value', {
    value: secret,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  Object.defineProperty(canary, 'toJSON', {
    value: () => '[LogLeakCanary]',
    enumerable: false,
  });
  Object.defineProperty(canary, Symbol.for('nodejs.util.inspect.custom'), {
    value: () => '[LogLeakCanary]',
    enumerable: false,
  });
  return Object.freeze(canary);
}
