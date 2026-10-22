/**
 * Winston capture adapter.
 *
 * Winston applies logger-level and transport-level formats before a transport
 * receives `info`. Winston's formats place the final rendered line on the
 * `Symbol.for('message')` property. This adapter captures that string, which is
 * what Winston's own console/file transports write, and falls back to a shallow
 * copy of the structured `info` object when no rendered message exists.
 *
 * The adapter imports `winston-transport` (an optional peer dependency) and
 * never patches Winston globals or existing transports.
 *
 * @module capture/winston
 */

import Transport from 'winston-transport';
import { ConfigurationError } from '../errors.js';
import { createMemoryCapture } from './memory.js';
import { captureLimitSubset, resolveCaptureOptions } from './options.js';

const MESSAGE = Symbol.for('message');

/**
 * @param {unknown} value
 * @returns {value is {add: Function, remove: Function}}
 */
function isLogger(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    typeof /** @type {any} */ (value).add === 'function' &&
    typeof /** @type {any} */ (value).remove === 'function'
  );
}

/**
 * Copies own enumerable data properties without invoking getters.
 *
 * @param {unknown} info
 * @returns {Record<string, unknown>}
 */
function snapshotInfo(info) {
  if (info === null || typeof info !== 'object') return {};
  /** @type {Record<string, unknown>} */
  const copy = {};
  for (const key of Object.keys(info)) {
    const descriptor = Object.getOwnPropertyDescriptor(info, key);
    if (!descriptor || descriptor.get || descriptor.set) continue;
    copy[key] = descriptor.value;
  }
  return copy;
}

/**
 * @param {unknown} info
 * @returns {string | Record<string, unknown>}
 */
function extractCapturedValue(info) {
  if (info !== null && typeof info === 'object') {
    const rendered = /** @type {any} */ (info)[MESSAGE];
    if (typeof rendered === 'string' && rendered.length > 0) return rendered;
  }
  return snapshotInfo(info);
}

/**
 * @typedef {object} WinstonCapture
 * @property {Transport} transport Transport instance to add to a Winston logger.
 * @property {(logger: object) => WinstonCapture} attach Adds the transport to a logger.
 * @property {(logger: object) => void} detach Removes the transport from a logger.
 * @property {() => import('./memory.js').CaptureResult} finish Detaches from all loggers and finishes the capture.
 * @property {(logger: object, fn: () => unknown | Promise<unknown>) => Promise<{ok: boolean, value: unknown, error: unknown, captured: import('./memory.js').CaptureResult}>} run Attaches, runs, always detaches, and finishes.
 * @property {readonly number} size
 * @property {readonly 'complete'|'incomplete'} coverage
 * @property {readonly boolean} finished
 */

/**
 * Creates a Winston transport that writes into an isolated in-memory capture.
 *
 * @param {{source?: string, maxRecords?: number, maxRecordBytes?: number, maxTotalBytes?: number}} [options]
 * @returns {WinstonCapture}
 */
export function createWinstonCapture(options = {}) {
  const resolved = resolveCaptureOptions(options, 'winston');
  const capture = createMemoryCapture({
    source: resolved.source,
    ...captureLimitSubset(resolved),
  });

  /** @type {Map<object, boolean>} */
  const attached = new Map();

  class CaptureTransport extends Transport {
    constructor() {
      super({});
      this.name = 'logleak-test-capture';
    }

    /**
     * @param {unknown} info
     * @param {(error?: Error) => void} [callback]
     */
    log(info, callback) {
      /** @type {Error | undefined} */
      let failure;
      try {
        capture.push(extractCapturedValue(info));
      } catch (error) {
        failure = error instanceof Error ? error : new Error('Winston capture failed.');
        try {
          capture.reportIssue('serialization-failed');
        } catch {
          // The capture is already closed; the transport cannot do more.
        }
      }
      if (typeof callback === 'function') callback(failure);
    }
  }

  const transport = new CaptureTransport();

  /**
   * @param {unknown} logger
   */
  function assertLogger(logger) {
    if (!isLogger(logger)) {
      throw new ConfigurationError(
        'Winston capture requires a logger with add() and remove() methods.',
      );
    }
  }

  /**
   * Adds the transport unless it is already present on the logger. Returns
   * whether this adapter owns the attachment (and should remove it later).
   *
   * @param {object} logger
   * @returns {boolean}
   */
  function attachOnce(logger) {
    assertLogger(logger);
    if (attached.has(logger)) return attached.get(logger) ?? false;
    const existing = /** @type {any} */ (logger).transports;
    const alreadyPresent =
      existing !== null &&
      typeof existing === 'object' &&
      Object.values(existing).includes(transport);
    if (!alreadyPresent) {
      /** @type {any} */ (logger).add(transport);
    }
    attached.set(logger, !alreadyPresent);
    return !alreadyPresent;
  }

  /**
   * @param {object} logger
   * @returns {WinstonCapture}
   */
  function attach(logger) {
    attachOnce(logger);
    return api;
  }

  /**
   * @param {object} logger
   */
  function detach(logger) {
    if (!isLogger(logger)) return;
    if (!attached.has(logger)) return;
    if (attached.get(logger) === true) {
      /** @type {any} */ (logger).remove(transport);
    }
    attached.delete(logger);
  }

  function detachAll() {
    for (const logger of [...attached.keys()]) detach(logger);
  }

  /** @type {WinstonCapture} */
  const api = {
    transport: /** @type {Transport} */ (transport),
    attach,
    detach,
    finish() {
      detachAll();
      return capture.finish();
    },
    async run(logger, fn) {
      assertLogger(logger);
      if (typeof fn !== 'function') {
        throw new ConfigurationError('winstonCapture.run(logger, fn) requires a function.');
      }
      attach(logger);
      try {
        return await capture.run(fn);
      } finally {
        detachAll();
      }
    },
    get size() {
      return capture.size;
    },
    get coverage() {
      return capture.coverage;
    },
    get finished() {
      return capture.finished;
    },
  };

  return Object.freeze(api);
}
