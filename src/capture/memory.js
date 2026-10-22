/**
 * In-memory capture buffer.
 *
 * Records are stored in an instance-local array. There is no module-level
 * buffer, so concurrent test captures cannot mix records.
 *
 * Bounds: the number of records, the size of an individual string/Buffer
 * record, and the combined byte size are enforced while pushing. Exceeding a
 * bound marks the capture incomplete and keeps the records captured so far.
 *
 * Object records are stored by reference and are not deep-cloned: cloning
 * arbitrary objects can invoke getters or `toJSON`, which this library avoids.
 * Analyze object records before mutating them.
 *
 * @module capture/memory
 */

import { ConfigurationError, CaptureError } from '../errors.js';
import { byteLength } from '../text.js';
import { assertPlainObject, rejectUnknownKeys } from '../validation.js';
import { sanitizeSourceName } from '../privacy.js';
import { captureLimitSubset, resolveCaptureOptions } from './options.js';

const ISSUE_MESSAGES = Object.freeze({
  'max-records-exceeded': 'The capture stopped at the maximum number of log records.',
  'max-record-bytes-exceeded': 'The capture rejected a log record larger than the configured maximum.',
  'max-total-bytes-exceeded': 'The capture stopped at the configured total byte budget.',
  'serialization-failed': 'The capture could not serialize a log record.',
});

/**
 * @typedef {object} CapturedRecord
 * @property {string} source
 * @property {unknown} value
 */

/**
 * @typedef {object} CaptureResult
 * @property {readonly CapturedRecord[]} records
 * @property {'complete'|'incomplete'} coverage
 * @property {readonly {code: string, message: string}[]} issues
 */

/**
 * @typedef {object} MemoryCapture
 * @property {(value: unknown, meta?: {source?: string}) => boolean} push
 * @property {() => CaptureResult} finish
 * @property {(fn: () => unknown | Promise<unknown>) => Promise<{ok: boolean, value: unknown, error: unknown, captured: CaptureResult}>} run
 * @property {(code: string) => void} reportIssue
 * @property {readonly number} size
 * @property {readonly 'complete'|'incomplete'} coverage
 * @property {readonly boolean} finished
 */

/**
 * @param {string} code
 */
function issueMessage(code) {
  return ISSUE_MESSAGES[code] ?? 'The capture reported an unspecified issue.';
}

/**
 * @param {unknown} raw
 * @returns {{source?: string}}
 */
function normalizeMeta(raw) {
  if (raw === undefined) return {};
  const value = assertPlainObject(raw, 'push meta');
  rejectUnknownKeys(value, ['source'], 'push meta');
  if (value.source === undefined) return {};
  if (typeof value.source !== 'string') {
    throw new ConfigurationError('push meta.source must be a string.');
  }
  return { source: sanitizeSourceName(value.source) };
}

/**
 * Creates a bounded in-memory capture.
 *
 * @param {{source?: string, maxRecords?: number, maxRecordBytes?: number, maxTotalBytes?: number}} [options]
 * @returns {MemoryCapture}
 */
export function createMemoryCapture(options = {}) {
  const resolved = resolveCaptureOptions(options, 'memory');
  const limits = captureLimitSubset(resolved);

  /** @type {CapturedRecord[]} */
  const records = [];
  /** @type {{code: string, message: string}[]} */
  const issues = [];
  const issueCodes = new Set();

  let totalBytes = 0;
  let state = /** @type {'open'|'finished'} */ ('open');
  /** @type {CaptureResult | null} */
  let finishedResult = null;

  /**
   * @param {string} code
   * @param {string} [message]
   */
  function reportIssue(code, message) {
    if (typeof code !== 'string' || code.length === 0) {
      throw new ConfigurationError('reportIssue(code) requires a non-empty string.');
    }
    if (issueCodes.has(code)) return;
    issueCodes.add(code);
    issues.push(
      Object.freeze({
        code,
        message: message ?? issueMessage(code),
      }),
    );
  }

  function assertOpen() {
    if (state !== 'open') {
      throw new CaptureError(
        'This capture has already been finished. Create a new capture for another test.',
      );
    }
  }

  /**
   * @param {unknown} value
   * @param {{source?: string}} [meta]
   * @returns {boolean}
   */
  function push(value, meta) {
    assertOpen();
    const metaValue = normalizeMeta(meta);
    const source = metaValue.source ?? resolved.source;

    if (records.length >= limits.maxRecords) {
      reportIssue('max-records-exceeded');
      return false;
    }

    /** @type {unknown} */
    let stored = value;
    let bytes = 0;

    if (typeof value === 'string') {
      bytes = byteLength(value);
    } else if (Buffer.isBuffer(value)) {
      bytes = value.byteLength;
      stored = Buffer.from(value);
    } else if (value instanceof Uint8Array) {
      bytes = value.byteLength;
      stored = new Uint8Array(value);
    }

    if (bytes > limits.maxRecordBytes) {
      reportIssue('max-record-bytes-exceeded');
      return false;
    }
    if (totalBytes + bytes > limits.maxTotalBytes) {
      reportIssue('max-total-bytes-exceeded');
      return false;
    }

    records.push(Object.freeze({ source, value: stored }));
    totalBytes += bytes;
    return true;
  }

  /**
   * @returns {CaptureResult}
   */
  function finish() {
    if (finishedResult) return finishedResult;
    state = 'finished';
    finishedResult = Object.freeze({
      records: Object.freeze(records.slice()),
      coverage: issues.length === 0 ? 'complete' : 'incomplete',
      issues: Object.freeze(issues.slice()),
    });
    return finishedResult;
  }

  /**
   * Runs `fn`, always finishing the capture, and returns an outcome. Errors
   * thrown by `fn` are returned instead of being swallowed: check
   * `outcome.ok` and rethrow `outcome.error` after analyzing if needed.
   *
   * @param {() => unknown | Promise<unknown>} fn
   * @returns {Promise<{ok: boolean, value: unknown, error: unknown, captured: CaptureResult}>}
   */
  async function run(fn) {
    assertOpen();
    if (typeof fn !== 'function') {
      throw new ConfigurationError('capture.run(fn) requires a function.');
    }
    let ok = true;
    /** @type {unknown} */
    let value;
    /** @type {unknown} */
    let error;
    try {
      value = await fn();
    } catch (caught) {
      ok = false;
      error = caught;
    }
    const captured = finish();
    return Object.freeze({ ok, value, error, captured });
  }

  return Object.freeze({
    push,
    finish,
    run,
    reportIssue(code) {
      reportIssue(code);
    },
    get size() {
      return records.length;
    },
    get coverage() {
      return issues.length === 0 ? 'complete' : 'incomplete';
    },
    get finished() {
      return state === 'finished';
    },
  });
}
