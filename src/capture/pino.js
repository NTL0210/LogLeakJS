/**
 * Pino capture adapter.
 *
 * Pino writes serialized, already-redacted lines to a destination stream. This
 * adapter provides such a stream and analyzes exactly what the logger emitted,
 * after Pino's serializers, formatters, and redaction ran.
 *
 * Usage:
 *
 * ```js
 * import pino from 'pino';
 * import { createPinoCapture } from 'logleak-test/pino';
 *
 * const capture = createPinoCapture();
 * const logger = pino({ redact: ['req.headers.authorization'] }, capture.stream);
 * logger.info({ password: 'x' });
 * const analysis = detector.analyze(capture.finish());
 * ```
 *
 * The adapter does not import Pino and does not patch any Pino or process
 * global. The destination writes synchronously, so `finish()` observes every
 * record written before the call.
 *
 * @module capture/pino
 */

import { createMemoryCapture } from './memory.js';
import { captureLimitSubset, resolveCaptureOptions } from './options.js';

/**
 * Creates a Pino destination stream plus scoped helpers.
 *
 * @param {{source?: string, maxRecords?: number, maxRecordBytes?: number, maxTotalBytes?: number}} [options]
 * @returns {{
 *   stream: {write: (line: unknown) => boolean},
 *   finish: () => import('./memory.js').CaptureResult,
 *   run: (fn: () => unknown | Promise<unknown>) => Promise<{ok: boolean, value: unknown, error: unknown, captured: import('./memory.js').CaptureResult}>,
 *   readonly size: number,
 *   readonly coverage: 'complete'|'incomplete',
 *   readonly finished: boolean
 * }}
 */
export function createPinoCapture(options = {}) {
  const resolved = resolveCaptureOptions(options, 'pino');
  const capture = createMemoryCapture({
    source: resolved.source,
    ...captureLimitSubset(resolved),
  });

  const stream = Object.freeze({
    /**
     * Pino's DestinationStream contract.
     *
     * @param {unknown} line
     * @returns {boolean}
     */
    write(line) {
      if (typeof line === 'string') {
        capture.push(line);
        return true;
      }
      if (Buffer.isBuffer(line) || line instanceof Uint8Array) {
        capture.push(Buffer.from(line));
        return true;
      }
      // Pino always writes strings or Buffers. If that changes, do not call
      // arbitrary toString() implementations on untrusted values.
      capture.reportIssue('serialization-failed');
      return false;
    },
  });

  return Object.freeze({
    stream,
    finish: () => capture.finish(),
    run: (fn) => capture.run(fn),
    get size() {
      return capture.size;
    },
    get coverage() {
      return capture.coverage;
    },
    get finished() {
      return capture.finished;
    },
  });
}
