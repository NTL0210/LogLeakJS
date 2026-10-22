/**
 * LogLeak Test — detect sensitive values in logs emitted during tests.
 *
 * This entry point is logger-agnostic and has no runtime dependencies. Pino and
 * Winston adapters live behind the `logleak-test/pino` and
 * `logleak-test/winston` subpath exports and are never imported here.
 *
 * @module logleak-test
 */

export { createLogLeakDetector, listDetectorRules } from './analyze.js';
export {
  assertAnalysisComplete,
  assertNoSensitiveLogLeaks,
  getExitCode,
} from './assertions.js';
export { createCanarySecret } from './canary.js';
export { createMemoryCapture } from './capture/memory.js';
export { formatJsonReport, formatTerminalReport } from './report.js';
export {
  AnalysisError,
  CaptureError,
  ConfigurationError,
  EXIT_CODES,
  LogLeakAssertionError,
  LogLeakError,
} from './errors.js';
