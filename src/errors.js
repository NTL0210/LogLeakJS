/**
 * Error types and process exit codes used by logleak-test.
 *
 * All error messages produced by this package are written so that they never
 * contain captured log values, registered synthetic secrets, or credentials.
 *
 * @module errors
 */

/**
 * Stable process exit codes. Intended for CI scripts that run a test command
 * and translate the analyzer result into a process exit status.
 *
 * @readonly
 * @enum {number}
 */
export const EXIT_CODES = Object.freeze({
  /** No findings and analysis was complete. */
  OK: 0,
  /** At least one finding was reported. */
  LEAKS: 1,
  /** The detector was configured incorrectly or called incorrectly. */
  CONFIGURATION: 2,
  /** Analysis could not be completed within the configured limits. */
  INCOMPLETE: 3,
  /** An unexpected internal failure occurred. */
  INTERNAL: 4,
});

/**
 * Base class for every error thrown by logleak-test.
 */
export class LogLeakError extends Error {
  /**
   * @param {string} message Safe, value-free error message.
   * @param {{code?: string, cause?: unknown}} [options]
   */
  constructor(message, options = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = new.target.name;
    /** @type {string} Stable machine-readable error code. */
    this.code = options.code ?? 'ERR_LOGLEAK';
  }
}

/**
 * Thrown when detector configuration is missing, invalid, or contains unknown
 * options. Fails fast before any log data is analyzed.
 */
export class ConfigurationError extends LogLeakError {
  /**
   * @param {string} message
   */
  constructor(message) {
    super(message, { code: 'ERR_LOGLEAK_CONFIGURATION' });
    /** @type {number} */
    this.exitCode = EXIT_CODES.CONFIGURATION;
  }
}

/**
 * Thrown when a capture adapter is used outside of its documented lifecycle,
 * for example when pushing a record after the capture has been finished.
 */
export class CaptureError extends LogLeakError {
  /**
   * @param {string} message
   */
  constructor(message) {
    super(message, { code: 'ERR_LOGLEAK_CAPTURE' });
    /** @type {number} */
    this.exitCode = EXIT_CODES.INTERNAL;
  }
}

/**
 * Thrown when the analyzer cannot continue because of an unexpected internal
 * condition. Distinct from {@link ConfigurationError} so CI can tell a bug
 * from a policy problem.
 */
export class AnalysisError extends LogLeakError {
  /**
   * @param {string} message
   * @param {{cause?: unknown}} [options]
   */
  constructor(message, options = {}) {
    super(message, { code: 'ERR_LOGLEAK_ANALYSIS', cause: options.cause });
    /** @type {number} */
    this.exitCode = EXIT_CODES.INTERNAL;
  }
}

/**
 * Thrown by the assertion helpers when a security policy is violated.
 *
 * The message contains finding metadata only: rule ids, record indexes, and
 * sanitized field paths. It never contains the detected value, a raw log line,
 * or a hash of a detected value.
 */
export class LogLeakAssertionError extends LogLeakError {
  /**
   * @param {string} message
   * @param {{result: object, exitCode: number}} options
   */
  constructor(message, options) {
    super(message, { code: 'ERR_LOGLEAK_ASSERTION' });
    /** @type {number} */
    this.exitCode = options.exitCode;
    /**
     * The full, privacy-safe analysis result. Safe to print and serialize.
     * @type {object}
     */
    this.result = options.result;
  }
}
