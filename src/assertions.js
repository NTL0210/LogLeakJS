/**
 * Test-framework-neutral assertions and exit-code mapping.
 *
 * The helpers work with plain exceptions, so they can be used from `node:test`,
 * Vitest, Jest, or any other runner without a framework-specific dependency.
 *
 * @module assertions
 */

import { ConfigurationError, EXIT_CODES, LogLeakAssertionError } from './errors.js';
import { isAtLeast, isSeverity } from './severity.js';
import { assertPlainObject, optionalBoolean, rejectUnknownKeys } from './validation.js';

/**
 * @param {unknown} result
 * @returns {asserts result is Record<string, any>}
 */
function assertAnalysisResult(result) {
  if (
    result === null ||
    typeof result !== 'object' ||
    !Array.isArray(/** @type {any} */ (result).findings) ||
    typeof /** @type {any} */ (result).coverage !== 'string'
  ) {
    throw new ConfigurationError(
      'Expected a result returned by createLogLeakDetector().analyze().',
    );
  }
}

/**
 * Maps an analysis result to a stable process exit code.
 *
 * - 0: no findings, complete analysis
 * - 1: findings
 * - 3: incomplete analysis without findings
 *
 * Configuration and internal failures are thrown as errors instead of being
 * encoded in a result.
 *
 * @param {object} result
 * @returns {number}
 */
export function getExitCode(result) {
  assertAnalysisResult(result);
  const value = /** @type {any} */ (result);
  if (value.findings.length > 0) return EXIT_CODES.LEAKS;
  return value.coverage === 'complete' ? EXIT_CODES.OK : EXIT_CODES.INCOMPLETE;
}

/**
 * @typedef {object} AssertOptions
 * @property {import('./severity.js').Severity} [minSeverity='low'] Ignore
 *   findings below this severity.
 * @property {boolean} [allowIncomplete=false] Do not fail when analysis was
 *   incomplete. This is an explicit escape hatch; using it means the test no
 *   longer proves that the captured output is clean.
 */

/**
 * @param {unknown} options
 * @returns {AssertOptions}
 */
function normalizeAssertOptions(options) {
  if (options === undefined) return { minSeverity: 'low', allowIncomplete: false };
  const value = assertPlainObject(options, 'assert options');
  rejectUnknownKeys(value, ['minSeverity', 'allowIncomplete'], 'assert options');
  const minSeverity = value.minSeverity ?? 'low';
  if (!isSeverity(minSeverity)) {
    throw new ConfigurationError('assert options.minSeverity is not a valid severity.');
  }
  return {
    minSeverity,
    allowIncomplete: optionalBoolean(value.allowIncomplete, 'assert options.allowIncomplete') ?? false,
  };
}

/**
 * Builds a privacy-safe assertion message. Only rule metadata and sanitized
 * paths are included.
 *
 * @param {Array<Record<string, any>>} findings
 * @param {object} result
 * @param {number} totalFindings
 * @returns {string}
 */
function buildAssertionMessage(findings, result, totalFindings) {
  const lines = [];
  const findingLabel = totalFindings === 1 ? 'finding' : 'findings';

  if (totalFindings > 0) {
    lines.push(
      `LogLeak Test detected ${totalFindings} sensitive-log ${findingLabel} (policy: ${result.policy}).`,
    );
    for (const finding of findings) {
      lines.push(
        `  [${String(finding.severity).toUpperCase()}] ${finding.detector} · ${finding.ruleId} · record ${finding.recordIndex} · ${finding.path}`,
      );
    }
    const shown = findings.length;
    if (totalFindings > shown) {
      lines.push(`  ... and ${totalFindings - shown} more.`);
    }
  } else {
    lines.push(
      `LogLeak Test could not complete log analysis (policy: ${result.policy}). A clean result cannot be claimed.`,
    );
  }

  if (result.coverage !== 'complete') {
    const reasons = result.summary?.incompleteReasons ?? [];
    lines.push(
      `Analysis coverage: incomplete${reasons.length > 0 ? ` (${reasons.join(', ')})` : ''}.`,
    );
  } else {
    lines.push('Analysis coverage: complete.');
  }

  lines.push('No sensitive values are included in this message.');
  return lines.join('\n');
}

/**
 * Throws a {@link LogLeakAssertionError} when the result contains findings at
 * or above `minSeverity`, or when the analysis was incomplete and the detector
 * policy requires completeness.
 *
 * Returns the result unchanged on success so it can be used inline.
 *
 * @param {object} result Result from `detector.analyze()`.
 * @param {AssertOptions} [options]
 * @returns {object}
 */
export function assertNoSensitiveLogLeaks(result, options) {
  assertAnalysisResult(result);
  const value = /** @type {any} */ (result);
  const { minSeverity, allowIncomplete } = normalizeAssertOptions(options);

  const relevant = value.findings.filter((finding) => isAtLeast(finding.severity, minSeverity));
  const incompleteFailure =
    value.coverage !== 'complete' && value.failOnIncomplete !== false && !allowIncomplete;

  if (relevant.length === 0 && !incompleteFailure) return result;

  const shown = relevant.slice(0, 20);
  const exitCode =
    relevant.length > 0 ? EXIT_CODES.LEAKS : EXIT_CODES.INCOMPLETE;

  throw new LogLeakAssertionError(
    buildAssertionMessage(shown, value, relevant.length),
    { result: value, exitCode },
  );
}

/**
 * Throws when the analysis was incomplete, regardless of the detector policy.
 * Use this when a test must prove that the configured capture actually observed
 * all relevant output.
 *
 * @param {object} result
 * @returns {object}
 */
export function assertAnalysisComplete(result) {
  assertAnalysisResult(result);
  const value = /** @type {any} */ (result);
  if (value.coverage === 'complete') return result;
  throw new LogLeakAssertionError(
    buildAssertionMessage([], value, 0),
    { result: value, exitCode: EXIT_CODES.INCOMPLETE },
  );
}
