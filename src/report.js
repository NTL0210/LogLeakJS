/**
 * Privacy-safe report formatting.
 *
 * Every finding contains rule metadata only. Reports never include detected
 * values, raw log lines, nearby snippets, authorization headers, cookie values,
 * serialized errors, or hashes of detected values.
 *
 * @module report
 */

import { ConfigurationError } from './errors.js';
import { assertPlainObject, optionalBoolean, rejectUnknownKeys, requiredInteger } from './validation.js';

const ANSI = Object.freeze({
  reset: '\u001B[0m',
  bold: '\u001B[1m',
  dim: '\u001B[2m',
  red: '\u001B[31m',
  yellow: '\u001B[33m',
  cyan: '\u001B[36m',
  green: '\u001B[32m',
});

const SEVERITY_COLORS = Object.freeze({
  critical: ANSI.red,
  high: ANSI.red,
  medium: ANSI.yellow,
  low: ANSI.cyan,
});

/**
 * @param {object} result
 * @returns {asserts result is Record<string, any>}
 */
function assertResult(result) {
  if (
    result === null ||
    typeof result !== 'object' ||
    !Array.isArray(/** @type {any} */ (result).findings)
  ) {
    throw new ConfigurationError('Expected a result returned by detector.analyze().');
  }
}

/**
 * @param {string} value
 * @param {string} color
 * @param {boolean} enabled
 * @returns {string}
 */
function paint(value, color, enabled) {
  return enabled ? `${color}${value}${ANSI.reset}` : value;
}

/**
 * Formats a human-readable report suitable for a terminal or CI log.
 *
 * @param {object} result
 * @param {{color?: boolean, maxFindings?: number, includeRemediation?: boolean}} [options]
 * @returns {string}
 */
export function formatTerminalReport(result, options = {}) {
  assertResult(result);
  const value = assertPlainObject(options, 'report options');
  rejectUnknownKeys(value, ['color', 'maxFindings', 'includeRemediation'], 'report options');

  const color = optionalBoolean(value.color, 'report options.color') ?? false;
  const maxFindings =
    value.maxFindings === undefined
      ? 20
      : requiredInteger(value.maxFindings, 'report options.maxFindings', { min: 1, max: 1000 });
  const includeRemediation =
    optionalBoolean(value.includeRemediation, 'report options.includeRemediation') ?? true;

  const report = /** @type {any} */ (result);
  const lines = [];

  lines.push(paint(`LogLeak Test ${report.version ?? ''}`.trim(), ANSI.bold, color));
  lines.push(
    `Status: ${paint(String(report.status).toUpperCase(), statusColor(report.status), color)} · policy: ${report.policy} · coverage: ${report.coverage}`,
  );
  lines.push('');

  if (report.findings.length === 0) {
    if (report.coverage === 'complete') {
      lines.push(paint('No findings in the captured log output.', ANSI.green, color));
    } else {
      lines.push(
        paint(
          'No findings, but the analysis was incomplete. A clean result cannot be claimed.',
          ANSI.yellow,
          color,
        ),
      );
    }
  } else {
    const shown = report.findings.slice(0, maxFindings);
    for (const finding of shown) {
      const severity = String(finding.severity).toUpperCase();
      lines.push(
        `${paint(severity.padEnd(8), SEVERITY_COLORS[finding.severity] ?? ANSI.reset, color)} ${finding.detector} · ${finding.ruleId}`,
      );
      lines.push(
        `  record ${finding.recordIndex} · ${finding.path}${finding.redacted ? ' · value was redacted' : ''}`,
      );
      lines.push(`  ${finding.message}`);
      if (includeRemediation) {
        lines.push(paint(`  fix: ${finding.remediation}`, ANSI.dim, color));
      }
      lines.push('');
    }
    if (report.findings.length > shown.length) {
      lines.push(
        `... and ${report.findings.length - shown.length} more finding(s). Raise report options.maxFindings to show more.`,
      );
      lines.push('');
    }
  }

  const summary = report.summary ?? {};
  lines.push(
    `Summary: ${summary.recordsAnalyzed ?? 0} record(s), ${summary.bytesAnalyzed ?? 0} byte(s) analyzed, ${summary.findings?.total ?? 0} finding(s), ${summary.suppressedFindings ?? 0} suppressed, ${summary.redactedFields ?? 0} redacted field(s).`,
  );

  if (report.coverage !== 'complete') {
    const reasons = summary.incompleteReasons ?? [];
    lines.push(
      `Incomplete analysis: ${reasons.length > 0 ? reasons.join(', ') : 'unspecified'}. This result must not be reported as clean.`,
    );
  }

  if (Array.isArray(report.diagnostics) && report.diagnostics.length > 0) {
    lines.push('');
    lines.push('Diagnostics:');
    for (const diagnostic of report.diagnostics) {
      lines.push(
        `  - ${diagnostic.code}${diagnostic.path ? ` at ${diagnostic.path}` : ''}: ${diagnostic.message}`,
      );
    }
  }

  lines.push('');
  lines.push('No sensitive values are included in this report.');
  return lines.join('\n');
}

/**
 * @param {string} status
 * @returns {string}
 */
function statusColor(status) {
  if (status === 'pass') return ANSI.green;
  if (status === 'incomplete') return ANSI.yellow;
  return ANSI.red;
}

/**
 * Serializes a result as JSON for CI systems. The result object itself is
 * designed to be safe to serialize.
 *
 * @param {object} result
 * @param {{pretty?: boolean, includeTimestamp?: boolean}} [options]
 * @returns {string}
 */
export function formatJsonReport(result, options = {}) {
  assertResult(result);
  const value = assertPlainObject(options, 'report options');
  rejectUnknownKeys(value, ['pretty', 'includeTimestamp'], 'report options');
  const pretty = optionalBoolean(value.pretty, 'report options.pretty') ?? true;
  const includeTimestamp =
    optionalBoolean(value.includeTimestamp, 'report options.includeTimestamp') ?? false;

  const report = /** @type {any} */ (result);
  const payload = {
    tool: report.tool,
    version: report.version,
    schemaVersion: report.schemaVersion,
    status: report.status,
    exitCode: report.exitCode,
    policy: report.policy,
    coverage: report.coverage,
    failOnIncomplete: report.failOnIncomplete,
    findings: report.findings,
    diagnostics: report.diagnostics,
    summary: report.summary,
  };
  if (includeTimestamp === true) {
    payload.generatedAt = new Date().toISOString();
  }
  return JSON.stringify(payload, null, pretty ? 2 : 0);
}
