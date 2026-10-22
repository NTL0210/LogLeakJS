import { createLogLeakDetector } from '../src/index.js';

/**
 * Creates a detector and analyzes a single input in one step.
 *
 * @param {unknown} input
 * @param {object} [options]
 * @returns {any}
 */
export function analyze(input, options = {}) {
  return createLogLeakDetector(options).analyze(input);
}

/**
 * @param {any} result
 * @returns {string[]}
 */
export function ruleIds(result) {
  return result.findings.map((finding) => finding.ruleId);
}

/**
 * @param {any} result
 * @returns {string[]}
 */
export function paths(result) {
  return result.findings.map((finding) => finding.path);
}

/**
 * @param {any} result
 * @param {string} ruleId
 * @returns {any[]}
 */
export function findingsFor(result, ruleId) {
  return result.findings.filter((finding) => finding.ruleId === ruleId);
}

/**
 * @param {any} result
 * @returns {string[]}
 */
export function detectorNames(result) {
  return result.findings.map((finding) => finding.detector);
}

/**
 * @param {any} result
 * @returns {Record<string, number>}
 */
export function bySeverity(result) {
  return result.summary.findings.bySeverity;
}

/**
 * JSON-safe deep clone used to assert that the analyzer does not mutate input.
 *
 * @param {unknown} value
 * @returns {unknown}
 */
export function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}
