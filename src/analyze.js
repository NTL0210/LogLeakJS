/**
 * The analyzer: bounded, local-only detection of sensitive values in captured
 * log output.
 *
 * @module analyze
 */

import { resolveConfig } from './config.js';
import { LIBRARY_NAME, LIBRARY_VERSION, REPORT_SCHEMA_VERSION } from './constants.js';
import { EXIT_CODES, ConfigurationError } from './errors.js';
import { ALL_RULE_IDS, RULE_IDS } from './detectors/catalog.js';
import { fieldIndex } from './detectors/field-names.js';
import { createSecretRegistry } from './detectors/known-secrets.js';
import { LOG_INJECTION_RULES } from './detectors/log-injection.js';
import { COMPILED_PATTERNS } from './detectors/patterns.js';
import { PERSONAL_DATA_RULES } from './detectors/personal-data.js';
import { walkValue } from './normalize.js';
import {
  appendKey,
  makeFindingId,
  sanitizeSegment,
  sanitizeSourceName,
} from './privacy.js';
import { createPlaceholderMatcher } from './redaction.js';
import { SEVERITY_RANK } from './severity.js';
import { byteLength, decodeBytes, isBlank } from './text.js';
import { deepFreeze, isPlainObject } from './validation.js';

/** @typedef {import('./config.js').ResolvedConfig} ResolvedConfig */

const EVIDENCE = Object.freeze({
  knownSecret: 'known-secret',
  sensitiveField: 'sensitive-field',
  credentialPattern: 'credential-pattern',
  personalData: 'personal-data',
  logInjection: 'log-injection',
});

const DETECTOR_NAMES = Object.freeze([
  'sensitive-field',
  'known-secret',
  'credential-pattern',
  'personal-data',
  'log-injection',
]);

const CAPTURE_MESSAGES = Object.freeze({
  'max-records-exceeded': 'The capture stopped at the maximum number of log records.',
  'max-record-bytes-exceeded': 'The capture rejected a log record larger than the configured maximum.',
  'max-total-bytes-exceeded': 'The capture stopped at the configured total byte budget.',
  'serialization-failed': 'The capture could not serialize a log record.',
  'capture-incomplete': 'The capture reported that it did not observe all log output.',
});

const DIAGNOSTIC_MESSAGES = Object.freeze({
  'no-records': 'No log records were supplied to the analyzer.',
  'capture-incomplete': 'The log capture reported incomplete coverage; a clean result cannot be claimed.',
  'max-records-exceeded': 'The input contained more records than the configured maximum; the remainder was not analyzed.',
  'max-total-bytes-exceeded': 'The configured total byte budget was exhausted; the remainder was not analyzed.',
  'max-findings-exceeded': 'The configured finding limit was reached; additional findings were not retained.',
  'max-diagnostics-exceeded': 'The configured diagnostic limit was reached; additional diagnostics were dropped.',
  'time-limit-exceeded': 'The configured analysis time limit was reached; the remainder was not analyzed.',
  'invalid-json': 'A serialized record was not valid JSON; it was analyzed as plain text.',
  'invalid-utf8': 'Invalid UTF-8 was replaced while decoding; the decoded text may be incomplete.',
  'max-depth-exceeded': 'Maximum structured-record depth was reached; deeper values were not inspected.',
  'max-nodes-exceeded': 'Maximum number of visited record nodes was reached; the remainder was not inspected.',
  'max-record-bytes-exceeded': 'Maximum estimated record size was reached; the remainder was not inspected.',
  'unsupported-accessor': 'An accessor property was skipped to avoid executing caller code; its value was not inspected.',
  'unsupported-container': 'A WeakMap or WeakSet was skipped because its contents cannot be enumerated safely.',
  'unsupported-value': 'A function, promise, or unsupported value type was skipped during normalization.',
  'circular-reference': 'A repeated object reference was skipped after its first visit.',
  'invalid-date': 'An invalid Date value was skipped.',
  'analysis-error': 'An unexpected analysis condition was reported.',
});

/** Issue codes that must make the whole analysis incomplete. */
const INCOMPLETE_CODES = new Set([
  'capture-incomplete',
  'max-records-exceeded',
  'max-total-bytes-exceeded',
  'max-findings-exceeded',
  'max-diagnostics-exceeded',
  'time-limit-exceeded',
  'invalid-utf8',
  'max-depth-exceeded',
  'max-nodes-exceeded',
  'max-record-bytes-exceeded',
  'unsupported-accessor',
  'unsupported-container',
]);

/**
 * @param {string} path
 * @param {string} ancestor
 * @returns {boolean}
 */
function isUnder(path, ancestor) {
  return (
    path === ancestor ||
    path.startsWith(`${ancestor}.`) ||
    path.startsWith(`${ancestor}[`)
  );
}

/**
 * @param {string} path
 * @returns {string[]}
 */
function ancestorPaths(path) {
  const candidates = [];
  for (let index = path.length - 1; index > 0; index -= 1) {
    const character = path[index];
    if (character === '.' || character === '[') {
      candidates.push(path.slice(0, index));
    }
  }
  return candidates;
}

/**
 * @param {unknown} value
 * @returns {boolean}
 */
function isEmptyContainer(value) {
  if (Array.isArray(value)) return value.length === 0;
  if (value instanceof Map || value instanceof Set) return value.size === 0;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return value.byteLength === 0;
  if (value instanceof Error) {
    const messageDescriptor = Object.getOwnPropertyDescriptor(value, 'message');
    const stackDescriptor = Object.getOwnPropertyDescriptor(value, 'stack');
    const message =
      messageDescriptor && 'value' in messageDescriptor ? messageDescriptor.value : undefined;
    return message === '' && stackDescriptor === undefined;
  }
  if (value === null || typeof value !== 'object') return true;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  return !Object.values(descriptors).some((descriptor) => descriptor.enumerable);
}

/**
 * @param {unknown} input
 * @returns {{value: unknown, source: string}}
 */
function unwrapCaptureRecord(input) {
  if (isPlainObject(input) && Object.hasOwn(input, 'value')) {
    return { value: input.value, source: sanitizeSourceName(input.source) };
  }
  if (input === null || input === undefined) {
    return { value: input, source: 'memory' };
  }
  return { value: input, source: 'memory' };
}

/**
 * @typedef {object} NormalizedInput
 * @property {Array<{value: unknown, source: string}>} records
 * @property {Array<{code: string, message: string}>} issues
 * @property {boolean} captureIncomplete
 */

/**
 * @param {unknown} input
 * @returns {NormalizedInput}
 */
function normalizeInput(input) {
  if (input === undefined) {
    throw new ConfigurationError(
      'analyze() requires a log record, an array of records, or a capture result.',
    );
  }

  if (Array.isArray(input)) {
    return {
      records: input.map((value) => unwrapCaptureRecord(value)),
      issues: [],
      captureIncomplete: false,
    };
  }

  if (isPlainObject(input) && Object.hasOwn(input, 'coverage')) {
    if (!Array.isArray(input.records)) {
      throw new ConfigurationError('A capture result must contain a `records` array.');
    }
    if (input.coverage !== 'complete' && input.coverage !== 'incomplete') {
      throw new ConfigurationError(
        'A capture result `coverage` must be "complete" or "incomplete".',
      );
    }
    const issues = [];
    if (Array.isArray(input.issues)) {
      for (const issue of input.issues) {
        if (isPlainObject(issue) && typeof issue.code === 'string') {
          issues.push({ code: issue.code, message: '[capture issue]' });
        }
      }
    }
    return {
      records: input.records.map((value) => unwrapCaptureRecord(value)),
      issues,
      captureIncomplete: input.coverage === 'incomplete',
    };
  }

  return {
    records: [{ value: input, source: 'memory' }],
    issues: [],
    captureIncomplete: false,
  };
}

/**
 * @param {unknown} value
 * @returns {boolean}
 */
function looksLikeJson(value) {
  return typeof value === 'string' && /^\s*[{[]/.test(value);
}

/**
 * Creates a log-leak detector.
 *
 * @param {object} [options] Validated configuration. See README.md for the
 *   complete configuration reference.
 * @returns {{
 *   analyze: (input: unknown) => object,
 *   registerSecret: (value: string) => number,
 *   dispose: () => void,
 *   getConfig: () => object,
 *   readonly secretCount: number,
 *   readonly disposed: boolean
 * }}
 */
export function createLogLeakDetector(options = {}) {
  /** @type {ResolvedConfig} */
  const config = resolveConfig(options);
  const disabledRules = new Set(config.disabledRules);
  const registry = createSecretRegistry(config.knownSecrets, {
    maxSecrets: config.limits.maxSecrets,
    maxSecretBytes: config.limits.maxSecretBytes,
    maxTotalSecretBytes: config.limits.maxTotalSecretBytes,
    minLength: config.detectors.knownSecrets.minLength,
  });
  const isPlaceholder = createPlaceholderMatcher(config.safePlaceholders);

  const fieldRulesEnabled = config.detectors.fieldNames.enabled;
  const knownSecretsEnabled = config.detectors.knownSecrets.enabled;

  const activePatterns = config.detectors.credentialPatterns.enabled
    ? COMPILED_PATTERNS.filter((rule) => !disabledRules.has(rule.id))
    : [];

  const activePersonalRules = config.detectors.personalData.enabled
    ? PERSONAL_DATA_RULES.filter((rule) => {
        if (disabledRules.has(rule.id)) return false;
        if (rule.kind === 'email') return config.detectors.personalData.email;
        if (rule.kind === 'phone') return config.detectors.personalData.phone;
        return false;
      })
    : [];

  const activeInjectionRules = config.detectors.logInjection.enabled
    ? LOG_INJECTION_RULES.filter((rule) => !disabledRules.has(rule.id))
    : [];

  /**
   * @param {import('./detectors/field-names.js').FieldRule} rule
   * @returns {boolean}
   */
  function isFieldRuleActive(rule) {
    if (disabledRules.has(rule.id)) return false;
    if (rule.requiresPersonalData && !config.detectors.personalData.enabled) return false;
    return true;
  }

  /**
   * @param {'knownSecret'|'sensitiveField'|'sensitiveFieldRedacted'|'credentialPattern'|'personalData'|'logInjection'} key
   * @returns {import('./severity.js').Severity | null}
   */
  function severityFor(key) {
    return config.severity[key] ?? null;
  }

  /**
   * Returns a privacy-safe view of the configuration. Registered secret values
   * are never included.
   *
   * @returns {object}
   */
  function getConfig() {
    return Object.freeze({
      policy: config.policy,
      failOnIncomplete: config.failOnIncomplete,
      detectors: config.detectors,
      severity: config.severity,
      limits: config.limits,
      safePlaceholders: config.safePlaceholders,
      disabledRules: config.disabledRules,
      exceptions: config.exceptions,
      knownSecretCount: registry.count,
    });
  }

  /**
   * Analyzes captured log records.
   *
   * @param {unknown} input
   * @returns {object} A frozen, privacy-safe analysis result.
   */
  function analyze(input) {
    if (registry.disposed) {
      throw new ConfigurationError(
        'The detector has been disposed. Create a new detector before analyzing logs.',
      );
    }

    const startedAt = Date.now();
    const deadline = startedAt + config.limits.timeLimitMs;
    const limits = config.limits;
    const normalized = normalizeInput(input);

    /** @type {Array<Record<string, unknown>>} */
    const findings = [];
    /** @type {Array<Record<string, unknown>>} */
    const diagnostics = [];
    /** @type {Set<string>} */
    const incompleteCodes = new Set();
    /** @type {Set<string>} */
    const findingKeys = new Set();
    /** @type {Set<string>} */
    const diagnosticKeys = new Set();
    /** @type {Array<Record<string, unknown>>} */
    let pendingContainers = [];

    let redactedFields = 0;
    let suppressedFindings = 0;
    let diagnosticsDropped = 0;
    let findingsOverflow = false;
    let totalBytes = 0;
    let recordsAnalyzed = 0;
    let stopped = false;

    const hardFindingCap = Math.max(limits.maxFindings * 10, 10);

    /**
     * @param {string} code
     * @param {string|null} path
     * @param {boolean} [forceIncomplete]
     */
    function addIssue(code, path, forceIncomplete = false) {
      const incomplete = forceIncomplete || INCOMPLETE_CODES.has(code);
      if (incomplete) incompleteCodes.add(code);
      const key = `${code}\u0000${path ?? ''}`;
      if (diagnosticKeys.has(key)) return;
      if (diagnostics.length >= limits.maxDiagnostics) {
        diagnosticsDropped += 1;
        incompleteCodes.add('max-diagnostics-exceeded');
        return;
      }
      diagnosticKeys.add(key);
      diagnostics.push(
        Object.freeze({
          code,
          message: DIAGNOSTIC_MESSAGES[code] ?? DIAGNOSTIC_MESSAGES['analysis-error'],
          path: path ?? null,
          incomplete,
        }),
      );
    }

    /**
     * @param {object} draft
     */
    function pushFinding(draft) {
      const key = [
        draft.recordIndex,
        draft.detector,
        draft.ruleId,
        draft.path,
        draft.reference ?? '',
      ].join('\u0000');
      if (findingKeys.has(key)) return;
      findingKeys.add(key);
      if (findings.length >= hardFindingCap) {
        findingsOverflow = true;
        return;
      }
      findings.push(Object.freeze({ ...draft }));
    }

    /**
     * @param {string} text
     * @param {string} path
     * @param {'value'|'key'|'raw-text'} kind
     * @param {number} recordIndex
     * @param {string} source
     */
    function scanText(text, path, kind, recordIndex, source) {
      if (text.length === 0) return;
      const scope = kind === 'key' ? 'field-name' : kind === 'raw-text' ? 'record-text' : 'field';

      if (knownSecretsEnabled) {
        const matches = registry.findMatches(text);
        for (const secretIndex of matches) {
          pushFinding({
            detector: 'known-secret',
            ruleId: 'known-secret',
            category: 'credentials',
            severity: severityFor('knownSecret') ?? 'critical',
            confidence: 'high',
            evidence: EVIDENCE.knownSecret,
            recordIndex,
            source,
            path,
            scope,
            redacted: false,
            reference: `secret-${secretIndex + 1}`,
            message: 'A registered synthetic secret appeared in log output.',
            remediation:
              'Remove the value from the emitted log. If this was a real credential, treat it as exposed and rotate it.',
          });
        }
      }

      for (const rule of activePatterns) {
        if (!rule.regex.test(text)) continue;
        pushFinding({
          detector: 'credential-pattern',
          ruleId: rule.id,
          category: rule.category,
          severity: severityFor('credentialPattern') ?? rule.severity,
          confidence: rule.confidence,
          evidence: EVIDENCE.credentialPattern,
          recordIndex,
          source,
          path,
          scope,
          redacted: false,
          message: rule.message,
          remediation: rule.remediation,
        });
      }

      for (const rule of activePersonalRules) {
        if (!rule.regex.test(text)) continue;
        pushFinding({
          detector: 'personal-data',
          ruleId: rule.id,
          category: rule.category,
          severity: severityFor('personalData') ?? rule.severity,
          confidence: rule.confidence,
          evidence: EVIDENCE.personalData,
          recordIndex,
          source,
          path,
          scope,
          redacted: false,
          message: rule.message,
          remediation: rule.remediation,
        });
      }

      for (const rule of activeInjectionRules) {
        if (!rule.regex.test(text)) continue;
        pushFinding({
          detector: 'log-injection',
          ruleId: rule.id,
          category: rule.category,
          severity: severityFor('logInjection') ?? rule.severity,
          confidence: rule.confidence,
          evidence: EVIDENCE.logInjection,
          recordIndex,
          source,
          path,
          scope,
          redacted: false,
          message: rule.message,
          remediation: rule.remediation,
        });
      }
    }

    /**
     * Marks a sensitive field whose value matched a documented placeholder.
     *
     * @param {import('./detectors/field-names.js').FieldRule} rule
     * @param {number} recordIndex
     * @param {string} source
     * @param {string} path
     */
    function handleRedactedField(rule, recordIndex, source, path) {
      if (config.detectors.fieldNames.allowRedactedValues) {
        redactedFields += 1;
        return;
      }
      pushFinding({
        detector: 'sensitive-field',
        ruleId: rule.id,
        category: rule.category,
        severity: severityFor('sensitiveFieldRedacted') ?? 'low',
        confidence: rule.confidence,
        evidence: EVIDENCE.sensitiveField,
        recordIndex,
        source,
        path,
        scope: 'field',
        redacted: true,
        message: 'A sensitive field name was present even though its value was redacted.',
        remediation:
          'Remove the sensitive field name from output, or relax detectors.fieldNames.allowRedactedValues if a redacted field is acceptable.',
      });
    }

    /**
     * @param {import('./detectors/field-names.js').FieldRule} rule
     * @param {number} recordIndex
     * @param {string} source
     * @param {string} path
     */
    function handleSensitiveField(rule, recordIndex, source, path) {
      pushFinding({
        detector: 'sensitive-field',
        ruleId: rule.id,
        category: rule.category,
        severity: severityFor('sensitiveField') ?? rule.severity,
        confidence: rule.confidence,
        evidence: EVIDENCE.sensitiveField,
        recordIndex,
        source,
        path,
        scope: 'field',
        redacted: false,
        message: rule.message,
        remediation: rule.remediation,
      });
    }

    /**
     * @param {import('./normalize.js').PropertyEvent} event
     * @param {number} recordIndex
     * @param {string} source
     */
    function handleProperty(event, recordIndex, source) {
      if (!fieldRulesEnabled) return;
      const rule = fieldIndex.lookup(event.key);
      if (!rule || !isFieldRuleActive(rule)) return;

      const value = event.value;
      if (value === null || value === undefined) return;
      if (typeof value === 'boolean' || typeof value === 'symbol') return;
      if (typeof value === 'function') return;

      if (typeof value === 'string') {
        if (isBlank(value)) return;
        if (isPlaceholder(value)) {
          handleRedactedField(rule, recordIndex, source, event.path);
          return;
        }
        handleSensitiveField(rule, recordIndex, source, event.path);
        return;
      }

      if (typeof value === 'object') {
        if (isEmptyContainer(value)) return;
        pendingContainers.push({
          rule,
          recordIndex,
          source,
          path: event.path,
          sawLeaf: false,
          sawUnsafeLeaf: false,
        });
        return;
      }

      if (typeof value === 'number' || typeof value === 'bigint') {
        handleSensitiveField(rule, recordIndex, source, event.path);
      }
    }

    /**
     * Detects structured header name/value pairs such as
     * `[{ name: "authorization", value: "..." }]`.
     *
     * @param {import('./normalize.js').ContainerEvent} event
     * @param {number} recordIndex
     * @param {string} source
     */
    function handleContainer(event, recordIndex, source) {
      if (!fieldRulesEnabled) return;
      const nameEntry = event.entries.find(
        (entry) => entry.key === 'name' || entry.key === 'key' || entry.key === 'header',
      );
      if (!nameEntry || typeof nameEntry.value !== 'string') return;
      const rule = fieldIndex.lookup(nameEntry.value);
      if (!rule || !isFieldRuleActive(rule)) return;

      const valueEntry = event.entries.find(
        (entry) => entry.key === 'value' || entry.key === 'values',
      );
      if (!valueEntry) return;

      const value = valueEntry.value;
      if (value === null || value === undefined) return;
      if (typeof value === 'boolean' || typeof value === 'symbol' || typeof value === 'function') {
        return;
      }
      const valuePath = appendKey(event.path, sanitizeSegment(valueEntry.key));
      if (typeof value === 'string') {
        if (isBlank(value)) return;
        if (isPlaceholder(value)) {
          handleRedactedField(rule, recordIndex, source, valuePath);
          return;
        }
      } else if (typeof value === 'object' && isEmptyContainer(value)) {
        return;
      }

      pushFinding({
        detector: 'sensitive-field',
        ruleId: rule.id,
        category: rule.category,
        severity: severityFor('sensitiveField') ?? rule.severity,
        confidence: 'medium',
        evidence: EVIDENCE.sensitiveField,
        recordIndex,
        source,
        path: valuePath,
        scope: 'field',
        redacted: false,
        message: 'A sensitive header name appears in a structured name/value pair.',
        remediation: rule.remediation,
      });
    }

    /**
     * @param {unknown} root
     * @param {number} recordIndex
     * @param {string} source
     * @param {number} maxEstimatedBytes
     */
    function walkStructured(root, recordIndex, source, maxEstimatedBytes) {
      pendingContainers = [];
      const walk = walkValue(root, {
        maxDepth: limits.maxDepth,
        maxNodes: limits.maxNodesPerRecord,
        maxEstimatedBytes,
        deadline,
        safeKey(key) {
          const segment = sanitizeSegment(key);
          const sensitiveKey =
            knownSecretsEnabled && registry.findMatches(key).length > 0
              ? true
              : activePatterns.some((rule) => rule.regex.test(key));
          return sensitiveKey ? '[redacted-key]' : segment;
        },
        onProperty(event) {
          handleProperty(event, recordIndex, source);
        },
        onText(event) {
          if (pendingContainers.length > 0) {
            for (const pending of pendingContainers) {
              if (event.kind !== 'value') continue;
              if (!isUnder(event.path, /** @type {string} */ (pending.path))) continue;
              pending.sawLeaf = true;
              if (isBlank(event.text) || isPlaceholder(event.text)) continue;
              pending.sawUnsafeLeaf = true;
            }
          }
          scanText(event.text, event.path, event.kind, recordIndex, source);
        },
        onContainer(event) {
          handleContainer(event, recordIndex, source);
        },
        onIssue(issue) {
          addIssue(issue.code, issue.path, issue.incomplete);
        },
      });

      for (const pending of pendingContainers) {
        if (!pending.sawLeaf) continue;
        if (pending.sawUnsafeLeaf) {
          handleSensitiveField(
            /** @type {import('./detectors/field-names.js').FieldRule} */ (pending.rule),
            recordIndex,
            source,
            /** @type {string} */ (pending.path),
          );
        } else {
          handleRedactedField(
            /** @type {import('./detectors/field-names.js').FieldRule} */ (pending.rule),
            recordIndex,
            source,
            /** @type {string} */ (pending.path),
          );
        }
      }
      pendingContainers = [];
      return walk.estimatedBytes;
    }

    /**
     * @param {{value: unknown, source: string}} record
     * @param {number} recordIndex
     * @returns {boolean} False when analysis must stop because the total byte
     *   budget is exhausted.
     */
    function analyzeRecord(record, recordIndex) {
      const source = record.source;
      const value = record.value;
      const remaining = limits.maxTotalBytes - totalBytes;
      if (remaining <= 0) {
        addIssue('max-total-bytes-exceeded', null, true);
        return false;
      }

      let text = null;
      if (typeof value === 'string') {
        text = value;
      } else if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
        const decoded = decodeBytes(value);
        if (decoded.lossy) addIssue('invalid-utf8', '$', true);
        text = decoded.text;
      }

      if (text !== null) {
        const bytes = byteLength(text);
        if (bytes > limits.maxRecordBytes) {
          addIssue('max-record-bytes-exceeded', '$', true);
          totalBytes += Math.min(bytes, remaining);
          return true;
        }
        if (bytes > remaining) {
          addIssue('max-total-bytes-exceeded', null, true);
          return false;
        }
        totalBytes += bytes;
        recordsAnalyzed += 1;

        if (looksLikeJson(text)) {
          let parsed;
          let parsedOk = false;
          try {
            parsed = JSON.parse(text);
            parsedOk = true;
          } catch {
            addIssue('invalid-json', '$');
          }
          if (parsedOk && parsed !== null && typeof parsed === 'object') {
            walkStructured(parsed, recordIndex, source, limits.maxRecordBytes);
            return true;
          }
        }
        scanText(text, '$', 'raw-text', recordIndex, source);
        return true;
      }

      if (value !== null && typeof value === 'object') {
        recordsAnalyzed += 1;
        const estimated = walkStructured(
          value,
          recordIndex,
          source,
          Math.min(limits.maxRecordBytes, remaining),
        );
        totalBytes += Math.min(estimated, remaining);
        return true;
      }

      if (typeof value === 'number' || typeof value === 'bigint') {
        recordsAnalyzed += 1;
        scanText(String(value), '$', 'raw-text', recordIndex, source);
        totalBytes += Math.min(String(value).length, remaining);
        return true;
      }

      recordsAnalyzed += 1;
      return true;
    }

    for (const issue of normalized.issues) {
      addIssue(
        CAPTURE_MESSAGES[issue.code] ? issue.code : 'capture-incomplete',
        null,
        true,
      );
    }
    if (normalized.captureIncomplete) {
      addIssue('capture-incomplete', null, true);
    }

    const records = normalized.records.slice(0, limits.maxRecords);
    if (normalized.records.length > limits.maxRecords) {
      addIssue('max-records-exceeded', null, true);
    }
    if (records.length === 0) {
      addIssue('no-records', null);
    }

    for (let index = 0; index < records.length; index += 1) {
      if (Date.now() > deadline) {
        addIssue('time-limit-exceeded', null, true);
        stopped = true;
        break;
      }
      const keepGoing = analyzeRecord(records[index], index);
      if (!keepGoing) {
        stopped = true;
        break;
      }
    }

    if (!stopped) {
      for (const pending of pendingContainers) {
        // Defensive: pending containers are resolved per record, but do not
        // leave unprocessed state if a future code path returns early.
        if (!pending.sawLeaf) continue;
        if (pending.sawUnsafeLeaf) {
          handleSensitiveField(
            /** @type {import('./detectors/field-names.js').FieldRule} */ (pending.rule),
            /** @type {number} */ (pending.recordIndex),
            /** @type {string} */ (pending.source),
            /** @type {string} */ (pending.path),
          );
        }
      }
    }

    // ---- Post-processing -------------------------------------------------

    /**
     * @type {Array<Record<string, unknown>>}
     */
    let processed = findings.slice();

    // Prefer the most specific field-name finding: drop a sensitive-field
    // finding when a descendant sensitive field was also found in the same
    // record.
    const fieldKeep = new Map();
    const fieldPathsByRecord = new Map();
    const fieldSorted = processed
      .filter((finding) => finding.detector === 'sensitive-field')
      .sort((left, right) => {
        const leftPath = /** @type {string} */ (left.path);
        const rightPath = /** @type {string} */ (right.path);
        if (left.recordIndex !== right.recordIndex) {
          return /** @type {number} */ (left.recordIndex) - /** @type {number} */ (right.recordIndex);
        }
        return leftPath.length - rightPath.length;
      });

    for (const finding of fieldSorted) {
      const recordIndex = /** @type {number} */ (finding.recordIndex);
      const path = /** @type {string} */ (finding.path);
      let paths = fieldPathsByRecord.get(recordIndex);
      if (!paths) {
        paths = new Set();
        fieldPathsByRecord.set(recordIndex, paths);
      }
      paths.add(path);
      fieldKeep.set(`${recordIndex}\u0000${path}`, finding);
    }

    /** @type {Set<string>} */
    const droppedFieldKeys = new Set();
    for (const [recordIndex, paths] of fieldPathsByRecord) {
      for (const path of paths) {
        for (const candidate of ancestorPaths(path)) {
          if (paths.has(candidate)) {
            droppedFieldKeys.add(`${recordIndex}\u0000${candidate}`);
            break;
          }
        }
      }
    }

    /** @type {Map<number, Set<string>>} */
    const keptFieldPaths = new Map();
    for (const [key, finding] of fieldKeep) {
      if (droppedFieldKeys.has(key)) continue;
      const recordIndex = /** @type {number} */ (finding.recordIndex);
      let paths = keptFieldPaths.get(recordIndex);
      if (!paths) {
        paths = new Set();
        keptFieldPaths.set(recordIndex, paths);
      }
      paths.add(/** @type {string} */ (finding.path));
    }

    processed = processed.filter((finding) => {
      const recordIndex = /** @type {number} */ (finding.recordIndex);
      const path = /** @type {string} */ (finding.path);
      if (finding.detector === 'sensitive-field') {
        return !droppedFieldKeys.has(`${recordIndex}\u0000${path}`);
      }
      if (finding.detector === 'known-secret') return true;
      const paths = keptFieldPaths.get(recordIndex);
      if (!paths) return true;
      if (paths.has(path)) return false;
      return !ancestorPaths(path).some((candidate) => paths.has(candidate));
    });

    // Narrow, explicitly configured exceptions. Known-secret findings are
    // never suppressible and are not matched here.
    if (config.exceptions.length > 0) {
      processed = processed.filter((finding) => {
        if (finding.detector === 'known-secret') return true;
        const matched = config.exceptions.some((exception) => {
          if (exception.detector !== finding.detector) return false;
          if (exception.ruleId && exception.ruleId !== finding.ruleId) return false;
          if (exception.path && exception.path !== finding.path) return false;
          if (
            exception.recordIndex !== undefined &&
            exception.recordIndex !== finding.recordIndex
          ) {
            return false;
          }
          return true;
        });
        if (matched) suppressedFindings += 1;
        return !matched;
      });
    }

    if (findingsOverflow) {
      addIssue('max-findings-exceeded', null, true);
    }
    if (processed.length > limits.maxFindings) {
      processed = processed.slice(0, limits.maxFindings);
      addIssue('max-findings-exceeded', null, true);
    }
    if (diagnosticsDropped > 0) {
      incompleteCodes.add('max-diagnostics-exceeded');
    }

    processed.sort((left, right) => {
      const leftRecord = /** @type {number} */ (left.recordIndex);
      const rightRecord = /** @type {number} */ (right.recordIndex);
      if (leftRecord !== rightRecord) return leftRecord - rightRecord;
      const severityDelta =
        SEVERITY_RANK[/** @type {import('./severity.js').Severity} */ (right.severity)] -
        SEVERITY_RANK[/** @type {import('./severity.js').Severity} */ (left.severity)];
      if (severityDelta !== 0) return severityDelta;
      const leftPath = /** @type {string} */ (left.path);
      const rightPath = /** @type {string} */ (right.path);
      if (leftPath !== rightPath) return leftPath < rightPath ? -1 : 1;
      return String(left.ruleId) < String(right.ruleId) ? -1 : 1;
    });

    const finalizedFindings = processed.map((finding) => {
      const id = makeFindingId([
        String(finding.detector),
        String(finding.ruleId),
        String(finding.recordIndex),
        String(finding.path),
        String(finding.reference ?? ''),
        String(finding.redacted ?? false),
      ]);
      return Object.freeze({ id, ...finding });
    });

    const bySeverity = { low: 0, medium: 0, high: 0, critical: 0 };
    const byDetector = Object.fromEntries(DETECTOR_NAMES.map((name) => [name, 0]));
    for (const finding of finalizedFindings) {
      bySeverity[/** @type {keyof bySeverity} */ (finding.severity)] += 1;
      byDetector[/** @type {keyof byDetector} */ (finding.detector)] += 1;
    }

    const coverageComplete = incompleteCodes.size === 0;
    const status =
      finalizedFindings.length > 0
        ? 'leaks'
        : coverageComplete
          ? 'pass'
          : 'incomplete';
    const exitCode =
      finalizedFindings.length > 0
        ? EXIT_CODES.LEAKS
        : coverageComplete
          ? EXIT_CODES.OK
          : EXIT_CODES.INCOMPLETE;

    const result = deepFreeze({
      tool: LIBRARY_NAME,
      version: LIBRARY_VERSION,
      schemaVersion: REPORT_SCHEMA_VERSION,
      status,
      exitCode,
      policy: config.policy,
      coverage: coverageComplete ? 'complete' : 'incomplete',
      failOnIncomplete: config.failOnIncomplete,
      findings: finalizedFindings,
      diagnostics,
      summary: {
        recordsAnalyzed,
        bytesAnalyzed: totalBytes,
        findings: {
          total: finalizedFindings.length,
          bySeverity,
          byDetector,
        },
        suppressedFindings,
        redactedFields,
        incompleteReasons: [...incompleteCodes].sort(),
        diagnosticsDropped,
        limits,
        durationMs: Date.now() - startedAt,
      },
    });

    return result;
  }

  /**
   * @param {string} value
   * @returns {number} Number of registered secrets after the addition.
   */
  function registerSecret(value) {
    registry.add(value);
    return registry.count;
  }

  return Object.freeze({
    analyze,
    registerSecret,
    getConfig,
    dispose() {
      registry.dispose();
    },
    get secretCount() {
      return registry.count;
    },
    get disposed() {
      return registry.disposed;
    },
  });
}

/**
 * Returns the stable rule ids shipped with this version. Useful for building
 * `disabledRules` and exception configuration.
 *
 * @returns {{fieldNames: readonly string[], credentialPatterns: readonly string[], personalData: readonly string[], logInjection: readonly string[]}}
 */
export function listDetectorRules() {
  return RULE_IDS;
}

/** Exposed for tests that verify catalog consistency. */
export { ALL_RULE_IDS };
