/**
 * Bounded, side-effect-aware normalization of log records.
 *
 * The walker never invokes caller-defined getters, never calls `toJSON`,
 * `toString`, or `inspect`, and never mutates the input. It traverses:
 *
 * - strings, numbers, booleans, bigints, symbols
 * - plain objects and arrays (own enumerable string-keyed data properties)
 * - Error objects (message, stack, cause, AggregateError errors, custom
 *   enumerable properties)
 * - Map and Set containers
 * - Date, URL, Buffer and Uint8Array values
 *
 * Unsupported or unsafe constructs are reported as diagnostics. Limits that
 * prevent the walker from inspecting data mark the analysis incomplete.
 *
 * @module normalize
 */

import { decodeBytes } from './text.js';
import { appendIndex, appendKey } from './privacy.js';

/**
 * @typedef {object} WalkIssue
 * @property {string} code
 * @property {string} message
 * @property {string|null} path
 * @property {boolean} incomplete
 */

/**
 * @typedef {object} PropertyEvent
 * @property {string} key
 * @property {string} path
 * @property {unknown} value
 * @property {number} depth
 * @property {string} containerType
 */

/**
 * @typedef {object} TextEvent
 * @property {string} path
 * @property {string} key
 * @property {string} text
 * @property {'value'|'key'|'raw-text'} kind
 * @property {string} valueType
 */

/**
 * @typedef {object} ContainerEvent
 * @property {string} path
 * @property {string} containerType
 * @property {Array<{key: string, value: unknown}>} entries
 */

/**
 * @typedef {object} WalkOptions
 * @property {number} maxDepth
 * @property {number} maxNodes
 * @property {number} maxEstimatedBytes
 * @property {number} deadline Epoch milliseconds; Date.now() beyond this
 *   aborts the walk.
 * @property {(key: string) => string} safeKey Returns a path-safe segment,
 *   possibly redacted by the caller.
 * @property {(event: PropertyEvent) => void} onProperty
 * @property {(event: TextEvent) => void} onText
 * @property {(event: ContainerEvent) => void} onContainer
 * @property {(issue: WalkIssue) => void} onIssue
 */

const INCOMPLETE_ISSUES = new Set([
  'max-depth-exceeded',
  'max-nodes-exceeded',
  'max-record-bytes-exceeded',
  'time-limit-exceeded',
  'unsupported-accessor',
  'unsupported-container',
  'invalid-utf8',
]);

class BudgetError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(code);
    this.code = code;
  }
}

/**
 * @param {string} code
 * @returns {string}
 */
function issueMessage(code) {
  switch (code) {
    case 'max-depth-exceeded':
      return 'Maximum structured-record depth was reached; deeper values were not inspected.';
    case 'max-nodes-exceeded':
      return 'Maximum number of visited record nodes was reached; the remainder was not inspected.';
    case 'max-record-bytes-exceeded':
      return 'Maximum estimated record size was reached; the remainder was not inspected.';
    case 'time-limit-exceeded':
      return 'The analysis time limit was reached; the remainder of the record was not inspected.';
    case 'unsupported-accessor':
      return 'An accessor property (getter/setter) was skipped to avoid executing caller code; its value was not inspected.';
    case 'unsupported-container':
      return 'A WeakMap or WeakSet was skipped because its contents cannot be enumerated safely.';
    case 'invalid-utf8':
      return 'Invalid UTF-8 was replaced while decoding; the decoded text may be incomplete.';
    case 'circular-reference':
      return 'A repeated object reference was skipped after its first visit.';
    case 'unsupported-value':
      return 'A function, promise, or unsupported value type was skipped during normalization.';
    case 'invalid-date':
      return 'An invalid Date value was skipped.';
    default:
      return 'A normalization condition was reported.';
  }
}

/**
 * @param {WalkOptions} options
 * @returns {{nodes: number, estimatedBytes: number}}
 */
export function walkValue(root, options) {
  const {
    maxDepth,
    maxNodes,
    maxEstimatedBytes,
    deadline,
    safeKey,
    onProperty,
    onText,
    onContainer,
    onIssue,
  } = options;

  let nodes = 0;
  let estimatedBytes = 0;
  let aborted = false;
  const seen = new WeakSet();

  /**
   * @param {string} code
   * @param {string|null} path
   */
  function reportIssue(code, path) {
    onIssue({
      code,
      message: issueMessage(code),
      path,
      incomplete: INCOMPLETE_ISSUES.has(code),
    });
  }

  function bump() {
    nodes += 1;
    if (nodes > maxNodes) throw new BudgetError('max-nodes-exceeded');
    if ((nodes & 255) === 0 && Date.now() > deadline) {
      throw new BudgetError('time-limit-exceeded');
    }
  }

  /**
   * @param {number} amount
   */
  function addBytes(amount) {
    estimatedBytes += amount;
    if (estimatedBytes > maxEstimatedBytes) {
      throw new BudgetError('max-record-bytes-exceeded');
    }
  }

  /**
   * @param {string} key
   * @param {string} path
   * @param {number} depth
   * @param {string} containerType
   * @param {unknown} value
   */
  function emitProperty(key, path, depth, containerType, value) {
    bump();
    addBytes(Buffer.byteLength(key, 'utf8') + 4);
    onText({ path, key, text: key, kind: 'key', valueType: 'string' });
    onProperty({ key, path, value, depth, containerType });
    visit(value, path, key, depth + 1);
  }

  /**
   * @param {Record<PropertyKey, PropertyDescriptor>} descriptors
   * @param {string} path
   * @param {number} depth
   * @param {string} containerType
   * @param {boolean} onlyEnumerable
   */
  function emitDescriptors(descriptors, path, depth, containerType, onlyEnumerable) {
    for (const key of Object.keys(descriptors)) {
      const descriptor = descriptors[key];
      if (onlyEnumerable && !descriptor.enumerable) continue;
      if (descriptor.get || descriptor.set) {
        reportIssue('unsupported-accessor', appendKey(path, safeKey(key)));
        continue;
      }
      const childPath = appendKey(path, safeKey(key));
      emitProperty(key, childPath, depth, containerType, descriptor.value);
    }
  }

  /**
   * @param {object} object
   * @param {string} path
   * @param {number} depth
   */
  function visitPlainObject(object, path, depth) {
    const descriptors = Object.getOwnPropertyDescriptors(object);
    /** @type {Array<{key: string, value: unknown}>} */
    const entries = [];
    for (const key of Object.keys(descriptors)) {
      const descriptor = descriptors[key];
      if (!descriptor.enumerable) continue;
      if (descriptor.get || descriptor.set) continue;
      entries.push({ key, value: descriptor.value });
    }
    onContainer({ path, containerType: 'object', entries });
    emitDescriptors(descriptors, path, depth, 'object', true);
  }

  /**
   * @param {unknown[]} array
   * @param {string} path
   * @param {number} depth
   */
  function visitArray(array, path, depth) {
    const descriptors = Object.getOwnPropertyDescriptors(array);
    for (const key of Object.keys(descriptors)) {
      if (key === 'length') continue;
      const descriptor = descriptors[key];
      if (!descriptor.enumerable) continue;
      if (descriptor.get || descriptor.set) {
        reportIssue('unsupported-accessor', appendKey(path, safeKey(key)));
        continue;
      }
      const childPath = /^\d+$/.test(key)
        ? appendIndex(path, Number(key))
        : appendKey(path, safeKey(key));
      emitProperty(key, childPath, depth, 'array', descriptor.value);
    }
  }

  /**
   * @param {Error} error
   * @param {string} path
   * @param {number} depth
   */
  function visitError(error, path, depth) {
    const handled = new Set(['message', 'stack', 'cause', 'errors']);
    const nameDescriptor =
      Object.getOwnPropertyDescriptor(error, 'name') ??
      Object.getOwnPropertyDescriptor(Object.getPrototypeOf(error) ?? {}, 'name');
    if (nameDescriptor && 'value' in nameDescriptor && typeof nameDescriptor.value === 'string') {
      const namePath = appendKey(path, safeKey('name'));
      onText({ path: namePath, key: 'name', text: nameDescriptor.value, kind: 'value', valueType: 'string' });
    }

    for (const key of ['message', 'stack', 'cause', 'errors']) {
      const descriptor = Object.getOwnPropertyDescriptor(error, key);
      if (!descriptor) continue;
      const childPath = appendKey(path, safeKey(key));
      if (descriptor.get || descriptor.set) {
        if (key === 'stack') {
          // V8 exposes `stack` as an own accessor. Reading it is the documented
          // way to obtain a stack trace and mirrors what loggers do. It may run
          // a customized Error.prepareStackTrace hook; see the security model.
          let stack;
          try {
            stack = /** @type {{stack?: unknown}} */ (error).stack;
          } catch {
            reportIssue('unsupported-accessor', childPath);
            continue;
          }
          if (typeof stack === 'string') {
            emitProperty(key, childPath, depth, 'error', stack);
          }
          continue;
        }
        reportIssue('unsupported-accessor', childPath);
        continue;
      }
      emitProperty(key, childPath, depth, 'error', descriptor.value);
    }

    const descriptors = Object.getOwnPropertyDescriptors(error);
    for (const key of Object.keys(descriptors)) {
      if (handled.has(key) || !descriptors[key].enumerable) continue;
      const descriptor = descriptors[key];
      if (descriptor.get || descriptor.set) {
        reportIssue('unsupported-accessor', appendKey(path, safeKey(key)));
        continue;
      }
      emitProperty(key, appendKey(path, safeKey(key)), depth, 'error', descriptor.value);
    }
  }

  /**
   * @param {Map<unknown, unknown>} map
   * @param {string} path
   * @param {number} depth
   */
  function visitMap(map, path, depth) {
    let index = 0;
    for (const [mapKey, mapValue] of map) {
      bump();
      const entryPath = appendIndex(path, index);
      let keyText;
      if (typeof mapKey === 'string') keyText = mapKey;
      else if (typeof mapKey === 'number' || typeof mapKey === 'bigint') keyText = String(mapKey);
      else keyText = '[non-primitive-key]';
      onText({
        path: appendKey(entryPath, 'key'),
        key: 'key',
        text: keyText,
        kind: 'key',
        valueType: typeof mapKey,
      });
      const valuePath = appendKey(entryPath, 'value');
      onProperty({
        key: keyText,
        path: valuePath,
        value: mapValue,
        depth,
        containerType: 'map',
      });
      visit(mapValue, valuePath, keyText, depth + 1);
      index += 1;
    }
  }

  /**
   * @param {Set<unknown>} set
   * @param {string} path
   * @param {number} depth
   */
  function visitSet(set, path, depth) {
    let index = 0;
    for (const item of set) {
      bump();
      visit(item, appendIndex(path, index), String(index), depth + 1);
      index += 1;
    }
  }

  /**
   * @param {unknown} value
   * @param {string} path
   * @param {string} key
   * @param {number} depth
   */
  function visit(value, path, key, depth) {
    bump();
    if (value === null || value === undefined) return;

    const type = typeof value;

    if (type === 'string') {
      addBytes(Buffer.byteLength(/** @type {string} */ (value), 'utf8'));
      onText({ path, key, text: /** @type {string} */ (value), kind: 'value', valueType: 'string' });
      return;
    }
    if (type === 'number' || type === 'bigint') {
      const text = String(value);
      addBytes(text.length);
      onText({ path, key, text, kind: 'value', valueType: type });
      return;
    }
    if (type === 'boolean') return;
    if (type === 'symbol') {
      onText({ path, key, text: String(value), kind: 'value', valueType: 'symbol' });
      return;
    }
    if (type === 'function') {
      reportIssue('unsupported-value', path);
      return;
    }
    if (type !== 'object') return;

    const object = /** @type {object} */ (value);

    if (seen.has(object)) {
      reportIssue('circular-reference', path);
      return;
    }
    seen.add(object);

    if (Buffer.isBuffer(object) || object instanceof Uint8Array) {
      const bytes = /** @type {Uint8Array} */ (object);
      const decoded = decodeBytes(bytes);
      if (decoded.lossy) reportIssue('invalid-utf8', path);
      addBytes(bytes.byteLength);
      onText({ path, key, text: decoded.text, kind: 'value', valueType: 'bytes' });
      return;
    }

    if (object instanceof Date) {
      const time = object.getTime();
      if (Number.isNaN(time)) {
        reportIssue('invalid-date', path);
        return;
      }
      const text = object.toISOString();
      addBytes(text.length);
      onText({ path, key, text, kind: 'value', valueType: 'date' });
      return;
    }

    if (object instanceof URL) {
      /** @type {string} */
      let href;
      try {
        href = object.href;
      } catch {
        reportIssue('unsupported-value', path);
        return;
      }
      addBytes(href.length);
      onText({ path, key, text: href, kind: 'value', valueType: 'url' });
      return;
    }

    if (object instanceof Error) {
      const descriptors = Object.getOwnPropertyDescriptors(object);
      /** @type {Array<{key: string, value: unknown}>} */
      const entries = [];
      for (const entryKey of Object.keys(descriptors)) {
        const descriptor = descriptors[entryKey];
        if (descriptor.enumerable && !descriptor.get && !descriptor.set) {
          entries.push({ key: entryKey, value: descriptor.value });
        }
      }
      onContainer({ path, containerType: 'error', entries });
      if (depth >= maxDepth) {
        reportIssue('max-depth-exceeded', path);
        return;
      }
      visitError(object, path, depth);
      return;
    }

    if (object instanceof Map) {
      if (depth >= maxDepth) {
        reportIssue('max-depth-exceeded', path);
        return;
      }
      visitMap(object, path, depth);
      return;
    }

    if (object instanceof Set) {
      if (depth >= maxDepth) {
        reportIssue('max-depth-exceeded', path);
        return;
      }
      visitSet(object, path, depth);
      return;
    }

    if (object instanceof WeakMap || object instanceof WeakSet) {
      reportIssue('unsupported-container', path);
      return;
    }

    if (object instanceof Promise) {
      reportIssue('unsupported-value', path);
      return;
    }

    if (object instanceof RegExp) {
      reportIssue('unsupported-value', path);
      return;
    }

    if (ArrayBuffer.isView(object)) {
      reportIssue('unsupported-value', path);
      return;
    }

    if (depth >= maxDepth) {
      reportIssue('max-depth-exceeded', path);
      return;
    }

    if (Array.isArray(object)) {
      visitArray(object, path, depth);
      return;
    }

    visitPlainObject(object, path, depth);
  }

  try {
    visit(root, '$', '', 0);
  } catch (error) {
    if (error instanceof BudgetError) {
      aborted = true;
      reportIssue(error.code, null);
    } else {
      throw error;
    }
  }

  return { nodes, estimatedBytes, aborted };
}
