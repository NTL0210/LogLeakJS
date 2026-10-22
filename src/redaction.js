/**
 * Redaction-placeholder recognition.
 *
 * A sensitive field whose value is a recognized placeholder is not treated as
 * a value leak by default. Recognition is deliberately narrow: exact matches
 * against a short list, an explicitly configured placeholder, or a value made
 * entirely of asterisks. Arbitrary strings such as `***abc***` are NOT
 * considered safe.
 *
 * @module redaction
 */

/** Built-in placeholders, compared after trimming, quote stripping, and lowercasing. */
export const BUILTIN_PLACEHOLDERS = Object.freeze([
  '[redacted]',
  '<redacted>',
  'redacted',
  'redacted!',
  '[secure]',
  '<secure>',
  'secure',
  '[hidden]',
  '<hidden>',
  '[masked]',
  '<masked>',
  'masked',
  '[filtered]',
  '<filtered>',
  '[censored]',
  '<censored>',
  '[removed]',
  '<removed>',
  '[sensitive]',
  '<sensitive>',
]);

/**
 * @param {string} value
 * @returns {string}
 */
export function normalizePlaceholder(value) {
  let normalized = value.trim();
  if (
    normalized.length >= 2 &&
    ((normalized.startsWith('"') && normalized.endsWith('"')) ||
      (normalized.startsWith("'") && normalized.endsWith("'")))
  ) {
    normalized = normalized.slice(1, -1).trim();
  }
  return normalized.toLowerCase();
}

/**
 * @param {string} value
 * @returns {boolean}
 */
export function isAsteriskPlaceholder(value) {
  return /^\*{3,}$/.test(value.trim());
}

/**
 * Builds a matcher for safe placeholder values.
 *
 * @param {readonly string[]} [extraPlaceholders] Application-configured
 *   placeholders. Matching is exact and case-insensitive.
 * @returns {(value: unknown) => boolean}
 */
export function createPlaceholderMatcher(extraPlaceholders = []) {
  const placeholders = new Set(BUILTIN_PLACEHOLDERS);
  for (const placeholder of extraPlaceholders) {
    placeholders.add(normalizePlaceholder(placeholder));
  }

  return function isPlaceholder(value) {
    if (typeof value !== 'string') return false;
    const normalized = normalizePlaceholder(value);
    if (normalized.length === 0) return false;
    if (placeholders.has(normalized)) return true;
    return isAsteriskPlaceholder(normalized);
  };
}
