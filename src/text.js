/**
 * Text decoding helpers with explicit handling of malformed UTF-8.
 *
 * @module text
 */

const fatalDecoder = new TextDecoder('utf-8', { fatal: true });
const lossyDecoder = new TextDecoder('utf-8', { fatal: false });

/**
 * @typedef {object} DecodedText
 * @property {string} text
 * @property {boolean} lossy True when invalid UTF-8 sequences were replaced.
 */

/**
 * Decodes bytes as UTF-8. Invalid sequences are replaced with U+FFFD and
 * reported through `lossy` so the caller can mark the analysis incomplete.
 *
 * @param {Uint8Array} bytes
 * @returns {DecodedText}
 */
export function decodeBytes(bytes) {
  try {
    return { text: fatalDecoder.decode(bytes), lossy: false };
  } catch {
    return { text: lossyDecoder.decode(bytes), lossy: true };
  }
}

/**
 * @param {string} text
 * @returns {number} UTF-8 byte length.
 */
export function byteLength(text) {
  return Buffer.byteLength(text, 'utf8');
}

/**
 * @param {string} text
 * @returns {boolean}
 */
export function isBlank(text) {
  return text.trim().length === 0;
}
