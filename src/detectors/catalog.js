/**
 * Aggregated rule catalog. Used to validate `disabledRules` and exceptions, and
 * to document which rule ids are stable public identifiers.
 *
 * @module detectors/catalog
 */

import { FIELD_RULES } from './field-names.js';
import { LOG_INJECTION_RULES } from './log-injection.js';
import { PATTERN_IDS } from './patterns.js';
import { PERSONAL_DATA_RULE_IDS } from './personal-data.js';

/** All stable rule ids, grouped by detector family. @readonly */
export const RULE_IDS = Object.freeze({
  fieldNames: Object.freeze(FIELD_RULES.map((rule) => rule.id)),
  credentialPatterns: PATTERN_IDS,
  personalData: PERSONAL_DATA_RULE_IDS,
  logInjection: Object.freeze(LOG_INJECTION_RULES.map((rule) => rule.id)),
});

/** Flat set of every rule id. */
export const ALL_RULE_IDS = Object.freeze(
  new Set([
    ...RULE_IDS.fieldNames,
    ...RULE_IDS.credentialPatterns,
    ...RULE_IDS.personalData,
    ...RULE_IDS.logInjection,
  ]),
);

/** Set of rule ids that belong to the optional personal-data detector. */
export const PERSONAL_DATA_RULE_ID_SET = Object.freeze(new Set(RULE_IDS.personalData));

/** Set of field-name rule ids. */
export const FIELD_RULE_ID_SET = Object.freeze(new Set(RULE_IDS.fieldNames));

/**
 * Returns the stable rule ids for a detector family.
 *
 * @param {'fieldNames'|'credentialPatterns'|'personalData'|'logInjection'} family
 * @returns {readonly string[]}
 */
export function listRuleIds(family) {
  return RULE_IDS[family] ?? Object.freeze([]);
}
