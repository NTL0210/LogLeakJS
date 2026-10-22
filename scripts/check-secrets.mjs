#!/usr/bin/env node
/**
 * Repository credential scan.
 *
 * The test suite intentionally contains synthetic secrets. Those exact values
 * are removed from the scanned text before matching, so this scanner can still
 * detect a real credential pasted next to a fixture. Matches are reported by
 * file, line, and rule id only; the matched text is never printed.
 *
 * This complements, but does not replace, GitHub secret scanning and a
 * dedicated secret manager.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { extname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SYNTHETIC_VALUES } from '../test-support/synthetic.js';

const root = fileURLToPath(new URL('..', import.meta.url));

const SKIP_DIRECTORIES = new Set([
  '.git',
  'node_modules',
  'coverage',
  'reports',
]);

const BINARY_EXTENSIONS = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.ico',
  '.pdf',
  '.woff',
  '.woff2',
  '.ttf',
  '.zip',
  '.gz',
  '.tgz',
  '.exe',
  '.dll',
  '.node',
  '.wasm',
  '.map',
]);

const RULES = Object.freeze([
  {
    id: 'aws-access-key-id',
    regex: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/u,
  },
  {
    id: 'github-token',
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/u,
  },
  {
    id: 'npm-token',
    regex: /\bnpm_[A-Za-z0-9]{36}\b/u,
  },
  {
    id: 'slack-token',
    regex: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/u,
  },
  {
    id: 'stripe-live-key',
    regex: /\bsk_live_[A-Za-z0-9]{16,}\b/u,
  },
  {
    id: 'google-api-key',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/u,
  },
  {
    id: 'pem-private-key',
    regex: /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----/u,
  },
  {
    id: 'jwt',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/u,
  },
  {
    id: 'connection-string-credentials',
    regex: /\b[a-z][a-z0-9+.-]{1,15}:\/\/[^\s:/@]{1,64}:[^\s/@]{1,64}@/iu,
  },
]);

const FORBIDDEN_FILE = /\.(?:pem|key|p12|pfx)$/iu;

/** Matches that are obviously documentation or synthetic fixtures. */
const ALLOWED_MARKER = /(?:SYNTHETIC|EXAMPLE|REDACTED|PLACEHOLDER|FAKE|DEMO)/iu;

/**
 * Tests a line without printing the match. Matches containing a documented
 * synthetic or placeholder marker are ignored.
 *
 * @param {string} line
 * @param {RegExp} regex
 * @returns {boolean}
 */
function containsCredential(line, regex) {
  const flags = regex.flags.includes('g') ? regex.flags : `${regex.flags}g`;
  const global = new RegExp(regex.source, flags);
  for (const match of line.matchAll(global)) {
    if (ALLOWED_MARKER.test(match[0])) continue;
    return true;
  }
  return false;
}

/**
 * @param {string} absolute
 * @returns {boolean}
 */
function shouldScan(absolute) {
  const extension = extname(absolute).toLowerCase();
  if (BINARY_EXTENSIONS.has(extension)) return false;
  if (absolute.endsWith(`${sep}package-lock.json`)) return false;
  const size = statSync(absolute).size;
  return size > 0 && size <= 2 * 1024 * 1024;
}

/**
 * Removes synthetic fixture values so intentional test data does not create
 * noise. A real credential is unaffected.
 *
 * @param {string} text
 * @returns {string}
 */
function stripSyntheticFixtures(text) {
  let result = text;
  for (const value of SYNTHETIC_VALUES) {
    const variants = new Set([value, JSON.stringify(value).slice(1, -1)]);
    for (const variant of variants) {
      if (variant.length === 0) continue;
      result = result.split(variant).join('[SYNTHETIC_FIXTURE]');
    }
  }
  return result;
}

/** @type {Array<{file: string, line: number, rule: string}>} */
const matches = [];
/** @type {string[]} */
const forbiddenFiles = [];

/**
 * @param {string} directory
 */
function walk(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === '.' || entry.name === '..') continue;
    const absolute = join(directory, entry.name);

    if (entry.isDirectory()) {
      if (SKIP_DIRECTORIES.has(entry.name)) continue;
      if (entry.name.startsWith('.tmp-')) continue;
      walk(absolute);
      continue;
    }
    if (!entry.isFile()) continue;
    if (entry.name.startsWith('.tmp-')) continue;

    const shown = relative(root, absolute).split(sep).join('/');
    if (FORBIDDEN_FILE.test(entry.name)) {
      forbiddenFiles.push(shown);
      continue;
    }
    if (!shouldScan(absolute)) continue;

    let text;
    try {
      text = readFileSync(absolute, 'utf8');
    } catch {
      continue;
    }
    const sanitized = stripSyntheticFixtures(text);
    const lines = sanitized.split(/\r\n|\n|\r/u);
    for (const [index, line] of lines.entries()) {
      for (const rule of RULES) {
        if (containsCredential(line, rule.regex)) {
          matches.push({ file: shown, line: index + 1, rule: rule.id });
        }
      }
    }
  }
}

walk(root);

if (forbiddenFiles.length > 0 || matches.length > 0) {
  console.error('check:secrets failed.');

  for (const file of forbiddenFiles) {
    console.error(`  - private key material file present: ${file}`);
  }
  for (const match of matches) {
    console.error(`  - ${match.rule} in ${match.file}:${match.line}`);
  }

  console.error(
    'Remove the credential from the repository, treat it as exposed, and rotate it. ' +
      'Do not paste the value into an issue or log.',
  );
  process.exit(1);
}

console.log(
  `check:secrets passed: scanned the repository for ${RULES.length} credential patterns; ` +
    'no matches outside documented synthetic fixtures.',
);
