#!/usr/bin/env node
/**
 * Verifies the publishable package without publishing it.
 *
 * - validates the package metadata and runtime dependency-free core
 * - rejects install lifecycle scripts and unexpected export targets
 * - runs `npm pack --dry-run --json` and inspects the exact file allowlist
 * - fails if tests, scripts, examples, lockfiles, or hidden files are packed
 *
 * This script never contacts a registry. `npm pack --dry-run` builds the
 * tarball description locally and writes no archive.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const failures = [];

/**
 * @param {boolean} condition
 * @param {string} message
 */
function check(condition, message) {
  if (!condition) failures.push(message);
}

/**
 * @param {string} file
 * @returns {string}
 */
function read(file) {
  return readFileSync(join(root, file), 'utf8');
}

const pkg = JSON.parse(read('package.json'));

// ---- Metadata ------------------------------------------------------------

check(pkg.name === 'logleak-test', 'package name must be logleak-test');
check(/^\d+\.\d+\.\d+$/u.test(pkg.version), 'version must be semver');
check(pkg.type === 'module', 'package must be native ESM');
check(pkg.license === 'MIT', 'license must stay MIT');
check(pkg.sideEffects === false, 'sideEffects must be false');
check(pkg.engines?.node === '>=22.12.0', 'engines.node must be >=22.12.0');
check(pkg.dependencies === undefined, 'runtime dependencies are not allowed');

const lifecycle = [
  'preinstall',
  'install',
  'postinstall',
  'prepublish',
  'prepublishOnly',
  'prepare',
];
for (const name of lifecycle) {
  check(pkg.scripts?.[name] === undefined, `install lifecycle script "${name}" is not allowed`);
}

check(pkg.main === './src/index.js', 'main must point at src/index.js');
check(Boolean(pkg.exports?.['.']), 'package must export the root entry point');
check(Boolean(pkg.exports?.['./pino']), 'package must export ./pino');
check(Boolean(pkg.exports?.['./winston']), 'package must export ./winston');

for (const name of Object.keys(pkg.peerDependencies ?? {})) {
  check(
    pkg.peerDependenciesMeta?.[name]?.optional === true,
    `peer dependency ${name} must be optional`,
  );
}

const allowedTopLevel = new Set([
  'package.json',
  'LICENSE',
  'README.md',
  'CHANGELOG.md',
  'SECURITY.md',
]);

const expectedFiles = pkg.files ?? [];
check(
  JSON.stringify(expectedFiles) ===
    JSON.stringify(['src/', 'README.md', 'CHANGELOG.md', 'SECURITY.md', 'LICENSE']),
  'files allowlist must be exactly src/, README.md, CHANGELOG.md, SECURITY.md, LICENSE',
);

for (const entry of expectedFiles) {
  const target = join(root, entry.replace(/\/$/u, ''));
  check(existsSync(target), `files entry is missing on disk: ${entry}`);
}

for (const [key, target] of Object.entries(pkg.exports ?? {})) {
  if (key === './package.json') continue;
  check(
    typeof target === 'string' && target.startsWith('./src/'),
    `export ${key} must point inside src/`,
  );
  if (typeof target === 'string') {
    check(existsSync(join(root, target.slice(2))), `export target is missing: ${target}`);
  }
}

// ---- Source inventory ----------------------------------------------------

const sourceRoot = join(root, 'src');
const sourceFiles = [];
for (const entry of readdirSync(sourceRoot, { recursive: true, withFileTypes: true })) {
  if (!entry.isFile()) continue;
  const absolute = join(entry.parentPath, entry.name);
  const packedPath = relative(root, absolute).split(sep).join('/');
  sourceFiles.push(packedPath);
  check(entry.name.endsWith('.js'), `unexpected non-JS source file: ${packedPath}`);
  check(statSync(absolute).size < 1024 * 1024, `source file is unexpectedly large: ${packedPath}`);
}
check(sourceFiles.includes('src/index.js'), 'src/index.js is missing');
check(sourceFiles.includes('src/capture/pino.js'), 'src/capture/pino.js is missing');
check(sourceFiles.includes('src/capture/winston.js'), 'src/capture/winston.js is missing');

// ---- Layering ------------------------------------------------------------

const coreEntry = read('src/index.js');
check(!/from\s+['"]pino['"]/u.test(coreEntry), 'core entry point must not import pino');
check(!/from\s+['"]winston['"]/u.test(coreEntry), 'core entry point must not import winston');
check(
  !/from\s+['"]winston-transport['"]/u.test(coreEntry),
  'core entry point must not import winston-transport',
);

for (const file of ['package-lock.json']) {
  check(existsSync(join(root, file)), `${file} must be committed`);
}

// ---- Packed contents -----------------------------------------------------

const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
let packOutput;
try {
  packOutput = execFileSync(
    npm,
    ['pack', '--dry-run', '--json', '--ignore-scripts'],
    {
      cwd: root,
      encoding: 'utf8',
      shell: process.platform === 'win32',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 120000,
    },
  );
} catch (error) {
  console.error('check:package failed: npm pack --dry-run did not complete.');
  if (error.stderr) console.error(String(error.stderr).trim());
  process.exit(1);
}

let packed;
try {
  const parsed = JSON.parse(packOutput);
  packed = Array.isArray(parsed) ? parsed[0] : parsed;
} catch {
  console.error('check:package failed: npm pack --dry-run did not return JSON.');
  process.exit(1);
}

check(packed?.name === pkg.name, 'packed name does not match package.json');
check(packed?.version === pkg.version, 'packed version does not match package.json');

const packedFiles = (packed?.files ?? []).map((file) => file.path.split(sep).join('/'));
check(packedFiles.length > 0, 'npm pack returned no files');

for (const file of packedFiles) {
  const allowed =
    allowedTopLevel.has(file) || (file.startsWith('src/') && file.endsWith('.js'));
  check(allowed, `unexpected file in package tarball: ${file}`);
}

for (const required of ['package.json', 'LICENSE', 'README.md', 'CHANGELOG.md', 'SECURITY.md']) {
  check(packedFiles.includes(required), `required file is missing from tarball: ${required}`);
}
for (const required of sourceFiles) {
  check(packedFiles.includes(required), `source file is missing from tarball: ${required}`);
}

const forbidden = [
  /^test\//u,
  /^test-support\//u,
  /^scripts\//u,
  /^examples\//u,
  /^node_modules\//u,
  /^\.github\//u,
  /^coverage\//u,
  /^package-lock\.json$/u,
  /^\./u,
  /\.tgz$/u,
  /\.log$/u,
];
for (const file of packedFiles) {
  for (const pattern of forbidden) {
    check(!pattern.test(file), `forbidden file in package tarball: ${file}`);
  }
}

// ---- Result --------------------------------------------------------------

if (failures.length > 0) {
  console.error('check:package failed:');
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}

const sourceBytes = (packed?.files ?? [])
  .filter((file) => file.path.startsWith('src/'))
  .reduce((total, file) => total + file.size, 0);

console.log(
  `check:package passed: ${packedFiles.length} files, ${sourceBytes} source bytes, ` +
    `${pkg.name}@${pkg.version}, no runtime dependencies, no lifecycle scripts.`,
);
