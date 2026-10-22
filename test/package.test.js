import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { LIBRARY_NAME, LIBRARY_VERSION, REPORT_SCHEMA_VERSION } from '../src/constants.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

test('package identity and metadata are consistent', () => {
  assert.equal(pkg.name, 'logleak-test');
  assert.equal(pkg.name, LIBRARY_NAME);
  assert.equal(pkg.version, LIBRARY_VERSION);
  assert.match(pkg.version, /^\d+\.\d+\.\d+$/u);
  assert.equal(REPORT_SCHEMA_VERSION, 1);
  assert.equal(pkg.type, 'module');
  assert.equal(pkg.license, 'MIT');
  assert.equal(pkg.author, 'NTL');
  assert.equal(pkg.sideEffects, false);
  assert.equal(pkg.repository.url, 'git+https://github.com/NTL0210/LogLeakJS.git');
  assert.equal(pkg.bugs.url, 'https://github.com/NTL0210/LogLeakJS/issues');
});

test('the package has no runtime dependencies and no install lifecycle scripts', () => {
  assert.equal(pkg.dependencies, undefined);
  const lifecycle = [
    'preinstall',
    'install',
    'postinstall',
    'prepublish',
    'prepublishOnly',
    'prepare',
  ];
  for (const name of lifecycle) {
    assert.equal(pkg.scripts[name], undefined, `${name} must not run on install`);
  }
});

test('optional logger integrations are declared as optional peer dependencies', () => {
  assert.deepEqual(Object.keys(pkg.peerDependencies).sort(), [
    'pino',
    'winston',
    'winston-transport',
  ]);
  for (const name of Object.keys(pkg.peerDependencies)) {
    assert.equal(pkg.peerDependenciesMeta[name].optional, true);
  }
});

test('every export and packed path exists', () => {
  assert.equal(pkg.main, './src/index.js');
  assert.deepEqual(Object.keys(pkg.exports), ['.', './pino', './winston', './package.json']);

  for (const target of Object.values(pkg.exports)) {
    assert.equal(existsSync(new URL(`../${target.replace(/^\.\//u, '')}`, import.meta.url)), true);
  }
  for (const entry of pkg.files) {
    assert.equal(existsSync(`${root}${entry.replace(/\/$/u, '')}`), true, `${entry} is missing`);
  }
});

test('the packed file allowlist is minimal', () => {
  assert.deepEqual(pkg.files, ['src/', 'README.md', 'CHANGELOG.md', 'SECURITY.md', 'LICENSE']);
  assert.equal(pkg.files.includes('test/'), false);
  assert.equal(pkg.files.includes('node_modules/'), false);
});

test('supported Node versions and scripts are declared', () => {
  assert.equal(pkg.engines.node, '>=22.12.0');
  assert.equal(typeof pkg.scripts.test, 'string');
  assert.equal(pkg.scripts.test, 'node --test');
  assert.equal(pkg.scripts['test:coverage'], 'node --test --experimental-test-coverage');
  assert.equal(pkg.scripts.lint, 'eslint .');
  assert.equal(pkg.scripts['check:secrets'], 'node scripts/check-secrets.mjs');
  assert.equal(pkg.scripts['check:package'], 'node scripts/check-package.mjs');
  assert.equal(pkg.scripts.verify, 'npm run lint && npm test && npm run check:secrets && npm run check:package');
});

test('the original MIT license is preserved', () => {
  const license = readFileSync(new URL('../LICENSE', import.meta.url), 'utf8');
  assert.match(license, /MIT License/u);
  assert.match(license, /Copyright \(c\) 2026 NTL/u);
  assert.match(license, /THE SOFTWARE IS PROVIDED "AS IS"/u);
});
