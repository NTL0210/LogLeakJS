# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-22

### Added

- Dependency-free core analyzer for sensitive values in captured log output.
- Explicit, instance-local capture adapters:
  - in-memory capture with bounded records and bytes
  - Pino destination-stream adapter on `logleak-test/pino`
  - Winston transport adapter on `logleak-test/winston`
- Detection families and evidence types:
  - exact synthetic-secret (known-secret) matching
  - curated sensitive field names
  - bounded credential patterns for common providers and connection strings
  - opt-in email and phone detection
  - log-injection indicators (control characters, lone CR, Unicode separators)
- `default`, `strict`, and `audit` policies.
- Severity overrides, narrow rule/path exceptions, and stable rule ids.
- Privacy-safe terminal and JSON reports with sanitized paths.
- Test-framework-neutral assertions and stable exit codes:
  `0` pass, `1` leaks, `2` configuration, `3` incomplete, `4` internal.
- Bounded analysis for records, bytes, depth, nodes, secrets, findings,
  diagnostics, and wall-clock time. Exceeding a bound yields incomplete
  coverage, never a silent pass.
- Canary secret helper that hides its value from serialization and inspection.
- Pino and Winston as optional peer dependencies; no runtime dependencies.
- Node.js `>=22.12.0`, native ESM, JSDoc public APIs.
- Test suite, linting, package allowlist check, repository secret scan, CI, and
  Dependabot configuration.

[Unreleased]: https://github.com/NTL0210/LogLeakJS/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/NTL0210/LogLeakJS/releases/tag/v0.1.0
