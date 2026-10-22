# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| `0.1.x` | Yes |

This project is pre-1.0. Security fixes are made on the latest released minor
version. Older versions are not maintained.

## Reporting a vulnerability

Please do **not** open a public issue for a suspected vulnerability, and never
include real credentials, production log lines, customer data, or canary values
in a report.

Use GitHub's private vulnerability reporting:

<https://github.com/NTL0210/LogLeakJS/security/advisories/new>

Include:

- affected version or commit
- the smallest synthetic reproduction you can build
- expected and observed behavior
- security impact, especially whether a detected value, raw log line, or secret
  hash can appear in a report, assertion message, error, or stdout
- whether the issue requires a malicious configuration, a malicious logger, or
  only ordinary application output

You should receive an acknowledgement through the advisory thread. Please allow
time for triage and a coordinated fix before public disclosure.

## Scope

This policy covers the `logleak-test` package and its source in this repository,
including the core analyzer, capture adapters, assertions, reports, and canary
helpers.

Out of scope unless it demonstrates a flaw in this library:

- a secret that is logged but never passed through a capture
- a secret in a different process, file, container, or network path
- missing detection of an obfuscated or unknown secret format (see limitations)
- a false positive caused by a deliberately sensitive-looking field name
- vulnerabilities only present in an unsupported Node.js version or in a
  third-party logger

## Security model

`logleak-test` is a local, test-time analyzer.

- The core package has no runtime dependencies and makes no network requests.
- There is no telemetry, account system, hosted service, file scanning, or
  background process.
- The library does not patch `console`, `process`, Pino, Winston, or any global.
  Capture adapters are explicit and scoped to an instance.
- Captures are bounded and instance-local. Limits cover records, bytes, depth,
  nodes, secrets, findings, diagnostics, and time.
- Configuration is validated and frozen before analysis. Unknown options are
  rejected. Known-secret findings cannot be suppressed.
- Reports, result objects, and assertion messages contain rule metadata and
  sanitized paths only. They do not contain detected values, raw log lines,
  snippets, serialized errors, or hashes of detected values.
- Path segments containing a registered secret or credential-pattern match are
  replaced with `[redacted-key]`.
- Accessors are skipped during structured traversal to avoid executing caller
  code. The documented exception is `Error.stack`, which is read so stack traces
  can be inspected. Reading it may invoke a customized
  `Error.prepareStackTrace` hook. Do not install untrusted code that customizes
  that hook in the same process as sensitive tests.
- Object records are stored by reference in a memory capture. Analyze them
  before mutating them. Do not pass objects with side-effecting accessors and
  expect them to be inert; accessors are skipped and the analysis is marked
  incomplete.
- Registered secrets and captured values remain in process memory. JavaScript
  cannot guarantee that strings are wiped. `dispose()` drops registry
  references, but it is not a memory-erasure guarantee.
- The library cannot protect against a test or application that prints the raw
  record, the detector configuration, or a registered secret directly to its own
  output.

## Known limitations

Detection is intentionally bounded and heuristic. A clean result does **not**
prove that an application never leaks data.

- Only records routed to the provided capture are analyzed.
- Known-secret matching is exact, case-sensitive, and bounded by the configured
  registry limits.
- Credential patterns are fixed and finite. Encoded, split, transformed, or
  unknown-format secrets may not match.
- Field-name rules are curated. Renamed or obfuscated fields may not match, and
  generic names can produce false positives.
- Personal-data detection is opt-in, noisy, and not a legal compliance control.
- Log-injection indicators show that a character is present, not that an
  exploit is possible.
- Resource limits can make coverage incomplete. An incomplete result must never
  be reported as clean.

## Supply chain

The package is intended to be consumed with a committed lockfile.

- The core has zero runtime dependencies.
- Pino and Winston are optional peer dependencies, never bundled.
- No install lifecycle scripts are used by this package.
- CI installs with `npm ci --ignore-scripts`, runs tests and lint, audits
  dependencies, scans the repository for credential patterns, and verifies the
  packed file allowlist.
- Publishing is a manual, separately verified step. This repository does not
  publish automatically.

## Handling a real exposure

If a finding contains a real credential:

1. Do not paste the value into an issue, chat, or report.
2. Treat the credential as compromised and rotate or revoke it.
3. Remove it from the emitted log path and audit where it came from.
4. Add a synthetic canary to the regression test rather than the real value.
5. Check whether the same field is logged by other code paths, not just the one
   the test exercised.
