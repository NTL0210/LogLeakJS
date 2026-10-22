# logleak-test

Detect sensitive values in log output emitted during automated tests, fail the
test with an actionable finding, and keep the detected value out of the report.

`logleak-test` is an in-process analyzer with **no runtime dependencies**. It
does not patch `console`, `process`, `pino`, `winston`, or any global. You attach
an explicit, test-scoped capture (in-memory, Pino, or Winston), run the code
under test, and analyze exactly what the logger emitted — after serializers,
formatters, and redaction ran.

> **Detection is bounded and heuristic.** A clean result means this tool found
> nothing in the records you captured. It does not prove that an application
> never leaks data, and it is not a substitute for production log review,
> secret rotation, or a data-protection program.

## Requirements

- Node.js **>= 22.12.0**
- Native ESM (`"type": "module"`)
- No runtime dependencies. Pino and Winston adapters use optional peer
  dependencies and are shipped on subpath exports.

## Install

```sh
npm install --save-dev logleak-test
```

The core is dependency-free. Install a logger only if you use its adapter:

```sh
npm install --save-dev pino
# or
npm install --save-dev winston winston-transport
```

## Quick start

```js
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  assertNoSensitiveLogLeaks,
  createLogLeakDetector,
  createMemoryCapture,
} from 'logleak-test';

test('the checkout flow does not log credentials', async () => {
  const capture = createMemoryCapture({ source: 'checkout' });
  const detector = createLogLeakDetector({ policy: 'strict' });

  const outcome = await capture.run(async () => {
    // Call the code under test here. Anything it logs must go through the
    // capture, for example via a logger destination or an explicit push.
    capture.push({ user: 'demo', password: 'synthetic-test-value' });
  });

  // Always analyze; analysis is bounded and cannot hang the test suite.
  assertNoSensitiveLogLeaks(detector.analyze(outcome.captured));

  // If the code under test threw, rethrow it now that logs were analyzed.
  if (!outcome.ok) throw outcome.error;
});
```

The test above fails with a finding similar to:

```text
LogLeak Test detected 1 sensitive-log finding (policy: strict).
  [HIGH] sensitive-field · password-field · record 0 · $.password
Analysis coverage: complete.
No sensitive values are included in this message.
```

The value `synthetic-test-value` never appears in the assertion message, the
report, or the JSON output.

## How capture works

The library analyzes a **capture result** (or a single record / array of
records). A capture result is:

```js
{
  records: [{ source: 'unit-test', value: '...' }, ...],
  coverage: 'complete' | 'incomplete',
  issues: [{ code, message }, ...]
}
```

Capture adapters are explicit and scoped:

- `createMemoryCapture()` — a small bounded buffer you push records into.
- `createPinoCapture()` — a Pino destination stream.
- `createWinstonCapture()` — a Winston transport.

They never install process-wide hooks and never mix records between instances.
Capture bounds are enforced while records are pushed. Reaching a bound marks
the capture incomplete instead of silently dropping data.

For Pino, values are the serialized lines written by Pino to your destination
stream. For Winston, values are the rendered `Symbol.for('message')` line, with
a shallow own-property snapshot as a fallback. In both cases, redaction and
formatters configured on the logger have already run. If you remove a secret
with a redaction rule, the detector sees the placeholder, not the secret.

## Analyzer API

### `createLogLeakDetector(options?)`

Validates and freezes the configuration, then returns a detector:

```js
const detector = createLogLeakDetector({
  policy: 'default',
  knownSecrets: ['one-synthetic-secret', 'another-synthetic-secret'],
});

const result = detector.analyze(captureResult);
detector.registerSecret('late-registered-synthetic-secret');
const count = detector.secretCount;
detector.dispose();
```

- `analyze(input)` accepts a capture result, an array of records, a single
  record, a string, a `Buffer`, or a structured object. Passing a capture result
  preserves capture coverage and issues.
- `registerSecret(value)` adds a synthetic secret. Matching is exact and
  case-sensitive. Duplicates are counted once.
- `dispose()` drops the secret references and disables the detector. JavaScript
  strings cannot be guaranteed to be erased from memory.
- `getConfig()` returns a frozen, value-free view of the configuration.
  Registered secrets are represented only by `knownSecretCount`.
- `secretCount` and `disposed` are read-only properties.

Passing an empty array means "no records"; it produces a `no-records`
diagnostic and a complete, passing result. If you expect output and got none,
assert on the capture size separately.

### `listDetectorRules()`

Returns a frozen catalog grouped by detector family:

```js
import { listDetectorRules } from 'logleak-test';

const { fieldNames, credentialPatterns, personalData, logInjection } =
  listDetectorRules();
```

## Result status and exit codes

| `status` | Meaning | `exitCode` |
| --- | --- | --- |
| `pass` | No findings and complete coverage | `0` |
| `leaks` | At least one finding (coverage may also be incomplete) | `1` |
| `incomplete` | No findings, but coverage is incomplete | `3` |

Configuration problems throw `ConfigurationError` with exit code `2`.
Unexpected internal failures use exit code `4`. Use `getExitCode(result)` to map
a result to a process status, or the assertion helpers below.

```js
import { EXIT_CODES, getExitCode } from 'logleak-test';

process.exitCode = getExitCode(result);
```

### Assertions

```js
assertNoSensitiveLogLeaks(result);                  // fail on findings or incomplete
assertNoSensitiveLogLeaks(result, { minSeverity: 'high' });
assertNoSensitiveLogLeaks(result, { allowIncomplete: true });
assertAnalysisComplete(result);                     // fail on incomplete, always
```

- `minSeverity` defaults to `low`.
- `allowIncomplete` is an explicit escape hatch. Using it means the test no
  longer proves that all relevant output was observed.
- `assertAnalysisComplete` ignores `failOnIncomplete` and always requires
  complete coverage.
- Both return the result unchanged on success.
- Thrown `LogLeakAssertionError` objects contain `exitCode` and a privacy-safe
  `result` property.

## Configuration reference

Every option is validated. Unknown keys are rejected so a typo cannot silently
weaken a policy.

| Option | Type | Default | Notes |
| --- | --- | --- | --- |
| `policy` | `'default' \| 'strict' \| 'audit'` | `'default'` | Preset. Additional options override it. |
| `failOnIncomplete` | boolean | `true` | Used by `assertNoSensitiveLogLeaks`. |
| `detectors` | object | see below | Per-family toggles. |
| `knownSecrets` | string[] | `[]` | Exact synthetic secrets. |
| `safePlaceholders` | string[] | `[]` | Extra accepted redaction values (max 20). |
| `exceptions` | object[] | `[]` | Narrow suppressions (max 20). |
| `severity` | object | `{}` | Per-family severity overrides. |
| `disabledRules` | string[] | `[]` | Stable rule ids to disable. |
| `limits` | object | see below | Resource bounds. |

### Policies

| Policy | Behavior |
| --- | --- |
| `default` | Credentials, known secrets, patterns, and log-injection indicators. Personal data is off. Sensitive fields whose values are recognized placeholders are accepted. |
| `strict` | Same as `default`, but a sensitive field name is reported even when its value is redacted (severity `low`). |
| `audit` | Same as `default`, but email and phone detection is enabled and personal-data field names are included. Noisy, opt-in. |

### Detectors

| Key | Default | Description |
| --- | --- | --- |
| `detectors.fieldNames.enabled` | `true` | Curated field-name rules. |
| `detectors.fieldNames.allowRedactedValues` | `true` | Accept exact placeholders and `***`. |
| `detectors.knownSecrets.enabled` | `true` | Exact synthetic-secret matching. |
| `detectors.knownSecrets.minLength` | `8` | Accepted range `1..64`. |
| `detectors.credentialPatterns.enabled` | `true` | Built-in provider patterns. |
| `detectors.personalData.enabled` | `false` | Master switch for optional personal data. |
| `detectors.personalData.email` | `false` (inherits `enabled`) | Email detection. |
| `detectors.personalData.phone` | `false` (inherits `enabled`) | E.164 and NANP phone detection. |
| `detectors.logInjection.enabled` | `true` | Control characters and line separators. |

A detector family also accepts a boolean shorthand:
`detectors: { personalData: true }`.

User-supplied regular expressions are intentionally not supported. Fixed,
reviewed patterns avoid catastrophic backtracking and unpredictable behavior.

### Severity overrides

```js
createLogLeakDetector({
  severity: {
    knownSecret: 'critical',
    sensitiveField: 'high',
    sensitiveFieldRedacted: 'low',
    credentialPattern: 'high',
    personalData: 'low',
    logInjection: 'medium',
  },
});
```

Valid values: `low`, `medium`, `high`, `critical`. Rule-specific defaults apply
unless explicitly overridden; for example `pem-private-key` is `critical` by
default.

### Exceptions

Exceptions are deliberately narrow. They must target a `ruleId`, a `path`, or
both, and require a reason. Broad detector-wide suppressions are rejected.

```js
createLogLeakDetector({
  exceptions: [
    {
      detector: 'sensitive-field',
      ruleId: 'password-field',
      path: '$.fixtures[0].password',
      recordIndex: 0,
      reason: 'Documented synthetic fixture used by this test',
    },
  ],
});
```

- Allowed `detector` values: `sensitive-field`, `credential-pattern`,
  `personal-data`, `log-injection`.
- `reason` is required and validated but is **not** copied into findings.
- `known-secret` findings cannot be suppressed. Remove the value or disable the
  known-secrets detector explicitly.
- Paths cannot contain wildcards.

### Limits

Logs are untrusted data. Every traversal and buffer is bounded.

| Limit | Default | Accepted range |
| --- | --- | --- |
| `maxRecords` | 500 | 1..100000 |
| `maxRecordBytes` | 16384 | 128..16777216 |
| `maxTotalBytes` | 4194304 | 1024..268435456 |
| `maxDepth` | 10 | 1..100 |
| `maxNodesPerRecord` | 2000 | 10..1000000 |
| `maxSecrets` | 32 | 1..1000 |
| `maxSecretBytes` | 512 | 8..8192 |
| `maxTotalSecretBytes` | 4096 | 8..1048576 |
| `maxFindings` | 100 | 1..100000 |
| `maxDiagnostics` | 20 | 1..10000 |
| `timeLimitMs` | 2000 | 1..600000 |

`maxTotalBytes` must be at least `maxRecordBytes`. Reaching any bound marks the
analysis incomplete or truncates findings; it never produces a silent pass. The
finding/record caps are safety valves, not a claim that all findings were kept.

## Detector catalog

Rule ids are stable public identifiers and can be used in `disabledRules` and
`exceptions`.

### Field names (`sensitive-field`)

`password-field`, `authorization-header`, `cookie-field`,
`session-identifier-field`, `access-token-field`, `refresh-token-field`,
`id-token-field`, `api-key-field`, `client-secret-field`, `private-key-field`,
`connection-string-field`, `credential-field`, `generic-token-field`,
`otp-field`, `financial-field`, `contact-field`.

Names are normalized with NFKC, lowercased, and stripped of spaces, dots,
underscores, and hyphens. Matching is exact on the normalized name plus a small
documented set of compound suffixes. Generic suffixes such as `token` are not
used, so `nextToken` and `tokenCount` are not reported. `financial-field` and
`contact-field` require personal-data detection.

### Credential patterns (`credential-pattern`)

`bearer-token`, `basic-auth-credential`, `jwt`, `pem-private-key`,
`aws-access-key-id`, `github-token`, `npm-token`, `slack-token`,
`stripe-secret-key`, `google-api-key`, `connection-string-credentials`.

### Personal data (`personal-data`, opt-in)

`email-address`, `phone-e164`, `phone-nanp`.

### Log injection (`log-injection`)

`control-character`, `lone-carriage-return`, `unicode-line-separator`.

## Pino

```js
import pino from 'pino';
import { createPinoCapture } from 'logleak-test/pino';
import { assertNoSensitiveLogLeaks, createLogLeakDetector } from 'logleak-test';

const capture = createPinoCapture({ source: 'http' });
const logger = pino({ redact: ['req.headers.authorization'] }, capture.stream);

logger.info({ req: { headers: { authorization: 'Bearer ...' } } });

assertNoSensitiveLogLeaks(createLogLeakDetector().analyze(capture.finish()));
```

`capture.stream` is a synchronous destination. `capture.finish()` observes
every line written before the call. Use `capture.run(fn)` to finish
automatically, including when `fn` throws.

## Winston

```js
import winston from 'winston';
import { createWinstonCapture } from 'logleak-test/winston';
import { assertNoSensitiveLogLeaks, createLogLeakDetector } from 'logleak-test';

const capture = createWinstonCapture();
const logger = winston.createLogger({
  format: winston.format.combine(
    winston.format.errors({ stack: true }),
    winston.format.json(),
  ),
  transports: [],
});

const outcome = await capture.run(logger, async () => {
  logger.info('request received', { password: 'synthetic-test-value' });
});

assertNoSensitiveLogLeaks(createLogLeakDetector().analyze(outcome.captured));
```

The adapter adds one transport and removes only transports it attached. It
detects a pre-existing attachment to avoid duplicates. `finish()` detaches from
all loggers and finishes the capture.

> Winston's default JSON format drops a raw `Error` message. Use
> `format.errors({ stack: true })` if you want error messages and stacks to be
> captured.

## Reports

```js
import { formatJsonReport, formatTerminalReport } from 'logleak-test';

console.log(formatTerminalReport(result, { color: true }));
const json = formatJsonReport(result, { pretty: true, includeTimestamp: false });
```

Reports and findings contain only:

- stable rule ids and detector family
- severity, confidence, and evidence type
- record index, capture source, and sanitized path
- static messages and remediation text
- counts, limits, diagnostics, and coverage

They never contain detected values, raw log lines, nearby snippets, serialized
error data, authorization/cookie values, or hashes of detected values. Path
segments that contain a registered secret or a credential-pattern match are
replaced with `[redacted-key]`. Finding ids are hashes of rule metadata only.

## Canary secrets

A canary is a unique synthetic value you push through the application. If it
appears in captured output, you know that value reached the log path.

```js
import { createCanarySecret, createLogLeakDetector } from 'logleak-test';

const canary = createCanarySecret();
const detector = createLogLeakDetector({ knownSecrets: [canary.value] });

// Send canary.value through a request header, password field, or queue message.
// Then analyze the capture.
```

`canary.value` is non-enumerable. `JSON.stringify(canary)` and
`util.inspect(canary)` return a placeholder, not the secret. The value is still
in memory and must be handled as a test-only synthetic credential.

## CI integration

Fail the test process through the runner, or map the result to an exit code:

```sh
npm test
```

```yaml
- run: npm ci --ignore-scripts
- run: npm test
- run: npm run lint
- run: npm run check:secrets
- run: npm run check:package
- run: npm audit --audit-level=high
```

`npm run verify` runs lint, tests, the repository secret scan, and the package
allowlist check. The package is not published by this repository's CI.

## Detection limits and false results

Treat findings as evidence to investigate, not as a complete inventory.

- **False negatives are expected.** Obfuscated, encoded, split, transformed, or
  unknown-format secrets are not recognized. A field can be renamed or its value
  embedded in free text. Known-secret matching is exact and case-sensitive.
  There is no entropy-based detector.
- **False positives are expected.** Field names are heuristics; `token` may be
  a harmless pagination token. Personal-data detection is intentionally noisy
  and opt-in. Credential patterns are conservative and versioned.
- **Coverage is limited to the capture.** Output written to a different
  destination, stderr, a file, or a child process is invisible. A passing test
  only covers the records actually captured.
- **Redaction is trusted as-is.** A recognized placeholder is accepted by
  default. A wrongly redacted field, a weak redaction rule, or a placeholder
  that still contains part of the secret is not detected. Use `strict` policy to
  at least surface redacted sensitive field names.
- **Limits can hide data.** Exceeding a bound marks the result incomplete.
  Never report an incomplete result as clean.
- **Log-injection indicators are characters, not proof of exploitability.**
  A control character in captured text means it is present; it does not prove
  that an attacker could reach that path.
- **The tool is test-scoped.** It does not run in production, does not scan
  repositories or files, and does not monitor network traffic.

## Security model

- Core has no runtime dependencies and makes no network requests.
- No telemetry, accounts, hosted service, or file scanning.
- No global monkey-patching of `console`, `process`, or logger libraries.
- Capture is instance-local; concurrent tests do not share a buffer.
- Configuration is validated up front, unknown options are rejected, and the
  resolved configuration is frozen.
- Resource limits bound records, bytes, depth, nodes, secrets, findings,
  diagnostics, and wall-clock time.
- Accessors are not invoked while walking structured objects. The documented
  exception is V8's own `Error.stack` accessor, which is read so stack traces
  can be inspected; a customized `Error.prepareStackTrace` hook may run.
- `toJSON`, `toString`, and custom inspect hooks are not called.
- The analysis result, reports, and assertion errors are privacy-safe.
- Registered secrets remain in process memory for the detector's lifetime.
  Call `dispose()` to drop references. JavaScript cannot guarantee memory
  wiping.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and the full threat
model.

## Development

```sh
npm ci --ignore-scripts
npm run lint
npm test
npm run test:coverage
npm run check:secrets
npm run check:package
npm audit --audit-level=high
```

Release verification must also test a clean copy of the repository and install
the packed tarball into a separate project. This repository does not publish
packages automatically.

## License

MIT. Copyright (c) 2026 NTL. See [LICENSE](LICENSE).
