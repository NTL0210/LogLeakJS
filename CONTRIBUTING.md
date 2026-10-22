# Contributing

Thanks for helping improve `logleak-test`.

## Ground rules

- JavaScript only, native ESM, no TypeScript.
- The core (`src/`, excluding `src/capture/pino.js` and `src/capture/winston.js`)
  must have **no runtime dependencies** and must not import optional logger
  packages.
- Do not add telemetry, network calls, hosted services, file scanning, or global
  monkey-patching.
- Do not add install lifecycle scripts (`preinstall`, `install`, `postinstall`,
  `prepare`).
- Never include real credentials, production log lines, or customer data in a
  test, issue, or commit. Use the synthetic fixtures in
  `test-support/synthetic.js` or generate a canary with `createCanarySecret()`.
- Preserve the MIT license and the existing copyright notice.

## Setup

```sh
npm ci --ignore-scripts
npm run verify
```

`npm run verify` runs lint, the full test suite, the repository secret scan, and
the package allowlist check.

Useful commands:

```sh
npm test
npm run test:coverage
npm run lint
npm run check:secrets
npm run check:package
npm audit --audit-level=high
```

## Making a change

1. Add or update a test first. Security behavior needs a regression test.
2. Keep public APIs documented with JSDoc and update `README.md` when behavior
   or configuration changes.
3. Update `CHANGELOG.md` for user-visible changes.
4. Run the full verification above, plus a clean-environment check for packaging
   changes.
5. Do not commit generated tarballs, `node_modules`, coverage output, or
   temporary probe scripts.

## Adding a detector rule

- Prefer a fixed, reviewed implementation. User-supplied regular expressions are
  not accepted.
- Give the rule a stable id. Rule ids are public identifiers used by
  `disabledRules` and `exceptions`.
- Avoid catastrophic backtracking. Test large and adversarial inputs.
- Never include the detected value in the finding. Add a test asserting that the
  value, raw line, and hashes of the value are absent from the JSON report and
  terminal report.
- Add the rule to the catalog, document it in the README, and cover it in the
  test suite.
- Consider false positives and false negatives. If a rule is noisy, keep it
  opt-in or document the tradeoff.

## Privacy requirements for tests

Every new sensitive fixture must be added to `SYNTHETIC_VALUES` or to the
forbidden-value list in `test/privacy.test.js`. Privacy tests must assert that
reports, assertion messages, and serialized results contain none of those
values.

Do not weaken a privacy test to make a feature pass. Fix the leak.

## Pull requests

- Keep changes focused and explain the security rationale.
- Include the commands you ran and their results.
- Note any remaining risks or coverage gaps.
- Do not claim that detection is complete. Absence of findings is not proof that
  no leak exists.

## License

By contributing, you agree that your contribution is licensed under the MIT
license used by this project.
