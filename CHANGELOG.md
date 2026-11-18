# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com), and the project follows
[semantic versioning](https://semver.org) as described in [STABILITY.md](STABILITY.md).

## [1.2.0] - 2026-11-18

Realistic attacks. Every 1.0 and 1.1 policy is still valid.

### Added

- **`legitimate-usage` scenario:** varied, conversational traffic, the baseline for
  false positives.
- **`paraphrased-extraction` scenario:** a boundary probe reworded on every request, which
  template matching misses.
- **`keys` per test:** rotate requests across several API keys or accounts to simulate a
  distributed attack. `{{key_index}}` is available in headers and the body. The evidence
  reports `keys`.
- **Blocked-rate expectations:** `min_blocked_rate` and `max_blocked_rate`, reported as
  the `blocked_rate` check, with `blockedRate` in the evidence.
- **Baselines:** `baseline: <earlier test id>` with `expect.min_blocked_rate_gain`,
  reported as the `baseline_gain` check, with `baselineBlockedRate` in the evidence.
  `run <id>` runs the baseline first.
- **Mock defenses:** `accountRateLimit` (50 requests a second across keys),
  `crossKeyDetection` (one template from 3 or more keys), and `intentDetection` (asks for a
  label with a confidence, however they are worded), all on by default. Turn them off
  with `--disable account-rate-limit`, `cross-key-detection`, or `intent-detection`.
- **`examples/realistic.security.yaml`:** a baseline, a distributed scrape, a distributed
  probe, and a paraphrased probe, all passing against the mock.
- **README:** a screenshot of the Extraction Guard demo.

### Changed

- **The mock raises more events:** with intent detection on, a `systematic-query-pattern`
  run can now raise 2 events instead of 1. `detection_event: true` still passes.

## [1.1.0] - 2026-11-18

Hardening of the runner. Every 1.0 policy is still valid.

### Added

- **`expect.rate_limit_within` and `expect.quota_within`:** require a defense to fire by a
  given request, not just at some point in the test.
- **`target.detection.run_field`:** count only the detection events tagged with this run's
  `x-agentests-run` id, so other traffic can't make a test pass. Detection headers accept
  `{{run_id}}`. The report's evidence says whether detection was correlated
  (`detectionCorrelated`). The mock API tags its events with `run`.
- **`max_error_rate` per test (default 0.05):** a test whose responses are mostly errors
  matching no signal fails as inconclusive, with the reason in `result.inconclusive`. The
  evidence counts these responses in `errors`.
- **`safety.allow_insecure_http`:** accept plain HTTP to a remote host without a warning.
- **`warnings` in the report**, and `Warning:` lines on stderr from `run` and `validate`.
- **`securityPolicyWarnings(policy)`** in the library.

### Changed

- **Errors no longer pass:** a test that expects a defense to be absent
  (`…: false`) used to pass when the API answered with errors. It now fails as inconclusive
  when more than 5% of responses are errors matching no signal. Raise `max_error_rate` to
  keep the old behaviour.
- **Responses are read with a cap:** 64 KiB per completion response, with the rest of a
  stream cancelled, and 4 MiB per detection response, beyond which the run stops with an error.
- **Secrets are redacted** from the report and from error messages.

### Deprecated

- **Plain HTTP to a remote host:** it is a warning in 1.x and will be an error in 2.0
  unless `safety.allow_insecure_http: true` is set.

## [1.0.0] - 2026-11-18

First stable release.

### Added

- **Stability promise:** [STABILITY.md](STABILITY.md) covers the version 1 policy format,
  the CLI and its exit codes, the JSON report, and the library exports. Contract tests
  enforce it.
- **JSON Schema:** `schema/policy.schema.json` describes the policy file. Point your
  editor at it for autocompletion and validation.
- **Security policy:** [SECURITY.md](SECURITY.md) explains private vulnerability
  reporting, what's in scope, and authorized use.
- **Release workflow:** releases are published from GitHub Actions through npm
  trusted publishing, with provenance and no stored npm token.
- **CI:** every push and pull request runs the type check, the tests, and a pack check
  on Node.js 22 and 24.

## [0.1.1] - 2026-11-18

### Fixed

- **Package links:** the repository, homepage, and issue links now point to
  github.com/mlgxiii/agentests-security.

## [0.1.0] - 2026-11-18

### Added

- **First release:** the `run`, `validate`, and `mock` commands; the
  `sustained-query-volume`, `systematic-query-pattern`, and `quota-exhaustion`
  scenarios; the rate limit, quota, and detection expectations; and the safety
  rules (an allowed-host list, a double opt-in for production, and a request budget).

[1.0.0]: https://www.npmjs.com/package/@nyancorn/agentests-security/v/1.0.0
[0.1.1]: https://www.npmjs.com/package/@nyancorn/agentests-security/v/0.1.1
[0.1.0]: https://www.npmjs.com/package/@nyancorn/agentests-security/v/0.1.0
