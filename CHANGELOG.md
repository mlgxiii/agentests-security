# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com), and the project follows
[semantic versioning](https://semver.org) as described in [STABILITY.md](STABILITY.md).

## [1.0.0] - 2026-11-18

First stable release, under its new name `@lastware/agentests-security`.

### Added

- **Stability promise:** [STABILITY.md](STABILITY.md) covers the version 1 policy format,
  the CLI and its exit codes, the JSON report, and the library exports. Contract tests
  enforce it.
- **JSON Schema:** `schema/policy.schema.json` describes the policy file. Point your
  editor at it for autocompletion and validation.
- **Security policy:** [SECURITY.md](SECURITY.md) explains private vulnerability
  reporting, what's in scope, and authorized use.
- **Release workflow:** from 1.0.1 on, releases are published from GitHub Actions
  through npm trusted publishing, with provenance. 1.0.0 itself was published by hand
  to create the package.
- **CI:** every push and pull request runs the type check, the tests, and a pack check
  on Node.js 22 and 24.

### Changed

- **New package name:** `@nyancorn/agentests-security` is now
  `@lastware/agentests-security`. The CLI is still called `agentests-security`.
  Update the name in `package.json` or in `npx` commands; nothing else changes.

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

[1.0.0]: https://github.com/mlgxiii/agentests-security/releases/tag/v1.0.0
[0.1.1]: https://www.npmjs.com/package/@nyancorn/agentests-security/v/0.1.1
[0.1.0]: https://www.npmjs.com/package/@nyancorn/agentests-security/v/0.1.0
