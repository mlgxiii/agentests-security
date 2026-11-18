# Stability

`@lastware/agentests-security` follows [semantic versioning](https://semver.org).
From 1.0.0, everything below is a public contract. It changes in a breaking way only
in a new major version, announced in the [changelog](CHANGELOG.md) at least one minor
release ahead, with a deprecation warning wherever one is possible.

## Covered by the 1.x promise

| Surface | Promise |
| --- | --- |
| Policy file, `version: 1` | Every policy valid on 1.0 stays valid and keeps its meaning on every 1.x release. New optional fields may be added. A breaking format change would introduce `version: 2`, and 1.x would keep reading `version: 1`. |
| [`schema/policy.schema.json`](schema/policy.schema.json) | Matches the format above, and is published at `https://unpkg.com/@lastware/agentests-security@1/schema/policy.schema.json`. |
| CLI | The commands `run`, `validate`, and `mock`, their flags, and the exit codes: 0 means every test passed, 1 means a regression, 2 means an error (an invalid policy, or an unreachable or unauthorized target). |
| `run --json` report | Existing fields keep their names, types, and meanings. New fields may be added. |
| Request headers | `x-agentests-run` and `x-agentests-test` are sent on every request. |
| Safety rules | Defaults never loosen in 1.x: only local hosts unless listed, production only with both opt-ins, and a hard request budget. |
| Library exports | The names exported from the package root, and their documented signatures. |

## Not covered

- **Human-readable output:** the wording of `run`, `validate`, and error messages. Parse `--json`, not text.
- **Prompt wording:** the exact prompts each scenario sends. They stay deterministic within a release, but may change in a minor release to better resemble real extraction traffic. A minor release may also tighten a scenario's traffic shape, so check the changelog when an expectation's result changes after an upgrade.
- **The mock API's internals:** its default limits, response bodies, and event format, beyond what the bundled example policy needs to pass.
- **Undocumented modules:** anything imported from a path inside `dist/`.

## Supported versions

The latest 1.x minor release gets fixes. When 2.0 ships, the last 1.x release gets
security fixes for 6 months.

These promises are enforced by `tests/contract.test.ts`: a frozen version 1 policy,
the shipped schema, the export list, and the report fields.
