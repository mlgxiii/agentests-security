# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub:
**[Report a vulnerability](https://github.com/mlgxiii/agentests-security/security/advisories/new)**.
Please don't open a public issue.

Include the version, a description, and the steps or a policy file that reproduce it.
You can expect an acknowledgement within 3 business days and a fix or mitigation
plan within 14 days. Fixes are announced in a GitHub security advisory and the
[changelog](CHANGELOG.md), with credit if you want it.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x (latest minor) | Yes |
| 0.x | No. Upgrade to 1.x. |

## In scope

Ways to make the runner do something its safety rules should prevent:

- sending a request to a host that the policy doesn't authorize
- running against a production target without both opt-ins
- sending more requests than `safety.max_requests`
- leaking a `${VAR}` value into output, the report, or a host it wasn't meant for
- a malicious policy file executing code or reading files beyond the policy itself

## Authorized use

This tool generates traffic that resembles a model extraction attack. Only run it
against APIs you own or have written permission to test. The safety rules guard
against mistakes; they don't make unauthorized testing acceptable.

## Supply chain

Every release from 1.0.0 on is published from [GitHub Actions](.github/workflows/release.yml)
through npm trusted publishing, with [npm provenance](https://docs.npmjs.com/generating-provenance-statements)
and no long-lived npm token. (The 0.x releases were published by hand.)
You can check that a release was built from this repository:

```sh
npm audit signatures
```

The package has three runtime dependencies (`zod`, `yaml`, and `clinguini`) and no
install scripts.
