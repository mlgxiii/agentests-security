# agentests-security

Test your AI API's defenses against model extraction in CI. A security policy sends
bounded, deterministic attack traffic to a local or explicitly authorized endpoint,
then checks that the rate limits, quotas, and detection events still fire. If one of
them regresses, the run exits 1 and CI fails.

```
PASS  extraction-rate-limit  rate_limit_enforced: expected true, got true (first rate-limited at request 21 of 60; 39 rejected)
PASS  extraction-alerting  detection_event: expected true, got true (1 new detection event(s))
FAIL  extraction-quota  quota_enforced: expected true, got false (no quota response in 80 requests)
Result: 2 of 3 security test(s) passed.
```

This is the security runner proposed for [agentests](https://github.com/feuersteiner/agentests)
in [PR #105](https://github.com/feuersteiner/agentests/pull/105), published on its own.
It needs no model or API key. Requires Node.js 22+.

## Try it in one minute

```sh
# 1. A local mock AI API with every defense switched on
npx @nyancorn/agentests-security mock

# 2. In another terminal: fetch the example policy and run it (about 13 seconds)
curl -O https://raw.githubusercontent.com/mlgxiii/agentests/main/examples/security/agentests.security.yaml
npx @nyancorn/agentests-security run
```

Restart the mock with `--disable rate-limit`, `quota`, or `detection`, then run the
policy again to see that defense's test fail.

## Point it at your API

Write `agentests.security.yaml`:

```yaml
version: 1
name: model-extraction-protection
target:
  url: https://staging.api.example.com/v1/complete
  environment: staging
  headers:
    authorization: 'Bearer ${STAGING_API_KEY}' # read from the environment or .env
  body:
    model: my-model
    messages: [{ role: user, content: '{{prompt}}' }]
tests:
  - id: extraction-rate-limit
    scenario: sustained-query-volume
    requests: 120
    duration_seconds: 10
    expect: { rate_limit_enforced: true }
safety:
  max_requests: 200
  allowed_hosts: [staging.api.example.com]
```

```sh
npx @nyancorn/agentests-security validate       # check the policy without sending anything
npx @nyancorn/agentests-security run [id]       # exit 0 pass, 1 regression, 2 error
npx @nyancorn/agentests-security run --json     # full report with evidence, for CI artifacts
```

The [policy reference](https://github.com/mlgxiii/agentests/tree/main/examples/security#the-policy)
covers every field: the three scenarios, the response signals, the detection
endpoint, and the safety limits.

## Safety

- **Allowed hosts:** only `localhost`, `127.0.0.1`, and `::1` by default. Any other host
  must be listed in `safety.allowed_hosts`.
- **Production:** a production target needs `safety.allow_production: true` in the policy
  and the `--allow-production` flag on the command line.
- **Request budget:** `safety.max_requests` is checked before anything is sent, and again
  as a hard stop during the run.
- **Credentials:** URLs that contain credentials are rejected. Put secrets in headers as
  `${VAR}` references instead.
- **Traceability:** every request carries `x-agentests-run` and `x-agentests-test` headers,
  so your logs can tell test traffic apart.

Only test APIs you own or are authorized to test.

## Library

```ts
import { parseSecurityPolicy, ProbeOrchestrator } from '@nyancorn/agentests-security';

const report = await new ProbeOrchestrator(parseSecurityPolicy(yamlText), process.env).run();
```

## License

MIT
