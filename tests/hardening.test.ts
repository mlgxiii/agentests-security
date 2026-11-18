import { afterEach, describe, expect, test } from 'bun:test';
import {
	ProbeOrchestrator,
	securityPolicyWarnings,
	startMockApi,
	validateSecurityPolicy
} from '../src/index.ts';
import type { MockApi } from '../src/index.ts';
import { MAX_BODY, MAX_EVENTS_BODY, readCapped, send } from '../src/probe/http.ts';
import { REDACTED, redactText } from '../src/probe/redact.ts';
import { policyWith, rawPolicy } from './helpers.ts';

let api: MockApi | undefined;
afterEach(async () => {
	await api?.close();
	api = undefined;
});

const REMOTE = 'api.example.com';

/** A validated policy against a remote host, with these target fields, Tests, and safety fields merged in. */
const remotePolicy = (
	target: Record<string, unknown> = {},
	tests?: unknown[],
	safety: Record<string, unknown> = {}
) =>
	validateSecurityPolicy(
		rawPolicy(`https://${REMOTE}`, {
			target: { url: `https://${REMOTE}/v1/complete`, environment: 'staging', ...target },
			...(tests ? { tests } : {}),
			safety: { max_requests: 100, allowed_hosts: [REMOTE], ...safety }
		})
	);

/** A fetch answering POSTs with `status` and the events endpoint with whatever `events()` returns at that moment. */
const fake = (status = 200, events: () => unknown[] = () => []) =>
	(async (_url: string | URL | Request, init?: RequestInit) =>
		init?.method === 'POST'
			? new Response('{}', { status })
			: Response.json({ events: events() })) as typeof fetch;

/** A response whose body never ends: `chunk` bytes at a time, forever. */
const endless = (chunk = 16 * 1024): Response => {
	const bytes = new Uint8Array(chunk).fill(120);
	return new Response(new ReadableStream({ pull: (controller) => controller.enqueue(bytes) }));
};

describe('TLS for remote targets', () => {
	test('plain HTTP to a remote host is a warning, not an error, in 1.x', () => {
		const policy = remotePolicy({ url: `http://${REMOTE}/v1/complete`, detection: undefined });
		expect(securityPolicyWarnings(policy)).toEqual([
			`target.url: Plain HTTP to ${REMOTE} sends credentials unencrypted; use https, or set safety.allow_insecure_http: true. This becomes an error in 2.0.`
		]);
	});

	test('https, local hosts, and allow_insecure_http raise no warning', () => {
		expect(securityPolicyWarnings(remotePolicy({ detection: undefined }))).toEqual([]);
		expect(securityPolicyWarnings(validateSecurityPolicy(rawPolicy()))).toEqual([]);
		const accepted = remotePolicy(
			{ url: `http://${REMOTE}/v1/complete`, detection: undefined },
			undefined,
			{ allow_insecure_http: true }
		);
		expect(securityPolicyWarnings(accepted)).toEqual([]);
	});

	test('the report carries the warnings', async () => {
		const policy = remotePolicy({ url: `http://${REMOTE}/v1/complete`, detection: undefined }, [
			{
				id: 'rate',
				scenario: 'sustained-query-volume',
				requests: 1,
				expect: { rate_limit_enforced: false }
			}
		]);
		const report = await new ProbeOrchestrator(policy, {}, { fetch: fake() }).run();
		expect(report.warnings).toHaveLength(1);
	});
});

describe('detection correlated to the run', () => {
	const detectTest = {
		id: 'detect',
		scenario: 'systematic-query-pattern',
		requests: 2,
		expect: { detection_event: true }
	};

	test('with run_field, an event from another run does not count', async () => {
		let events: unknown[] = [];
		const fetcher = (async (url: string | URL | Request, init?: RequestInit) => {
			if (init?.method === 'POST') {
				events = [{ run: 'someone-else' }];
				return new Response('{}');
			}
			return Response.json(events);
		}) as typeof fetch;
		const detection = { url: `https://${REMOTE}/events` };
		const loose = remotePolicy({ detection }, [detectTest]);
		const strict = remotePolicy({ detection: { ...detection, run_field: 'run' } }, [detectTest]);
		const looseReport = await new ProbeOrchestrator(loose, {}, { fetch: fetcher }).run();
		events = [];
		const strictReport = await new ProbeOrchestrator(strict, {}, { fetch: fetcher }).run();
		expect(looseReport.results[0]!.evidence).toMatchObject({
			detectionEvents: 1,
			detectionCorrelated: false
		});
		expect(strictReport.results[0]!.evidence).toMatchObject({
			detectionEvents: 0,
			detectionCorrelated: true
		});
		expect(strictReport.results[0]!.passed).toBe(false);
	});

	test('the mock tags events with the run, so run_field counts this run only', async () => {
		api = await startMockApi({ port: 0, defenses: { detection: { threshold: 2 } } });
		const policy = validateSecurityPolicy(
			rawPolicy(api.url, {
				target: {
					url: `${api.url}/v1/complete`,
					environment: 'test',
					detection: { url: `${api.url}/v1/security/events`, run_field: 'run' }
				},
				tests: [detectTest]
			})
		);
		const report = await new ProbeOrchestrator(policy, {}, { runId: 'run-1' }).run();
		expect(api.events.map((event) => event.run)).toEqual(['run-1']);
		expect(report.results[0]!.checks[0]!.detail).toBe('1 new detection event(s) for this run');
	});

	test('detection headers may carry {{run_id}}, for APIs that filter server-side', async () => {
		const seen: Record<string, string>[] = [];
		const fetcher = (async (_url: string | URL | Request, init?: RequestInit) => {
			if (init?.method !== 'POST') seen.push(init?.headers as Record<string, string>);
			return init?.method === 'POST' ? new Response('{}') : Response.json([]);
		}) as typeof fetch;
		const policy = remotePolicy(
			{ detection: { url: `https://${REMOTE}/events`, headers: { 'x-run': '{{run_id}}' } } },
			[detectTest]
		);
		await new ProbeOrchestrator(policy, {}, { fetch: fetcher, runId: 'run-9' }).run();
		expect(seen[0]!['x-run']).toBe('run-9');
	});
});

describe('stricter verdicts', () => {
	test('rate_limit_within fails a limit that fires too late', async () => {
		const statuses = [200, 200, 200, 429, 429];
		let index = 0;
		const fetcher = (async (_url: string | URL | Request, init?: RequestInit) =>
			init?.method === 'POST'
				? new Response('{}', { status: statuses[index++] ?? 429 })
				: Response.json([])) as typeof fetch;
		const run = async (within: number) => {
			index = 0;
			const policy = remotePolicy({ detection: undefined }, [
				{
					id: 'rate',
					scenario: 'sustained-query-volume',
					requests: 5,
					expect: { rate_limit_enforced: true, rate_limit_within: within }
				}
			]);
			return (await new ProbeOrchestrator(policy, {}, { fetch: fetcher }).run()).results[0]!;
		};
		const late = await run(3);
		expect(late.passed).toBe(false);
		expect(late.checks[0]!.detail).toBe('first rate-limited at request 4, after the limit of 3');
		expect((await run(4)).passed).toBe(true);
	});

	test('a *_within needs its expectation set to true, and fits in the Test', () => {
		const test = (expect: Record<string, unknown>) => [
			{ id: 'rate', scenario: 'sustained-query-volume', requests: 10, expect }
		];
		expect(() =>
			policyWith('http://127.0.0.1:1', test({ rate_limit_enforced: false, rate_limit_within: 3 }))
		).toThrow('tests.0.expect.rate_limit_within: Requires rate_limit_enforced: true');
		expect(() =>
			policyWith('http://127.0.0.1:1', test({ quota_enforced: true, quota_within: 11 }))
		).toThrow("tests.0.expect.quota_within: 11 is more than the Test's 10 requests");
		expect(() => policyWith('http://127.0.0.1:1', test({ rate_limit_within: 3 }))).toThrow(
			'Expected at least one expectation'
		);
	});

	test('a target that mostly errors makes the Test inconclusive instead of passing', async () => {
		const tests = (max?: number) => [
			{
				id: 'no-limit',
				scenario: 'sustained-query-volume',
				requests: 10,
				...(max === undefined ? {} : { max_error_rate: max }),
				expect: { rate_limit_enforced: false }
			}
		];
		const broken = remotePolicy({ detection: undefined }, tests());
		const result = (await new ProbeOrchestrator(broken, {}, { fetch: fake(500) }).run())
			.results[0]!;
		expect(result.checks[0]!.passed).toBe(true);
		expect(result.passed).toBe(false);
		expect(result.evidence.errors).toBe(10);
		expect(result.inconclusive).toBe(
			'10 of 10 responses were errors matching no signal (non-2xx: 500×10), over max_error_rate 0.05'
		);
		const tolerant = remotePolicy({ detection: undefined }, tests(1));
		expect((await new ProbeOrchestrator(tolerant, {}, { fetch: fake(500) }).run()).passed).toBe(1);
	});
});

describe('response limits', () => {
	test('an endless completion stream is cut at 64 KiB instead of hanging the run', async () => {
		const fetcher = (async () => endless()) as unknown as typeof fetch;
		const response = await send(fetcher, 'https://x.test', {}, {}, 5_000);
		expect(response.body.length).toBe(MAX_BODY);
	});

	test('readCapped reports a short body whole and untruncated', async () => {
		expect(await readCapped(new Response('hello'), 10)).toEqual({
			text: 'hello',
			truncated: false
		});
		expect(await readCapped(new Response('hello'), 5)).toEqual({ text: 'hello', truncated: false });
		expect(await readCapped(new Response('hello!'), 5)).toEqual({ text: 'hello', truncated: true });
	});

	test('an events list over 4 MiB is an error, not a guess', async () => {
		const fetcher = (async (_url: string | URL | Request, init?: RequestInit) =>
			init?.method === 'POST' ? new Response('{}') : endless(MAX_EVENTS_BODY / 4)) as typeof fetch;
		const policy = remotePolicy({ detection: { url: `https://${REMOTE}/events` } }, [
			{
				id: 'detect',
				scenario: 'systematic-query-pattern',
				requests: 1,
				expect: { detection_event: true }
			}
		]);
		await expect(new ProbeOrchestrator(policy, {}, { fetch: fetcher }).run()).rejects.toThrow(
			'returned more than 4 MiB'
		);
	});
});

describe('secret redaction', () => {
	const SECRET = 'sk-test-0123456789abcdef';

	test('a secret the policy sends never appears in a thrown message', async () => {
		const fetcher = (async (_url: string | URL | Request, init?: RequestInit) => {
			const headers = init?.headers as Record<string, string>;
			throw new Error(`connection reset while sending ${headers.authorization}`);
		}) as typeof fetch;
		const policy = remotePolicy({
			detection: undefined,
			headers: { authorization: 'Bearer ${API_KEY}' }
		});
		const error = await new ProbeOrchestrator(policy, { API_KEY: SECRET }, { fetch: fetcher })
			.run()
			.catch((caught: unknown) => caught as Error);
		expect(error.message).toContain(`Bearer ${REDACTED}`);
		expect(error.message).not.toContain(SECRET);
		expect(error.cause).toBeUndefined();
	});

	test('the report hides literal keys in headers and URLs, and keeps ${VAR} references', async () => {
		const policy = remotePolicy(
			{ url: `https://${REMOTE}/v1/complete?api_key=${SECRET}&model=m`, detection: undefined },
			[
				{
					id: 'rate',
					scenario: 'sustained-query-volume',
					requests: 1,
					headers: { 'x-api-key': SECRET, authorization: 'Bearer ${API_KEY}', 'x-tenant': 'acme' },
					expect: { rate_limit_enforced: false }
				}
			]
		);
		const report = await new ProbeOrchestrator(
			policy,
			{ API_KEY: SECRET },
			{ fetch: fake() }
		).run();
		const text = JSON.stringify(report);
		expect(text).not.toContain(SECRET);
		expect(report.target.url).toBe(
			`https://${REMOTE}/v1/complete?api_key=${encodeURIComponent(REDACTED)}&model=m`
		);
		expect(report.results[0]!.test.headers).toEqual({
			'x-api-key': REDACTED,
			authorization: 'Bearer ${API_KEY}',
			'x-tenant': 'acme'
		});
	});

	test('redactText redacts sensitive query parameters and leaves ordinary URLs alone', () => {
		expect(redactText('status 429 at https://a.test/v1?model=m', [])).toBe(
			'status 429 at https://a.test/v1?model=m'
		);
		expect(redactText('GET https://a.test/v1?token=abc failed', [])).toBe(
			`GET https://a.test/v1?token=${encodeURIComponent(REDACTED)} failed`
		);
	});
});
