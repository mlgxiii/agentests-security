import { afterEach, describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import {
	parseSecurityPolicy,
	PROTECTED_DEFENSES,
	ProbeOrchestrator,
	startMockApi,
	validateSecurityPolicy
} from '../src/index.ts';
import type { MockApi, MockDefenses } from '../src/index.ts';
import { scenarioPrompt } from '../src/probe/scenarios.ts';
import { REDACTED } from '../src/probe/redact.ts';
import { policyWith, rawPolicy } from './helpers.ts';

let api: MockApi | undefined;
afterEach(async () => {
	await api?.close();
	api = undefined;
});

/** A clock that only moves when the runner sleeps, shared by the runner and the mock, so paced Tests run instantly. */
const fakeClock = () => {
	let time = 1_000_000;
	return {
		now: () => time,
		sleep: async (ms: number) => {
			time += Math.max(0, ms);
		}
	};
};

/** The example policy, pointed at `url` instead of the default mock port. */
const examplePolicy = (url: string) =>
	parseSecurityPolicy(
		readFileSync(
			new URL('../examples/realistic.security.yaml', import.meta.url),
			'utf8'
		).replaceAll('http://127.0.0.1:4010', url)
	);

/** Run the example policy against a mock with every defense except `without`, on a fake clock. */
const runExample = async (without?: keyof MockDefenses) => {
	const clock = fakeClock();
	const defenses: MockDefenses = { ...PROTECTED_DEFENSES };
	if (without) delete defenses[without];
	api = await startMockApi({ port: 0, defenses, now: clock.now });
	return new ProbeOrchestrator(examplePolicy(api.url), {}, clock).run();
};

/** The digit-masked template, as the mock's per-key detector sees a prompt. */
const template = (prompt: string) => prompt.replace(/\d+/g, '#');

describe('realistic scenarios', () => {
	test('paraphrased-extraction never repeats a template in a row, and every prompt asks for a label and confidence', () => {
		const prompts = Array.from({ length: 40 }, (_, i) =>
			scenarioPrompt('paraphrased-extraction', i)
		);
		for (let i = 1; i < prompts.length; i++)
			expect(template(prompts[i]!)).not.toBe(template(prompts[i - 1]!));
		const counts = new Map<string, number>();
		for (const prompt of prompts)
			counts.set(template(prompt), (counts.get(template(prompt)) ?? 0) + 1);
		expect(Math.max(...counts.values())).toBeLessThan(25);
		expect(scenarioPrompt('paraphrased-extraction', 7)).toBe(
			scenarioPrompt('paraphrased-extraction', 7)
		);
	});

	test('legitimate-usage prompts are varied questions with no label-and-confidence ask', () => {
		const prompts = Array.from({ length: 20 }, (_, i) => scenarioPrompt('legitimate-usage', i));
		expect(new Set(prompts).size).toBe(20);
		for (const prompt of prompts) expect(prompt).not.toMatch(/confiden|probabilit|label/i);
	});
});

describe('multi-key Tests', () => {
	test('keys rotate one header set per request, with {{key_index}}', async () => {
		const seen: Record<string, string>[] = [];
		const fetcher = (async (_url: string | URL | Request, init?: RequestInit) => {
			seen.push(init?.headers as Record<string, string>);
			return new Response('{}');
		}) as typeof fetch;
		const policy = policyWith('http://127.0.0.1:1', [
			{
				id: 'spread',
				scenario: 'sustained-query-volume',
				requests: 5,
				headers: { 'x-client': 'k{{key_index}}' },
				keys: [{ authorization: 'Bearer a' }, { authorization: 'Bearer b' }],
				expect: { rate_limit_enforced: false }
			}
		]);
		const report = await new ProbeOrchestrator(policy, {}, { fetch: fetcher }).run();
		expect(seen.map((h) => `${h.authorization} ${h['x-client']}`)).toEqual([
			'Bearer a k0',
			'Bearer b k1',
			'Bearer a k0',
			'Bearer b k1',
			'Bearer a k0'
		]);
		expect(report.results[0]!.evidence.keys).toBe(2);
	});

	test('literal keys are redacted in the report', async () => {
		const fetcher = (async () => new Response('{}')) as unknown as typeof fetch;
		const policy = policyWith('http://127.0.0.1:1', [
			{
				id: 'spread',
				scenario: 'sustained-query-volume',
				requests: 2,
				keys: [{ authorization: 'Bearer sk-literal-123456' }, { authorization: 'Bearer ${KEY_B}' }],
				expect: { rate_limit_enforced: false }
			}
		]);
		const report = await new ProbeOrchestrator(
			policy,
			{ KEY_B: 'sk-env-abcdef' },
			{ fetch: fetcher }
		).run();
		expect(report.results[0]!.test.keys).toEqual([
			{ authorization: REDACTED },
			{ authorization: 'Bearer ${KEY_B}' }
		]);
		expect(JSON.stringify(report)).not.toContain('sk-literal-123456');
	});
});

describe('blocked-rate thresholds and baselines', () => {
	/** A fetch that rate-limits every request whose index is in `blocked`. */
	const blocking = (blocked: (index: number) => boolean) => {
		let index = 0;
		return (async () =>
			new Response('{}', { status: blocked(index++) ? 429 : 200 })) as unknown as typeof fetch;
	};

	test('min_blocked_rate and max_blocked_rate bound the share of rejected requests', async () => {
		const policy = policyWith('http://127.0.0.1:1', [
			{
				id: 'half',
				scenario: 'sustained-query-volume',
				requests: 10,
				expect: { min_blocked_rate: 0.4, max_blocked_rate: 0.6 }
			}
		]);
		const half = await new ProbeOrchestrator(
			policy,
			{},
			{ fetch: blocking((i) => i % 2 === 1) }
		).run();
		expect(half.results[0]!.checks).toEqual([
			{
				expectation: 'blocked_rate',
				expected: true,
				actual: true,
				passed: true,
				detail: 'blocked 50% of 10 requests; expected at least 40% and at most 60%'
			}
		]);
		const all = await new ProbeOrchestrator(policy, {}, { fetch: blocking(() => true) }).run();
		expect(all.results[0]!.passed).toBe(false);
		expect(all.results[0]!.evidence.blockedRate).toBe(1);
	});

	test('min_blocked_rate_gain compares against the baseline, and run(id) runs the baseline first', async () => {
		const tests = [
			{
				id: 'normal',
				scenario: 'legitimate-usage',
				requests: 4,
				expect: { max_blocked_rate: 0.5 }
			},
			{
				id: 'attack',
				scenario: 'sustained-query-volume',
				requests: 4,
				baseline: 'normal',
				expect: { min_blocked_rate_gain: 0.5 }
			}
		];
		// The first 4 requests (the baseline) get 1 rejection; the attack gets 4.
		const fetcher = blocking((i) => i === 0 || i >= 4);
		const report = await new ProbeOrchestrator(
			policyWith('http://127.0.0.1:1', tests),
			{},
			{ fetch: fetcher }
		).run('attack');
		expect(report.results.map((r) => r.test.id)).toEqual(['normal', 'attack']);
		const attack = report.results[1]!;
		expect(attack.evidence.baselineBlockedRate).toBe(0.25);
		expect(attack.checks[0]!.detail).toBe(
			'blocked 100% against 25% for the baseline; expected a gain of at least 50%'
		);
		expect(attack.passed).toBe(true);
	});

	test('baselines must name an earlier Test, and a gain needs one', () => {
		const attack = { id: 'attack', scenario: 'sustained-query-volume', requests: 4 };
		const check = (tests: unknown[]) => () =>
			validateSecurityPolicy(rawPolicy(undefined, { tests }));
		expect(check([{ ...attack, baseline: 'later', expect: { min_blocked_rate: 0.5 } }])).toThrow(
			'tests.0.baseline: No earlier Test has id later'
		);
		expect(check([{ ...attack, baseline: 'attack', expect: { min_blocked_rate: 0.5 } }])).toThrow(
			'tests.0.baseline: A Test cannot be its own baseline'
		);
		expect(check([{ ...attack, expect: { min_blocked_rate_gain: 0.5 } }])).toThrow(
			'tests.0.expect.min_blocked_rate_gain: Requires baseline'
		);
		expect(
			check([{ ...attack, expect: { min_blocked_rate: 0.8, max_blocked_rate: 0.2 } }])
		).toThrow('tests.0.expect.min_blocked_rate: 0.8 is above max_blocked_rate 0.2');
	});
});

describe('the realistic example policy against the mock', () => {
	test('passes against a fully protected API', async () => {
		const report = await runExample();
		expect(report.results.map((r) => [r.test.id, r.passed])).toEqual([
			['legitimate-baseline', true],
			['distributed-scrape', true],
			['distributed-probe', true],
			['paraphrased-probe', true]
		]);
	});

	test.each([
		['accountRateLimit', 'distributed-scrape'],
		['crossKeyDetection', 'distributed-probe'],
		['intentDetection', 'paraphrased-probe']
	] as const)('without %s, only %s fails', async (defense, failing) => {
		const report = await runExample(defense);
		expect(report.results.filter((r) => !r.passed).map((r) => r.test.id)).toEqual([failing]);
	});

	test('per-key defenses alone miss both distributed and paraphrased attacks', async () => {
		const clock = fakeClock();
		const { rateLimit, quota, detection } = PROTECTED_DEFENSES;
		api = await startMockApi({
			port: 0,
			defenses: { rateLimit, quota, detection },
			now: clock.now
		});
		const report = await new ProbeOrchestrator(examplePolicy(api.url), {}, clock).run();
		expect(report.results.filter((r) => !r.passed).map((r) => r.test.id)).toEqual([
			'distributed-scrape',
			'distributed-probe',
			'paraphrased-probe'
		]);
	});
});
