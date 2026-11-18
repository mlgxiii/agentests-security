import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import * as pkg from '../src/index.ts';
import { policyJsonSchema } from '../scripts/schema.ts';

/**
 * The 1.x stability contract. A failure here means a breaking change:
 * fix the code, or ship it in a new major version and update STABILITY.md.
 * Minor releases may add exports and report fields; none may be removed or renamed.
 */
describe('1.x stability contract', () => {
	test('the frozen version 1 policy still parses', () => {
		const text = readFileSync(new URL('./fixtures/policy-v1.yaml', import.meta.url), 'utf8');
		const policy = pkg.parseSecurityPolicy(text);
		expect(policy.tests.map((t) => t.id)).toEqual([
			'extraction-rate-limit',
			'extraction-alerting',
			'extraction-quota'
		]);
	});

	test('the shipped JSON Schema matches the code (run `bun scripts/schema.ts` after a compatible change)', () => {
		const shipped = JSON.parse(
			readFileSync(new URL('../schema/policy.schema.json', import.meta.url), 'utf8')
		);
		expect(shipped).toEqual(JSON.parse(JSON.stringify(policyJsonSchema())));
	});

	test('every 1.0 runtime export is still exported', () => {
		expect(Object.keys(pkg)).toEqual(
			expect.arrayContaining([
				'AgentTestSecurityPolicySchema',
				'LOCAL_HOSTS',
				'PROTECTED_DEFENSES',
				'ProbeOrchestrator',
				'RUN_HEADER',
				'SECURITY_PATH',
				'TEST_HEADER',
				'loadSecurityPolicy',
				'parseSecurityPolicy',
				'startMockApi',
				'validateSecurityPolicy'
			])
		);
	});

	test('the JSON report keeps its fields', async () => {
		const policy = pkg.parseSecurityPolicy(
			readFileSync(new URL('./fixtures/policy-v1.yaml', import.meta.url), 'utf8')
		);
		policy.tests = [{ ...policy.tests[2]!, requests: 1 }];
		const fetcher = (async (_url: string | URL | Request, init?: RequestInit) =>
			init?.method === 'POST' ? new Response('{}') : Response.json({ events: [] })) as typeof fetch;
		const report = await new pkg.ProbeOrchestrator(policy, {}, { fetch: fetcher }).run();
		expect(Object.keys(report)).toEqual(
			expect.arrayContaining(['passed', 'policy', 'results', 'runId', 'target', 'total'])
		);
		const [result] = report.results;
		expect(Object.keys(result!)).toEqual(
			expect.arrayContaining(['checks', 'evidence', 'passed', 'test'])
		);
		expect(Object.keys(result!.checks[0]!)).toEqual(
			expect.arrayContaining(['actual', 'detail', 'expectation', 'expected', 'passed'])
		);
		// Optional fields (firstRateLimit, firstQuota, detectionEvents) appear only when observed.
		expect(Object.keys(result!.evidence)).toEqual(
			expect.arrayContaining([
				'elapsedMs',
				'quotaRejected',
				'rateLimited',
				'sent',
				'statuses',
				'succeeded',
				'succeededAfterQuota'
			])
		);
	});
});
