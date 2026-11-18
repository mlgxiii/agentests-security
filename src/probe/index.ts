import { randomUUID } from 'node:crypto';
import type { AgentTestSecurityPolicy } from '../policy/types.ts';
import { expandHeaders, expandValue, readEvents, send } from './http.ts';
import type { ProbeResponse } from './http.ts';
import { scenarioPrompt } from './scenarios.ts';
import type {
	AgentTestSecurityEvidence,
	AgentTestSecurityReport,
	AgentTestSecurityResult,
	AgentTestSecurityTest,
	AgentTestSignal
} from './types.ts';
import { policySecrets, redactTest, redactText, redactUrl } from './redact.ts';
import { message, sleep } from './utils.ts';
import { securityPolicyWarnings } from '../policy/validate.ts';
import { inconclusive, judge } from './verdict.ts';

/** Seams for tests and callers: the HTTP client, the clock, and a callback after each Test. */
export interface ProbeOptions {
	fetch?: typeof fetch;
	now?: () => number;
	sleep?: (ms: number) => Promise<void>;
	runId?: string;
	onResult?: (result: AgentTestSecurityResult) => void;
}

/** Headers sent on every request, so the target's logs can tell test traffic apart. */
export const RUN_HEADER = 'x-agentests-run';
export const TEST_HEADER = 'x-agentests-test';

/** Whether a response is the signal: one of its statuses and, when set, a body matching its case-insensitive regex. */
const matches = ({ status, body }: AgentTestSignal, response: ProbeResponse): boolean =>
	status.includes(response.status) &&
	(body === undefined || new RegExp(body, 'i').test(response.body));

/** The Test with `id` and, first, its baseline chain, in policy order; empty when no Test has `id`. */
const withBaselines = (tests: AgentTestSecurityTest[], id: string): AgentTestSecurityTest[] => {
	const needed = new Set<string>();
	let current = tests.find((test) => test.id === id);
	while (current && !needed.has(current.id)) {
		needed.add(current.id);
		const baseline: string | undefined = current.baseline;
		current = baseline === undefined ? undefined : tests.find((test) => test.id === baseline);
	}
	return tests.filter((test) => needed.has(test.id));
};

/**
 * Runs a validated security policy against its target: each Test sends its scenario one request at a time,
 * spread over `duration_seconds`, never more than `safety.max_requests` in the whole run, then judges the evidence.
 * Built once per policy from the policy and an environment map for `${VAR}` references, never the process environment.
 */
export class ProbeOrchestrator {
	readonly #policy: AgentTestSecurityPolicy;
	readonly #env: Record<string, string | undefined>;
	readonly #fetch: typeof fetch;
	readonly #now: () => number;
	readonly #sleep: (ms: number) => Promise<void>;
	readonly #runId: string;
	readonly #onResult?: (result: AgentTestSecurityResult) => void;
	#budget = 0;

	constructor(
		policy: AgentTestSecurityPolicy,
		env: Record<string, string | undefined>,
		options: ProbeOptions = {}
	) {
		this.#policy = policy;
		this.#env = env;
		this.#fetch = options.fetch ?? fetch;
		this.#now = options.now ?? Date.now;
		this.#sleep = options.sleep ?? sleep;
		this.#runId = options.runId ?? randomUUID();
		this.#onResult = options.onResult;
	}

	/**
	 * Run every Test in policy order, or only the one with `id`; throws on an unknown id or an unreachable target.
	 * Secrets the policy sends never appear in the report or in a thrown message.
	 */
	readonly run = async (id?: string): Promise<AgentTestSecurityReport> => {
		const secrets = policySecrets(this.#policy, this.#env);
		try {
			return await this.#run(id);
		} catch (error) {
			throw new Error(redactText(message(error), secrets));
		}
	};

	readonly #run = async (id?: string): Promise<AgentTestSecurityReport> => {
		const { name, target, tests } = this.#policy;
		const selected = id === undefined ? tests : withBaselines(tests, id);
		if (!selected.length) throw new Error(`Unknown security test: ${id}`);
		this.#budget = this.#policy.safety.max_requests;
		const results: AgentTestSecurityResult[] = [];
		const blockedRates = new Map<string, number>();
		for (const test of selected) {
			const evidence = await this.#probe(test);
			blockedRates.set(test.id, evidence.blockedRate);
			if (test.baseline !== undefined)
				evidence.baselineBlockedRate = blockedRates.get(test.baseline) ?? 0;
			const checks = judge(test.expect, evidence);
			const reason = inconclusive(test, evidence);
			const result: AgentTestSecurityResult = {
				test: redactTest(test),
				passed: reason === undefined && checks.every((check) => check.passed),
				...(reason === undefined ? {} : { inconclusive: reason }),
				checks,
				evidence
			};
			results.push(result);
			this.#onResult?.(result);
		}
		return {
			policy: name,
			runId: this.#runId,
			target: { url: redactUrl(target.url), environment: target.environment },
			passed: results.filter((result) => result.passed).length,
			total: results.length,
			results,
			warnings: securityPolicyWarnings(this.#policy)
		};
	};

	/** This run's share of the detection events: all of them, or with `run_field` only those carrying this run's id. */
	readonly #countEvents = async (headers: Record<string, string>): Promise<number> => {
		const { detection, timeout_ms } = this.#policy.target;
		if (!detection) return 0;
		const events = await readEvents(this.#fetch, detection.url, headers, timeout_ms);
		const field = detection.run_field;
		if (field === undefined) return events.length;
		return events.filter(
			(event) =>
				!!event &&
				typeof event === 'object' &&
				String((event as Record<string, unknown>)[field]) === this.#runId
		).length;
	};

	/** Send one Test's scenario and collect its evidence. */
	readonly #probe = async (test: AgentTestSecurityTest): Promise<AgentTestSecurityEvidence> => {
		const { target } = this.#policy;
		const detection = test.expect.detection_event !== undefined ? target.detection : undefined;
		const detectionHeaders = detection
			? expandHeaders(detection.headers, this.#env, { run_id: this.#runId })
			: {};
		const before = detection ? await this.#countEvents(detectionHeaders) : 0;
		const interval = (test.duration_seconds * 1000) / test.requests;
		const keys = test.keys ?? [{}];
		const evidence: AgentTestSecurityEvidence = {
			sent: 0,
			statuses: {},
			succeeded: 0,
			rateLimited: 0,
			quotaRejected: 0,
			succeededAfterQuota: 0,
			errors: 0,
			keys: keys.length,
			blockedRate: 0,
			elapsedMs: 0
		};
		const start = this.#now();
		let last: number | undefined;
		for (let index = 0; index < test.requests; index++) {
			if (this.#budget <= 0)
				throw new Error(`Stopped at safety.max_requests (${this.#policy.safety.max_requests})`);
			if (last !== undefined && interval > 0) await this.#sleep(last + interval - this.#now());
			last = this.#now();
			const keyIndex = index % keys.length;
			const placeholders = {
				prompt: scenarioPrompt(test.scenario, index),
				index: String(index),
				scenario: test.scenario,
				run_id: this.#runId,
				key_index: String(keyIndex)
			};
			const headers = {
				...expandHeaders(
					{ ...target.headers, ...test.headers, ...keys[keyIndex] },
					this.#env,
					placeholders
				),
				[RUN_HEADER]: this.#runId,
				[TEST_HEADER]: test.id
			};
			const body = expandValue(target.body, this.#env, placeholders);
			this.#budget--;
			const response = await send(this.#fetch, target.url, headers, body, target.timeout_ms);
			this.#record(evidence, response);
		}
		if (detection) {
			const deadline = this.#now() + detection.wait_ms;
			let after = await this.#countEvents(detectionHeaders);
			while (after <= before && this.#now() < deadline) {
				await this.#sleep(Math.min(250, deadline - this.#now()));
				after = await this.#countEvents(detectionHeaders);
			}
			evidence.detectionEvents = Math.max(0, after - before);
			evidence.detectionCorrelated = detection.run_field !== undefined;
		}
		evidence.blockedRate = evidence.sent
			? (evidence.rateLimited + evidence.quotaRejected) / evidence.sent
			: 0;
		evidence.elapsedMs = this.#now() - start;
		return evidence;
	};

	/** Classify one response, quota first, and update the counts. */
	readonly #record = (evidence: AgentTestSecurityEvidence, response: ProbeResponse): void => {
		const { signals } = this.#policy.target;
		evidence.sent++;
		evidence.statuses[response.status] = (evidence.statuses[response.status] ?? 0) + 1;
		if (matches(signals.quota, response)) {
			evidence.quotaRejected++;
			evidence.firstQuota ??= evidence.sent;
		} else if (matches(signals.rate_limit, response)) {
			evidence.rateLimited++;
			evidence.firstRateLimit ??= evidence.sent;
		} else if (response.status >= 200 && response.status < 300) {
			evidence.succeeded++;
			if (evidence.firstQuota !== undefined) evidence.succeededAfterQuota++;
		} else evidence.errors++;
	};
}
