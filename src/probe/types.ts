import { z } from 'zod';
import { IdSchema, TextSchema } from './shared.ts';

/** The traffic shapes a security Test can send; each one is generated deterministically from the request index. */
export const ScenarioSchema = z.enum([
	'sustained-query-volume',
	'systematic-query-pattern',
	'quota-exhaustion'
]);
export type AgentTestScenario = z.infer<typeof ScenarioSchema>;

/** The deployment stage the target belongs to; `production` needs explicit authorization twice. */
export const EnvironmentSchema = z.enum(['local', 'test', 'staging', 'production']);
export type AgentTestEnvironment = z.infer<typeof EnvironmentSchema>;

/** Header names to values; values may hold `${VAR}` references to the environment map and `{{…}}` placeholders. */
export const HeadersSchema = z.record(z.string().min(1), z.string());

/** How a response is recognized as one defense firing: one of these statuses and, when `body` is set, a body matching that case-insensitive regex. */
export const SignalSchema = z.strictObject({
	status: z.array(z.number().int().min(100).max(599)).min(1),
	body: TextSchema.optional()
});
export type AgentTestSignal = z.infer<typeof SignalSchema>;

/** Response classification; quota is tried before rate limit, so an OpenAI-style `429 insufficient_quota` counts as quota. */
export const SignalsSchema = z.strictObject({
	rate_limit: SignalSchema.default({ status: [429] }),
	quota: SignalSchema.default({ status: [402, 403, 429], body: 'quota' })
});
export type AgentTestSignals = z.infer<typeof SignalsSchema>;

/** Where detection events are read: a GET returning a JSON array, or an object with an `events` array. */
export const DetectionSchema = z.strictObject({
	url: z.url({ protocol: /^https?$/ }),
	headers: HeadersSchema.default({}),
	/** How long to keep polling for a new event after the scenario ends. */
	wait_ms: z.number().int().min(0).max(60_000).default(0),
	/** The event field holding the run id the API saw in `x-agentests-run`; when set, only this run's events count. */
	run_field: TextSchema.optional()
});
export type AgentTestDetection = z.infer<typeof DetectionSchema>;

/** The API under test. Requests are POSTs of `body`, a JSON template whose strings may hold `{{prompt}}`, `{{index}}`, `{{scenario}}`, and `{{run_id}}`. */
export const TargetSchema = z.strictObject({
	url: z.url({ protocol: /^https?$/ }),
	environment: EnvironmentSchema,
	headers: HeadersSchema.default({}),
	body: z.unknown().default({ prompt: '{{prompt}}' }),
	timeout_ms: z.number().int().min(100).max(60_000).default(10_000),
	signals: SignalsSchema.default({
		rate_limit: { status: [429] },
		quota: { status: [402, 403, 429], body: 'quota' }
	}),
	detection: DetectionSchema.optional()
});
export type AgentTestTarget = z.infer<typeof TargetSchema>;

/** What a security Test expects of the defenses; at least one of the three expectations. */
export const ExpectSchema = z
	.strictObject({
		rate_limit_enforced: z.boolean().optional(),
		quota_enforced: z.boolean().optional(),
		detection_event: z.boolean().optional(),
		/** With `rate_limit_enforced: true`: the first rate-limited response must come by this request. */
		rate_limit_within: z.number().int().min(1).optional(),
		/** With `quota_enforced: true`: the first quota response must come by this request. */
		quota_within: z.number().int().min(1).optional()
	})
	.refine(
		(value) =>
			value.rate_limit_enforced !== undefined ||
			value.quota_enforced !== undefined ||
			value.detection_event !== undefined,
		'Expected at least one expectation'
	);
export type AgentTestExpect = z.infer<typeof ExpectSchema>;
export type AgentTestExpectation = 'rate_limit_enforced' | 'quota_enforced' | 'detection_event';

/** One bounded attack simulation and its expectations; `duration_seconds` spreads the requests evenly, 0 sends them back to back. */
export const SecurityTestSchema = z.strictObject({
	id: IdSchema,
	description: TextSchema.optional(),
	scenario: ScenarioSchema,
	requests: z.number().int().min(1).max(10_000),
	duration_seconds: z.number().min(0).max(3_600).default(0),
	/** Merged over the target's headers for this Test only, e.g. its own API key. */
	headers: HeadersSchema.default({}),
	/** The largest share of responses that may be errors matching no signal before the Test is inconclusive, and fails. */
	max_error_rate: z.number().min(0).max(1).default(0.05),
	expect: ExpectSchema
});
export type AgentTestSecurityTest = z.infer<typeof SecurityTestSchema>;

/** Hard limits the runner never exceeds. Hosts other than localhost need listing; production needs `allow_production` and the `--allow-production` flag. */
export const SafetySchema = z.strictObject({
	max_requests: z.number().int().min(1).max(10_000),
	allow_production: z.boolean().default(false),
	allowed_hosts: z.array(TextSchema).default([]),
	/** Accept plain `http://` to a non-local host. Without it, such a URL is a warning in 1.x and an error from 2.0. */
	allow_insecure_http: z.boolean().default(false)
});
export type AgentTestSafety = z.infer<typeof SafetySchema>;

/** The result of one expectation: what was expected, what the evidence shows, and why. */
export interface AgentTestSecurityCheck {
	expectation: AgentTestExpectation;
	expected: boolean;
	actual: boolean;
	passed: boolean;
	detail: string;
}

/** What one scenario observed: every count needed to judge or audit the run. */
export interface AgentTestSecurityEvidence {
	sent: number;
	statuses: Record<string, number>;
	succeeded: number;
	rateLimited: number;
	quotaRejected: number;
	/** 1-based index of the first rate-limited response. */
	firstRateLimit?: number;
	/** 1-based index of the first quota response. */
	firstQuota?: number;
	/** Successful responses after the first quota response: a quota that lets traffic through again is not enforced. */
	succeededAfterQuota: number;
	/** Non-2xx responses that match no signal, such as 500s: evidence about the target, not its defenses. */
	errors: number;
	/** New detection events seen during the scenario; absent without `target.detection`. */
	detectionEvents?: number;
	/** Whether `detectionEvents` counts only this run's events (`target.detection.run_field`); absent without detection. */
	detectionCorrelated?: boolean;
	elapsedMs: number;
}

/** One security Test with its checks, evidence, and overall pass. */
export interface AgentTestSecurityResult {
	test: AgentTestSecurityTest;
	passed: boolean;
	/** Why the evidence cannot be trusted, such as too many errors; set only then, and the Test fails. */
	inconclusive?: string;
	checks: AgentTestSecurityCheck[];
	evidence: AgentTestSecurityEvidence;
}

/** The whole run: the policy, the run id sent on every request, and each Test's result in policy order. */
export interface AgentTestSecurityReport {
	policy: string;
	runId: string;
	target: { url: string; environment: AgentTestEnvironment };
	passed: number;
	total: number;
	results: AgentTestSecurityResult[];
	/** Policy problems that are not errors yet, such as plain HTTP to a remote host. */
	warnings: string[];
}
