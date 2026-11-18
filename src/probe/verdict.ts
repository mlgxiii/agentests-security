import type {
	AgentTestSecurityTest,
	AgentTestExpect,
	AgentTestExpectation,
	AgentTestSecurityCheck,
	AgentTestSecurityEvidence
} from './types.ts';

/** What the evidence shows for one expectation, and the sentence explaining it. */
const observe = (
	expectation: Exclude<AgentTestExpectation, 'blocked_rate' | 'baseline_gain'>,
	evidence: AgentTestSecurityEvidence,
	within?: number
): { actual: boolean; detail: string } => {
	const { sent } = evidence;
	switch (expectation) {
		case 'rate_limit_enforced': {
			const first = evidence.firstRateLimit;
			if (first === undefined)
				return { actual: false, detail: `no rate-limited response in ${sent} requests` };
			if (within !== undefined && first > within)
				return {
					actual: false,
					detail: `first rate-limited at request ${first}, after the limit of ${within}`
				};
			return {
				actual: true,
				detail: `first rate-limited at request ${first} of ${sent}; ${evidence.rateLimited} rejected`
			};
		}
		case 'quota_enforced':
			if (evidence.firstQuota === undefined)
				return { actual: false, detail: `no quota response in ${sent} requests` };
			if (within !== undefined && evidence.firstQuota > within)
				return {
					actual: false,
					detail: `quota hit at request ${evidence.firstQuota}, after the limit of ${within}`
				};
			if (evidence.succeededAfterQuota > 0)
				return {
					actual: false,
					detail: `quota hit at request ${evidence.firstQuota}, but ${evidence.succeededAfterQuota} later requests succeeded`
				};
			return {
				actual: true,
				detail: `quota hit at request ${evidence.firstQuota} of ${sent}; every later request rejected`
			};
		case 'detection_event': {
			const events = evidence.detectionEvents ?? 0;
			const scope = evidence.detectionCorrelated ? ' for this run' : '';
			return { actual: events > 0, detail: `${events} new detection event(s)${scope}` };
		}
	}
};

const percent = (rate: number): string => `${Math.round(rate * 100)}%`;

/** The checks for the rate expectations: one for the blocked-rate bounds, one for the gain over the baseline. */
const rateChecks = (
	expect: AgentTestExpect,
	evidence: AgentTestSecurityEvidence
): AgentTestSecurityCheck[] => {
	const checks: AgentTestSecurityCheck[] = [];
	const { min_blocked_rate: min, max_blocked_rate: max, min_blocked_rate_gain: gain } = expect;
	const rate = evidence.blockedRate;
	if (min !== undefined || max !== undefined) {
		const actual = (min === undefined || rate >= min) && (max === undefined || rate <= max);
		const bounds = [
			min === undefined ? undefined : `at least ${percent(min)}`,
			max === undefined ? undefined : `at most ${percent(max)}`
		]
			.filter(Boolean)
			.join(' and ');
		checks.push({
			expectation: 'blocked_rate',
			expected: true,
			actual,
			passed: actual,
			detail: `blocked ${percent(rate)} of ${evidence.sent} requests; expected ${bounds}`
		});
	}
	if (gain !== undefined) {
		const base = evidence.baselineBlockedRate ?? 0;
		const actual = rate - base >= gain - 1e-9;
		checks.push({
			expectation: 'baseline_gain',
			expected: true,
			actual,
			passed: actual,
			detail: `blocked ${percent(rate)} against ${percent(base)} for the baseline; expected a gain of at least ${percent(gain)}`
		});
	}
	return checks;
};

/** One check per expectation the Test sets, in a fixed order. */
export const judge = (
	expect: AgentTestExpect,
	evidence: AgentTestSecurityEvidence
): AgentTestSecurityCheck[] => [
	...(['rate_limit_enforced', 'quota_enforced', 'detection_event'] as const).flatMap(
		(expectation): AgentTestSecurityCheck[] => {
			const expected = expect[expectation];
			if (expected === undefined) return [];
			const within =
				expectation === 'rate_limit_enforced'
					? expect.rate_limit_within
					: expectation === 'quota_enforced'
						? expect.quota_within
						: undefined;
			const { actual, detail } = observe(expectation, evidence, within);
			return [{ expectation, expected, actual, passed: actual === expected, detail }];
		}
	),
	...rateChecks(expect, evidence)
];

/** Why a Test's evidence says more about the target's errors than its defenses, or undefined when it is sound. */
export const inconclusive = (
	{ max_error_rate }: AgentTestSecurityTest,
	{ sent, errors, statuses }: AgentTestSecurityEvidence
): string | undefined => {
	if (!sent || errors / sent <= max_error_rate) return undefined;
	const codes = Object.entries(statuses)
		.filter(([status]) => !/^2/.test(status))
		.map(([status, count]) => `${status}×${count}`)
		.join(', ');
	return `${errors} of ${sent} responses were errors matching no signal (non-2xx: ${codes}), over max_error_rate ${max_error_rate}`;
};
