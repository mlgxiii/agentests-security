import { AgentTestSecurityPolicySchema } from './types.ts';
import type { AgentTestSecurityPolicy } from './types.ts';
import { describeIssues } from './issues.ts';

/** How the caller authorizes the run beyond the policy file itself. */
export interface AgentTestSecurityOptions {
	/** The `--allow-production` flag: a production target needs it and `safety.allow_production`. */
	allowProduction?: boolean;
}

/** Hosts every policy may target without listing them. */
export const LOCAL_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

/** Validate a parsed value as a security policy, or throw `path: message` lines: every schema problem; else, once the schema passes, every rule and safety problem. */
export const validateSecurityPolicy = (
	value: unknown,
	options: AgentTestSecurityOptions = {}
): AgentTestSecurityPolicy => {
	const result = AgentTestSecurityPolicySchema.safeParse(value);
	if (!result.success) throw new Error(describeIssues(result.error.issues).join('\n'));
	const problems = policyProblems(result.data, options);
	if (problems.length) throw new Error(problems.join('\n'));
	return result.data;
};

/** Problems the schema cannot express: duplicate ids, budgets, regexes, and every host and environment authorization. */
const policyProblems = (
	policy: AgentTestSecurityPolicy,
	{ allowProduction = false }: AgentTestSecurityOptions
): string[] => {
	const { target, tests, safety } = policy;
	const ids = new Set<string>();
	const total = tests.reduce((sum, test) => sum + test.requests, 0);
	const urls: [string, string][] = [
		['target.url', target.url],
		...(target.detection
			? [['target.detection.url', target.detection.url] as [string, string]]
			: [])
	];
	const allowed = new Set([
		...LOCAL_HOSTS,
		...safety.allowed_hosts.map((host) => host.toLowerCase())
	]);
	return [
		...tests.flatMap(({ id }, index) => {
			const duplicate = ids.has(id);
			ids.add(id);
			return duplicate ? [`tests.${index}.id: Duplicate test id`] : [];
		}),
		...tests.flatMap(({ baseline, expect, id }, index) => {
			const problems: string[] = [];
			const earlier = tests.slice(0, index).map((test) => test.id);
			if (baseline !== undefined && !earlier.includes(baseline))
				problems.push(
					`tests.${index}.baseline: ${baseline === id ? 'A Test cannot be its own baseline' : `No earlier Test has id ${baseline}`}`
				);
			if (expect.min_blocked_rate_gain !== undefined && baseline === undefined)
				problems.push(`tests.${index}.expect.min_blocked_rate_gain: Requires baseline`);
			if (
				expect.min_blocked_rate !== undefined &&
				expect.max_blocked_rate !== undefined &&
				expect.min_blocked_rate > expect.max_blocked_rate
			)
				problems.push(
					`tests.${index}.expect.min_blocked_rate: ${expect.min_blocked_rate} is above max_blocked_rate ${expect.max_blocked_rate}`
				);
			return problems;
		}),
		...(total > safety.max_requests
			? [
					`safety.max_requests: The tests send ${total} requests, over the limit of ${safety.max_requests}`
				]
			: []),
		...(['rate_limit', 'quota'] as const).flatMap((signal) => {
			const body = target.signals[signal].body;
			return body === undefined || compiles(body)
				? []
				: [`target.signals.${signal}.body: Invalid regular expression`];
		}),
		...tests.flatMap(({ expect }, index) =>
			expect.detection_event !== undefined && !target.detection
				? [`tests.${index}.expect.detection_event: Requires target.detection`]
				: []
		),
		...tests.flatMap(({ expect, requests }, index) =>
			(
				[
					['rate_limit_within', 'rate_limit_enforced'],
					['quota_within', 'quota_enforced']
				] as const
			).flatMap(([within, enforced]) => {
				const limit = expect[within];
				if (limit === undefined) return [];
				if (expect[enforced] !== true)
					return [`tests.${index}.expect.${within}: Requires ${enforced}: true`];
				return limit > requests
					? [
							`tests.${index}.expect.${within}: ${limit} is more than the Test's ${requests} requests`
						]
					: [];
			})
		),
		...urls.flatMap(([path, value]) => {
			const url = new URL(value);
			if (url.username || url.password)
				return [`${path}: Credentials in the URL are not allowed; use headers with \${VAR}`];
			return allowed.has(url.hostname.toLowerCase())
				? []
				: [`${path}: Host ${url.hostname} is not authorized; list it in safety.allowed_hosts`];
		}),
		...(target.environment === 'production' && !safety.allow_production
			? ['target.environment: Production targets need safety.allow_production: true']
			: []),
		...(target.environment === 'production' && !allowProduction
			? ['target.environment: Production targets need the --allow-production flag']
			: [])
	];
};

/**
 * Problems that are not errors in 1.x but will be in 2.0: a plain `http://` URL to a host outside `LOCAL_HOSTS`,
 * which sends the API key unencrypted, unless `safety.allow_insecure_http` accepts it.
 */
export const securityPolicyWarnings = (policy: AgentTestSecurityPolicy): string[] => {
	const { target, safety } = policy;
	if (safety.allow_insecure_http) return [];
	const urls: [string, string][] = [
		['target.url', target.url],
		...(target.detection
			? [['target.detection.url', target.detection.url] as [string, string]]
			: [])
	];
	return urls.flatMap(([path, value]) => {
		const url = new URL(value);
		return url.protocol === 'http:' && !LOCAL_HOSTS.includes(url.hostname.toLowerCase())
			? [
					`${path}: Plain HTTP to ${url.hostname} sends credentials unencrypted; use https, or set safety.allow_insecure_http: true. This becomes an error in 2.0.`
				]
			: [];
	});
};

const compiles = (pattern: string): boolean => {
	try {
		new RegExp(pattern, 'i');
		return true;
	} catch {
		return false;
	}
};
