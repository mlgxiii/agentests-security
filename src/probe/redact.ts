import type { AgentTestSecurityPolicy } from '../policy/types.ts';
import type { AgentTestSecurityTest } from './types.ts';

/** What every redacted value becomes. */
export const REDACTED = '[REDACTED]';

/** Header and query parameter names whose values are treated as secrets. */
const SENSITIVE = /auth|key|token|secret|password|cookie|session|signature|^sig$/i;

/** Shorter values are left alone: redacting `1` or `abc` would mangle every message. */
const MIN_SECRET = 6;

/** The names of every `${VAR}` a value refers to. */
const references = (value: unknown): string[] => {
	if (typeof value === 'string')
		return [...value.matchAll(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g)].map((match) => match[1]!);
	if (Array.isArray(value)) return value.flatMap(references);
	if (value && typeof value === 'object') return Object.values(value).flatMap(references);
	return [];
};

/** The environment values a policy sends, plus literal values of its sensitive headers: what must never be printed. */
export const policySecrets = (
	policy: AgentTestSecurityPolicy,
	env: Record<string, string | undefined>
): string[] => {
	const { target, tests } = policy;
	const headerSets = [
		target.headers,
		target.detection?.headers ?? {},
		...tests.map((t) => t.headers)
	];
	const names = references([target.body, ...headerSets]);
	const literals = headerSets.flatMap((headers) =>
		Object.entries(headers)
			.filter(([name, value]) => SENSITIVE.test(name) && !references(value).length)
			.map(([, value]) => value.replace(/^(Bearer|Basic|Token)\s+/i, ''))
	);
	const values = [...names.map((name) => env[name] ?? ''), ...literals];
	return [...new Set(values.filter((value) => value.length >= MIN_SECRET))].sort(
		(a, b) => b.length - a.length
	);
};

/** A URL with the values of its sensitive query parameters redacted; anything unparsable is returned as is. */
export const redactUrl = (value: string): string => {
	let url: URL;
	try {
		url = new URL(value);
	} catch {
		return value;
	}
	let changed = false;
	for (const name of [...url.searchParams.keys()])
		if (SENSITIVE.test(name)) {
			url.searchParams.set(name, REDACTED);
			changed = true;
		}
	return changed ? url.toString() : value;
};

/** `text` with every secret, and every sensitive query parameter of every URL in it, redacted. */
export const redactText = (text: string, secrets: string[]): string =>
	secrets
		.reduce((result, secret) => result.split(secret).join(REDACTED), text)
		.replace(/https?:\/\/[^\s"'<>]+/g, redactUrl);

/** Header values as the report shows them: sensitive ones redacted unless they are only `${VAR}` references. */
const redactHeaders = (headers: Record<string, string>): Record<string, string> =>
	Object.fromEntries(
		Object.entries(headers).map(([name, value]) => [
			name,
			SENSITIVE.test(name) &&
			value
				.replace(/\$\{[A-Za-z_][A-Za-z0-9_]*\}/g, '')
				.replace(/^(Bearer|Basic|Token)\s*/i, '')
				.trim()
				? REDACTED
				: value
		])
	);

/** A Test as the report shows it, with `redactHeaders` applied to its headers and key sets. */
export const redactTest = (test: AgentTestSecurityTest): AgentTestSecurityTest => ({
	...test,
	headers: redactHeaders(test.headers),
	...(test.keys ? { keys: test.keys.map(redactHeaders) } : {})
});
