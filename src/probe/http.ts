import { message } from './utils.ts';

/** The values `{{…}}` placeholders resolve to for one request. */
export type Placeholders = Record<string, string>;

/** Replace `${VAR}` with the environment map's value, throwing on an unset variable, then `{{name}}` with its placeholder. */
export const expand = (
	text: string,
	env: Record<string, string | undefined>,
	placeholders: Placeholders = {}
): string =>
	text
		.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_match, name: string) => {
			const value = env[name];
			if (value === undefined || value === '')
				throw new Error(`Missing environment variable: ${name}`);
			return value;
		})
		.replace(/\{\{([a-z_]+)\}\}/g, (match, name: string) => placeholders[name] ?? match);

/** `expand` applied to every string inside a JSON-like value. */
export const expandValue = (
	value: unknown,
	env: Record<string, string | undefined>,
	placeholders: Placeholders
): unknown => {
	if (typeof value === 'string') return expand(value, env, placeholders);
	if (Array.isArray(value)) return value.map((item) => expandValue(item, env, placeholders));
	if (value && typeof value === 'object')
		return Object.fromEntries(
			Object.entries(value).map(([key, item]) => [key, expandValue(item, env, placeholders)])
		);
	return value;
};

/** `expand` applied to each header value. */
export const expandHeaders = (
	headers: Record<string, string>,
	env: Record<string, string | undefined>,
	placeholders: Placeholders = {}
): Record<string, string> =>
	Object.fromEntries(
		Object.entries(headers).map(([name, value]) => [name, expand(value, env, placeholders)])
	);

/** What the runner keeps of one response. Bodies are cut at 64 KiB: enough to match an error code. */
export interface ProbeResponse {
	status: number;
	body: string;
}

/** The most of a completion response the runner reads; the rest of a long or endless stream is cancelled. */
export const MAX_BODY = 64 * 1024;
/** The most of a detection events response the runner reads; a larger list should be filtered by the API. */
export const MAX_EVENTS_BODY = 4 * 1024 * 1024;

/**
 * Read at most `limit` bytes of a body and cancel the rest, so a streaming or oversized response cannot hold
 * the run or its memory. Returns the text and whether it was cut.
 */
export const readCapped = async (
	response: Response,
	limit: number
): Promise<{ text: string; truncated: boolean }> => {
	if (!response.body) return { text: '', truncated: false };
	const reader = response.body.getReader();
	const chunks: Uint8Array[] = [];
	let size = 0;
	let truncated = false;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			const room = limit - size;
			if (value.byteLength >= room) {
				chunks.push(value.subarray(0, room));
				size += room;
				truncated = value.byteLength > room || !(await reader.read()).done;
				break;
			}
			chunks.push(value);
			size += value.byteLength;
		}
	} finally {
		if (truncated) await reader.cancel().catch(() => undefined);
		reader.releaseLock();
	}
	const bytes = new Uint8Array(size);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return { text: new TextDecoder().decode(bytes), truncated };
};

/** POST one JSON request; a network failure or timeout throws, so an unreachable target is an error, never a pass or a fail. */
export const send = async (
	fetcher: typeof fetch,
	url: string,
	headers: Record<string, string>,
	body: unknown,
	timeoutMs: number
): Promise<ProbeResponse> => {
	try {
		const response = await fetcher(url, {
			method: 'POST',
			headers: { 'content-type': 'application/json', ...headers },
			body: JSON.stringify(body),
			signal: AbortSignal.timeout(timeoutMs),
			redirect: 'manual'
		});
		const { text } = await readCapped(response, MAX_BODY);
		return { status: response.status, body: text };
	} catch (error) {
		throw new Error(`${url} unreachable: ${message(error)}`, { cause: error });
	}
};

/** The detection events the endpoint reports: a JSON array, or an object's `events` array. */
export const readEvents = async (
	fetcher: typeof fetch,
	url: string,
	headers: Record<string, string>,
	timeoutMs: number
): Promise<unknown[]> => {
	let text: string;
	try {
		const response = await fetcher(url, {
			headers: { accept: 'application/json', ...headers },
			signal: AbortSignal.timeout(timeoutMs),
			redirect: 'manual'
		});
		if (!response.ok) {
			await response.body?.cancel().catch(() => undefined);
			throw new Error(`${url} returned ${response.status}`);
		}
		const read = await readCapped(response, MAX_EVENTS_BODY);
		if (read.truncated)
			throw new Error(
				`${url} returned more than ${MAX_EVENTS_BODY / 1024 / 1024} MiB; filter events by run or time on the API side`
			);
		text = read.text;
	} catch (error) {
		if (error instanceof Error && error.message.startsWith(url)) throw error;
		throw new Error(`${url} unreachable: ${message(error)}`, { cause: error });
	}
	let value: unknown;
	try {
		value = JSON.parse(text);
	} catch {
		throw new Error(`${url} did not return JSON`);
	}
	if (Array.isArray(value)) return value;
	if (value && typeof value === 'object' && 'events' in value && Array.isArray(value.events))
		return value.events;
	throw new Error(`${url} returned neither an array nor an object with an events array`);
};
