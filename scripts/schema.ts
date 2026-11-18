import { writeFileSync } from 'node:fs';
import { z } from 'zod';
import { AgentTestSecurityPolicySchema } from '../src/policy/types.ts';

/** The policy file's JSON Schema, as editors and CI linters read it; defaults make fields optional. */
export const policyJsonSchema = (): Record<string, unknown> => ({
	$schema: 'https://json-schema.org/draft/2020-12/schema',
	$id: 'https://unpkg.com/@lastware/agentests-security@1/schema/policy.schema.json',
	title: 'agentests-security policy, version 1',
	...z.toJSONSchema(AgentTestSecurityPolicySchema, { io: 'input', unrepresentable: 'any' })
});

if (import.meta.main) {
	writeFileSync('schema/policy.schema.json', `${JSON.stringify(policyJsonSchema(), null, '\t')}\n`);
	console.log('Wrote schema/policy.schema.json');
}
