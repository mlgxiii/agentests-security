import { z } from 'zod';
import { IdSchema } from '../probe/shared.ts';
import { SafetySchema, SecurityTestSchema, TargetSchema } from '../probe/types.ts';

/** agentests.security.yaml at `version: 1`: one target, its security Tests, and the safety limits that bound them. */
export const AgentTestSecurityPolicySchema = z.strictObject({
	version: z.literal(1),
	name: IdSchema,
	target: TargetSchema,
	tests: z.array(SecurityTestSchema).min(1),
	safety: SafetySchema
});
export type AgentTestSecurityPolicy = z.infer<typeof AgentTestSecurityPolicySchema>;
