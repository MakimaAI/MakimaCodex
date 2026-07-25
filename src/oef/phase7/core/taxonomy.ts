import { z } from "zod";
import { phase7SemverSchema } from "./shared";

export const FAILURE_TAXONOMY_VERSION = "1.0.0" as const;

export const BUILTIN_FAILURE_TYPES = [
  "opencodex.runtime-missing",
  "opencodex.runtime-incompatible",
  "opencodex.runtime-startup-failed",
  "opencodex.authentication-failed",
  "opencodex.authorization-failed",
  "opencodex.rate-limited",
  "opencodex.provider-unavailable",
  "opencodex.network-failed",
  "opencodex.startup-timeout",
  "opencodex.idle-timeout",
  "opencodex.total-timeout",
  "opencodex.output-limit-exceeded",
  "opencodex.context-limit-exceeded",
  "opencodex.protocol-error",
  "opencodex.event-stream-incomplete",
  "opencodex.tool-failed",
  "opencodex.command-failed",
  "opencodex.workspace-conflict",
  "opencodex.path-policy-violation",
  "opencodex.secret-leak-detected",
  "opencodex.model-refusal",
  "opencodex.model-behavior-error",
  "opencodex.verification-failed",
  "opencodex.cancelled-by-user",
  "opencodex.runner-lost",
  "opencodex.unknown",
] as const;

export type BuiltinFailureType = typeof BUILTIN_FAILURE_TYPES[number];

const namespacedFailureTypeSchema = z.string().trim().min(3).max(256)
  .regex(/^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/);

const failureTypeExtensionSchema = z.object({
  taxonomy_version: phase7SemverSchema,
  type: namespacedFailureTypeSchema,
}).strict();

export interface FailureTypeExtension {
  taxonomy_version: string;
  type: string;
}
export function validateFailureTypeExtension(input: unknown): FailureTypeExtension {
  const value = failureTypeExtensionSchema.parse(input);
  if (value.taxonomy_version !== FAILURE_TAXONOMY_VERSION) throw new Error("FAILURE_TAXONOMY_VERSION_UNSUPPORTED");
  if (value.type.startsWith("opencodex.")) throw new Error("FAILURE_TAXONOMY_SHADOW_FORBIDDEN");
  return value;
}

export function isValidFailureType(value: string): boolean {
  if (!namespacedFailureTypeSchema.safeParse(value).success) return false;
  return !value.startsWith("opencodex.") || (BUILTIN_FAILURE_TYPES as readonly string[]).includes(value);
}
