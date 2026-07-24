import { z } from "zod";

export const phase7HashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
export const phase7SemverSchema = z.string().regex(/^\d+\.\d+\.\d+$/);
export const phase7IdentifierSchema = z.string().trim().min(1).max(512)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/);
export const phase7TimestampSchema = z.string()
  .regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)
  .refine(value => Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value);

export const PHASE7_SCOPE_TYPES = [
  "ATTEMPT", "TASK", "REPOSITORY", "PROJECT", "USER", "ROLE", "MODEL", "PROVIDER", "ORGANIZATION", "GLOBAL",
] as const;

export const phase7ScopeSchema = z.object({
  type: z.enum(PHASE7_SCOPE_TYPES),
  id: phase7IdentifierSchema,
}).strict();

export type Phase7Scope = z.infer<typeof phase7ScopeSchema>;

export function samePhase7Scope(left: Phase7Scope, right: Phase7Scope): boolean {
  return left.type === right.type && left.id === right.id;
}
export function deepFreezePhase7<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreezePhase7(child);
  }
  return value;
}
