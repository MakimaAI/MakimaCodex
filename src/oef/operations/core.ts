import { z } from "zod";
import { assertNoPhase1Secret, assertNoStructuredPhase1Secret } from "../phase1/core/security/secrets";

export const JOB_STATES = ["PENDING", "LEASED", "RUNNING", "RETRY_PENDING", "SUCCEEDED", "FAILED", "DEAD_LETTER", "CANCELLED"] as const;
export const jobStateSchema = z.enum(JOB_STATES);
export type JobState = z.infer<typeof jobStateSchema>;

export const operationJobSchema = z.object({
  job_id: z.string().min(1), kind: z.string().min(1), idempotency_key: z.string().min(1),
  payload: z.record(z.string(), z.unknown()), priority: z.number().int(), max_attempts: z.number().int().positive(),
  attempt_count: z.number().int().nonnegative(), state: jobStateSchema, available_at: z.string(),
  lease_owner: z.string().nullable(), lease_expires_at: z.string().nullable(), lease_acquired_at: z.string().nullable(),
  run_started_at: z.string().nullable(), created_at: z.string(), updated_at: z.string(),
}).strict();
export type OperationJob = z.infer<typeof operationJobSchema>;

export const operationAttemptSchema = z.object({
  attempt_id: z.string().min(1), job_id: z.string().min(1), attempt_number: z.number().int().positive(),
  owner: z.string().min(1), outcome: z.enum(["SUCCEEDED", "FAILED", "LEASE_EXPIRED"]), error: z.string().nullable(),
  started_at: z.string(), finished_at: z.string(),
}).strict();
export type OperationAttempt = z.infer<typeof operationAttemptSchema>;

export const effectReceiptSchema = z.object({ job_id: z.string().min(1), effect_hash: z.string().min(1), succeeded_at: z.string() }).strict();
export type EffectReceipt = z.infer<typeof effectReceiptSchema>;

const ownerPattern = /^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$/;
const transitionMap: Readonly<Record<JobState, readonly JobState[]>> = {
  PENDING: ["LEASED", "CANCELLED"], LEASED: ["PENDING", "RUNNING", "CANCELLED"],
  RUNNING: ["RETRY_PENDING", "SUCCEEDED", "FAILED", "DEAD_LETTER", "CANCELLED"],
  RETRY_PENDING: ["LEASED", "CANCELLED"], SUCCEEDED: [], FAILED: [], DEAD_LETTER: [], CANCELLED: [],
};

export function assertOperationTimestamp(value: string): void {
  if (!Number.isFinite(Date.parse(value))) throw new Error("OPERATION_TIMESTAMP_INVALID");
}

export function assertOperationOwner(value: string): void {
  if (!ownerPattern.test(value)) throw new Error("OPERATION_OWNER_INVALID");
}

export function assertOperationPayload(value: unknown): asserts value is Record<string, unknown> {
  if (!value || Array.isArray(value) || typeof value !== "object") throw new Error("OPERATION_PAYLOAD_INVALID");
  try { assertNoStructuredPhase1Secret(value); }
  catch { throw new Error("OPERATION_PAYLOAD_SECRET_REJECTED"); }
  try { JSON.stringify(value); }
  catch { throw new Error("OPERATION_PAYLOAD_INVALID"); }
}

export function assertOperationErrorSafe(value: string): void {
  if (!value.trim() || value.length > 4_000) throw new Error("OPERATION_FAILURE_INVALID");
  try { assertNoPhase1Secret(value, "operation error"); }
  catch { throw new Error("OPERATION_FAILURE_SECRET_REJECTED"); }
}

export function assertOperationTransition(from: JobState, to: JobState): void {
  if (!transitionMap[from].includes(to)) throw new Error("OPERATION_STATE_TRANSITION_INVALID");
}

export function retryAvailableAt(now: string, baseBackoffMs: number, attemptNumber: number): string {
  assertOperationTimestamp(now);
  if (!Number.isSafeInteger(baseBackoffMs) || baseBackoffMs < 1 || baseBackoffMs > 86_400_000 || !Number.isSafeInteger(attemptNumber) || attemptNumber < 1 || attemptNumber > 30) {
    throw new Error("OPERATION_BACKOFF_INVALID");
  }
  return new Date(Date.parse(now) + baseBackoffMs * (2 ** (attemptNumber - 1))).toISOString();
}

export function leaseExpiry(now: string, leaseMs: number): string {
  assertOperationTimestamp(now);
  if (!Number.isSafeInteger(leaseMs) || leaseMs < 1 || leaseMs > 86_400_000) throw new Error("OPERATION_LEASE_INVALID");
  return new Date(Date.parse(now) + leaseMs).toISOString();
}
