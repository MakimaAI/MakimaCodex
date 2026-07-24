import { z } from "zod";
import { assertNoPhase1Secret, assertNoStructuredPhase1Secret } from "../phase1/core/security/secrets";
import { canonicalSha256 } from "../phase1/core/contract/task-contract";

export const JOB_STATES = ["PENDING", "LEASED", "RUNNING", "RETRY_PENDING", "SUCCEEDED", "FAILED", "DEAD_LETTER", "CANCELLED"] as const;
export const jobStateSchema = z.enum(JOB_STATES);
export type JobState = z.infer<typeof jobStateSchema>;

export interface RetryPolicy { base_backoff_ms: number; max_backoff_ms: number }
export interface FailureDetails { code: string; summary: string; artifact_ref: string | null }
export interface EffectReceipt { scope_id: string; job_id: string; effect_hash: string; effect: Record<string, JsonValue>; succeeded_at: string }
export interface OperationAttempt { attempt_id: string; scope_id: string; job_id: string; attempt_number: number; owner: string; outcome: "SUCCEEDED" | "FAILED" | "LEASE_EXPIRED" | "CANCELLED"; failure: FailureDetails | null; started_at: string; finished_at: string }
export interface OperationJob { job_id: string; scope_id: string; kind: string; idempotency_key: string; payload: Record<string, JsonValue>; priority: number; max_attempts: number; retry_policy: RetryPolicy; attempt_count: number; state: JobState; available_at: string; lease_owner: string | null; lease_expires_at: string | null; lease_acquired_at: string | null; run_started_at: string | null; created_at: string; updated_at: string }
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

const ownerPattern = /^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$/;
const scopePattern = /^[a-z][a-z0-9-]{0,79}:[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$/;
const maxTimestamp = "9999-12-31T23:59:59.999Z";
const transitionMap: Readonly<Record<JobState, readonly JobState[]>> = {
  PENDING: ["LEASED", "CANCELLED"], LEASED: ["PENDING", "RUNNING", "CANCELLED"], RUNNING: ["RETRY_PENDING", "SUCCEEDED", "FAILED", "DEAD_LETTER", "CANCELLED"], RETRY_PENDING: ["LEASED", "CANCELLED"], SUCCEEDED: [], FAILED: [], DEAD_LETTER: [], CANCELLED: [],
};

export function assertOperationTimestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) throw new Error("OPERATION_TIMESTAMP_INVALID");
}
export function assertOperationOwner(value: string): void { if (!ownerPattern.test(value)) throw new Error("OPERATION_OWNER_INVALID"); }
export function assertOperationScope(value: string): void { if (!scopePattern.test(value)) throw new Error("OPERATION_SCOPE_INVALID"); }
export function assertOperationTransition(from: JobState, to: JobState): void { if (!transitionMap[from].includes(to)) throw new Error("OPERATION_STATE_TRANSITION_INVALID"); }

export function parseRetryPolicy(value: RetryPolicy): RetryPolicy {
  if (!Number.isSafeInteger(value?.base_backoff_ms) || !Number.isSafeInteger(value?.max_backoff_ms) || value.base_backoff_ms < 1 || value.max_backoff_ms < value.base_backoff_ms || value.max_backoff_ms > 86_400_000) throw new Error("OPERATION_RETRY_POLICY_INVALID");
  return { base_backoff_ms: value.base_backoff_ms, max_backoff_ms: value.max_backoff_ms };
}

export function retryAvailableAt(now: string, policy: RetryPolicy, attemptNumber: number): string {
  assertOperationTimestamp(now); const parsed = parseRetryPolicy(policy);
  if (!Number.isSafeInteger(attemptNumber) || attemptNumber < 1 || attemptNumber > 30) throw new Error("OPERATION_BACKOFF_INVALID");
  const delay = Math.min(parsed.max_backoff_ms, parsed.base_backoff_ms * (2 ** (attemptNumber - 1)));
  return new Date(Math.min(Date.parse(now) + delay, Date.parse(maxTimestamp))).toISOString();
}

export function leaseExpiry(now: string, leaseMs: number): string {
  assertOperationTimestamp(now); if (!Number.isSafeInteger(leaseMs) || leaseMs < 1 || leaseMs > 86_400_000) throw new Error("OPERATION_LEASE_INVALID");
  const expiry = Math.min(Date.parse(now) + leaseMs, Date.parse(maxTimestamp));
  if (expiry <= Date.parse(now)) throw new Error("OPERATION_LEASE_INVALID");
  return new Date(expiry).toISOString();
}

export function serializeOperationPayload(value: unknown): { value: Record<string, JsonValue>; json: string } { return serializePlainObject(value, "OPERATION_PAYLOAD_INVALID", "OPERATION_PAYLOAD_SECRET_REJECTED"); }
export function parseOperationFailure(value: unknown): FailureDetails {
  const serialized = serializePlainObject(value, "OPERATION_FAILURE_INVALID", "OPERATION_FAILURE_SECRET_REJECTED", false);
  const snapshot = serialized.value;
  const keys = Object.keys(snapshot).sort();
  if (keys.join(",") !== "artifact_ref,code,summary" || typeof snapshot.code !== "string" || typeof snapshot.summary !== "string" || !(typeof snapshot.artifact_ref === "string" || snapshot.artifact_ref === null) || !/^[A-Z][A-Z0-9_]{0,63}$/.test(snapshot.code) || !snapshot.summary.trim() || snapshot.summary.length > 500 || (typeof snapshot.artifact_ref === "string" && (!/^artifact:[A-Za-z0-9:._/-]{1,480}$/.test(snapshot.artifact_ref)))) throw new Error("OPERATION_FAILURE_INVALID");
  try { assertNoStructuredPhase1Secret(snapshot); assertNoPhase1Secret(serialized.json, "operation failure"); } catch { throw new Error("OPERATION_FAILURE_SECRET_REJECTED"); }
  return { code: snapshot.code, summary: snapshot.summary, artifact_ref: snapshot.artifact_ref };
}
export function canonicalEffectDescriptor(value: unknown): { effect: Record<string, JsonValue>; effect_json: string; effect_hash: string } {
  const snapshot = serializePlainObject(value, "OPERATION_EFFECT_DESCRIPTOR_INVALID", "OPERATION_EFFECT_DESCRIPTOR_SECRET_REJECTED");
  if (Object.keys(snapshot.value).length === 0) throw new Error("OPERATION_EFFECT_DESCRIPTOR_INVALID");
  return { effect: snapshot.value, effect_json: snapshot.json, effect_hash: canonicalSha256(snapshot.value) };
}

function serializePlainObject(value: unknown, invalidCode: string, secretCode: string, scanSecrets = true): { value: Record<string, JsonValue>; json: string } {
  let cloned: JsonValue;
  try { cloned = cloneJson(value); } catch { throw new Error(invalidCode); }
  if (!cloned || Array.isArray(cloned) || typeof cloned !== "object") throw new Error(invalidCode);
  const json = JSON.stringify(cloned);
  if (scanSecrets) try { assertNoStructuredPhase1Secret(cloned); assertNoPhase1Secret(json, "operation snapshot"); } catch { throw new Error(secretCode); }
  return { value: cloned, json };
}
function cloneJson(value: unknown): JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") { if (!Number.isFinite(value)) throw new Error("invalid"); return value; }
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype || Object.getOwnPropertySymbols(value).length > 0) throw new Error("invalid");
    const output: JsonValue[] = []; for (let index = 0; index < value.length; index += 1) { if (!Object.hasOwn(value, index)) throw new Error("invalid"); output.push(cloneJson(value[index])); } return output;
  }
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype || Object.getOwnPropertySymbols(value).length > 0 || Object.hasOwn(value, "toJSON")) throw new Error("invalid");
  const output: { [key: string]: JsonValue } = {};
  for (const key of Object.keys(value)) { const descriptor = Object.getOwnPropertyDescriptor(value, key); if (!descriptor || !("value" in descriptor)) throw new Error("invalid"); output[key] = cloneJson(descriptor.value); }
  return output;
}
