import { z } from "zod";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { redactSecrets } from "../../../lib/redact";
import {
  MEMORY_SCOPE_TYPES,
  createMemoryRecord,
  type MemoryActor,
  type MemoryRecord,
  type MemoryScope,
} from "../core/domain";
import type { MemoryRecordStore } from "../storage/ports";

const identifier = z.string().trim().min(1).max(512).regex(/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/);
const instant = z.string().datetime();
const scopeSchema = z.object({ type: z.enum(MEMORY_SCOPE_TYPES), id: identifier }).strict();
const actorSchema = z.object({ type: z.enum(["human", "system", "agent", "verifier"]), id: identifier }).strict();

export const memorySourceEventSchema = z.object({
  schema_version: z.literal(1),
  event_id: identifier,
  idempotency_key: z.string().trim().min(1).max(1_024),
  source: z.object({ phase: z.number().int().min(1).max(5), kind: z.string().trim().min(3).max(256), ref: identifier }).strict(),
  scopes: z.array(scopeSchema).min(1),
  subject: z.object({ type: z.string().trim().min(1).max(128), key: z.string().trim().min(1).max(512) }).strict(),
  summary: z.string().trim().min(1).max(20_000),
  structured: z.record(z.string(), z.unknown()).optional(),
  evidence_refs: z.array(identifier).min(1),
  sensitivity: z.enum(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]),
  observed_at: instant,
}).strict();
export type MemorySourceEvent = z.infer<typeof memorySourceEventSchema>;

export const memoryIngestionJobSchema = z.object({
  job_id: identifier,
  idempotency_key: z.string().trim().min(1).max(1_024),
  event_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  status: z.enum(["QUEUED", "LEASED", "RETRY", "COMPLETED", "DEAD_LETTER"]),
  priority: z.number().int().min(0).max(100),
  max_attempts: z.number().int().min(1).max(100),
  attempt_count: z.number().int().nonnegative(),
  lease_owner: identifier.nullable(),
  lease_token: identifier.nullable().default(null),
  lease_expires_at: instant.nullable(),
  next_attempt_at: instant,
  source_event: memorySourceEventSchema,
  output_memory_ids: z.array(identifier),
  last_error: z.object({ code: z.string().trim().min(1).max(128), message: z.string().trim().min(1).max(2_000) }).strict().nullable(),
  created_at: instant,
  updated_at: instant,
}).strict();
export type MemoryIngestionJob = z.infer<typeof memoryIngestionJobSchema>;

export interface MemoryJobPersistence {
  enqueueIngestionJob(job: MemoryIngestionJob): { job: MemoryIngestionJob; deduplicated: boolean };
  claimIngestionJob(input: { worker_id: string; now: string; lease_expires_at: string }): MemoryIngestionJob | null;
  completeIngestionJob(input: { job_id: string; worker_id: string; lease_token: string; at: string; output_memory_ids: string[] }): MemoryIngestionJob;
  failIngestionJob(input: { job_id: string; worker_id: string; lease_token: string; at: string; error: { code: string; message: string } }): MemoryIngestionJob;
  inspectIngestionJob(jobId: string): MemoryIngestionJob | null;
}

export interface MemoryCandidateProposal {
  candidate_id: string;
  idempotency_key: string;
  memory_id?: string;
  layer: "FACT" | "LESSON" | "PROCEDURE_CANDIDATE" | "GOVERNANCE";
  kind: string;
  scopes: MemoryScope[];
  subject: { type: string; key: string };
  summary: string;
  structured?: Record<string, unknown>;
  evidence_refs: string[];
  derived_from: string[];
  access: { sensitivity: "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "RESTRICTED"; read_roles: string[] };
  retention_policy: string;
  proposed_by: MemoryActor;
  proposed_at: string;
}

export interface MemoryCandidate extends MemoryCandidateProposal {
  status: "CANDIDATE" | "PROMOTED" | "REJECTED";
  promoted_memory_id: string | null;
  decided_at: string | null;
  decided_by: MemoryActor | null;
}

export const memoryCandidateSchema: z.ZodType<MemoryCandidate> = z.object({
  candidate_id: identifier,
  idempotency_key: z.string().trim().min(1).max(1_024),
  memory_id: identifier.optional(),
  layer: z.enum(["FACT", "LESSON", "PROCEDURE_CANDIDATE", "GOVERNANCE"]),
  kind: z.string().trim().min(3).max(256).regex(/^[a-z0-9][a-z0-9.-]+$/),
  scopes: z.array(scopeSchema).min(1),
  subject: z.object({ type: z.string().trim().min(1), key: z.string().trim().min(1) }).strict(),
  summary: z.string().trim().min(1).max(20_000),
  structured: z.record(z.string(), z.unknown()).optional(),
  evidence_refs: z.array(identifier),
  derived_from: z.array(identifier),
  access: z.object({
    sensitivity: z.enum(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]),
    read_roles: z.array(z.union([identifier, z.literal("*")])),
  }).strict(),
  retention_policy: identifier,
  proposed_by: actorSchema,
  proposed_at: instant,
  status: z.enum(["CANDIDATE", "PROMOTED", "REJECTED"]),
  promoted_memory_id: identifier.nullable(),
  decided_at: instant.nullable(),
  decided_by: actorSchema.nullable(),
}).strict();

export interface MemoryCandidatePersistence extends MemoryRecordStore {
  saveMemoryCandidate(candidate: MemoryCandidate): { candidate: MemoryCandidate; deduplicated: boolean };
  getMemoryCandidate(candidateId: string): MemoryCandidate | null;
  listMemoryCandidates(status?: MemoryCandidate["status"]): MemoryCandidate[];
  decideMemoryCandidate(candidate: MemoryCandidate): void;
}

export function createMemorySourceEvent(input: unknown): MemorySourceEvent {
  return immutable(memorySourceEventSchema.parse(redactSecrets(input)));
}

export class DurableMemoryIngestionQueue {
  constructor(private readonly store: MemoryJobPersistence) {}

  enqueue(event: MemorySourceEvent, options: { priority: number; max_attempts: number; at: string }): MemoryIngestionJob & { deduplicated: boolean } {
    const parsedEvent = memorySourceEventSchema.parse(event);
    const eventHash = canonicalSha256(parsedEvent);
    const job = memoryIngestionJobSchema.parse({
      job_id: `memory-job:${canonicalSha256({ idempotency_key: parsedEvent.idempotency_key }).slice(7, 31)}`,
      idempotency_key: parsedEvent.idempotency_key,
      event_hash: eventHash,
      status: "QUEUED",
      priority: options.priority,
      max_attempts: options.max_attempts,
      attempt_count: 0,
      lease_owner: null,
      lease_token: null,
      lease_expires_at: null,
      next_attempt_at: options.at,
      source_event: parsedEvent,
      output_memory_ids: [],
      last_error: null,
      created_at: options.at,
      updated_at: options.at,
    });
    const saved = this.store.enqueueIngestionJob(job);
    return { ...saved.job, deduplicated: saved.deduplicated };
  }

  claim(input: { worker_id: string; now: string; lease_ms: number }): MemoryIngestionJob | null {
    if (!Number.isInteger(input.lease_ms) || input.lease_ms < 1) throw new Error("MEMORY_JOB_LEASE_INVALID");
    const now = parseInstant(input.now, "MEMORY_JOB_TIME_INVALID");
    return this.store.claimIngestionJob({
      worker_id: input.worker_id,
      now,
      lease_expires_at: new Date(Date.parse(now) + input.lease_ms).toISOString(),
    });
  }

  complete(input: { job_id: string; worker_id: string; lease_token: string; at: string; output_memory_ids: string[] }): MemoryIngestionJob {
    return this.store.completeIngestionJob({ ...input, at: parseInstant(input.at, "MEMORY_JOB_TIME_INVALID") });
  }

  fail(input: { job_id: string; worker_id: string; lease_token: string; at: string; error: { code: string; message: string } }): MemoryIngestionJob {
    const safeError = redactSecrets(input.error) as { code: string; message: string };
    return this.store.failIngestionJob({ ...input, at: parseInstant(input.at, "MEMORY_JOB_TIME_INVALID"), error: safeError });
  }
}

export class MemoryEpisodeCompiler {
  compile(event: MemorySourceEvent): MemoryRecord {
    if (event.source.kind !== "execution.evidence") throw new Error("MEMORY_EPISODE_SOURCE_UNSUPPORTED");
    return createMemoryRecord({
      memory_id: `memory:episode-${canonicalSha256({ event_id: event.event_id }).slice(7, 31)}`,
      layer: "EPISODE",
      kind: "opencodex.episode.execution",
      scopes: event.scopes,
      subject: event.subject,
      content: { summary: event.summary, structured: event.structured },
      lifecycle: { status: "OBSERVED" },
      trust: { level: "HIGH", confidence: 0.9 },
      temporal: { observed_at: event.observed_at, valid_from: event.observed_at, valid_until: null, last_verified_at: null },
      provenance: { source_refs: [...new Set([event.source.ref, ...event.evidence_refs])], extractor_ref: { id: "memory-episode-compiler", version: "1.0.0" } },
      relations: { supersedes: [], contradicts: [], derived_from: [] },
      access: { sensitivity: event.sensitivity, read_roles: ["*"] },
      retention: { policy: "task-history" },
      created_at: event.observed_at,
      created_by: { type: "system", id: "system:memory-pipeline" },
    });
  }
}

export class MemoryIngestionWorker {
  constructor(private readonly options: {
    store: MemoryRecordStore;
    queue: DurableMemoryIngestionQueue;
    compiler: Pick<MemoryEpisodeCompiler, "compile">;
  }) {}

  runOnce(input: { worker_id: string; now: string; lease_ms: number }): (MemoryIngestionJob & { memory_ids: string[] }) | null {
    const job = this.options.queue.claim(input);
    if (!job) return null;
    try {
      const record = this.options.compiler.compile(job.source_event);
      this.options.store.create(record);
      const completed = this.options.queue.complete({ job_id: job.job_id, worker_id: input.worker_id, lease_token: job.lease_token!, at: input.now, output_memory_ids: [record.memory_id] });
      return { ...completed, memory_ids: [record.memory_id] };
    } catch (error) {
      const failed = this.options.queue.fail({
        job_id: job.job_id,
        worker_id: input.worker_id,
        lease_token: job.lease_token!,
        at: input.now,
        error: { code: errorCode(error), message: error instanceof Error ? error.message : String(error) },
      });
      return { ...failed, memory_ids: [] };
    }
  }
}

export class MemoryCandidateService {
  constructor(private readonly store: MemoryCandidatePersistence) {}

  propose(proposal: MemoryCandidateProposal): MemoryCandidate {
    const safe = redactSecrets(proposal) as MemoryCandidateProposal;
    const candidate = memoryCandidateSchema.parse({
      ...safe,
      status: "CANDIDATE",
      promoted_memory_id: null,
      decided_at: null,
      decided_by: null,
    });
    if (candidate.layer === "GOVERNANCE" && candidate.proposed_by.type !== "human") throw new Error("MEMORY_GOVERNANCE_HUMAN_APPROVAL_REQUIRED");
    return this.store.saveMemoryCandidate(candidate).candidate;
  }

  list(input: { status?: MemoryCandidate["status"] } = {}): MemoryCandidate[] {
    return this.store.listMemoryCandidates(input.status);
  }

  promote(candidateId: string, input: {
    actor: MemoryActor;
    evidence_refs: string[];
    evaluation_ref?: string;
    at: string;
  }): { candidate: MemoryCandidate; record: MemoryRecord } {
    const candidate = this.store.getMemoryCandidate(candidateId);
    if (!candidate) throw new Error("MEMORY_CANDIDATE_NOT_FOUND");
    if (candidate.status !== "CANDIDATE") throw new Error("MEMORY_CANDIDATE_ALREADY_DECIDED");
    if (input.actor.type !== "human" && input.actor.type !== "verifier") throw new Error("MEMORY_PROMOTION_ACTOR_UNAUTHORIZED");
    if (input.evidence_refs.length === 0) throw new Error("MEMORY_PROMOTION_EVIDENCE_REQUIRED");
    if (candidate.layer === "GOVERNANCE" && input.actor.type !== "human") throw new Error("MEMORY_GOVERNANCE_HUMAN_APPROVAL_REQUIRED");
    if (candidate.layer === "PROCEDURE_CANDIDATE" && !input.evaluation_ref) throw new Error("MEMORY_PROCEDURE_EVALUATION_REQUIRED");
    const at = parseInstant(input.at, "MEMORY_PROMOTION_TIME_INVALID");
    const sourceRefs = [...new Set([...candidate.evidence_refs, ...input.evidence_refs, ...(input.evaluation_ref ? [input.evaluation_ref] : [])])];
    const memoryId = candidate.memory_id ?? `memory:${canonicalSha256({ candidate_id: candidate.candidate_id }).slice(7, 31)}`;
    const record = createMemoryRecord({
      memory_id: memoryId,
      layer: candidate.layer,
      kind: candidate.kind,
      scopes: candidate.scopes,
      subject: candidate.subject,
      content: { summary: candidate.summary, structured: candidate.structured },
      lifecycle: { status: "VERIFIED" },
      trust: { level: "HIGH", confidence: 0.9 },
      temporal: { observed_at: candidate.proposed_at, valid_from: candidate.proposed_at, valid_until: null, last_verified_at: at },
      provenance: { source_refs: sourceRefs, extractor_ref: { id: "memory-candidate-promotion", version: "1.0.0" } },
      relations: { supersedes: [], contradicts: [], derived_from: candidate.derived_from },
      access: candidate.access,
      retention: { policy: candidate.retention_policy },
      created_at: at,
      created_by: input.actor,
    });
    this.store.create(record);
    const decided = memoryCandidateSchema.parse({ ...candidate, status: "PROMOTED", promoted_memory_id: record.memory_id, decided_at: at, decided_by: input.actor });
    this.store.decideMemoryCandidate(decided);
    return { candidate: decided, record };
  }
}

function parseInstant(value: string, code: string): string {
  if (!Number.isFinite(Date.parse(value))) throw new Error(code);
  return new Date(value).toISOString();
}

function errorCode(error: unknown): string {
  if (!(error instanceof Error)) return "MEMORY_INGESTION_FAILED";
  return /^[A-Z][A-Z0-9_]+$/.test(error.message) ? error.message : "MEMORY_INGESTION_FAILED";
}

function immutable<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) immutable(child);
    Object.freeze(value);
  }
  return value;
}
