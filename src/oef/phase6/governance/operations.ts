import { existsSync, lstatSync, realpathSync, unlinkSync } from "node:fs";
import { isAbsolute, resolve, sep } from "node:path";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { appendMemoryRevision, type MemoryRecord } from "../core/domain";

export interface MemoryArtifactPurger {
  purge(jobId: string, reference: string): VerifiedMemoryArtifactReceipt;
}

export interface VerifiedMemoryArtifactReceipt {
  readonly job_id: string;
  readonly reference: string;
  readonly status: "PURGED" | "VERIFIED_ABSENT" | "UNRESOLVED";
}

const authenticatedArtifactReceipts = new WeakSet<object>();

export function assertMemoryArtifactReceiptsAuthentic(jobId: string, receipts: VerifiedMemoryArtifactReceipt[]): void {
  if (receipts.some(receipt => !authenticatedArtifactReceipts.has(receipt) || receipt.job_id !== jobId)) {
    throw new Error("MEMORY_DELETE_ARTIFACT_RECEIPT_UNTRUSTED");
  }
}

export interface MemoryDerivedIndexPurger {
  deleteMemory(memoryId: string): number;
}

export interface MemoryForgettingStore {
  get(memoryId: string): MemoryRecord | null;
  planMemoryDeletion(memoryId: string): { memory_ids: string[]; revision_ids: string[]; artifact_refs: string[] };
  prepareDeletionJob(job: MemoryDeletionJob): void;
  verifyDeletionArtifacts(jobId: string, receipts: VerifiedMemoryArtifactReceipt[], at: string): MemoryDeletionJob;
  resumeVerifiedDeletionJob(jobId: string, at: string): MemoryDeletionJob;
  recordDeletionProgress(jobId: string, memoryId: string, at: string): MemoryDeletionJob;
  completeDeletionJob(jobId: string, at: string): MemoryDeletionJob;
  failDeletionJob(jobId: string, error: string, at: string): void;
  assertDeletionClosureComplete(jobId: string): void;
  getDeletionJob(jobId: string): MemoryDeletionJob | null;
  forget(memoryId: string, input: {
    mode: "SOFT_FORGET" | "HARD_DELETE" | "LEGAL_DELETE" | "SECRET_PURGE";
    reason: string;
    at: string;
    deletion_receipt?: { job_id: string; receipt_hash: string };
  }): void;
}

export interface MemoryDeletionJob {
  job_id: string;
  root_memory_id: string;
  mode: "LEGAL_DELETE" | "SECRET_PURGE";
  reason: string;
  memory_ids: string[];
  revision_ids: string[];
  artifact_refs: string[];
  artifact_receipts: Array<{ reference: string; status: "PURGED" | "VERIFIED_ABSENT" }>;
  canonical_deleted: string[];
  status: "PREPARED" | "ARTIFACTS_VERIFIED" | "COMPLETED" | "FAILED";
  receipt_hash: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

export class LocalMemoryArtifactPurger implements MemoryArtifactPurger {
  private readonly root: string;

  constructor(private readonly options: { root: string; manifest: Record<string, string> }) {
    const requested = resolve(options.root);
    if (!existsSync(requested) || lstatSync(requested).isSymbolicLink() || !lstatSync(requested).isDirectory()) {
      throw new Error("MEMORY_ARTIFACT_ROOT_UNSAFE");
    }
    this.root = realpathSync(requested);
    for (const path of Object.values(options.manifest)) this.safePath(path, false);
  }

  purge(jobId: string, reference: string): VerifiedMemoryArtifactReceipt {
    const relative = this.options.manifest[reference];
    let status: VerifiedMemoryArtifactReceipt["status"] = "UNRESOLVED";
    if (relative) {
      const path = this.safePath(relative, true);
      if (!existsSync(path)) status = "VERIFIED_ABSENT";
      else {
        if (lstatSync(path).isSymbolicLink() || !lstatSync(path).isFile()) throw new Error("MEMORY_ARTIFACT_PATH_UNSAFE");
        unlinkSync(path);
        status = "PURGED";
      }
    }
    const receipt = Object.freeze({ job_id: jobId, reference, status });
    authenticatedArtifactReceipts.add(receipt);
    return receipt;
  }

  private safePath(relative: string, resolveExisting: boolean): string {
    if (!relative || isAbsolute(relative)) throw new Error("MEMORY_ARTIFACT_PATH_UNSAFE");
    const candidate = resolve(this.root, relative);
    const prefix = this.root.endsWith(sep) ? this.root : `${this.root}${sep}`;
    const comparable = (value: string) => process.platform === "win32" ? value.toLowerCase() : value;
    if (!comparable(candidate).startsWith(comparable(prefix))) throw new Error("MEMORY_ARTIFACT_PATH_UNSAFE");
    if (resolveExisting && existsSync(candidate)) {
      const actual = realpathSync.native(candidate);
      if (!comparable(actual).startsWith(comparable(prefix))) throw new Error("MEMORY_ARTIFACT_PATH_UNSAFE");
    }
    return candidate;
  }
}

export class MemoryForgettingService {
  constructor(private readonly options: {
    store: MemoryForgettingStore;
    derived_indexes?: MemoryDerivedIndexPurger[];
    artifact_purger?: MemoryArtifactPurger;
  }) {}

  forget(memoryId: string, input: { mode: "SOFT_FORGET" | "HARD_DELETE" | "LEGAL_DELETE" | "SECRET_PURGE"; reason: string; at: string }) {
    const record = this.options.store.get(memoryId);
    if (!record) throw new Error("MEMORY_NOT_FOUND");
    if (input.mode === "SOFT_FORGET") {
      this.options.store.forget(memoryId, input);
      return { memory_id: memoryId, mode: input.mode, canonical_deleted: false, artifacts_purged: 0, derived_entries_purged: 0 };
    }
    if (input.mode === "HARD_DELETE") {
      let derivedEntriesPurged = 0;
      for (const index of this.options.derived_indexes ?? []) derivedEntriesPurged += index.deleteMemory(memoryId);
      this.options.store.forget(memoryId, input);
      return { memory_id: memoryId, mode: input.mode, canonical_deleted: true, artifacts_purged: 0, derived_entries_purged: derivedEntriesPurged };
    }
    const plan = this.options.store.planMemoryDeletion(memoryId);
    if (plan.artifact_refs.length > 0 && !this.options.artifact_purger) {
      throw new Error("MEMORY_DELETE_ARTIFACT_PURGER_REQUIRED");
    }
    const job: MemoryDeletionJob = {
      job_id: `memory-deletion:${canonicalSha256({ memoryId, mode: input.mode, revision_ids: plan.revision_ids, at: input.at }).slice(7, 31)}`,
      root_memory_id: memoryId,
      mode: input.mode,
      reason: input.reason,
      ...plan,
      artifact_receipts: [], canonical_deleted: [], status: "PREPARED", receipt_hash: null, last_error: null,
      created_at: input.at, updated_at: input.at,
    };
    this.options.store.prepareDeletionJob(job);
    return this.executeDeletion(job);
  }

  reconcile(jobId: string): ReturnType<MemoryForgettingService["executeDeletion"]> {
    const job = this.options.store.getDeletionJob(jobId);
    if (!job) throw new Error("MEMORY_DELETION_JOB_NOT_FOUND");
    if (job.status === "COMPLETED") return this.receipt(job, 0);
    return this.executeDeletion(job);
  }

  private executeDeletion(job: MemoryDeletionJob) {
    let derivedEntriesPurged = 0;
    try {
      let current = job;
      if (current.status === "FAILED" && current.receipt_hash) {
        current = this.options.store.resumeVerifiedDeletionJob(current.job_id, new Date().toISOString());
      } else if (current.status !== "ARTIFACTS_VERIFIED") {
        const artifactReceipts = current.artifact_refs.map(reference => this.options.artifact_purger?.purge(current.job_id, reference));
        if (artifactReceipts.some(receipt => !receipt || receipt.status === "UNRESOLVED")) throw new Error("MEMORY_DELETE_ARTIFACT_UNRESOLVED");
        current = this.options.store.verifyDeletionArtifacts(
          current.job_id,
          artifactReceipts as VerifiedMemoryArtifactReceipt[],
          new Date().toISOString(),
        );
      }
      const receiptHash = current.receipt_hash!;
      for (const memoryId of current.memory_ids) for (const index of this.options.derived_indexes ?? []) derivedEntriesPurged += index.deleteMemory(memoryId);
      for (const memoryId of current.memory_ids) {
        if (this.options.store.get(memoryId)) this.options.store.forget(memoryId, {
          mode: current.mode, reason: current.reason, at: current.updated_at,
          deletion_receipt: { job_id: current.job_id, receipt_hash: receiptHash },
        });
        current = this.options.store.recordDeletionProgress(current.job_id, memoryId, new Date().toISOString());
      }
      this.options.store.assertDeletionClosureComplete(current.job_id);
      current = this.options.store.completeDeletionJob(current.job_id, new Date().toISOString());
      return this.receipt(current, derivedEntriesPurged);
    } catch (error) {
      this.options.store.failDeletionJob(job.job_id, error instanceof Error ? error.message : String(error), new Date().toISOString());
      throw error;
    }
  }

  private receipt(job: MemoryDeletionJob, derivedEntriesPurged: number) {
    return {
      memory_id: job.root_memory_id, mode: job.mode, deletion_job_id: job.job_id,
      canonical_deleted: job.status === "COMPLETED", deleted_memory_ids: job.canonical_deleted,
      artifacts_purged: job.artifact_receipts.filter(receipt => receipt.status === "PURGED").length,
      artifacts_verified_absent: job.artifact_receipts.filter(receipt => receipt.status === "VERIFIED_ABSENT").length,
      derived_entries_purged: derivedEntriesPurged,
    };
  }
}

export interface MemoryHygieneStore {
  listCurrentRecords(): MemoryRecord[];
  appendRevision(revision: MemoryRecord, expectedRevision: number): void;
  saveHealthSnapshot?(snapshot: Record<string, unknown>): void;
}

export class MemoryHygieneService {
  constructor(private readonly store: MemoryHygieneStore) {}

  run(input: { at: string }): { scanned: number; expired: number; duplicate_groups: number; at: string } {
    if (!Number.isFinite(Date.parse(input.at))) throw new Error("MEMORY_HYGIENE_TIME_INVALID");
    const at = new Date(input.at).toISOString();
    const records = this.store.listCurrentRecords();
    let expired = 0;
    const summaries = new Map<string, number>();
    for (const record of records) {
      const summaryKey = record.content.summary.trim().toLocaleLowerCase("en-US");
      summaries.set(summaryKey, (summaries.get(summaryKey) ?? 0) + 1);
      if (!record.temporal.valid_until || Date.parse(record.temporal.valid_until) > Date.parse(at)) continue;
      if (["EXPIRED", "DEPRECATED", "SUPERSEDED", "REJECTED", "FORGOTTEN"].includes(record.lifecycle.status)) continue;
      const next = appendMemoryRevision(record, { lifecycle: { status: "EXPIRED" } }, {
        expected_revision: record.revision_number,
        reason: "temporal validity elapsed",
        actor: { type: "system", id: "system:memory-hygiene" },
        at,
      });
      this.store.appendRevision(next, record.revision_number);
      expired += 1;
    }
    const report = { scanned: records.length, expired, duplicate_groups: [...summaries.values()].filter(count => count > 1).length, at };
    this.store.saveHealthSnapshot?.(report);
    return report;
  }
}
