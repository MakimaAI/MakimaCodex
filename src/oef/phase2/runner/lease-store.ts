import { createHash } from "node:crypto";
import { existsSync, mkdirSync, openSync, closeSync, readFileSync, renameSync, writeFileSync, writeSync, fsyncSync } from "node:fs";
import { join } from "node:path";

export interface RunnerLease {
  schema_version: 1;
  lease_id: string;
  execution_id: string;
  runner_id: string;
  leased_at: string;
  heartbeat_at: string;
  expires_at: string;
  runner_instance_nonce: string;
  status: "ACTIVE" | "RELEASED";
}

export class RunnerLeaseStore {
  private readonly root: string;
  private readonly quarantine: string;
  private readonly now: () => number;
  constructor(options: { root: string; now?: () => number }) {
    this.root = options.root;
    this.quarantine = join(options.root, "quarantine");
    this.now = options.now ?? Date.now;
    mkdirSync(this.root, { recursive: true });
    mkdirSync(this.quarantine, { recursive: true });
  }

  acquire(input: { execution_id: string; runner_id: string; runner_instance_nonce: string; ttl_ms: number }):
    | { ok: true; lease: RunnerLease }
    | { ok: false; reason: "LEASE_HELD"; lease: RunnerLease } {
    if (!Number.isInteger(input.ttl_ms) || input.ttl_ms <= 0) throw new Error("Lease TTL must be a positive integer");
    const path = this.pathFor(input.execution_id);
    const existing = this.readPath(path);
    const now = this.now();
    if (existing && existing.status === "ACTIVE" && Date.parse(existing.expires_at) > now) {
      if (existing.runner_instance_nonce === input.runner_instance_nonce && existing.runner_id === input.runner_id) return { ok: true, lease: existing };
      return { ok: false, reason: "LEASE_HELD", lease: existing };
    }
    if (existing) {
      const quarantineName = `${createHash("sha256").update(input.execution_id).digest("hex")}-${now}.json`;
      renameSync(path, join(this.quarantine, quarantineName));
    }
    const timestamp = new Date(now).toISOString();
    const lease: RunnerLease = {
      schema_version: 1,
      lease_id: `lease:${createHash("sha256").update(`${input.execution_id}\u0000${input.runner_instance_nonce}`).digest("hex").slice(0, 32)}`,
      execution_id: input.execution_id,
      runner_id: input.runner_id,
      leased_at: timestamp,
      heartbeat_at: timestamp,
      expires_at: new Date(now + input.ttl_ms).toISOString(),
      runner_instance_nonce: input.runner_instance_nonce,
      status: "ACTIVE",
    };
    writeExclusive(path, JSON.stringify(lease));
    return { ok: true, lease };
  }

  heartbeat(executionId: string, nonce: string, ttlMs: number): RunnerLease {
    const path = this.pathFor(executionId);
    const lease = this.readPath(path);
    if (!lease || lease.status !== "ACTIVE") throw new Error("RUNNER_LEASE_NOT_ACTIVE");
    if (lease.runner_instance_nonce !== nonce) throw new Error("RUNNER_LEASE_NONCE_MISMATCH");
    const now = this.now();
    const updated: RunnerLease = { ...lease, heartbeat_at: new Date(now).toISOString(), expires_at: new Date(now + ttlMs).toISOString() };
    writeFileSync(path, JSON.stringify(updated), "utf8");
    return updated;
  }

  release(executionId: string, nonce: string): RunnerLease {
    const path = this.pathFor(executionId);
    const lease = this.readPath(path);
    if (!lease) throw new Error("RUNNER_LEASE_NOT_FOUND");
    if (lease.runner_instance_nonce !== nonce) throw new Error("RUNNER_LEASE_NONCE_MISMATCH");
    if (lease.status === "RELEASED") return lease;
    const updated: RunnerLease = { ...lease, status: "RELEASED", heartbeat_at: new Date(this.now()).toISOString() };
    writeFileSync(path, JSON.stringify(updated), "utf8");
    return updated;
  }

  inspect(executionId: string): { status: "MISSING" | "ACTIVE" | "EXPIRED" | "RELEASED"; lease: RunnerLease | null } {
    const lease = this.readPath(this.pathFor(executionId));
    if (!lease) return { status: "MISSING", lease: null };
    if (lease.status === "RELEASED") return { status: "RELEASED", lease };
    return { status: Date.parse(lease.expires_at) <= this.now() ? "EXPIRED" : "ACTIVE", lease };
  }

  private pathFor(executionId: string): string {
    return join(this.root, `${createHash("sha256").update(executionId).digest("hex")}.json`);
  }
  private readPath(path: string): RunnerLease | null {
    if (!existsSync(path)) return null;
    const value = JSON.parse(readFileSync(path, "utf8")) as RunnerLease;
    if (value.schema_version !== 1 || !value.execution_id || !value.runner_instance_nonce) throw new Error("RUNNER_LEASE_CORRUPT");
    return value;
  }
}

function writeExclusive(path: string, content: string): void {
  const descriptor = openSync(path, "wx");
  try { writeSync(descriptor, content, undefined, "utf8"); fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
}
