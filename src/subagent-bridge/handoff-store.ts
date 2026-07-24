import { randomBytes } from "node:crypto";
import { slugsEquivalent } from "../providers/slug-codec";
import { parseVerifiedSubagentTarget, verifiedSubagentTargetsMatch } from "./target";

export const HANDOFF_TTL_MS = 300_000;
export const HANDOFF_MAX_MESSAGE_BYTES = 64 * 1024;
export const HANDOFF_MAX_RECORDS = 256;
export const HANDOFF_MAX_TOTAL_BYTES = 4 * 1024 * 1024;

export type SubagentHandoffKind = "spawn" | "message" | "followup";
export type CodexAgentMessageType = "NEW_TASK" | "MESSAGE";

export interface ConsumedSubagentHandoff {
  kind: SubagentHandoffKind;
  target: string;
  message: string;
  model?: string;
  expiresAt: number;
}

interface HandoffRecord extends ConsumedSubagentHandoff {
  messageType: CodexAgentMessageType;
  bytes: number;
}

export class SubagentHandoffError extends Error {
  constructor(readonly code: "message_too_large" | "record_capacity_exceeded" | "byte_capacity_exceeded" | "invalid_target" | "spawn_name_generation_failed") {
    super(code);
    this.name = "SubagentHandoffError";
  }
}

export function normalizeSpawnNameBase(value: string): string {
  const normalized = value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .replace(/_+/g, "_")
    .slice(0, 40)
    .replace(/_+$/g, "");
  return normalized || "agent";
}

export class SubagentHandoffStore {
  private records: HandoffRecord[] = [];
  private totalBytes = 0;
  private readonly now: () => number;
  private readonly randomHex: () => string;

  constructor(options: { now?: () => number; randomHex?: () => string } = {}) {
    this.now = options.now ?? Date.now;
    this.randomHex = options.randomHex ?? (() => randomBytes(6).toString("hex"));
  }

  stageSpawn(input: { taskName: string; model: string; message: string }): { taskName: string; expiresAt: number } {
    this.pruneExpired();
    const base = normalizeSpawnNameBase(input.taskName);
    let taskName: string | undefined;
    for (let attempt = 0; attempt < 32; attempt += 1) {
      const suffix = this.randomHex();
      if (!/^[a-f0-9]{12}$/.test(suffix)) continue;
      const candidate = `${base}_${suffix}`;
      if (!this.records.some(record => record.kind === "spawn" && record.target === candidate)) {
        taskName = candidate;
        break;
      }
    }
    if (!taskName) throw new SubagentHandoffError("spawn_name_generation_failed");
    const record = this.stage({ kind: "spawn", target: taskName, model: input.model, message: input.message, messageType: "NEW_TASK" });
    return { taskName, expiresAt: record.expiresAt };
  }

  stageMessage(input: { kind: "message" | "followup"; target: string; message: string }): { target: string; expiresAt: number } {
    const record = this.stage({ ...input, messageType: input.kind === "followup" ? "NEW_TASK" : "MESSAGE" });
    return { target: input.target, expiresAt: record.expiresAt };
  }

  consume(target: string, messageType: CodexAgentMessageType, routedModel?: string): ConsumedSubagentHandoff | null {
    this.pruneExpired();
    const index = this.records.findIndex(record => (
      record.messageType === messageType
      && verifiedSubagentTargetsMatch(record.target, target)
    ));
    if (index < 0) return null;
    const candidate = this.records[index]!;
    if (candidate.kind === "spawn"
      && (typeof routedModel !== "string"
        || typeof candidate.model !== "string"
        || !slugsEquivalent(candidate.model, routedModel))) return null;
    const [record] = this.records.splice(index, 1);
    this.totalBytes -= record.bytes;
    const { kind, target: storedTarget, message, model, expiresAt } = record;
    return { kind, target: storedTarget, message, ...(model ? { model } : {}), expiresAt };
  }

  stats(): { records: number; totalBytes: number } {
    this.pruneExpired();
    return { records: this.records.length, totalBytes: this.totalBytes };
  }

  clear(): void {
    this.records = [];
    this.totalBytes = 0;
  }

  private stage(input: { kind: SubagentHandoffKind; target: string; model?: string; message: string; messageType: CodexAgentMessageType }): HandoffRecord {
    this.pruneExpired();
    if (!parseVerifiedSubagentTarget(input.target)) throw new SubagentHandoffError("invalid_target");
    const bytes = Buffer.byteLength(input.message, "utf8");
    if (bytes > HANDOFF_MAX_MESSAGE_BYTES) throw new SubagentHandoffError("message_too_large");
    if (this.records.length >= HANDOFF_MAX_RECORDS) throw new SubagentHandoffError("record_capacity_exceeded");
    if (this.totalBytes + bytes > HANDOFF_MAX_TOTAL_BYTES) throw new SubagentHandoffError("byte_capacity_exceeded");
    const record: HandoffRecord = {
      ...input,
      expiresAt: this.now() + HANDOFF_TTL_MS,
      bytes,
    };
    this.records.push(record);
    this.totalBytes += bytes;
    return record;
  }

  private pruneExpired(): void {
    if (this.records.length === 0) return;
    const now = this.now();
    const active: HandoffRecord[] = [];
    let activeBytes = 0;
    for (const record of this.records) {
      if (record.expiresAt <= now) continue;
      active.push(record);
      activeBytes += record.bytes;
    }
    this.records = active;
    this.totalBytes = activeBytes;
  }
}

export const subagentHandoffStore = new SubagentHandoffStore();
