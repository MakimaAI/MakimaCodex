import { createHash } from "node:crypto";
import { appendFileSync, existsSync, fsyncSync, mkdirSync, openSync, closeSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { parseNormalizedRuntimeEvent, type NormalizedRuntimeEvent } from "../runtime/protocol";

export type SpoolAppendResult =
  | { status: "APPENDED" }
  | { status: "DUPLICATE" }
  | { status: "GAP"; missing_sequences: number[] };

export class RunnerEventSpool {
  private readonly root: string;
  constructor(options: { root: string }) {
    this.root = options.root;
    mkdirSync(this.root, { recursive: true });
  }

  append(input: NormalizedRuntimeEvent): SpoolAppendResult {
    const event = parseNormalizedRuntimeEvent(input);
    const existing = this.read(event.execution_id, 1);
    const sameId = existing.find(value => value.event_id === event.event_id);
    if (sameId) {
      if (canonicalSha256(sameId) !== canonicalSha256(event)) throw new Error("EVENT_ID_CONFLICT");
      return { status: "DUPLICATE" };
    }
    const sameSequence = existing.find(value => value.attempt_id === event.attempt_id && value.sequence === event.sequence);
    if (sameSequence) {
      if (canonicalSha256(sameSequence) !== canonicalSha256(event)) throw new Error("EVENT_SEQUENCE_CONFLICT");
      return { status: "DUPLICATE" };
    }
    const attemptEvents = existing.filter(value => value.attempt_id === event.attempt_id);
    const maximum = attemptEvents.reduce((value, item) => Math.max(value, item.sequence), 0);
    const missing: number[] = [];
    if (event.sequence > maximum + 1) {
      const present = new Set(attemptEvents.map(value => value.sequence));
      for (let sequence = maximum + 1; sequence < event.sequence; sequence += 1) if (!present.has(sequence)) missing.push(sequence);
    }
    const path = this.pathFor(event.execution_id);
    const descriptor = openSync(path, "a");
    try {
      appendFileSync(descriptor, `${JSON.stringify(event)}\n`, "utf8");
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
    return missing.length > 0 ? { status: "GAP", missing_sequences: missing } : { status: "APPENDED" };
  }

  read(executionId: string, fromSequence = 1): NormalizedRuntimeEvent[] {
    const path = this.pathFor(executionId);
    if (!existsSync(path)) return [];
    const source = readFileSync(path, "utf8");
    if (source && !source.endsWith("\n")) throw new Error("EVENT_SPOOL_INCOMPLETE_RECORD");
    const events = source.split(/\r?\n/).filter(Boolean).map((line, index) => {
      try {
        const event = parseNormalizedRuntimeEvent(JSON.parse(line));
        if (event.execution_id !== executionId) throw new Error("execution mismatch");
        return event;
      } catch (error) {
        throw new Error(`EVENT_SPOOL_CORRUPT at line ${index + 1}: ${error instanceof Error ? error.message : String(error)}`);
      }
    });
    return events.filter(event => event.sequence >= fromSequence).sort((left, right) => left.sequence - right.sequence);
  }

  integrity(executionId: string, attemptId: string): { complete: boolean; next_expected_sequence: number; missing_sequences: number[] } {
    const sequences = new Set(this.read(executionId, 1).filter(event => event.attempt_id === attemptId).map(event => event.sequence));
    const maximum = sequences.size > 0 ? Math.max(...sequences) : 0;
    const missing: number[] = [];
    for (let sequence = 1; sequence <= maximum; sequence += 1) if (!sequences.has(sequence)) missing.push(sequence);
    return { complete: missing.length === 0, next_expected_sequence: missing[0] ?? maximum + 1, missing_sequences: missing };
  }

  private pathFor(executionId: string): string {
    const digest = createHash("sha256").update(executionId, "utf8").digest("hex");
    return join(this.root, `${digest}.jsonl`);
  }
}
