import { randomBytes } from "node:crypto";

export const PHASE2_ENTITY_TYPES = [
  "assignment", "binding", "execution", "attempt", "runner", "runtime", "workspace", "context-bundle", "checkpoint",
  "failure", "execution-evidence", "event", "command", "lease", "health", "manifest",
] as const;

export type Phase2EntityType = typeof PHASE2_ENTITY_TYPES[number];

export interface Phase2IdGenerator {
  next(type: Phase2EntityType): string;
}

export function createPhase2IdGenerator(options: {
  now?: () => number;
  random?: (size: number) => Uint8Array;
} = {}): Phase2IdGenerator {
  const now = options.now ?? Date.now;
  const random = options.random ?? (size => randomBytes(size));
  let lastTimestamp = -1;
  let sequence = 0;
  return {
    next(type) {
      const timestamp = now();
      if (!Number.isSafeInteger(timestamp) || timestamp < 0) throw new Error("Phase 2 id clock must be a non-negative safe integer");
      if (timestamp < lastTimestamp) throw new Error("Phase 2 id clock moved backwards");
      sequence = timestamp === lastTimestamp ? sequence + 1 : 0;
      if (sequence >= 36 ** 4) throw new Error("Phase 2 id sequence exhausted");
      lastTimestamp = timestamp;
      const suffix = Array.from(random(8), byte => byte.toString(16).padStart(2, "0")).join("");
      return `${type}:${timestamp.toString(36).padStart(10, "0")}${sequence.toString(36).padStart(4, "0")}${suffix}`;
    },
  };
}
