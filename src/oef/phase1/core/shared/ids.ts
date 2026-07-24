import { randomBytes as secureRandomBytes } from "node:crypto";

export const ENTITY_TYPES = [
  "task",
  "contract-revision",
  "criterion",
  "workflow-definition",
  "policy-pack",
  "approval",
  "evidence",
  "artifact",
  "verdict",
  "event",
  "trace",
  "span",
  "command",
] as const;

export type EntityType = typeof ENTITY_TYPES[number];

export interface IdGenerator {
  next(type: EntityType): string;
}

export interface SortableIdGeneratorOptions {
  now?: () => number;
  randomBytes?: (size: number) => Uint8Array;
}

const encodeBytes = (bytes: Uint8Array): string =>
  Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");

export function createSortableIdGenerator(
  options: SortableIdGeneratorOptions = {},
): IdGenerator {
  const now = options.now ?? Date.now;
  const random = options.randomBytes ?? (size => secureRandomBytes(size));
  let lastTimestamp = -1;
  let sequence = 0;

  return {
    next(type) {
      const timestamp = now();
      if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
        throw new Error("IdGenerator clock must return a non-negative safe integer");
      }
      if (timestamp < lastTimestamp) {
        throw new Error("IdGenerator clock moved backwards");
      }
      sequence = timestamp === lastTimestamp ? sequence + 1 : 0;
      if (sequence > 36 ** 4 - 1) throw new Error("IdGenerator sequence exhausted");
      lastTimestamp = timestamp;
      const timePart = timestamp.toString(36).padStart(10, "0");
      const sequencePart = sequence.toString(36).padStart(4, "0");
      return `${type}:${timePart}${sequencePart}${encodeBytes(random(8))}`;
    },
  };
}
