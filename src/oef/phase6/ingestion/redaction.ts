import { redactSecrets } from "../../../lib/redact";
import type { MemoryRecordInput } from "../core/domain";

export function sanitizeMemoryRecordInput<T extends MemoryRecordInput>(input: T): T {
  return {
    ...input,
    content: redactSecrets(input.content) as T["content"],
  };
}
