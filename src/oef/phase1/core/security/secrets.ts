import { z } from "zod";

const secretPatterns = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i,
  /\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+\/-]{12,}/i,
  /\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|private[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9._~+\/-]{12,}/i,
] as const;

const sensitiveFieldName = /^(?:authorization|proxy-authorization|api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|token|cookie|set[-_]?cookie|password|passwd|client[-_]?secret|private[-_]?key|secret)$/i;

export function containsLikelyPhase1Secret(value: string): boolean {
  return secretPatterns.some(pattern => pattern.test(value));
}

export function assertNoPhase1Secret(value: string, label = "payload"): void {
  if (containsLikelyPhase1Secret(value)) throw new Error(`${label} contains a likely secret`);
}

export function containsStructuredPhase1Secret(value: unknown): boolean {
  const visited = new Set<object>();
  const inspect = (candidate: unknown): boolean => {
    if (typeof candidate === "string") return containsLikelyPhase1Secret(candidate);
    if (candidate === null || typeof candidate !== "object") return false;
    if (visited.has(candidate)) return false;
    visited.add(candidate);
    if (Array.isArray(candidate)) return candidate.some(inspect);
    return Object.entries(candidate as Record<string, unknown>).some(([key, nested]) => (
      sensitiveFieldName.test(key) || inspect(nested)
    ));
  };
  return inspect(value);
}

export function assertNoStructuredPhase1Secret(value: unknown, label = "payload"): void {
  if (containsStructuredPhase1Secret(value)) throw new Error(`${label} contains a likely secret`);
}

export const secretRefSchema = z.object({
  provider: z.string().regex(/^[a-z][a-z0-9-]{0,79}$/),
  key: z.string().trim().min(1).max(500).refine(value => (
    !value.startsWith("/")
    && !value.startsWith("\\")
    && !/^[A-Za-z]:[\\/]/.test(value)
    && !value.split(/[\\/]/).includes("..")
    && !containsLikelyPhase1Secret(value)
  ), "SecretRef key must be a safe reference, not secret material or a path escape"),
}).strict();

export type SecretRef = z.infer<typeof secretRefSchema>;

export function parseSecretRef(input: unknown): SecretRef {
  return secretRefSchema.parse(input);
}
