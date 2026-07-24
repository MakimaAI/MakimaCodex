import { z } from "zod";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { assertNoPhase1Secret, assertNoStructuredPhase1Secret } from "../../phase1/core/security/secrets";
import { FAILURE_CATEGORIES } from "../core/failure-observation";
import { deepFreezePhase7, phase7SemverSchema } from "../core/shared";
import { isValidFailureType } from "../core/taxonomy";

export const SIGNATURE_PROFILE = deepFreezePhase7({ id: "opencodex.failure-signature", version: "1.0.0" as const });

const signatureInputSchema = z.object({
  profile: z.object({ id: z.literal(SIGNATURE_PROFILE.id), version: phase7SemverSchema }).strict(),
  message: z.string().trim().min(1).max(100_000),
  category: z.enum(FAILURE_CATEGORIES),
  code: z.string().trim().min(3).max(256).refine(isValidFailureType),
  provider: z.string().trim().min(1).max(160),
  runtime: z.string().trim().min(1).max(300),
  tool: z.string().trim().min(1).max(300),
  operation: z.string().trim().min(1).max(300),
  http_status: z.number().int().min(100).max(599).nullable().optional(),
  error_code: z.string().trim().min(1).max(300).nullable().optional(),
  exception: z.string().trim().min(1).max(500).nullable().optional(),
  symbol: z.string().trim().min(1).max(500).nullable().optional(),
  environment: z.object({
    os: z.string().trim().min(1).max(160),
    arch: z.string().trim().min(1).max(160),
    runtime_version: z.string().trim().min(1).max(300),
    container: z.string().trim().min(1).max(300).optional(),
    region: z.string().trim().min(1).max(300).optional(),
  }).strict(),
}).strict();

export type FailureSignatureInput = z.input<typeof signatureInputSchema>;

export interface FailureSignatures {
  profile: typeof SIGNATURE_PROFILE;
  exact_hash: string;
  normalized_signature: string;
  structural_signature: string;
  environment_fingerprint: string;
  normalized_text: string;
}
export function normalizeFailureText(input: string): string {
  let value = input.normalize("NFKC");
  value = value.replace(/\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\b/gi, "<timestamp>");
  value = value.replace(/(?:[A-Za-z]:\\[^\s]*?(?:AppData\\Local\\Temp|\\Temp)\\[^\s]+|\/(?:tmp|var\/tmp)\/[^\s]+)/gi, "<temp-path>");
  value = value.replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi, "<uuid>");
  value = value.replace(/\b((?:request|trace|correlation|random)[_-]?id)\s*[:=]\s*[A-Za-z0-9._:-]{6,}\b/gi, "$1=<id>");
  value = value.replace(/\b(req|run|rnd)_[A-Za-z0-9_-]{6,}\b/g, "$1_<id>");
  value = value.replace(/\b0x[0-9a-f]{5,}\b/gi, "<address>");
  value = value.replace(/\b(pid|process(?:[_ -]?id)?)\s*[:=#]?\s*\d+\b/gi, "$1=<pid>");
  value = value.replace(/\b(port)\s*[:=#]?\s*\d{2,5}\b/gi, "$1=<port>");
  value = value.replace(/(https?:\/\/[^\s/:]+):\d{2,5}\b/gi, "$1:<port>");
  value = value.replace(/\b([A-Za-z0-9_.-]+\.[A-Za-z0-9]+):\d+:\d+\b/g, "$1:<line>:<column>");
  value = value.replace(/\b(line)\s+\d+(?:\s*[,;:]\s*(?:column|col)\s+\d+)?\b/gi, "$1 <line> column <column>");
  value = value.replace(/\b(retr(?:y|ies)|attempt)\s*(?:#|number)?\s*\d+\s*(?:\/|of)\s*\d+\b/gi, "$1 <retry>/<retry-limit>");
  value = value.replace(/\b(retr(?:y|ies)|attempt)\s*(?:#|number)?\s*\d+\b/gi, "$1 <retry>");
  return value.replace(/\s+/g, " ").trim();
}

export function signFailure(input: FailureSignatureInput): FailureSignatures {
  const value = signatureInputSchema.parse(input);
  if (value.profile.version !== SIGNATURE_PROFILE.version) throw new Error("SIGNATURE_PROFILE_UNSUPPORTED");
  assertSignatureSecretSafe(value);
  const normalizedText = normalizeFailureText(value.message);
  const preservedContext = {
    category: value.category,
    code: value.code,
    provider: value.provider,
    runtime: value.runtime,
    tool: value.tool,
    operation: value.operation,
    http_status: value.http_status ?? null,
    error_code: value.error_code ?? null,
    exception: value.exception ?? null,
    symbol: value.symbol ?? null,
  };
  const structuralText = normalizedText
    .replace(/"[^"]*"|'[^']*'/g, "<quoted>")
    .replace(/\b\d+\b/g, "<number>");
  return deepFreezePhase7({
    profile: SIGNATURE_PROFILE,
    exact_hash: canonicalSha256({ profile: value.profile, message: value.message, context: preservedContext, environment: value.environment }),
    normalized_signature: canonicalSha256({ profile: value.profile, normalized_text: normalizedText, context: preservedContext }),
    structural_signature: canonicalSha256({ profile: value.profile, structural_text: structuralText, context: preservedContext }),
    environment_fingerprint: canonicalSha256({ profile: value.profile, environment: value.environment }),
    normalized_text: normalizedText,
  });
}

function assertSignatureSecretSafe(value: unknown): void {
  try {
    assertNoStructuredPhase1Secret(value);
    assertNoPhase1Secret(JSON.stringify(value), "failure signature input");
  } catch {
    throw new Error("FAILURE_SIGNATURE_SECRET_REJECTED");
  }
}
