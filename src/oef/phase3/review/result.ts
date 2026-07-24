import { z } from "zod";
import { containsStructuredPhase1Secret } from "../../phase1/core/security/secrets";
import { FINDING_SEVERITIES } from "../core/domain";
import { isSafeRepositoryPath } from "./context";

const hashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const entityId = (prefix: string) => z.string().regex(new RegExp(`^${prefix}:[A-Za-z0-9][A-Za-z0-9._:@/-]*$`));
const evidenceRefSchema = z.string().trim().min(1).max(500);
const repositoryPathSchema = z.string().trim().min(1).max(4_000).refine(isSafeRepositoryPath, "Repository path must be canonical and relative");

const codeLocationSchema = z.object({
  path: repositoryPathSchema,
  start_line: z.number().int().positive(),
  end_line: z.number().int().positive(),
  file_hash: hashSchema,
}).strict().refine(value => value.start_line <= value.end_line, { path: ["end_line"], message: "Code location range is reversed" });

const resultFindingSchema = z.object({
  finding_key: z.string().regex(/^FIND-[A-Z0-9-]+$/),
  category: z.string().regex(/^[a-z0-9][a-z0-9-]*$/).max(160),
  proposed_severity: z.enum(FINDING_SEVERITIES),
  confidence: z.number().min(0).max(1),
  claim: z.string().trim().min(1).max(20_000),
  impact: z.string().trim().min(1).max(20_000),
  contract_refs: z.array(z.string().trim().min(1).max(300)).max(64),
  code_locations: z.array(codeLocationSchema).min(1).max(64),
  evidence_refs: z.array(evidenceRefSchema).max(256),
  verification: z.object({
    reproducible: z.boolean(),
    reproduction_steps: z.array(z.string().trim().min(1).max(4_000)).max(64),
  }).strict(),
  recommendation: z.string().trim().min(1).max(20_000),
}).strict().superRefine((value, context) => {
  if ((value.proposed_severity === "CRITICAL" || value.proposed_severity === "HIGH") && value.evidence_refs.length === 0) {
    context.addIssue({ code: "custom", path: ["evidence_refs"], message: "Blocking findings require evidence" });
  }
});

export const reviewResultSchema = z.object({
  schema_version: z.literal(1),
  review_unit_id: entityId("review-unit"),
  snapshot_hash: hashSchema,
  decision: z.object({ recommendation: z.enum(["pass", "changes-requested", "blocked", "needs-human", "inconclusive"]) }).strict(),
  summary: z.string().trim().min(1).max(50_000),
  findings: z.array(resultFindingSchema).max(1_000),
  unanswered_questions: z.array(z.string().trim().min(1).max(10_000)).max(256),
  requested_evidence: z.array(evidenceRefSchema).max(256),
}).strict();

export type ReviewResult = z.infer<typeof reviewResultSchema>;

const validationContextSchema = z.object({
  review_unit_id: entityId("review-unit"),
  snapshot_hash: hashSchema,
  snapshot_files: z.array(z.object({
    path: repositoryPathSchema,
    file_hash: hashSchema,
    line_count: z.number().int().nonnegative(),
  }).strict()).max(100_000),
  evidence_refs: z.array(evidenceRefSchema).max(100_000),
}).strict();

export type ReviewResultValidationContext = z.infer<typeof validationContextSchema>;

export const REVIEW_PROTOCOL_ERROR_REASONS = [
  "SCHEMA_INVALID",
  "VALIDATION_CONTEXT_INVALID",
  "UNIT_MISMATCH",
  "SNAPSHOT_MISMATCH",
  "DUPLICATE_FINDING_KEY",
  "FILE_NOT_IN_SNAPSHOT",
  "LINE_RANGE_INVALID",
  "FILE_HASH_MISMATCH",
  "EVIDENCE_REF_MISSING",
  "SECRET_DETECTED",
  "RETRY_LIMIT_EXCEEDED",
] as const;
export type ReviewProtocolErrorReason = typeof REVIEW_PROTOCOL_ERROR_REASONS[number];

export class ReviewProtocolError extends Error {
  readonly code = "REVIEW_PROTOCOL_ERROR" as const;
  constructor(readonly reason: ReviewProtocolErrorReason) {
    super("REVIEW_PROTOCOL_ERROR");
    this.name = "ReviewProtocolError";
  }
}

export function validateReviewResult(input: unknown, validationInput: unknown): ReviewResult {
  const raw = parsePayload(input);
  if (containsStructuredPhase1Secret(raw)) throw new ReviewProtocolError("SECRET_DETECTED");
  const parsed = safeParseOrProtocolError(reviewResultSchema, raw, "SCHEMA_INVALID");
  const validation = safeParseOrProtocolError(validationContextSchema, validationInput, "VALIDATION_CONTEXT_INVALID");
  if (parsed.review_unit_id !== validation.review_unit_id) throw new ReviewProtocolError("UNIT_MISMATCH");
  if (parsed.snapshot_hash !== validation.snapshot_hash) throw new ReviewProtocolError("SNAPSHOT_MISMATCH");

  const findingKeys = parsed.findings.map(finding => finding.finding_key);
  if (new Set(findingKeys).size !== findingKeys.length) throw new ReviewProtocolError("DUPLICATE_FINDING_KEY");

  const snapshotFiles = new Map(validation.snapshot_files.map(file => [file.path, file]));
  if (snapshotFiles.size !== validation.snapshot_files.length) throw new ReviewProtocolError("VALIDATION_CONTEXT_INVALID");
  const evidence = new Set(validation.evidence_refs);
  if (evidence.size !== validation.evidence_refs.length) throw new ReviewProtocolError("VALIDATION_CONTEXT_INVALID");
  for (const finding of parsed.findings) {
    for (const location of finding.code_locations) {
      const file = snapshotFiles.get(location.path);
      if (!file) throw new ReviewProtocolError("FILE_NOT_IN_SNAPSHOT");
      if (location.end_line > file.line_count) throw new ReviewProtocolError("LINE_RANGE_INVALID");
      if (location.file_hash !== file.file_hash) throw new ReviewProtocolError("FILE_HASH_MISMATCH");
    }
    if (finding.evidence_refs.some(reference => !evidence.has(reference))) throw new ReviewProtocolError("EVIDENCE_REF_MISSING");
  }
  return deepFreeze(parsed);
}

export function assertReviewProtocolRetryAllowed(attempt: number, maximumAttempts: number): true {
  if (!Number.isInteger(attempt) || !Number.isInteger(maximumAttempts) || attempt < 0 || maximumAttempts < 1 || attempt >= maximumAttempts) {
    throw new ReviewProtocolError("RETRY_LIMIT_EXCEEDED");
  }
  return true;
}

function parsePayload(input: unknown): unknown {
  if (typeof input !== "string") return input;
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new ReviewProtocolError("SCHEMA_INVALID");
  }
}

function safeParseOrProtocolError<T>(schema: z.ZodType<T>, input: unknown, reason: ReviewProtocolErrorReason): T {
  const parsed = schema.safeParse(input);
  if (!parsed.success) throw new ReviewProtocolError(reason);
  return parsed.data;
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}
