import { z } from "zod";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";

const hashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);

export const REVIEW_CACHEABLE_ANALYSES = [
  "ast-index",
  "dependency-graph",
  "static-analysis",
  "file-summary",
  "symbol-map",
  "unchanged-file-hash-analysis",
] as const;

const cacheKeyInputSchema = z.object({
  analysis_type: z.enum(REVIEW_CACHEABLE_ANALYSES),
  file_hash: hashSchema,
  analyzer_version: z.string().trim().min(1).max(500),
  review_profile_version: z.string().trim().min(1).max(500),
}).strict();

export interface ReviewAnalysisCacheKey {
  readonly schema_version: 1;
  readonly analysis_type: (typeof REVIEW_CACHEABLE_ANALYSES)[number];
  readonly file_hash: string;
  readonly analyzer_version: string;
  readonly review_profile_version: string;
  readonly key: string;
}

export function createReviewAnalysisCacheKey(input: unknown): ReviewAnalysisCacheKey {
  const parsed = cacheKeyInputSchema.safeParse(input);
  if (!parsed.success) throw new Error("REVIEW_ANALYSIS_CACHE_KEY_INVALID");
  const content = { schema_version: 1 as const, ...parsed.data };
  return Object.freeze({ ...content, key: canonicalSha256(content) });
}
