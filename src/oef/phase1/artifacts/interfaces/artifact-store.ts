import { z } from "zod";
import { actorSchema, type Actor } from "../../core/shared/actor";

export type ArtifactClassification = "public" | "internal" | "confidential";

export const artifactRefSchema = z.object({
  artifact_id: z.string().trim().min(1),
  content_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  media_type: z.string().trim().min(1).max(200),
  size_bytes: z.number().int().nonnegative(),
  classification: z.enum(["public", "internal", "confidential"]),
  retention_policy: z.string().trim().min(1).max(200),
  created_by: actorSchema,
  storage_key: z.string().regex(/^[a-f0-9]{2}\/[a-f0-9]{2}\/[a-f0-9]{64}$/),
  deduplicated: z.boolean(),
}).strict();

export interface ArtifactRef {
  artifact_id: string;
  content_hash: string;
  media_type: string;
  size_bytes: number;
  classification: ArtifactClassification;
  retention_policy: string;
  created_by: Actor;
  storage_key: string;
  deduplicated: boolean;
}

export interface ArtifactInput {
  content: string | Uint8Array;
  media_type: string;
  classification: ArtifactClassification;
  retention_policy: string;
  created_by: Actor;
}

export interface IntegrityResult {
  valid: boolean;
  content_hash: string;
  reason?: "missing" | "hash-mismatch" | "unsafe-path";
}

export interface ArtifactStore {
  put(input: ArtifactInput): ArtifactRef;
  get(ref: ArtifactRef): Uint8Array;
  verify(ref: ArtifactRef): IntegrityResult;
}

export function parseArtifactRef(input: unknown): ArtifactRef {
  return artifactRefSchema.parse(input);
}
