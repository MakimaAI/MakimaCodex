import { z } from "zod";
import { REVIEWER_CAPABILITIES } from "../core/domain";
import type {
  ReviewPluginManifest,
  ReviewProfileRef,
  ReviewTypeDefinition,
  ReviewTypeRegistryPort,
} from "./types";

const hashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const semverSchema = z.string().regex(/^\d+\.\d+\.\d+$/);
const namespacedTypeSchema = z.string().regex(/^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/);

const profileRefSchema = z.object({
  id: z.string().trim().min(1).max(160),
  version: semverSchema,
  hash: hashSchema,
}).strict();

const definitionInputSchema = z.object({
  review_type: namespacedTypeSchema,
  profile_ref: profileRefSchema,
  required_capabilities: z.array(z.enum(REVIEWER_CAPABILITIES)).min(1),
  preferred_capabilities: z.array(z.enum(REVIEWER_CAPABILITIES)),
  prerequisites: z.array(z.string().regex(/^[a-z0-9][a-z0-9.-]*$/)),
}).strict();

const pluginManifestSchema = z.object({
  plugin_id: namespacedTypeSchema,
  protocol_version: z.literal(1),
  review_types: z.array(definitionInputSchema).min(1).max(32),
}).strict();

const DEFAULT_REQUIRED_CAPABILITIES = ["diff-analysis", "structured-findings"] as const;
const DEFAULT_PREFERRED_CAPABILITIES = ["repository-navigation"] as const;
const DEFAULT_PREREQUISITES = ["mechanical-verification.passed", "workspace.sealed"] as const;

function freezeDefinition(definition: ReviewTypeDefinition): ReviewTypeDefinition {
  return Object.freeze({
    ...definition,
    profile_ref: Object.freeze({ ...definition.profile_ref }),
    required_capabilities: Object.freeze([...definition.required_capabilities]),
    preferred_capabilities: Object.freeze([...definition.preferred_capabilities]),
    prerequisites: Object.freeze([...definition.prerequisites]),
    source: Object.freeze({ ...definition.source }),
  });
}

export class ReviewTypeRegistry implements ReviewTypeRegistryPort {
  readonly #definitions: ReadonlyMap<string, ReviewTypeDefinition>;

  constructor(definitions: Iterable<ReviewTypeDefinition> = []) {
    const next = new Map<string, ReviewTypeDefinition>();
    for (const definition of definitions) {
      if (next.has(definition.review_type)) throw new Error(`REVIEW_TYPE_ALREADY_REGISTERED:${definition.review_type}`);
      next.set(definition.review_type, freezeDefinition(definition));
    }
    this.#definitions = next;
    Object.freeze(this);
  }

  resolve(reviewType: string): ReviewTypeDefinition | undefined {
    return this.#definitions.get(reviewType);
  }

  list(): readonly ReviewTypeDefinition[] {
    return Object.freeze([...this.#definitions.values()].sort((left, right) => left.review_type.localeCompare(right.review_type)));
  }

  withPlugin(input: ReviewPluginManifest): ReviewTypeRegistry {
    const manifest = pluginManifestSchema.parse(input);
    const next = new Map(this.#definitions);
    for (const raw of [...manifest.review_types].sort((left, right) => left.review_type.localeCompare(right.review_type))) {
      if (next.has(raw.review_type)) throw new Error(`REVIEW_TYPE_ALREADY_REGISTERED:${raw.review_type}`);
      next.set(raw.review_type, freezeDefinition({
        ...raw,
        source: { type: "plugin", plugin_id: manifest.plugin_id },
      }));
    }
    return new ReviewTypeRegistry(next.values());
  }
}

export function createReviewTypeRegistry(): ReviewTypeRegistry {
  return new ReviewTypeRegistry();
}

export function createBuiltInReviewTypeRegistry(
  profileRefs: Readonly<Record<string, ReviewProfileRef>>,
): ReviewTypeRegistry {
  const definitions = Object.entries(profileRefs)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([reviewType, profileRef]) => {
      namespacedTypeSchema.parse(reviewType);
      const parsedRef = profileRefSchema.parse(profileRef);
      return {
        review_type: reviewType,
        profile_ref: parsedRef,
        required_capabilities: DEFAULT_REQUIRED_CAPABILITIES,
        preferred_capabilities: DEFAULT_PREFERRED_CAPABILITIES,
        prerequisites: DEFAULT_PREREQUISITES,
        source: { type: "built-in" as const },
      } satisfies ReviewTypeDefinition;
    });
  return new ReviewTypeRegistry(definitions);
}
