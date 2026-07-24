import { describe, expect, test } from "bun:test";
import {
  compileReviewPlan,
  createBuiltInReviewTypeRegistry,
  createReviewProfile,
  createReviewSnapshot,
  createReviewTypeRegistry,
  hashReviewPlan,
  type ReviewProfile,
  type ReviewProfileRef,
} from "../src/oef/phase3";

const NOW = "2026-07-23T19:00:00.000Z";
const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;
const HASH_C = `sha256:${"c".repeat(64)}`;

const reviewTypes = [
  "opencodex.spec-compliance",
  "opencodex.code-quality",
  "opencodex.security",
  "opencodex.data-migration",
  "opencodex.rollback",
  "opencodex.visual",
  "opencodex.accessibility",
  "opencodex.dependency-security",
  "opencodex.backward-compatibility",
  "opencodex.performance",
] as const;

function profile(reviewType: string): ReviewProfile {
  const slug = reviewType.split(".").at(-1)!;
  return createReviewProfile({
    review_profile_id: slug,
    version: "1.0.0",
    objective: `Independently review ${reviewType}.`,
    required_inputs: ["task-contract", "diff", "mechanical-verification"],
    required_capabilities: ["diff-analysis", "structured-findings"],
    preferred_capabilities: ["repository-navigation"],
    workspace: { source_mode: "read-only", temp_write: "allowed", network: "denied" },
    checks: { correctness: true },
    output_schema_ref: { id: "review-result", version: 1 },
    renderer_ref: { id: "generic-code-review", version: "1.0.0" },
    budgets: { max_wall_time_seconds: 1200, max_output_tokens: 12_000 },
    independence: { different_session: "required", different_context: "required", different_provider: "preferred" },
    extensions: {},
    created_at: NOW,
  });
}

function ref(value: ReviewProfile): ReviewProfileRef {
  return { id: value.review_profile_id, version: value.version, hash: value.content_hash };
}

function fixture() {
  const profiles = Object.fromEntries(reviewTypes.map(type => [type, profile(type)]));
  const refs = Object.fromEntries(Object.entries(profiles).map(([type, value]) => [type, ref(value)]));
  const registry = createBuiltInReviewTypeRegistry(refs);
  const snapshot = createReviewSnapshot({
    review_snapshot_id: "review-snapshot:compiler",
    contract: { revision_id: "contract-revision:compiler", revision: 1, hash: HASH_A },
    source: { base_commit: "abc123", result_tree_hash: HASH_B, diff_hash: HASH_C },
    evidence: { package_id: `evidence-package:${"d".repeat(64)}`, package_hash: `sha256:${"d".repeat(64)}` },
    workflow: { id: "software-development", version: "1.0.0", hash: `sha256:${"e".repeat(64)}` },
    policy: { id: "safe-default", version: "1.0.0", hash: `sha256:${"f".repeat(64)}` },
    created_at: NOW,
  });
  const base = {
    review_plan_id: "review-plan:compiler",
    revision: 1,
    previous_revision_hash: null,
    review_request_id: "review-request:compiler",
    task_id: "task:compiler",
    snapshot,
    risk: { level: "low" as const, reasons: [] as string[] },
    changes: {
      changed_files: [{ path: "src/core/service.ts", change: "modified" as const, classifications: [] as string[] }],
      dependency_changes: [] as Array<{ name: string; change: "added" | "updated" | "removed" }>,
      api_contract_changed: false,
      performance_critical_changed: false,
    },
    evidence_types: ["test-report"],
    workflow_id: "software-development",
    repository_class: "application",
    assignment_role: "implementer",
    requested_review_types: ["opencodex.spec-compliance", "opencodex.code-quality"],
    registry,
    profiles,
    recommendations: { add_review_types: [] as string[], remove_review_types: [] as string[] },
    adjudication_policy_ref: { id: "safe-default", version: "1.0.0", hash: HASH_A },
    created_at: NOW,
  };
  return { base, profiles, refs, registry };
}

function selected(input: Parameters<typeof compileReviewPlan>[0]): string[] {
  return compileReviewPlan(input).review_units.map(unit => unit.review_type);
}

describe("Phase 3 deterministic Review Plan Compiler", () => {
  test("always selects spec and quality for code, then adds all deterministic risk reviews", () => {
    const { base } = fixture();
    expect(selected({
      ...base,
      changes: {
        changed_files: [
          { path: "src/auth/credentials.ts", change: "modified", classifications: [] },
          { path: "src/db/migrations/002_accounts.sql", change: "added", classifications: [] },
          { path: "src/frontend/components/Login.tsx", change: "modified", classifications: [] },
          { path: "openapi/public-api.yaml", change: "modified", classifications: [] },
        ],
        dependency_changes: [{ name: "new-http-client", change: "added" }],
        api_contract_changed: false,
        performance_critical_changed: true,
      },
    })).toEqual([
      "opencodex.accessibility",
      "opencodex.backward-compatibility",
      "opencodex.code-quality",
      "opencodex.data-migration",
      "opencodex.dependency-security",
      "opencodex.performance",
      "opencodex.rollback",
      "opencodex.security",
      "opencodex.spec-compliance",
      "opencodex.visual",
    ]);
  });

  test("does not invent security review for a low-risk docs-only change", () => {
    const { base } = fixture();
    expect(selected({
      ...base,
      changes: {
        ...base.changes,
        changed_files: [{ path: "docs/review-governance.md", change: "modified", classifications: ["documentation"] }],
      },
    })).toEqual(["opencodex.code-quality", "opencodex.spec-compliance"]);
    expect(selected({
      ...base,
      changes: {
        ...base.changes,
        changed_files: [{ path: "docs/review-governance.md", change: "modified", classifications: ["documentation"] }],
      },
    })).not.toContain("opencodex.security");
  });

  test("keeps required rules when an advisor requests removal and allows registered additive review types", () => {
    const { base, profiles, refs, registry } = fixture();
    const architecture = profile("company.architecture");
    const extended = registry.withPlugin({
      plugin_id: "company.review-pack",
      protocol_version: 1,
      review_types: [{
        review_type: "company.architecture",
        profile_ref: ref(architecture),
        required_capabilities: ["architecture-reasoning", "structured-findings"],
        preferred_capabilities: ["repository-navigation"],
        prerequisites: ["workspace.sealed"],
      }],
    });
    const plan = compileReviewPlan({
      ...base,
      registry: extended,
      profiles: { ...profiles, "company.architecture": architecture },
      recommendations: {
        add_review_types: ["company.architecture"],
        remove_review_types: ["opencodex.spec-compliance", "opencodex.code-quality"],
      },
    });
    expect(plan.review_units.map(unit => unit.review_type)).toContain("company.architecture");
    expect(plan.review_units.filter(unit => unit.required).map(unit => unit.review_type)).toEqual([
      "opencodex.code-quality",
      "opencodex.spec-compliance",
    ]);
    expect(refs["opencodex.code-quality"]).toBeDefined();
  });

  test("fails closed when a selected profile is absent or does not match its pinned hash", () => {
    const { base, profiles } = fixture();
    const { "opencodex.code-quality": missing, ...withoutQuality } = profiles;
    expect(missing).toBeDefined();
    expect(() => compileReviewPlan({ ...base, profiles: withoutQuality }))
      .toThrow("REVIEW_PROFILE_NOT_FOUND:opencodex.code-quality");
    expect(() => compileReviewPlan({
      ...base,
      profiles: { ...profiles, "opencodex.code-quality": profile("opencodex.code-quality") },
    })).not.toThrow();
    const drifted = createReviewProfile({
      ...profiles["opencodex.code-quality"],
      objective: "Changed after registry pinning.",
      content_hash: undefined,
    } as never);
    expect(() => compileReviewPlan({
      ...base,
      profiles: { ...profiles, "opencodex.code-quality": drifted },
    })).toThrow("REVIEW_PROFILE_PIN_MISMATCH:opencodex.code-quality");
  });

  test("produces canonical order, ids, and plan hash for semantically identical unordered input", () => {
    const { base } = fixture();
    const left = compileReviewPlan({
      ...base,
      risk: { level: "high", reasons: ["credentials", "api-contract", "credentials"] },
      changes: {
        ...base.changes,
        changed_files: [
          { path: "src/auth/credentials.ts", change: "modified", classifications: [] },
          { path: "src/core/service.ts", change: "modified", classifications: [] },
        ],
      },
    });
    const right = compileReviewPlan({
      ...base,
      risk: { level: "high", reasons: ["api-contract", "credentials"] },
      changes: {
        ...base.changes,
        changed_files: [
          { path: "src/core/service.ts", change: "modified", classifications: [] },
          { path: "src/auth/credentials.ts", change: "modified", classifications: [] },
        ],
      },
    });
    expect(right).toEqual(left);
    expect(hashReviewPlan(right)).toBe(hashReviewPlan(left));
  });

  test("sets deterministic independence quorum and human gate from risk", () => {
    const expected = {
      low: { minimum_independent_providers: 1, minimum_independence_score: 1, human_approval: "not-required" },
      medium: { minimum_independent_providers: 1, minimum_independence_score: 1, human_approval: "not-required" },
      high: { minimum_independent_providers: 1, minimum_independence_score: 3, human_approval: "not-required" },
      critical: { minimum_independent_providers: 2, minimum_independence_score: 4, human_approval: "required" },
    } as const;
    for (const level of ["low", "medium", "high", "critical"] as const) {
      const { base } = fixture();
      const quorum = compileReviewPlan({ ...base, risk: { level, reasons: [level] } }).quorum;
      expect(quorum).toMatchObject(expected[level]);
    }
    const { base } = fixture();
    expect(compileReviewPlan({ ...base, risk: { level: "critical", reasons: ["production"] } }).quorum.required_review_types)
      .toContain("opencodex.security");
  });

  test("keeps plugin registration additive, namespaced, immutable, and outside policy authority", () => {
    const { refs, registry } = fixture();
    const plugin = {
      plugin_id: "company.review-pack",
      protocol_version: 1 as const,
      review_types: [{
        review_type: "company.compliance",
        profile_ref: refs["opencodex.code-quality"]!,
        required_capabilities: ["contract-traceability" as const],
        preferred_capabilities: [],
        prerequisites: [],
      }],
    };
    const extended = registry.withPlugin(plugin);
    expect(extended.resolve("company.compliance")?.source).toEqual({ type: "plugin", plugin_id: "company.review-pack" });
    expect(registry.resolve("company.compliance")).toBeUndefined();
    expect(() => extended.withPlugin({ ...plugin, review_types: [{ ...plugin.review_types[0]!, review_type: "opencodex.code-quality" }] }))
      .toThrow("REVIEW_TYPE_ALREADY_REGISTERED:opencodex.code-quality");
    expect(() => createReviewTypeRegistry().withPlugin({ ...plugin, review_types: [{ ...plugin.review_types[0]!, review_type: "not-namespaced" }] }))
      .toThrow();
  });
});
