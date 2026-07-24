import { describe, expect, test } from "bun:test";
import {
  REVIEW_CONTEXT_TRUST_ORDER,
  ReviewContextBundleCompiler,
  ReviewProtocolError,
  assertReviewProtocolRetryAllowed,
  assertReviewerCapabilities,
  parseReviewerBinding,
  validateReviewResult,
} from "../src/oef/phase3/review";

const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;
const HASH_C = `sha256:${"c".repeat(64)}`;
const NOW = "2026-07-23T15:00:00.000Z";

function binding(overrides: Record<string, unknown> = {}) {
  return {
    schema_version: 1,
    reviewer_binding_id: "reviewer-binding:test",
    review_unit_id: "review-unit:quality",
    reviewer_profile_ref: { id: "code-quality", version: "1.0.0", hash: HASH_A },
    runtime_ref: { id: "reviewer-runtime-1", adapter_version: "1.0.0" },
    model_ref: { provider: "provider-b", model_class: "review-high", resolved_model: "review-model-v1" },
    reviewer_capabilities: ["diff-analysis", "structured-findings", "contract-traceability"],
    risk_level: "high",
    independence: {
      implementer: { agent_id: "agent:implementer", provider: "provider-a", model_class: "coding-high", session_id: "session:impl", context_id: "context:impl" },
      reviewer: { agent_id: "agent:reviewer", provider: "provider-b", model_class: "review-high", session_id: "session:review", context_id: "context:review" },
      source_access: "read-only",
      human_approval_required: false,
    },
    created_by: { type: "system", id: "system:review-router" },
    created_at: NOW,
    ...overrides,
  };
}

function contextInput(overrides: Record<string, unknown> = {}) {
  return {
    context_bundle_id: "review-context-bundle:test",
    snapshot_hash: HASH_A,
    review_unit: {
      id: "review-unit:quality",
      objective: "Independently review correctness and maintainability.",
      profile_ref: { id: "code-quality", version: "1.0.0", hash: HASH_B },
    },
    task_contract: {
      revision_id: "contract-revision:test",
      revision: 3,
      hash: HASH_C,
      goal: "Classify provider errors correctly.",
      constraints: ["Do not rotate accounts for authentication errors."],
      acceptance_criteria: ["403 is classified as auth failure."],
    },
    review_plan: { id: "review-plan:test", revision: 1, hash: HASH_B },
    policy_pack: { id: "safe-default", version: "1.0.0", hash: HASH_A },
    assignment: { objective: "Fix error classification.", allowed_paths: ["src/providers/error-classifier.ts"] },
    source: {
      base_commit: "abc123",
      changed_files: ["src/providers/error-classifier.ts"],
      diff_artifact_ref: "artifact:diff",
      relevant_file_refs: [{ path: "src/providers/error-classifier.ts", artifact_ref: "artifact:source", file_hash: HASH_C }],
    },
    evidence: {
      mechanical_verification: ["evidence:test"],
      baseline: ["evidence:baseline"],
      secret_scan: ["evidence:secret-scan"],
      dependency_changes: [],
    },
    repository_rules: [{ path: "AGENTS.md", artifact_ref: "artifact:agents", file_hash: HASH_A }],
    implementer_summary: { content: "Implemented status-specific classification." },
    previous_findings: [],
    generated_at: NOW,
    history: [{ role: "assistant", content: "private implementation conversation" }],
    hidden_reasoning: "private chain of thought",
    ...overrides,
  };
}

function result(overrides: Record<string, unknown> = {}) {
  return {
    schema_version: 1,
    review_unit_id: "review-unit:quality",
    snapshot_hash: HASH_A,
    decision: { recommendation: "changes-requested" },
    summary: "The main behavior works, but 403 is misclassified.",
    findings: [{
      finding_key: "FIND-001",
      category: "correctness",
      proposed_severity: "HIGH",
      confidence: 0.93,
      claim: "403 is classified as a rate limit.",
      impact: "Authentication failures rotate to the wrong account.",
      contract_refs: ["constraint-auth-errors"],
      code_locations: [{ path: "src/providers/error-classifier.ts", start_line: 2, end_line: 4, file_hash: HASH_B }],
      evidence_refs: ["evidence:test-403"],
      verification: { reproducible: true, reproduction_steps: ["bun test tests/error-classifier.test.ts"] },
      recommendation: "Classify 401 and 403 as authentication failures.",
    }],
    unanswered_questions: [],
    requested_evidence: [],
    ...overrides,
  };
}

const validationContext = {
  review_unit_id: "review-unit:quality",
  snapshot_hash: HASH_A,
  snapshot_files: [{ path: "src/providers/error-classifier.ts", file_hash: HASH_B, line_count: 20 }],
  evidence_refs: ["evidence:test-403"],
};

describe("Phase 3 reviewer binding", () => {
  test("pins runtime/model selection and proves independent, read-only reviewer capabilities", () => {
    const parsed = parseReviewerBinding(binding());
    expect(parsed.model_ref.resolved_model).toBe("review-model-v1");
    expect(parsed.independence.source_access).toBe("read-only");
    expect(assertReviewerCapabilities(parsed, ["diff-analysis", "structured-findings"])).toBeTrue();
    expect(() => assertReviewerCapabilities(parsed, ["security-analysis"])).toThrow("REVIEWER_CAPABILITY_MISMATCH");
  });

  test("rejects self-review, shared session/context, and source write access", () => {
    const base = binding().independence as Record<string, unknown>;
    const implementer = base.implementer as Record<string, unknown>;
    const reviewer = base.reviewer as Record<string, unknown>;
    expect(() => parseReviewerBinding(binding({ independence: { ...base, reviewer: { ...reviewer, agent_id: implementer.agent_id } } }))).toThrow("REVIEWER_SELF_REVIEW_FORBIDDEN");
    expect(() => parseReviewerBinding(binding({ independence: { ...base, reviewer: { ...reviewer, session_id: implementer.session_id } } }))).toThrow("REVIEWER_SESSION_NOT_INDEPENDENT");
    expect(() => parseReviewerBinding(binding({ independence: { ...base, reviewer: { ...reviewer, context_id: implementer.context_id } } }))).toThrow("REVIEWER_CONTEXT_NOT_INDEPENDENT");
    expect(() => parseReviewerBinding(binding({ independence: { ...base, source_access: "read-write" } }))).toThrow();
  });

  test("requires another model/provider for high risk and another provider plus human gate for critical risk", () => {
    const base = binding().independence as Record<string, unknown>;
    const implementer = base.implementer as Record<string, unknown>;
    const reviewer = base.reviewer as Record<string, unknown>;
    expect(() => parseReviewerBinding(binding({
      model_ref: { provider: "provider-a", model_class: "coding-high", resolved_model: "same-model" },
      independence: { ...base, reviewer: { ...reviewer, provider: "provider-a", model_class: "coding-high" } },
    }))).toThrow("REVIEWER_HIGH_RISK_INDEPENDENCE_REQUIRED");
    expect(parseReviewerBinding(binding({
      model_ref: { provider: "provider-a", model_class: "review-high", resolved_model: "different-model" },
      independence: { ...base, reviewer: { ...reviewer, provider: "provider-a", model_class: "review-high" } },
    })).risk_level).toBe("high");
    expect(() => parseReviewerBinding(binding({ risk_level: "critical", independence: { ...base, human_approval_required: false } }))).toThrow("REVIEWER_CRITICAL_HUMAN_GATE_REQUIRED");
    expect(() => parseReviewerBinding(binding({
      risk_level: "critical",
      model_ref: { provider: "provider-a", model_class: "review-high", resolved_model: "different-model" },
      independence: { ...base, reviewer: { ...reviewer, provider: "provider-a", model_class: "review-high" }, human_approval_required: true },
    }))).toThrow("REVIEWER_CRITICAL_PROVIDER_INDEPENDENCE_REQUIRED");
    expect(parseReviewerBinding(binding({ risk_level: "critical", independence: { ...base, human_approval_required: true } })).risk_level).toBe("critical");
  });
});

describe("Phase 3 review context", () => {
  test("compiles a hashed allowlisted bundle without implementer history or hidden reasoning", () => {
    const bundle = new ReviewContextBundleCompiler().compile(contextInput());
    const serialized = JSON.stringify(bundle);
    expect(serialized).not.toContain("private implementation conversation");
    expect(serialized).not.toContain("private chain of thought");
    expect(bundle.implementer_summary.trust_level).toBe("unverified-claim");
    expect(bundle.trust_order).toEqual(REVIEW_CONTEXT_TRUST_ORDER);
    expect(bundle.output_contract).toEqual({ format: "structured-json", schema_ref: "review-result@1" });
    expect(bundle.provenance.content_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(Object.isFrozen(bundle)).toBeTrue();
  });

  test("rejects secrets and unsafe repository paths before producing reviewer context", () => {
    const compiler = new ReviewContextBundleCompiler();
    expect(() => compiler.compile(contextInput({ implementer_summary: { content: "Authorization: Bearer abcdefghijklmnopqrstuvwxyz" } })))
      .toThrow("REVIEW_CONTEXT_SECRET_DETECTED");
    expect(() => compiler.compile(contextInput({ assignment: { objective: "Fix it", allowed_paths: ["../secrets.env"] } })))
      .toThrow();
  });
});

describe("Phase 3 structured review result", () => {
  test("accepts model-independent results bound to the unit, snapshot, files, lines, and evidence", () => {
    const parsed = validateReviewResult(result(), validationContext);
    expect(parsed.findings[0]?.finding_key).toBe("FIND-001");
    expect(parsed).not.toHaveProperty("model_ref");
    expect(parsed).not.toHaveProperty("runtime_ref");
  });

  test("rejects stale/wrong bindings, missing snapshot files, line/hash drift, and missing evidence", () => {
    expectProtocolError(() => validateReviewResult(result({ review_unit_id: "review-unit:other" }), validationContext), "UNIT_MISMATCH");
    expectProtocolError(() => validateReviewResult(result({ snapshot_hash: HASH_C }), validationContext), "SNAPSHOT_MISMATCH");
    const finding = (result().findings as Array<Record<string, unknown>>)[0]!;
    expectProtocolError(() => validateReviewResult(result({ findings: [{ ...finding, code_locations: [{ path: "src/other.ts", start_line: 1, end_line: 2, file_hash: HASH_B }] }] }), validationContext), "FILE_NOT_IN_SNAPSHOT");
    expectProtocolError(() => validateReviewResult(result({ findings: [{ ...finding, code_locations: [{ path: "src/providers/error-classifier.ts", start_line: 2, end_line: 21, file_hash: HASH_B }] }] }), validationContext), "LINE_RANGE_INVALID");
    expectProtocolError(() => validateReviewResult(result({ findings: [{ ...finding, code_locations: [{ path: "src/providers/error-classifier.ts", start_line: 2, end_line: 4, file_hash: HASH_C }] }] }), validationContext), "FILE_HASH_MISMATCH");
    expectProtocolError(() => validateReviewResult(result({ findings: [{ ...finding, evidence_refs: ["evidence:missing"] }] }), validationContext), "EVIDENCE_REF_MISSING");
  });

  test("rejects duplicate finding keys, path escapes, secrets, and runtime/model metadata with a safe protocol error", () => {
    const finding = (result().findings as Array<Record<string, unknown>>)[0]!;
    expectProtocolError(() => validateReviewResult(result({ findings: [finding, finding] }), validationContext), "DUPLICATE_FINDING_KEY");
    expectProtocolError(() => validateReviewResult(result({ findings: [{ ...finding, code_locations: [{ path: "../secret", start_line: 1, end_line: 2, file_hash: HASH_B }] }] }), validationContext), "SCHEMA_INVALID");
    expectProtocolError(() => validateReviewResult(result({ summary: "api_key=abcdefghijklmnop" }), validationContext), "SECRET_DETECTED");
    expectProtocolError(() => validateReviewResult({ ...result(), model_ref: { provider: "provider-b" } }, validationContext), "SCHEMA_INVALID");
  });

  test("bounds protocol retries deterministically", () => {
    expect(assertReviewProtocolRetryAllowed(0, 2)).toBeTrue();
    expect(assertReviewProtocolRetryAllowed(1, 2)).toBeTrue();
    expectProtocolError(() => assertReviewProtocolRetryAllowed(2, 2), "RETRY_LIMIT_EXCEEDED");
  });
});

function expectProtocolError(run: () => unknown, reason: string): void {
  try {
    run();
    throw new Error("Expected review protocol failure");
  } catch (error) {
    expect(error).toBeInstanceOf(ReviewProtocolError);
    expect((error as Error).message).toBe("REVIEW_PROTOCOL_ERROR");
    expect((error as ReviewProtocolError).reason).toBe(reason);
    expect((error as Error).message).not.toContain("api_key");
  }
}
