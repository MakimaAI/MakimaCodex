import { describe, expect, test } from "bun:test";
import * as phase6 from "../src/oef/phase6";

const now = "2026-07-24T12:00:00.000Z";
const api = phase6 as Record<string, any>;

function lessonInput(overrides: Record<string, unknown> = {}) {
  return {
    memory_id: "memory:lesson-403",
    layer: "LESSON",
    kind: "opencodex.lesson.failure-pattern",
    scopes: [
      { type: "REPOSITORY", id: "opencodex" },
      { type: "PROVIDER", id: "clinepass" },
    ],
    subject: { type: "error-classification", key: "http-403" },
    content: {
      summary: "ClinePass provider v2 treats HTTP 403 as authorization failure, not quota.",
      structured: { status_code: 403, classification: "authorization-failed" },
    },
    lifecycle: { status: "VERIFIED" },
    trust: { level: "HIGH", confidence: 0.96 },
    temporal: { observed_at: now, valid_from: now, valid_until: null, last_verified_at: now },
    provenance: {
      source_refs: ["evidence:test-403", "finding:confirmed-403"],
      extractor_ref: { id: "failure-lesson-extractor", version: "1.0.0" },
    },
    relations: { supersedes: [], contradicts: [], derived_from: ["memory:episode-task-142"] },
    access: { sensitivity: "INTERNAL", read_roles: ["backend-implementer", "reviewer"] },
    retention: { policy: "repository-durable" },
    created_at: now,
    created_by: { type: "verifier", id: "verifier:phase3" },
    ...overrides,
  };
}

describe("Phase 6 memory domain", () => {
  test("creates an immutable, provenance-bound canonical revision", () => {
    expect(typeof api.createMemoryRecord).toBe("function");
    const record = api.createMemoryRecord(lessonInput());

    expect(record).toMatchObject({
      schema_version: 1,
      memory_id: "memory:lesson-403",
      revision_number: 1,
      layer: "LESSON",
      lifecycle: { status: "VERIFIED" },
    });
    expect(record.revision_id).toMatch(/^memory-revision:/);
    expect(record.integrity.content_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(record.integrity.provenance_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(Object.isFrozen(record)).toBe(true);
    expect(Object.isFrozen(record.content)).toBe(true);
  });

  test("fails closed for secret, unproven verified, and agent-authored governance memory", () => {
    expect(() => api.createMemoryRecord(lessonInput({
      memory_id: "memory:secret",
      access: { sensitivity: "SECRET", read_roles: [] },
    }))).toThrow("MEMORY_SECRET_FORBIDDEN");

    expect(() => api.createMemoryRecord(lessonInput({
      memory_id: "memory:no-evidence",
      provenance: { source_refs: [], extractor_ref: null },
    }))).toThrow("MEMORY_VERIFICATION_REQUIRES_PROVENANCE");

    expect(() => api.createMemoryRecord(lessonInput({
      memory_id: "memory:governance",
      layer: "GOVERNANCE",
      kind: "opencodex.governance.constitution",
      created_by: { type: "agent", id: "agent:architect" },
    }))).toThrow("MEMORY_GOVERNANCE_HUMAN_APPROVAL_REQUIRED");
  });

  test("appends a new revision without mutating the prior revision", () => {
    expect(typeof api.appendMemoryRevision).toBe("function");
    const first = api.createMemoryRecord(lessonInput());
    const second = api.appendMemoryRevision(first, {
      content: {
        summary: "ClinePass provider v3 documents HTTP 403 as permission denied.",
        structured: { status_code: 403, classification: "permission-denied", provider_version: 3 },
      },
      provenance: {
        source_refs: ["evidence:test-403-v3", "documentation:clinepass-v3"],
        extractor_ref: { id: "human-correction", version: "1.0.0" },
      },
      temporal: { observed_at: now, valid_from: now, valid_until: null, last_verified_at: now },
    }, {
      expected_revision: 1,
      reason: "Provider v3 behavior changed",
      actor: { type: "human", id: "human:owner" },
      at: "2026-07-24T13:00:00.000Z",
    });

    expect(first.revision_number).toBe(1);
    expect(first.content.summary).toContain("provider v2");
    expect(second).toMatchObject({ revision_number: 2, previous_revision_id: first.revision_id });
    expect(second.revision_id).not.toBe(first.revision_id);
    expect(second.change.reason).toBe("Provider v3 behavior changed");
    expect(() => api.appendMemoryRevision(first, {}, {
      expected_revision: 2,
      reason: "stale writer",
      actor: { type: "human", id: "human:owner" },
      at: now,
    })).toThrow("MEMORY_REVISION_CONFLICT");
  });

  test("allows facts to become valid before the system observes them", () => {
    const record = api.createMemoryRecord(lessonInput({
      memory_id: "memory:backdated-validity",
      temporal: {
        observed_at: "2026-07-24T12:00:00.000Z",
        valid_from: "2026-07-01T00:00:00.000Z",
        valid_until: null,
        last_verified_at: "2026-07-24T12:00:00.000Z",
      },
    }));

    expect(record.temporal.valid_from).toBe("2026-07-01T00:00:00.000Z");
    expect(record.temporal.observed_at).toBe("2026-07-24T12:00:00.000Z");
  });
});
