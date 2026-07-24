import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { appendMemoryRevision, createMemoryRecord, type MemoryQuery } from "../core/domain";
import { SqliteMemoryStore } from "../persistence/sqlite-store";
import { MemoryRetrievalEngine } from "../retrieval/engine";

const observedAt = "2026-07-24T10:00:00.000Z";

export async function runPhase6AcceptanceDemo(options: { root: string }): Promise<Record<string, unknown>> {
  const root = resolve(options.root);
  mkdirSync(root, { recursive: true });
  const store = new SqliteMemoryStore({ databasePath: join(root, "memory.sqlite") });
  try {
    const episode = createMemoryRecord({
      memory_id: "memory:episode-task-142",
      layer: "EPISODE",
      kind: "opencodex.episode.execution",
      scopes: [{ type: "TASK", id: "task-142" }, { type: "REPOSITORY", id: "opencodex" }],
      subject: { type: "task-attempt", key: "task-142-attempt-1" },
      content: { summary: "Task 142 first attempt misclassified HTTP 403 and failed verification." },
      lifecycle: { status: "OBSERVED" },
      trust: { level: "HIGH", confidence: 0.99 },
      temporal: { observed_at: observedAt, valid_from: observedAt, valid_until: null, last_verified_at: observedAt },
      provenance: { source_refs: ["artifact:test-output-403", "finding:confirmed-403"], extractor_ref: { id: "task-episode", version: "1.0.0" } },
      relations: { supersedes: [], contradicts: [], derived_from: [] },
      access: { sensitivity: "INTERNAL", read_roles: ["backend-implementer", "reviewer"] },
      retention: { policy: "task-history" },
      created_at: observedAt,
      created_by: { type: "system", id: "system:memory-pipeline" },
    });
    store.create(episode);
    const first = createMemoryRecord({
      memory_id: "memory:lesson-403",
      layer: "LESSON",
      kind: "opencodex.lesson.failure-pattern",
      scopes: [{ type: "REPOSITORY", id: "opencodex" }, { type: "PROVIDER", id: "clinepass" }],
      subject: { type: "error-classification", key: "http-403" },
      content: { summary: "ClinePass provider v2 classifies HTTP 403 as authorization failure, not quota.", structured: { status_code: 403, provider_version: 2 } },
      lifecycle: { status: "VERIFIED" },
      trust: { level: "AUTHORITATIVE", confidence: 0.98 },
      temporal: { observed_at: observedAt, valid_from: observedAt, valid_until: null, last_verified_at: observedAt },
      provenance: { source_refs: ["evidence:test-403", "finding:verified-resolved"], extractor_ref: { id: "failure-lesson-extractor", version: "1.0.0" } },
      relations: { supersedes: [], contradicts: [], derived_from: [episode.memory_id] },
      access: { sensitivity: "INTERNAL", read_roles: ["backend-implementer", "reviewer"] },
      retention: { policy: "repository-durable" },
      created_at: observedAt,
      created_by: { type: "verifier", id: "verifier:phase3" },
    });
    const second = appendMemoryRevision(first, {
      content: { summary: "ClinePass provider v3 classifies HTTP 403 as authorization or permission failure, never quota.", structured: { status_code: 403, provider_version: 3, classification: "authorization-or-permission" } },
      provenance: { source_refs: ["evidence:test-403-v3", "documentation:clinepass-v3"], extractor_ref: { id: "human-correction", version: "1.0.0" } },
      relations: { supersedes: [first.revision_id], contradicts: [], derived_from: [episode.memory_id] },
      temporal: { observed_at: "2026-07-24T11:00:00.000Z", valid_from: "2026-07-24T11:00:00.000Z", valid_until: null, last_verified_at: "2026-07-24T11:00:00.000Z" },
    }, {
      expected_revision: 1,
      reason: "Provider v3 documentation and regression evidence",
      actor: { type: "human", id: "human:owner" },
      at: "2026-07-24T11:05:00.000Z",
    });
    const existingLesson = store.get(first.memory_id);
    if (!existingLesson) {
      store.create(first);
      store.appendRevision(second, 1);
    } else if (existingLesson.revision_number === 1 && existingLesson.integrity.content_hash === first.integrity.content_hash) {
      store.appendRevision(second, 1);
    } else if (existingLesson.revision_number !== 2 || existingLesson.integrity.content_hash !== second.integrity.content_hash) {
      throw new Error("PHASE6_DEMO_EXISTING_STATE_CONFLICT");
    }
    const engine = new MemoryRetrievalEngine({ store });
    const query: MemoryQuery = {
      query_id: "memory-query:phase6-demo",
      text: "HTTP 403 authorization ClinePass",
      requester: {
        role: "backend-implementer",
        task_id: "task-202",
        authorized_scopes: [{ type: "REPOSITORY", id: "opencodex" }, { type: "PROVIDER", id: "clinepass" }],
        max_sensitivity: "INTERNAL",
      },
      scopes: { include: [{ type: "REPOSITORY", id: "opencodex" }] },
      layers: { include: ["LESSON", "FACT", "EPISODE"] },
      trust: { minimum: "MEDIUM" },
      temporal: { at: "2026-07-24T12:00:00.000Z" },
      budget: { max_tokens: 1_500, max_records: 8 },
      session: { execution_id: "execution:phase6-demo", session_id: "session:phase6-demo", context_reset: true },
      explain: true,
    };
    const firstPack = await engine.recall(query);
    const secondPack = await engine.recall({ ...query, query_id: "memory-query:phase6-demo-turn-2", session: { ...query.session!, context_reset: false } });
    const serializedPack = JSON.stringify(firstPack);
    const report = {
      status: "PASS",
      verified_lesson_recalled: firstPack.sections.relevant_lessons.some(item => item.memory_id === second.memory_id),
      raw_evidence_injected: serializedPack.includes("raw_tool_output") || serializedPack.includes("stderr payload"),
      repeated_memory_injected: secondPack.provenance.memory_revisions.length > 0,
      supersession_verified: store.get(second.memory_id, 1)?.revision_id === first.revision_id && store.get(second.memory_id)?.revision_id === second.revision_id,
      canonical_revision: second.revision_id,
      context_pack_hash: firstPack.pack_hash,
      second_turn_repeated: secondPack.injection.repeated_memories,
      health: store.health(),
    };
    if (!report.verified_lesson_recalled || report.raw_evidence_injected || report.repeated_memory_injected || !report.supersession_verified) report.status = "FAIL";
    writeFileSync(join(root, "phase6-demo-report.json"), `${JSON.stringify(report, null, 2)}\n`, "utf8");
    return report;
  } finally {
    store.close();
  }
}
