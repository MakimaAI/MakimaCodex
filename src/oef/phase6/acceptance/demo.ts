import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { appendMemoryRevision, type MemoryQuery } from "../core/domain";
import { runMemoryRetrievalBenchmark } from "../evaluation/benchmark";
import { DEFAULT_LOCAL_EMBEDDING_PROFILE, LocalHashEmbeddingProvider, SqliteVectorMemoryIndex } from "../indexing/local-vector-index";
import { createMemorySourceEvent, DurableMemoryIngestionQueue, MemoryCandidateService, MemoryEpisodeCompiler, MemoryIngestionWorker } from "../ingestion/pipeline";
import { SqliteMemoryBackupService } from "../persistence/backup";
import { SqliteMemoryStore } from "../persistence/sqlite-store";
import { GuardedExternalMemoryBackend, validateMemoryPluginManifest } from "../plugins/protocol";
import { MemoryRetrievalEngine } from "../retrieval/engine";

const observedAt = "2026-07-24T10:00:00.000Z";

export async function runPhase6AcceptanceDemo(options: { root: string }): Promise<Record<string, unknown>> {
  const root = resolve(options.root);
  mkdirSync(root, { recursive: true });
  const evidencePath = join(root, "test-output-403.log");
  writeFileSync(evidencePath, "sanitized HTTP 403 regression evidence\n", "utf8");
  writeFileSync(join(root, "phase6-artifact-manifest.json"), `${JSON.stringify({ "artifact:test-output-403": "test-output-403.log" }, null, 2)}\n`, "utf8");
  const store = new SqliteMemoryStore({ databasePath: join(root, "memory.sqlite") });
  try {
    const queue = new DurableMemoryIngestionQueue(store);
    const sourceEvent = createMemorySourceEvent({
      schema_version: 1,
      event_id: "event:phase6-demo-task-142-attempt-1",
      idempotency_key: "phase6-demo:task-142:attempt-1",
      source: { phase: 2, kind: "execution.evidence", ref: "evidence:task-142-attempt-1" },
      scopes: [{ type: "TASK", id: "task-142" }, { type: "REPOSITORY", id: "opencodex" }],
      subject: { type: "task-attempt", key: "task-142-attempt-1" },
      summary: "Task 142 attempt 1 misclassified HTTP 403 and failed verification.",
      structured: { status_code: 403, classification: "quota" },
      evidence_refs: ["artifact:test-output-403", "finding:confirmed-403"],
      sensitivity: "INTERNAL",
      observed_at: observedAt,
    });
    const queued = queue.enqueue(sourceEvent, { priority: 20, max_attempts: 3, at: observedAt });
    const duplicate = queue.enqueue(sourceEvent, { priority: 20, max_attempts: 3, at: observedAt });
    const worker = new MemoryIngestionWorker({ store, queue, compiler: new MemoryEpisodeCompiler() });
    const workerResult = worker.runOnce({ worker_id: "worker:phase6-demo", now: observedAt, lease_ms: 30_000 });
    const ingestionJob = workerResult ?? store.inspectIngestionJob(queued.job_id);
    const episode = ingestionJob?.output_memory_ids[0] ? store.get(ingestionJob.output_memory_ids[0]) : null;
    if (!episode || episode.layer !== "EPISODE") throw new Error("PHASE6_DEMO_EPISODE_LINK_MISSING");
    const candidateService = new MemoryCandidateService(store);
    const candidate = candidateService.propose({
      candidate_id: "memory-candidate:lesson-403",
      idempotency_key: "phase6-demo:lesson-403-promotion",
      memory_id: "memory:lesson-403",
      layer: "LESSON",
      kind: "opencodex.lesson.failure-pattern",
      scopes: [{ type: "REPOSITORY", id: "opencodex" }, { type: "PROVIDER", id: "clinepass" }],
      subject: { type: "error-classification", key: "http-403" },
      summary: "ClinePass provider v2 classifies HTTP 403 as authorization failure, not quota.",
      structured: { status_code: 403, provider_version: 2 },
      evidence_refs: ["evidence:test-403", "finding:verified-resolved"],
      derived_from: [episode.memory_id],
      access: { sensitivity: "INTERNAL", read_roles: ["backend-implementer", "reviewer"] },
      retention_policy: "repository-durable",
      proposed_by: { type: "agent", id: "agent:lesson-extractor" },
      proposed_at: observedAt,
    });
    const promotion = candidate.status === "CANDIDATE"
      ? candidateService.promote(candidate.candidate_id, {
        actor: { type: "verifier", id: "verifier:phase3" },
        evidence_refs: ["evidence:test-403-v2", "documentation:clinepass-v2"],
        at: "2026-07-24T10:30:00.000Z",
      })
      : { candidate, record: store.get(candidate.promoted_memory_id!, 1)! };
    const first = promotion.record;
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
    const existingLesson = store.get(first.memory_id)!;
    if (existingLesson.revision_number === 1 && existingLesson.integrity.content_hash === first.integrity.content_hash) {
      store.appendRevision(second, 1);
    } else if (existingLesson.revision_number !== 2 || existingLesson.integrity.content_hash !== second.integrity.content_hash) {
      throw new Error("PHASE6_DEMO_EXISTING_STATE_CONFLICT");
    }
    const vector = new SqliteVectorMemoryIndex({ databasePath: join(root, "memory.sqlite"), provider: new LocalHashEmbeddingProvider(DEFAULT_LOCAL_EMBEDDING_PROFILE) });
    await vector.rebuild({ at: "2026-07-24T11:07:00.000Z" });
    const vectorStatus = vector.status();
    vector.close();
    const plugin = new GuardedExternalMemoryBackend({
      manifest: validateMemoryPluginManifest({
        plugin: { id: "phase6-demo-external", version: "1.0.0" },
        protocol: { min: 1, max: 1 },
        capabilities: ["memory-search"],
        granted_scopes: [{ type: "REPOSITORY", id: "opencodex" }],
      }),
      adapter: { search: async () => [{
        external_id: "external:demo",
        summary: "External observation only",
        scopes: [{ type: "REPOSITORY" as const, id: "opencodex" }],
        source_refs: ["external-source:demo"],
        claimed_status: "PROMOTED",
        claimed_trust: "AUTHORITATIVE",
      }] },
    });
    const pluginResult = (await plugin.search({
      text: "403",
      scopes: [{ type: "REPOSITORY", id: "opencodex" }],
      authorization: { role: "backend-implementer", authorized_scopes: [{ type: "REPOSITORY", id: "opencodex" }], max_sensitivity: "INTERNAL" },
    }))[0]!;
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
      usage_mode: "AGENT_INJECTION",
      session: { execution_id: "execution:phase6-demo", session_id: "session:phase6-demo", context_reset: true },
      explain: true,
    };
    const prepared = await engine.prepareContextPack(query);
    const firstPack = prepared.pack;
    await engine.acknowledgeInjection({ delivery_id: prepared.delivery_id, pack_hash: firstPack.pack_hash });
    const secondPack = (await engine.prepareContextPack({ ...query, query_id: "memory-query:phase6-demo-turn-2", session: { ...query.session!, context_reset: false } })).pack;
    const benchmarkQuery = (queryId: string, text: string): MemoryQuery => ({
      ...query,
      query_id: queryId,
      text,
      scopes: { include: [{ type: "REPOSITORY", id: "opencodex" }, { type: "PROVIDER", id: "clinepass" }] },
      layers: { include: ["LESSON"] },
      usage_mode: "CLI_RESEARCH",
      session: undefined,
    });
    const benchmark = await runMemoryRetrievalBenchmark({
      engine,
      cases: [
        {
          case_id: "verified-403-lesson",
          query: benchmarkQuery("memory-query:phase6-benchmark-403", "ClinePass HTTP 403 authorization permission never quota"),
          relevant_memory_ids: [second.memory_id],
        },
        {
          case_id: "promotion-evidence",
          query: benchmarkQuery("memory-query:phase6-benchmark-promotion", "provider v3 classification permission failure"),
          relevant_memory_ids: [second.memory_id],
        },
      ],
    });
    const serializedPack = JSON.stringify(firstPack);
    const backup = new SqliteMemoryBackupService({ databasePath: join(root, "memory.sqlite") }).create({
      backup_root: join(root, "backups"),
      at: "2026-07-24T12:05:00.000Z",
      artifact_files: [{ reference: "artifact:test-output-403", path: evidencePath }],
    });
    const report = {
      status: "PASS",
      verified_lesson_recalled: firstPack.sections.relevant_lessons.some(item => item.memory_id === second.memory_id),
      raw_evidence_injected: serializedPack.includes("raw_tool_output") || serializedPack.includes("stderr payload"),
      repeated_memory_injected: secondPack.provenance.memory_revisions.length > 0,
      supersession_verified: store.get(second.memory_id, 1)?.revision_id === first.revision_id && store.get(second.memory_id)?.revision_id === second.revision_id,
      canonical_revision: second.revision_id,
      context_pack_hash: firstPack.pack_hash,
      second_turn_repeated: secondPack.injection.repeated_memories,
      ingestion_pipeline: { status: ingestionJob?.status ?? "MISSING", duplicate_effect: duplicate.deduplicated ? 0 : 1 },
      promotion_gate: { status: promotion.candidate.status, memory_id: promotion.record.memory_id, derived_from_episode: first.relations.derived_from.includes(episode.memory_id) },
      vector_index: vectorStatus,
      plugin_boundary: { untrusted: pluginResult.trust === "UNTRUSTED", instruction_authority: pluginResult.instruction_authority },
      backup: { database_hash: backup.manifest.database_hash, artifact_manifest_hash: backup.manifest.artifact_manifest_hash },
      retrieval_benchmark: benchmark,
      health: store.health(),
    };
    if (!report.verified_lesson_recalled || report.raw_evidence_injected || report.repeated_memory_injected || !report.supersession_verified
      || report.ingestion_pipeline.status !== "COMPLETED" || report.ingestion_pipeline.duplicate_effect !== 0
      || report.promotion_gate.status !== "PROMOTED" || !report.promotion_gate.derived_from_episode || report.vector_index.status !== "HEALTHY"
      || !report.plugin_boundary.untrusted || report.plugin_boundary.instruction_authority !== "NONE"
      || !report.retrieval_benchmark.passed) report.status = "FAIL";
    writeFileSync(join(root, "phase6-demo-report.json"), `${JSON.stringify(report, null, 2)}\n`, "utf8");
    return report;
  } finally {
    store.close();
  }
}
