import type { Actor } from "../core/shared/actor";
import { createPhase1Runtime } from "./runtime";
import { verifyTaskIntegrity, type TaskIntegrityView } from "./queries/integrity";
import { readTaskSummary } from "./queries/task-summary";

export interface Phase1DemoReport {
  schema_version: 1;
  task_id: string;
  policy_denied_before_missing_evidence: boolean;
  accepted_after_required_evidence: boolean;
  reached_terminal_done: boolean;
  restart_state_preserved: boolean;
  restart_timeline_preserved: boolean;
  summary: Record<string, unknown>;
  timeline: Array<Record<string, unknown>>;
  integrity: TaskIntegrityView;
}

export function runPhase1Demo(options: { home: string }): Phase1DemoReport {
  const human: Actor = { type: "human", id: "human:demo-owner" };
  const system: Actor = { type: "system", id: "system:demo-verifier" };
  const principals = [
    { actor: human, roles: ["human_owner", "task_operator", "verifier"] as const },
    { actor: system, roles: ["task_operator", "verifier"] as const },
  ];
  let runtime = createPhase1Runtime({ home: options.home, principals });
  const taskId = runtime.ids.next("task");
  let commandSequence = 0;
  const execute = (commandType: string, payload: unknown, actor: Actor = human) => {
    commandSequence += 1;
    const expectedVersion = runtime.store.getTask(taskId)?.aggregate_version ?? 0;
    const result = runtime.bus.execute({
      schema_version: 1,
      command_id: `command:demo-${commandSequence}`,
      command_type: commandType,
      task_id: taskId,
      expected_aggregate_version: expectedVersion,
      actor,
      idempotency_key: `demo:${commandSequence}`,
      payload,
    });
    if (!result.ok) throw new Error(`Demo command ${commandType} failed: ${JSON.stringify(result.error)}`);
    return result;
  };

  try {
    execute("CreateTask", {
      title: "Phase 1 control backbone demo",
      workflow: { id: "software-development", version: "1.0.0" },
      policy: { id: "safe-default", version: "1.0.0" },
      risk: { level: "medium", reasons: [] },
    });
    execute("CreateContractRevision", {
      parent_revision_id: null,
      document: {
        schema_version: 1,
        task_id: taskId,
        revision: 1,
        title: "Phase 1 demo contract",
        goal: { summary: "Prove denial, repair, acceptance, restart, and integrity." },
        scope: { included: ["Control backbone demo"], excluded: ["Model execution"] },
        constraints: ["No secret persistence."],
        acceptance_criteria: [
          {
            key: "tests",
            statement: "Integration tests pass.",
            required_evidence: ["opencodex.test-result"],
          },
          {
            key: "integrity",
            statement: "Integrity verification passes.",
            required_evidence: ["opencodex.integrity-check"],
          },
        ],
        risk: { level: "medium", reasons: [] },
        budgets: { max_attempts: 3, max_parallel_writers: 1, max_cost_units: 10 },
        extensions: {
          "opencodex.demo": { schema_version: 1 },
          "opencodex.plan": { schema_version: 1, exists: true },
        },
      },
    });
    const revision = runtime.store.listContractRevisions(taskId)[0];
    execute("ProposeContractRevision", { revision_id: revision.revision_id });
    execute("ApproveContractRevision", { revision_id: revision.revision_id, rationale: "Demo scope approved." });
    execute("TransitionTaskStage", { from_stage: "intake", to_stage: "specification" });
    execute("TransitionTaskStage", { from_stage: "specification", to_stage: "planning" });
    execute("TransitionTaskStage", { from_stage: "planning", to_stage: "execution" });
    execute("TransitionTaskStage", { from_stage: "execution", to_stage: "verification" });

    const testArtifact = runtime.artifacts.put({
      content: JSON.stringify({ passed: true, suite: "phase1-demo" }),
      media_type: "application/json",
      classification: "internal",
      retention_policy: "task-lifetime",
      created_by: system,
    });
    execute("RecordEvidence", {
      contract_revision_id: revision.revision_id,
      criterion_key: "tests",
      type: "opencodex.test-result",
      summary: "Demo integration test passed.",
      artifacts: [testArtifact],
      environment: { runtime: "bun", repository_commit: "demo-commit" },
    }, system);
    const testEvidence = runtime.store.listEvidence(taskId).at(-1)!;
    execute("VerifyEvidence", { evidence_id: testEvidence.evidence_id }, system);

    commandSequence += 1;
    const early = runtime.bus.execute({
      schema_version: 1,
      command_id: `command:demo-${commandSequence}`,
      command_type: "IssueVerdict",
      task_id: taskId,
      expected_aggregate_version: runtime.store.getTask(taskId)!.aggregate_version,
      actor: system,
      idempotency_key: `demo:${commandSequence}`,
      payload: {
        contract_revision_id: revision.revision_id,
        decision: "ACCEPT",
        rationale: "First criterion is complete.",
        evidence_refs: [testEvidence.evidence_id],
        repository_commit: "demo-commit",
      },
    });
    const denied = !early.ok && early.error.code === "policy_denied";
    execute("IssueVerdict", {
      contract_revision_id: revision.revision_id,
      decision: "REPAIR",
      rationale: "Integrity evidence is still missing.",
      evidence_refs: [testEvidence.evidence_id],
      repository_commit: "demo-commit",
    }, system);

    const integrityArtifact = runtime.artifacts.put({
      content: JSON.stringify({ hash_chain_valid: true }),
      media_type: "application/json",
      classification: "internal",
      retention_policy: "task-lifetime",
      created_by: system,
    });
    execute("RecordEvidence", {
      contract_revision_id: revision.revision_id,
      criterion_key: "integrity",
      type: "opencodex.integrity-check",
      summary: "Integrity check passed.",
      artifacts: [integrityArtifact],
      environment: { runtime: "bun", repository_commit: "demo-commit" },
    }, system);
    const integrityEvidence = runtime.store.listEvidence(taskId).at(-1)!;
    execute("VerifyEvidence", { evidence_id: integrityEvidence.evidence_id }, system);
    execute("TransitionTaskStage", { from_stage: "verification", to_stage: "review" }, system);
    const accepted = execute("IssueVerdict", {
      contract_revision_id: revision.revision_id,
      decision: "ACCEPT",
      rationale: "Every required evidence type is verified.",
      evidence_refs: [testEvidence.evidence_id, integrityEvidence.evidence_id],
      repository_commit: "demo-commit",
    }, system);
    execute("TransitionTaskStage", { from_stage: "review", to_stage: "merge" }, system);
    execute("TransitionTaskStage", { from_stage: "merge", to_stage: "done" }, system);
    const beforeTask = runtime.store.getTask(taskId);
    const beforeTimeline = runtime.store.getTimeline(taskId);
    runtime.close();

    runtime = createPhase1Runtime({ home: options.home, principals });
    const afterTask = runtime.store.getTask(taskId);
    const timeline = runtime.store.getTimeline(taskId);
    const summary = readTaskSummary({ taskId, store: runtime.store, artifactStore: runtime.artifacts }) ?? {};
    const integrity = verifyTaskIntegrity({ taskId, store: runtime.store, artifactStore: runtime.artifacts });
    return {
      schema_version: 1,
      task_id: taskId,
      policy_denied_before_missing_evidence: denied,
      accepted_after_required_evidence: accepted.ok,
      reached_terminal_done: afterTask?.status === "COMPLETED" && afterTask.stage === "done",
      restart_state_preserved: JSON.stringify(afterTask) === JSON.stringify(beforeTask),
      restart_timeline_preserved: JSON.stringify(timeline) === JSON.stringify(beforeTimeline),
      summary,
      timeline,
      integrity,
    };
  } finally {
    try { runtime.close(); } catch { /* already closed during restart seam */ }
  }
}
