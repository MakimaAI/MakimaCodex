import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  LocalArtifactStore,
  OefCommandBus,
  SqliteOefStore,
  createSortableIdGenerator,
  readTaskSummary,
} from "../src/oef/phase1";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* failed RED fixtures can retain SQLite handles */ }
  }
});

const human = { type: "human", id: "human:owner" } as const;
const system = { type: "system", id: "system:verifier" } as const;

const makeIds = () => {
  let now = 1_700_000_000_000;
  return createSortableIdGenerator({
    now: () => now++,
    randomBytes: size => new Uint8Array(size).fill(6),
  });
};

const workflow = {
  schema_version: 1,
  workflow_id: "verification",
  version: "1.0.0",
  stages: [{ id: "intake" }, { id: "done", terminal: true }],
  transitions: [{ from: "intake", to: "done", guards: ["contract.approved", "verdict.accepted"] }],
} as const;

const policy = {
  schema_version: 1,
  policy_pack_id: "evidence-required",
  version: "1.0.0",
  rules: [
    {
      id: "all-contract-evidence",
      when: { operation: "verdict", verdict: "ACCEPT" },
      require: { all_contract_evidence: true },
    },
    {
      id: "credential-security-review",
      when: { operation: "verdict", verdict: "ACCEPT", risk_reasons: ["credentials"] },
      require: { evidence_types: ["opencodex.security-scan", "opencodex.security-review"] },
    },
  ],
} as const;

const contract = (revision: number) => ({
  schema_version: 1,
  task_id: "task:evidence-verdict",
  revision,
  title: "Evidence governed task",
  goal: { summary: "Accept only after verified evidence." },
  scope: { included: ["Evidence pipeline"], excluded: ["Model execution"] },
  constraints: ["No credential value enters persistence."],
  acceptance_criteria: [
    {
      key: "tests",
      statement: "Integration tests pass.",
      required_evidence: ["opencodex.test-result"],
    },
    {
      key: "security",
      statement: "Secret scanning and security review pass.",
      required_evidence: ["opencodex.security-scan", "opencodex.security-review"],
    },
  ],
  risk: { level: "high", reasons: ["credentials"] },
  budgets: { max_attempts: 3, max_parallel_writers: 1, max_cost_units: 10 },
  extensions: { "opencodex.evidence": { schema_version: 1 } },
});

const setup = () => {
  const root = mkdtempSync(join(tmpdir(), "oef-phase1-evidence-"));
  roots.push(root);
  const ids = makeIds();
  const store = new SqliteOefStore({ databasePath: join(root, "oef.sqlite") });
  const artifacts = new LocalArtifactStore({ root: join(root, "artifacts"), ids });
  store.installWorkflow(workflow);
  store.installPolicy(policy);
  const bus = new OefCommandBus({
    store,
    artifactStore: artifacts,
    ids,
    clock: () => "2026-07-23T12:00:00.000Z",
    principals: [
      { actor: human, roles: ["human_owner", "task_operator", "verifier"] },
      { actor: system, roles: ["task_operator", "verifier"] },
      { actor: { type: "agent", id: "agent:worker" }, roles: ["task_operator"] },
    ],
  });
  return { root, store, artifacts, bus };
};

const command = (
  command_type: string,
  expected_aggregate_version: number,
  idempotency_key: string,
  payload: unknown,
  actor = human,
) => ({
  schema_version: 1,
  command_id: `command:${idempotency_key}`,
  command_type,
  task_id: "task:evidence-verdict",
  expected_aggregate_version,
  actor,
  idempotency_key,
  payload,
});

const initializeApprovedContract = (store: SqliteOefStore, bus: OefCommandBus) => {
  bus.execute(command("CreateTask", 0, "create", {
    title: "Evidence task",
    workflow: { id: "verification", version: "1.0.0" },
    policy: { id: "evidence-required", version: "1.0.0" },
    risk: { level: "high", reasons: ["credentials"] },
  }));
  bus.execute(command("CreateContractRevision", 1, "contract-create", {
    document: contract(1),
    parent_revision_id: null,
  }));
  const revision = store.listContractRevisions("task:evidence-verdict")[0];
  bus.execute(command("ProposeContractRevision", 2, "contract-propose", { revision_id: revision.revision_id }));
  bus.execute(command("ApproveContractRevision", 3, "contract-approve", {
    revision_id: revision.revision_id,
    rationale: "Evidence requirements are explicit.",
  }));
  return revision.revision_id;
};

const recordAndVerify = (
  store: SqliteOefStore,
  bus: OefCommandBus,
  artifacts: LocalArtifactStore,
  version: number,
  revisionId: string,
  criterion: string,
  type: string,
) => {
  const artifact = artifacts.put({
    content: JSON.stringify({ type, passed: true }),
    media_type: "application/json",
    classification: "internal",
    retention_policy: "task-lifetime",
    created_by: system,
  });
  const recorded = bus.execute(command("RecordEvidence", version, `record:${type}`, {
    contract_revision_id: revisionId,
    criterion_key: criterion,
    type,
    summary: `${type} passed.`,
    artifacts: [artifact],
    environment: { operating_system: "windows", repository_commit: "abc123" },
  }, system));
  expect(recorded.ok).toBe(true);
  const evidence = store.listEvidence("task:evidence-verdict").at(-1)!;
  const verified = bus.execute(command("VerifyEvidence", version + 1, `verify:${type}`, {
    evidence_id: evidence.evidence_id,
  }, system));
  expect(verified.ok).toBe(true);
  return evidence.evidence_id;
};

describe("Phase 1 evidence and verdict pipeline", () => {
  test("denies ACCEPT until all criterion evidence is verified, then issues a current verdict", () => {
    const { root, store, artifacts, bus } = setup();
    const revisionId = initializeApprovedContract(store, bus);
    const testEvidence = recordAndVerify(store, bus, artifacts, 4, revisionId, "tests", "opencodex.test-result");

    const denied = bus.execute(command("IssueVerdict", 6, "verdict:early", {
      contract_revision_id: revisionId,
      decision: "ACCEPT",
      rationale: "Tests passed.",
      evidence_refs: [testEvidence],
      repository_commit: "abc123",
    }, system));
    expect(denied).toMatchObject({
      ok: false,
      error: {
        code: "policy_denied",
        decision: {
          denied_by: ["all-contract-evidence", "credential-security-review"],
          missing_requirements: [
            "evidence:security:opencodex.security-scan",
            "evidence:security:opencodex.security-review",
            "evidence:opencodex.security-scan",
            "evidence:opencodex.security-review",
          ],
        },
      },
    });
    expect(store.listVerdicts("task:evidence-verdict")).toEqual([]);

    const scan = recordAndVerify(store, bus, artifacts, 6, revisionId, "security", "opencodex.security-scan");
    const review = recordAndVerify(store, bus, artifacts, 8, revisionId, "security", "opencodex.security-review");
    expect(bus.execute(command("IssueVerdict", 10, "verdict:wrong-commit", {
      contract_revision_id: revisionId,
      decision: "ACCEPT",
      rationale: "Evidence belongs to another commit.",
      evidence_refs: [testEvidence, scan, review],
      repository_commit: "different-commit",
    }, system))).toMatchObject({ ok: false, error: { code: "repository_commit_mismatch" } });
    const accepted = bus.execute(command("IssueVerdict", 10, "verdict:accept", {
      contract_revision_id: revisionId,
      decision: "ACCEPT",
      rationale: "Every required evidence type is verified.",
      evidence_refs: [testEvidence, scan, review],
      repository_commit: "abc123",
    }, system));
    expect(accepted.ok).toBe(true);
    expect(bus.execute(command("IssueVerdict", 11, "verdict:missing-commit", {
      contract_revision_id: revisionId,
      decision: "ACCEPT",
      rationale: "A commit binding is mandatory.",
      evidence_refs: [testEvidence, scan, review],
    }, system))).toMatchObject({ ok: false, error: { code: "repository_commit_required" } });
    expect(store.listVerdicts("task:evidence-verdict")).toEqual([
      expect.objectContaining({
        contract_revision_id: revisionId,
        decision: "ACCEPT",
        status: "CURRENT",
        policy_pack_ref: { id: "evidence-required", version: "1.0.0", hash: expect.any(String) },
      }),
    ]);
    expect(readTaskSummary({ taskId: "task:evidence-verdict", store, artifactStore: artifacts })).toMatchObject({
      criteria: { total: 2, passed: 2, failed: 0, waiting: 0 },
      latest_verdict: "ACCEPT",
      blockers: [],
    });
    const acceptedArtifact = store.getEvidence(testEvidence)!.artifacts[0];
    writeFileSync(join(root, "artifacts", ...acceptedArtifact.storage_key.split("/")), "tampered-after-verdict", "utf8");
    expect(readTaskSummary({ taskId: "task:evidence-verdict", store, artifactStore: artifacts })).toMatchObject({
      latest_verdict: null,
    });
    const staleDetection = bus.execute(command("TransitionTaskStage", 11, "transition:tampered-verdict", {
      from_stage: "intake",
      to_stage: "done",
    }, system));
    expect(staleDetection).toMatchObject({
      ok: true,
      value: {
        transition_applied: false,
        transition_denial: { allowed: false, reason: "guards-unsatisfied", missing_guards: ["verdict.accepted"] },
        task: { stage: "intake", aggregate_version: 12 },
      },
    });
    expect(store.getTask("task:evidence-verdict")?.aggregate_version).toBe(12);
    expect(store.listEvents("task:evidence-verdict").at(-1)).toMatchObject({
      event_type: "verdict.stale.detected",
      payload: { secondary_state_changes: { stale_verdict_ids: [expect.stringMatching(/^verdict:/)] } },
    });
    expect(readTaskSummary({ taskId: "task:evidence-verdict", store, artifactStore: artifacts })).toMatchObject({ latest_verdict: null });
    const invalidated = bus.execute(command("InvalidateEvidence", 12, "invalidate:after-verdict", {
      evidence_id: review,
    }, system));
    expect(invalidated.ok).toBe(true);
    if (invalidated.ok) expect(invalidated.value.event.payload).toMatchObject({
      secondary_state_changes: { stale_verdict_ids: [] },
    });
    expect(store.listVerdicts("task:evidence-verdict")[0].status).toBe("STALE");
    store.close();
  });

  test("binds evidence to the active criterion and rejects tampered artifacts or secret summaries", () => {
    const { root, store, artifacts, bus } = setup();
    const revisionId = initializeApprovedContract(store, bus);
    const artifact = artifacts.put({
      content: "clean",
      media_type: "text/plain",
      classification: "internal",
      retention_policy: "task-lifetime",
      created_by: system,
    });
    writeFileSync(join(root, "artifacts", ...artifact.storage_key.split("/")), "tampered", "utf8");

    expect(bus.execute(command("RecordEvidence", 4, "record:tampered", {
      contract_revision_id: revisionId,
      criterion_key: "tests",
      type: "opencodex.test-result",
      summary: "Test passed.",
      artifacts: [artifact],
      environment: {},
    }, system))).toMatchObject({ ok: false, error: { code: "artifact_integrity_failed" } });
    expect(bus.execute(command("RecordEvidence", 4, "record:secret", {
      contract_revision_id: revisionId,
      criterion_key: "tests",
      type: "opencodex.test-result",
      summary: "api_key=abcdefghijklmnop",
      artifacts: [],
      environment: {},
    }, system))).toMatchObject({ ok: false, error: { code: "secret_detected" } });
    const secretDocument = contract(2);
    secretDocument.extensions = {
      "opencodex.auth": { schema_version: 1, api_key: "abcdefghijklmnop" },
    };
    expect(bus.execute(command("CreateContractRevision", 4, "contract:structured-secret", {
      document: secretDocument,
      parent_revision_id: revisionId,
    }))).toMatchObject({ ok: false, error: { code: "secret_detected" } });
    expect(store.listEvidence("task:evidence-verdict")).toEqual([]);
    store.close();
  });

  test("requires criterion-specific evidence when criteria share one evidence type", () => {
    const { store, artifacts, bus } = setup();
    bus.execute(command("CreateTask", 0, "same-type:create", {
      title: "Criterion binding",
      workflow: { id: "verification", version: "1.0.0" },
      policy: { id: "evidence-required", version: "1.0.0" },
      risk: { level: "low", reasons: [] },
    }));
    const document = contract(1);
    document.risk = { level: "low", reasons: [] };
    document.acceptance_criteria = [
      { key: "criterion-a", statement: "A passes.", required_evidence: ["opencodex.test-result"] },
      { key: "criterion-b", statement: "B passes.", required_evidence: ["opencodex.test-result"] },
    ];
    bus.execute(command("CreateContractRevision", 1, "same-type:contract", { document, parent_revision_id: null }));
    const revision = store.listContractRevisions("task:evidence-verdict")[0];
    bus.execute(command("ProposeContractRevision", 2, "same-type:propose", { revision_id: revision.revision_id }));
    bus.execute(command("ApproveContractRevision", 3, "same-type:approve", {
      revision_id: revision.revision_id,
      rationale: "Approved.",
    }));
    const onlyA = recordAndVerify(store, bus, artifacts, 4, revision.revision_id, "criterion-a", "opencodex.test-result");
    expect(bus.execute(command("IssueVerdict", 6, "same-type:verdict", {
      contract_revision_id: revision.revision_id,
      decision: "ACCEPT",
      rationale: "Only criterion A is proven.",
      evidence_refs: [onlyA],
      repository_commit: "abc123",
    }, system))).toMatchObject({
      ok: false,
      error: {
        code: "policy_denied",
        decision: { missing_requirements: ["evidence:criterion-b:opencodex.test-result"] },
      },
    });
    store.close();
  });

  test("rejects an unregistered caller that self-labels as human", () => {
    const { store, bus } = setup();
    bus.execute(command("CreateTask", 0, "auth:create", {
      title: "Authorization",
      workflow: { id: "verification", version: "1.0.0" },
      policy: { id: "evidence-required", version: "1.0.0" },
      risk: { level: "low", reasons: [] },
    }));
    bus.execute(command("CreateContractRevision", 1, "auth:contract", { document: contract(1), parent_revision_id: null }));
    const revision = store.listContractRevisions("task:evidence-verdict")[0];
    bus.execute(command("ProposeContractRevision", 2, "auth:propose", { revision_id: revision.revision_id }));
    expect(bus.execute(command("ApproveContractRevision", 3, "auth:spoof", {
      revision_id: revision.revision_id,
      rationale: "Spoofed approval.",
    }, { type: "human", id: "human:spoof" }))).toMatchObject({
      ok: false,
      error: { code: "actor_forbidden", required: "authenticated_principal" },
    });
    expect(store.getContractRevision(revision.revision_id)?.status).toBe("PROPOSED");
    store.close();
  });

  test("marks a current verdict stale when its pinned workflow is migrated", () => {
    const { store, artifacts, bus } = setup();
    const revisionId = initializeApprovedContract(store, bus);
    const testEvidence = recordAndVerify(store, bus, artifacts, 4, revisionId, "tests", "opencodex.test-result");
    const scan = recordAndVerify(store, bus, artifacts, 6, revisionId, "security", "opencodex.security-scan");
    const review = recordAndVerify(store, bus, artifacts, 8, revisionId, "security", "opencodex.security-review");
    expect(bus.execute(command("IssueVerdict", 10, "migration:verdict", {
      contract_revision_id: revisionId,
      decision: "ACCEPT",
      rationale: "Current before migration.",
      evidence_refs: [testEvidence, scan, review],
      repository_commit: "abc123",
    }, system)).ok).toBe(true);
    store.installWorkflow({
      schema_version: 1,
      workflow_id: "verification",
      version: "2.0.0",
      stages: [{ id: "intake" }, { id: "review" }, { id: "done", terminal: true }],
      transitions: [
        { from: "intake", to: "review" },
        { from: "review", to: "done", guards: ["verdict.accepted"] },
      ],
    });
    const migrated = bus.execute(command("MigrateWorkflow", 11, "migration:workflow", {
      from: { id: "verification", version: "1.0.0" },
      to: { id: "verification", version: "2.0.0" },
      stage_map: { intake: "intake", done: "done" },
      rationale: "Adopt explicit review stage.",
    }));
    expect(migrated.ok).toBe(true);
    if (migrated.ok) expect(migrated.value.event.payload).toMatchObject({
      secondary_state_changes: { stale_verdict_ids: [expect.stringMatching(/^verdict:/)] },
    });
    expect(store.listVerdicts("task:evidence-verdict")[0].status).toBe("STALE");
    expect(readTaskSummary({ taskId: "task:evidence-verdict", store, artifactStore: artifacts })).toMatchObject({ latest_verdict: null });
    store.close();
  });

  test("marks verdict stale on a new contract and requires explicit human reopen for terminal tasks", () => {
    const { store, artifacts, bus } = setup();
    const revisionId = initializeApprovedContract(store, bus);
    const testEvidence = recordAndVerify(store, bus, artifacts, 4, revisionId, "tests", "opencodex.test-result");
    const scan = recordAndVerify(store, bus, artifacts, 6, revisionId, "security", "opencodex.security-scan");
    const review = recordAndVerify(store, bus, artifacts, 8, revisionId, "security", "opencodex.security-review");
    bus.execute(command("IssueVerdict", 10, "verdict:terminal", {
      contract_revision_id: revisionId,
      decision: "ACCEPT",
      rationale: "Complete.",
      evidence_refs: [testEvidence, scan, review],
      repository_commit: "abc123",
    }, system));
    expect(bus.execute(command("TransitionTaskStage", 11, "transition:done", {
      from_stage: "intake",
      to_stage: "done",
    }, system)).ok).toBe(true);
    expect(store.getTask("task:evidence-verdict")?.status).toBe("COMPLETED");

    expect(bus.execute(command("ReopenTask", 12, "reopen:agent", {
      to_stage: "intake",
      rationale: "Agent wants another attempt.",
    }, { type: "agent", id: "agent:worker" }))).toMatchObject({ ok: false, error: { code: "actor_forbidden" } });
    expect(bus.execute(command("ReopenTask", 12, "reopen:human", {
      to_stage: "intake",
      rationale: "A new contract revision is required.",
    })).ok).toBe(true);
    expect(store.getTask("task:evidence-verdict")).toMatchObject({ status: "OPEN", stage: "intake", aggregate_version: 13 });
    expect(store.listVerdicts("task:evidence-verdict")[0].status).toBe("STALE");

    const revision2Document = contract(2);
    revision2Document.constraints.push("Reopened work must be reverified.");
    bus.execute(command("CreateContractRevision", 13, "contract:v2:create", {
      document: revision2Document,
      parent_revision_id: revisionId,
    }));
    const revision2 = store.listContractRevisions("task:evidence-verdict")[1];
    bus.execute(command("ProposeContractRevision", 14, "contract:v2:propose", { revision_id: revision2.revision_id }));
    const approvedV2 = bus.execute(command("ApproveContractRevision", 15, "contract:v2:approve", {
      revision_id: revision2.revision_id,
      rationale: "Reopened scope is approved.",
    }));
    expect(approvedV2.ok).toBe(true);
    if (approvedV2.ok) expect(approvedV2.value.event.payload).toMatchObject({
      secondary_state_changes: { superseded_contract_revision_id: revisionId },
    });
    expect(store.listVerdicts("task:evidence-verdict")[0].status).toBe("STALE");
    store.close();
  });
});
