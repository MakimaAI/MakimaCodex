import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Database } from "bun:sqlite";
import {
  OefCommandBus,
  SqliteOefStore,
  approvalAuthorizationContextHash,
  canonicalContractHash,
  createSortableIdGenerator,
} from "../src/oef/phase1";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* open RED-test fixture */ }
  }
});

const actor = { type: "human", id: "human:owner" } as const;

const workflow = {
  schema_version: 1,
  workflow_id: "software-development",
  version: "1.0.0",
  stages: [
    { id: "intake" },
    { id: "specification" },
    { id: "planning" },
    { id: "done", terminal: true },
  ],
  transitions: [
    { from: "intake", to: "specification" },
    { from: "specification", to: "planning", guards: ["contract.approved"] },
    { from: "planning", to: "done", guards: ["verdict.accepted"] },
  ],
} as const;

const policy = {
  schema_version: 1,
  policy_pack_id: "safe-default",
  version: "1.0.0",
  rules: [
    {
      id: "approved-contract-before-planning",
      when: { operation: "transition", transition_to: "planning" },
      require: { contract_status: "APPROVED" },
    },
    {
      id: "critical-human-review",
      when: { operation: "transition", transition_to: "planning", risk_levels: ["critical"] },
      require: { human_approvals: 2 },
    },
  ],
} as const;

const contract = (taskId: string, revision: number) => ({
  schema_version: 1,
  task_id: taskId,
  revision,
  title: "Governed lifecycle",
  goal: { summary: "Prove contract and workflow invariants." },
  scope: { included: ["Phase 1 lifecycle"], excluded: ["Model execution"] },
  constraints: ["No secret persistence."],
  acceptance_criteria: [
    {
      key: "lifecycle",
      statement: "The lifecycle is enforced.",
      required_evidence: ["opencodex.test-result"],
    },
  ],
  risk: { level: "critical", reasons: ["credentials"] },
  budgets: { max_attempts: 3, max_parallel_writers: 1, max_cost_units: 10 },
  extensions: {
    "opencodex.lifecycle": { schema_version: 1, strict: true },
  },
});

const setup = () => {
  const root = mkdtempSync(join(tmpdir(), "oef-phase1-lifecycle-"));
  roots.push(root);
  const databasePath = join(root, "oef.sqlite");
  const store = new SqliteOefStore({ databasePath });
  store.installWorkflow(workflow);
  store.installPolicy(policy);
  let timestamp = 1_700_000_000_000;
  const bus = new OefCommandBus({
    store,
    ids: createSortableIdGenerator({
      now: () => timestamp++,
      randomBytes: size => new Uint8Array(size).fill(5),
    }),
    clock: () => "2026-07-23T12:00:00.000Z",
    principals: [
      { actor, roles: ["human_owner", "task_operator", "verifier"] },
      { actor: { type: "human", id: "human:security-owner" }, roles: ["human_owner", "task_operator", "verifier"] },
      { actor: { type: "agent", id: "agent:reviewer" }, roles: ["verifier"] },
      { actor: { type: "agent", id: "agent:operator" }, roles: ["task_operator"] },
    ],
  });
  return { root, databasePath, store, bus };
};

const base = (type: string, version: number, key: string, taskId = "task:phase1-lifecycle") => ({
  schema_version: 1,
  command_id: `command:${key}`,
  command_type: type,
  task_id: taskId,
  expected_aggregate_version: version,
  actor,
  idempotency_key: key,
});

const createTask = (bus: OefCommandBus, taskId = "task:phase1-lifecycle") => bus.execute({
  ...base("CreateTask", 0, `create:${taskId}`, taskId),
  payload: {
    title: "Lifecycle task",
    workflow: { id: "software-development", version: "1.0.0" },
    policy: { id: "safe-default", version: "1.0.0" },
    risk: { level: "critical", reasons: ["credentials"] },
  },
});

describe("Phase 1 contract and workflow lifecycle", () => {
  test("creates, proposes, approves, and supersedes immutable revisions", () => {
    const { databasePath, store, bus } = setup();
    createTask(bus);

    expect(bus.execute({
      ...base("CreateContractRevision", 1, "contract:v1:create"),
      payload: { document: contract("task:phase1-lifecycle", 1), parent_revision_id: null },
    }).ok).toBe(true);
    const revision1 = store.listContractRevisions("task:phase1-lifecycle")[0];
    expect(revision1).toMatchObject({ revision_number: 1, status: "DRAFT", parent_revision_id: null });
    expect(revision1.canonical_hash).toBe(canonicalContractHash(contract("task:phase1-lifecycle", 1)));

    expect(bus.execute({
      ...base("ProposeContractRevision", 2, "contract:v1:propose"),
      payload: { revision_id: revision1.revision_id },
    }).ok).toBe(true);
    expect(bus.execute({
      ...base("ApproveContractRevision", 3, "contract:v1:approve"),
      payload: { revision_id: revision1.revision_id, rationale: "Scope is acceptable." },
    }).ok).toBe(true);
    expect(store.getContractRevision(revision1.revision_id)?.status).toBe("APPROVED");
    expect(store.getTask("task:phase1-lifecycle")?.active_contract_revision_id).toBe(revision1.revision_id);
    expect(store.listApprovals("task:phase1-lifecycle")).toEqual([
      expect.objectContaining({
        subject: { type: "contract_revision", id: revision1.revision_id },
        subject_hash: revision1.canonical_hash,
        decision: "APPROVED",
      }),
    ]);

    const modified = contract("task:phase1-lifecycle", 1);
    modified.goal.summary = "Silently mutate the approved revision.";
    const duplicate = bus.execute({
      ...base("CreateContractRevision", 4, "contract:v1:mutate"),
      payload: { document: modified, parent_revision_id: null },
    });
    expect(duplicate).toMatchObject({ ok: false, error: { code: "revision_conflict" } });

    const revision2Document = contract("task:phase1-lifecycle", 2);
    revision2Document.acceptance_criteria.push({
      key: "audit",
      statement: "Audit history remains append-only.",
      required_evidence: ["opencodex.integrity-check"],
    });
    expect(bus.execute({
      ...base("CreateContractRevision", 4, "contract:v2:create"),
      payload: { document: revision2Document, parent_revision_id: revision1.revision_id },
    }).ok).toBe(true);
    const revision2 = store.listContractRevisions("task:phase1-lifecycle")[1];
    expect(revision2.change_summary.added).toEqual(["audit"]);
    expect(bus.execute({
      ...base("ProposeContractRevision", 5, "contract:v2:propose"),
      payload: { revision_id: revision2.revision_id },
    }).ok).toBe(true);
    expect(bus.execute({
      ...base("ApproveContractRevision", 6, "contract:v2:approve"),
      payload: { revision_id: revision2.revision_id, rationale: "The added criterion is required." },
    }).ok).toBe(true);

    expect(store.getContractRevision(revision1.revision_id)?.status).toBe("SUPERSEDED");
    expect(store.getContractRevision(revision2.revision_id)?.status).toBe("APPROVED");
    expect(store.getTask("task:phase1-lifecycle")?.active_contract_revision_id).toBe(revision2.revision_id);

    expect(bus.execute({
      ...base("TransitionTaskStage", 7, "stale-approval:intake-spec"),
      payload: { from_stage: "intake", to_stage: "specification" },
    }).ok).toBe(true);
    expect(bus.execute({
      ...base("TransitionTaskStage", 8, "stale-approval:spec-plan"),
      payload: { from_stage: "specification", to_stage: "planning" },
    })).toMatchObject({
      ok: false,
      error: {
        code: "policy_denied",
        decision: { missing_requirements: ["human_approvals:2"] },
      },
    });

    store.close();
    const raw = new Database(databasePath);
    expect(() => raw.query(
      "UPDATE contract_revisions SET document_json = ? WHERE revision_id = ?",
    ).run("{}", revision2.revision_id)).toThrow("immutable");
    raw.close();
  });

  test("enforces workflow guards and configurable policy requirements", () => {
    const { store, bus } = setup();
    createTask(bus);
    bus.execute({
      ...base("CreateContractRevision", 1, "guard:v1:create"),
      payload: { document: contract("task:phase1-lifecycle", 1), parent_revision_id: null },
    });
    const revision = store.listContractRevisions("task:phase1-lifecycle")[0];
    bus.execute({
      ...base("ProposeContractRevision", 2, "guard:v1:propose"),
      payload: { revision_id: revision.revision_id },
    });
    bus.execute({
      ...base("ApproveContractRevision", 3, "guard:v1:approve"),
      payload: { revision_id: revision.revision_id, rationale: "One approval." },
    });

    expect(bus.execute({
      ...base("TransitionTaskStage", 4, "transition:intake-spec"),
      payload: { from_stage: "intake", to_stage: "specification" },
    }).ok).toBe(true);
    const denied = bus.execute({
      ...base("TransitionTaskStage", 5, "transition:spec-plan:denied"),
      payload: { from_stage: "specification", to_stage: "planning" },
    });
    expect(denied).toMatchObject({
      ok: false,
      error: {
        code: "policy_denied",
        decision: {
          denied_by: ["critical-human-review"],
          missing_requirements: ["human_approvals:2"],
        },
      },
    });
    expect(store.getTask("task:phase1-lifecycle")?.aggregate_version).toBe(5);

    const approvalTask = store.getTask("task:phase1-lifecycle")!;
    const approvalContract = store.getContractRevision(approvalTask.active_contract_revision_id!)!;
    expect(bus.execute({
      ...base("GrantApproval", 5, "approval:second"),
      actor: { type: "human", id: "human:security-owner" },
      payload: {
        subject: { type: "task", id: "task:phase1-lifecycle", operation: "transition:planning" },
        subject_hash: approvalAuthorizationContextHash({
          task: approvalTask,
          activeContract: approvalContract,
          operation: "transition:planning",
        }),
        rationale: "Second critical-risk owner approval.",
      },
    }).ok).toBe(true);
    expect(bus.execute({
      ...base("TransitionTaskStage", 6, "transition:spec-plan:allowed"),
      payload: { from_stage: "specification", to_stage: "planning" },
    }).ok).toBe(true);
    expect(store.getTask("task:phase1-lifecycle")).toMatchObject({ stage: "planning", aggregate_version: 7 });
    store.close();
  });

  test("adopts approved contract risk and requires distinct human approvers", () => {
    const { store, bus } = setup();
    bus.execute({
      ...base("CreateTask", 0, "risk:create"),
      payload: {
        title: "Initially low risk",
        workflow: { id: "software-development", version: "1.0.0" },
        policy: { id: "safe-default", version: "1.0.0" },
        risk: { level: "low", reasons: [] },
      },
    });
    bus.execute({
      ...base("CreateContractRevision", 1, "risk:contract"),
      payload: { document: contract("task:phase1-lifecycle", 1), parent_revision_id: null },
    });
    const revision = store.listContractRevisions("task:phase1-lifecycle")[0];
    bus.execute({ ...base("ProposeContractRevision", 2, "risk:propose"), payload: { revision_id: revision.revision_id } });
    bus.execute({
      ...base("ApproveContractRevision", 3, "risk:approve"),
      payload: { revision_id: revision.revision_id, rationale: "Critical risk acknowledged." },
    });
    expect(store.getTask("task:phase1-lifecycle")?.risk).toEqual({ level: "critical", reasons: ["credentials"] });
    bus.execute({ ...base("TransitionTaskStage", 4, "risk:intake-spec"), payload: { from_stage: "intake", to_stage: "specification" } });
    const approvalTask = store.getTask("task:phase1-lifecycle")!;
    const approvalContract = store.getContractRevision(approvalTask.active_contract_revision_id!)!;
    bus.execute({
      ...base("GrantApproval", 5, "risk:duplicate-owner"),
      payload: {
        subject: { type: "task", id: "task:phase1-lifecycle", operation: "transition:planning" },
        subject_hash: approvalAuthorizationContextHash({
          task: approvalTask,
          activeContract: approvalContract,
          operation: "transition:planning",
        }),
        rationale: "Same owner cannot satisfy two-person approval.",
      },
    });
    expect(bus.execute({
      ...base("TransitionTaskStage", 6, "risk:planning-denied"),
      payload: { from_stage: "specification", to_stage: "planning" },
    })).toMatchObject({
      ok: false,
      error: { code: "policy_denied", decision: { missing_requirements: ["human_approvals:2"] } },
    });
    store.close();
  });

  test("does not reuse an operation approval after the active contract changes", () => {
    const { store, bus } = setup();
    createTask(bus);
    bus.execute({
      ...base("CreateContractRevision", 1, "context:v1:create"),
      payload: { document: contract("task:phase1-lifecycle", 1), parent_revision_id: null },
    });
    const revision1 = store.listContractRevisions("task:phase1-lifecycle")[0];
    bus.execute({ ...base("ProposeContractRevision", 2, "context:v1:propose"), payload: { revision_id: revision1.revision_id } });
    bus.execute({
      ...base("ApproveContractRevision", 3, "context:v1:approve"),
      payload: { revision_id: revision1.revision_id, rationale: "Approve v1." },
    });
    bus.execute({ ...base("TransitionTaskStage", 4, "context:intake-spec"), payload: { from_stage: "intake", to_stage: "specification" } });
    const approvalTask = store.getTask("task:phase1-lifecycle")!;
    bus.execute({
      ...base("GrantApproval", 5, "context:second-owner"),
      actor: { type: "human", id: "human:security-owner" },
      payload: {
        subject: { type: "task", id: approvalTask.task_id, operation: "transition:planning" },
        subject_hash: approvalAuthorizationContextHash({
          task: approvalTask,
          activeContract: store.getContractRevision(revision1.revision_id),
          operation: "transition:planning",
        }),
        rationale: "Approve planning for contract v1 only.",
      },
    });
    const document2 = contract("task:phase1-lifecycle", 2);
    document2.goal.summary = "Contract v2 changes the authorization context.";
    bus.execute({
      ...base("CreateContractRevision", 6, "context:v2:create"),
      payload: { document: document2, parent_revision_id: revision1.revision_id },
    });
    const revision2 = store.listContractRevisions("task:phase1-lifecycle")[1];
    bus.execute({ ...base("ProposeContractRevision", 7, "context:v2:propose"), payload: { revision_id: revision2.revision_id } });
    bus.execute({
      ...base("ApproveContractRevision", 8, "context:v2:approve"),
      payload: { revision_id: revision2.revision_id, rationale: "Approve v2 contract only." },
    });
    expect(bus.execute({
      ...base("TransitionTaskStage", 9, "context:v2:planning-denied"),
      payload: { from_stage: "specification", to_stage: "planning" },
    })).toMatchObject({
      ok: false,
      error: { code: "policy_denied", decision: { missing_requirements: ["human_approvals:2"] } },
    });
    store.close();
  });

  test("rejects contract approval by a non-human actor", () => {
    const { store, bus } = setup();
    createTask(bus);
    bus.execute({
      ...base("CreateContractRevision", 1, "actor:v1:create"),
      payload: { document: contract("task:phase1-lifecycle", 1), parent_revision_id: null },
    });
    const revision = store.listContractRevisions("task:phase1-lifecycle")[0];
    bus.execute({
      ...base("ProposeContractRevision", 2, "actor:v1:propose"),
      payload: { revision_id: revision.revision_id },
    });
    const denied = bus.execute({
      ...base("ApproveContractRevision", 3, "actor:v1:approve"),
      actor: { type: "agent", id: "agent:reviewer" },
      payload: { revision_id: revision.revision_id, rationale: "Self approval." },
    });
    expect(denied).toMatchObject({ ok: false, error: { code: "actor_forbidden" } });
    expect(store.getContractRevision(revision.revision_id)?.status).toBe("PROPOSED");
    store.close();
  });

  test("enforces task_operator and verifier roles across command families", () => {
    const { store, bus } = setup();
    expect(bus.execute({
      ...base("CreateTask", 0, "role:verifier-create"),
      actor: { type: "agent", id: "agent:reviewer" },
      payload: {
        title: "Forbidden verifier write",
        workflow: { id: "software-development", version: "1.0.0" },
        policy: { id: "safe-default", version: "1.0.0" },
        risk: { level: "low", reasons: [] },
      },
    })).toMatchObject({ ok: false, error: { code: "actor_forbidden", required: "task_operator" } });
    expect(bus.execute({
      ...base("IssueVerdict", 0, "role:operator-verdict"),
      actor: { type: "agent", id: "agent:operator" },
      payload: {
        contract_revision_id: "contract-revision:none",
        decision: "REPAIR",
        rationale: "Forbidden operator verdict.",
        evidence_refs: [],
      },
    })).toMatchObject({ ok: false, error: { code: "actor_forbidden", required: "verifier" } });
    expect(store.getTask("task:phase1-lifecycle")).toBeNull();
    store.close();
  });

  test("preserves an unknown .plan extension without granting workflow authority", () => {
    const { store, bus } = setup();
    store.installWorkflow({
      schema_version: 1,
      workflow_id: "plan-guard",
      version: "1.0.0",
      stages: [{ id: "intake" }, { id: "execution" }, { id: "done", terminal: true }],
      transitions: [
        { from: "intake", to: "execution", guards: ["plan.exists"] },
        { from: "execution", to: "done" },
      ],
    });
    store.installPolicy({ schema_version: 1, policy_pack_id: "plan-empty", version: "1.0.0", rules: [] });
    expect(bus.execute({
      ...base("CreateTask", 0, "unknown-plan:create"),
      payload: {
        title: "Unknown plan namespace",
        workflow: { id: "plan-guard", version: "1.0.0" },
        policy: { id: "plan-empty", version: "1.0.0" },
        risk: { level: "low", reasons: [] },
      },
    }).ok).toBe(true);
    const document = contract("task:phase1-lifecycle", 1);
    document.risk = { level: "low", reasons: [] };
    document.extensions = { "company.plan": { schema_version: 1, exists: true } };
    bus.execute({ ...base("CreateContractRevision", 1, "unknown-plan:contract"), payload: { document, parent_revision_id: null } });
    const revision = store.listContractRevisions("task:phase1-lifecycle")[0];
    bus.execute({ ...base("ProposeContractRevision", 2, "unknown-plan:propose"), payload: { revision_id: revision.revision_id } });
    bus.execute({
      ...base("ApproveContractRevision", 3, "unknown-plan:approve"),
      payload: { revision_id: revision.revision_id, rationale: "Unknown extension preserved only." },
    });
    expect(bus.execute({
      ...base("TransitionTaskStage", 4, "unknown-plan:transition"),
      payload: { from_stage: "intake", to_stage: "execution" },
    })).toMatchObject({
      ok: false,
      error: { code: "workflow_denied", decision: { missing_guards: ["plan.exists"] } },
    });
    expect(store.getContractRevision(revision.revision_id)?.document.extensions).toEqual({
      "company.plan": { schema_version: 1, exists: true },
    });
    store.close();
  });
});
