import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { pathToFileURL } from "node:url";

const bundlePath = process.env.OEF_CORE_BUNDLE;
if (!bundlePath) {
  test("OEF core coverage harness runs only through coverage:oef:core", { skip: true }, () => {});
} else {
const core = await import(pathToFileURL(bundlePath).href);
const {
  assertNoPhase1Secret,
  assertNoStructuredPhase1Secret,
  canonicalJson,
  canonicalContractHash,
  containsLikelyPhase1Secret,
  containsStructuredPhase1Secret,
  createDomainEvent,
  createSortableIdGenerator,
  diffTaskContracts,
  evaluatePolicy,
  evaluateWorkflowTransition,
  parseActor,
  parsePolicyPack,
  parseEvidenceRecord,
  parseSecretRef,
  parseTaskContractDocument,
  parseTask,
  parseWorkflowDefinition,
  upcastStoredEvent,
  verifyDomainEventHash,
} = core;

const contract = () => ({
  schema_version: 1,
  task_id: "task:node-coverage",
  revision: 1,
  title: "Coverage contract",
  goal: { summary: "Exercise core decisions." },
  scope: { included: ["Core"], excluded: [] },
  constraints: ["A"],
  acceptance_criteria: [{
    key: "one",
    statement: "One criterion.",
    required_evidence: ["opencodex.test-result"],
  }],
  risk: { level: "low", reasons: [] },
  budgets: { max_attempts: 1, max_parallel_writers: 1, max_cost_units: 0 },
  extensions: {},
});

const workflow = () => ({
  schema_version: 1,
  workflow_id: "coverage",
  version: "1.0.0",
  stages: [{ id: "a" }, { id: "b" }, { id: "done", terminal: true }],
  transitions: [
    { from: "a", to: "b", guards: ["contract.approved"] },
    { from: "b", to: "done" },
  ],
});

const policy = () => ({
  schema_version: 1,
  policy_pack_id: "coverage",
  version: "1.0.0",
  rules: [
    {
      id: "transition",
      when: { operation: "transition", transition_to: "b", risk_levels: ["high"], risk_reasons: ["credentials"] },
      require: { contract_status: "APPROVED", human_approvals: 2 },
    },
    {
      id: "verdict",
      when: { operation: "verdict", verdict: "ACCEPT" },
      require: { evidence_types: ["opencodex.security-scan"], all_contract_evidence: true },
    },
  ],
});

describe("ids and actors", () => {
  test("covers default, same-time, next-time, invalid, and backwards clocks", () => {
    assert.match(createSortableIdGenerator().next("task"), /^task:/);
    let time = 10;
    const generator = createSortableIdGenerator({
      now: () => time,
      randomBytes: size => new Uint8Array(size),
    });
    const first = generator.next("task");
    const same = generator.next("task");
    time += 1;
    const next = generator.next("task");
    assert.ok(first < same && same < next);
    const invalid = createSortableIdGenerator({ now: () => -1 });
    assert.throws(() => invalid.next("task"), /non-negative/);
    const fractional = createSortableIdGenerator({ now: () => 1.5 });
    assert.throws(() => fractional.next("task"), /safe integer/);
    let backwardsTime = 2;
    const backwards = createSortableIdGenerator({ now: () => backwardsTime-- });
    backwards.next("task");
    assert.throws(() => backwards.next("task"), /backwards/);
  });

  test("covers valid and invalid actor branches", () => {
    assert.deepEqual(parseActor({ type: "human", id: "human:x" }), { type: "human", id: "human:x" });
    assert.deepEqual(parseActor({ type: "agent", id: "agent:x", model_ref: "model:x", runtime_ref: "runtime:x" }), {
      type: "agent", id: "agent:x", model_ref: "model:x", runtime_ref: "runtime:x",
    });
    assert.throws(() => parseActor({ type: "human", id: "" }));
  });
});

describe("contracts", () => {
  test("covers canonical arrays, objects, primitives, undefined, and hashes", () => {
    assert.equal(canonicalJson({ z: 1, a: [2, { b: true, a: undefined }], n: null }), '{"a":[2,{"b":true}],"n":null,"z":1}');
    const parsed = parseTaskContractDocument(contract());
    assert.match(canonicalContractHash(parsed), /^sha256:[a-f0-9]{64}$/);
  });

  test("covers duplicate validation and every diff category", () => {
    const duplicate = contract();
    duplicate.acceptance_criteria.push({ ...duplicate.acceptance_criteria[0] });
    assert.throws(() => parseTaskContractDocument(duplicate));
    const before = contract();
    const after = contract();
    after.revision = 2;
    after.constraints[0] = "B";
    after.acceptance_criteria[0].statement = "Changed";
    after.acceptance_criteria.push({ key: "two", statement: "Two", required_evidence: [] });
    after.risk.level = "high";
    const changed = diffTaskContracts(before, after);
    assert.deepEqual(changed.added_criteria, ["two"]);
    assert.equal(changed.modified_criteria.length, 1);
    assert.equal(changed.modified_constraints.length, 1);
    assert.deepEqual(changed.risk_changed, { from: "low", to: "high" });
    const removed = contract();
    removed.revision = 2;
    removed.acceptance_criteria = [{ key: "other", statement: "Other", required_evidence: [] }];
    assert.deepEqual(diffTaskContracts(before, removed).removed_criteria, ["one"]);
    assert.equal("risk_changed" in diffTaskContracts(before, { ...before, revision: 2 }), false);
  });
});

describe("workflows", () => {
  test("covers graph validation failures", () => {
    const duplicateStage = workflow();
    duplicateStage.stages.push({ id: "a" });
    assert.throws(() => parseWorkflowDefinition(duplicateStage));
    const unknownFrom = workflow();
    unknownFrom.transitions.push({ from: "missing", to: "done" });
    assert.throws(() => parseWorkflowDefinition(unknownFrom));
    const unknownTo = workflow();
    unknownTo.transitions.push({ from: "a", to: "missing" });
    assert.throws(() => parseWorkflowDefinition(unknownTo));
    const terminalOutbound = workflow();
    terminalOutbound.transitions.push({ from: "done", to: "a" });
    assert.throws(() => parseWorkflowDefinition(terminalOutbound));
    const duplicateEdge = workflow();
    duplicateEdge.transitions.push({ from: "a", to: "b" });
    assert.throws(() => parseWorkflowDefinition(duplicateEdge));
  });

  test("covers every transition decision", () => {
    const definition = parseWorkflowDefinition(workflow());
    assert.deepEqual(evaluateWorkflowTransition({ workflow: definition, from: "missing", to: "b", satisfied_guards: [] }), { allowed: false, reason: "unknown-stage" });
    assert.deepEqual(evaluateWorkflowTransition({ workflow: definition, from: "a", to: "missing", satisfied_guards: [] }), { allowed: false, reason: "unknown-stage" });
    assert.deepEqual(evaluateWorkflowTransition({ workflow: definition, from: "done", to: "a", satisfied_guards: [] }), { allowed: false, reason: "terminal-stage" });
    assert.deepEqual(evaluateWorkflowTransition({ workflow: definition, from: "a", to: "done", satisfied_guards: [] }), { allowed: false, reason: "transition-not-defined" });
    assert.deepEqual(evaluateWorkflowTransition({ workflow: definition, from: "a", to: "b", satisfied_guards: [] }), { allowed: false, reason: "guards-unsatisfied", missing_guards: ["contract.approved"] });
    assert.deepEqual(evaluateWorkflowTransition({ workflow: definition, from: "a", to: "b", satisfied_guards: ["contract.approved"] }), { allowed: true, reason: "transition-allowed", terminal: false });
    assert.deepEqual(evaluateWorkflowTransition({ workflow: definition, from: "b", to: "done", satisfied_guards: [] }), { allowed: true, reason: "transition-allowed", terminal: true });
  });
});

describe("policies", () => {
  test("covers policy schema conflicts", () => {
    const duplicate = policy();
    duplicate.rules.push({ ...duplicate.rules[0] });
    assert.throws(() => parsePolicyPack(duplicate));
    const verdictWithTransition = policy();
    verdictWithTransition.rules[1].when.transition_to = "b";
    assert.throws(() => parsePolicyPack(verdictWithTransition));
    const transitionWithVerdict = policy();
    transitionWithVerdict.rules[0].when.verdict = "ACCEPT";
    assert.throws(() => parsePolicyPack(transitionWithVerdict));
  });

  test("covers non-applicable and failing requirements", () => {
    const pack = parsePolicyPack(policy());
    const base = {
      pack,
      task: {
        risk_level: "high" as const,
        risk_reasons: ["credentials"],
        contract_status: "PROPOSED" as const,
        required_evidence: [{ criterion_key: "tests", evidence_type: "opencodex.test-result" }],
      },
      human_approval_count: 0,
      verified_evidence: [] as Array<{ criterion_key: string; evidence_type: string }>,
    };
    const denied = evaluatePolicy({ ...base, operation: { kind: "transition", to: "b" } });
    assert.equal(denied.allowed, false);
    if (!denied.allowed) assert.deepEqual(denied.missing_requirements, ["contract.status=APPROVED", "human_approvals:2"]);
    assert.equal(evaluatePolicy({ ...base, operation: { kind: "transition", to: "other" } }).allowed, true);
    assert.equal(evaluatePolicy({
      ...base,
      operation: { kind: "transition", to: "b" },
      task: { ...base.task, risk_level: "low", risk_reasons: [] },
    }).allowed, true);
    assert.equal(evaluatePolicy({
      ...base,
      operation: { kind: "transition", to: "b" },
      task: { ...base.task, risk_reasons: [] },
    }).allowed, true);
  });

  test("covers verdict match, evidence requirements, dedupe, and allow", () => {
    const pack = parsePolicyPack(policy());
    const input = {
      pack,
      operation: { kind: "verdict" as const, decision: "ACCEPT" as const },
      task: {
        risk_level: "low" as const,
        risk_reasons: [],
        contract_status: "APPROVED" as const,
        required_evidence: [{ criterion_key: "security", evidence_type: "opencodex.security-scan" }],
      },
      human_approval_count: 2,
      verified_evidence: [] as Array<{ criterion_key: string; evidence_type: string }>,
    };
    const denied = evaluatePolicy(input);
    assert.equal(denied.allowed, false);
    if (!denied.allowed) assert.deepEqual(denied.missing_requirements, [
      "evidence:opencodex.security-scan",
      "evidence:security:opencodex.security-scan",
    ]);
    assert.equal(evaluatePolicy({ ...input, operation: { kind: "verdict", decision: "REPAIR" } }).allowed, true);
    assert.deepEqual(evaluatePolicy({
      ...input,
      verified_evidence: [{ criterion_key: "security", evidence_type: "opencodex.security-scan" }],
    }), {
      allowed: true,
      decision: "allowed",
      evaluated_policy: { id: "coverage", version: "1.0.0" },
    });
  });
});

describe("events, upcasters, and secrets", () => {
  test("covers event hash success and failure", () => {
    const event = createDomainEvent({
      eventId: "event:1",
      eventType: "task.created",
      aggregateId: "task:1",
      aggregateVersion: 1,
      actor: { type: "human", id: "human:x" },
      traceId: "trace:1",
      causationId: "command:1",
      occurredAt: "2026-07-23T00:00:00.000Z",
      recordedAt: "2026-07-23T00:00:00.000Z",
      payload: { title: "Task" },
      previousEventHash: null,
    });
    assert.equal(verifyDomainEventHash(event), true);
    assert.equal(verifyDomainEventHash({ ...event, payload: { title: "Tampered" } }), false);
  });

  test("covers current, human, system, missing, no-upcaster, cycle, and stalled upcasters", () => {
    const current = { event_type: "x", event_schema_version: 1 };
    assert.deepEqual(upcastStoredEvent(current), current);
    assert.deepEqual(upcastStoredEvent({ event_type: "x", event_schema_version: 0, actor_id: "human:x" }).actor, { type: "human", id: "human:x" });
    assert.deepEqual(upcastStoredEvent({ event_type: "x", event_schema_version: 0, actor_id: "agent:x" }).actor, { type: "system", id: "agent:x" });
    assert.deepEqual(upcastStoredEvent({ event_type: "x", event_schema_version: 0 }).actor, { type: "system", id: "system:legacy-upcaster" });
    assert.throws(() => upcastStoredEvent({ event_type: "x", event_schema_version: 2 }), /No upcaster/);
    assert.throws(() => upcastStoredEvent(
      { event_type: "x", event_schema_version: 0 },
      [{ supports: () => true, upcast: event => event }],
    ), /did not advance/);
    assert.throws(() => upcastStoredEvent(
      { event_type: "x", event_schema_version: 0 },
      [{ supports: () => true, upcast: event => ({ ...event, event_schema_version: event.event_schema_version === 0 ? 2 : 0 }) }],
    ), /cycle/);
  });

  test("covers secret detection and assertion", () => {
    assert.equal(containsLikelyPhase1Secret("safe"), false);
    assert.equal(containsLikelyPhase1Secret("api_key=abcdefghijklmnop"), true);
    assert.doesNotThrow(() => assertNoPhase1Secret("safe"));
    assert.throws(() => assertNoPhase1Secret("Authorization: Bearer abcdefghijklmnopqrstuvwxyz", "event"), /event contains/);
    assert.deepEqual(parseSecretRef({ provider: "system-keychain", key: "opencodex/provider/account-2" }), {
      provider: "system-keychain",
      key: "opencodex/provider/account-2",
    });
    assert.throws(() => parseSecretRef({ provider: "system-keychain", key: "../outside" }));
    assert.throws(() => parseSecretRef({ provider: "inline", key: "api_key=abcdefghijklmnop" }));
    assert.equal(containsStructuredPhase1Secret({ nested: { api_key: "abcdefghijklmnop" } }), true);
    assert.equal(containsStructuredPhase1Secret({ values: ["safe", 2, null] }), false);
    assert.doesNotThrow(() => assertNoStructuredPhase1Secret({ safe: "value" }));
    assert.throws(() => assertNoStructuredPhase1Secret({ authorization: "hidden" }, "command"), /command contains/);
  });

  test("covers task and evidence runtime validators", () => {
    const hash = `sha256:${"a".repeat(64)}`;
    const actor = { type: "system", id: "system:coverage" };
    const task = {
      schema_version: 1,
      task_id: "task:coverage",
      title: "Coverage",
      status: "OPEN",
      stage: "verification",
      active_contract_revision_id: null,
      workflow_ref: { id: "workflow", version: "1.0.0", hash },
      policy_pack_ref: { id: "policy", version: "1.0.0", hash },
      risk: { level: "low", reasons: [] },
      created_by: actor,
      created_at: "2026-07-23T00:00:00.000Z",
      updated_at: "2026-07-23T00:00:00.000Z",
      aggregate_version: 1,
    };
    assert.deepEqual(parseTask(task), task);
    assert.throws(() => parseTask({ ...task, workflow_ref: { id: "workflow" } }));
    const evidence = {
      schema_version: 1,
      evidence_id: "evidence:coverage",
      task_id: task.task_id,
      contract_revision_id: "contract-revision:coverage",
      criterion_key: "tests",
      type: "opencodex.test-result",
      status: "VERIFIED",
      producer: actor,
      summary: "Passed.",
      artifacts: [],
      environment: { repository_commit: "abc123" },
      created_at: "2026-07-23T00:00:00.000Z",
      verified_at: "2026-07-23T00:01:00.000Z",
    };
    assert.deepEqual(parseEvidenceRecord(evidence), evidence);
    assert.throws(() => parseEvidenceRecord({ ...evidence, status: "UNKNOWN" }));
  });
});
}
