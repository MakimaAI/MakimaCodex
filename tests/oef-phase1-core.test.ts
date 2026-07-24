import { describe, expect, test } from "bun:test";
import {
  canonicalContractHash,
  createSortableIdGenerator,
  diffTaskContracts,
  evaluatePolicy,
  evaluateWorkflowTransition,
  parseActor,
  parsePolicyPack,
  parseSecretRef,
  parseTaskContractDocument,
  parseWorkflowDefinition,
} from "../src/oef/phase1";

const contractInput = () => ({
  schema_version: 1,
  task_id: "task:01JPHASE1TASK00000000000001",
  revision: 1,
  title: "Secure account rotation",
  goal: { summary: "Rotate only after a genuine quota response." },
  scope: {
    included: ["Provider adapter", "Credential redaction tests"],
    excluded: ["Production deployment"],
  },
  constraints: ["Secrets must not enter prompts or events."],
  acceptance_criteria: [
    {
      key: "rotation",
      statement: "A 429 response selects another eligible account.",
      required_evidence: ["opencodex.test-result", "opencodex.routing-event"],
    },
    {
      key: "redaction",
      statement: "Credentials are absent from persisted records.",
      required_evidence: ["opencodex.security-scan"],
    },
  ],
  risk: { level: "high", reasons: ["credentials", "account-rotation"] },
  budgets: { max_attempts: 3, max_parallel_writers: 2, max_cost_units: 100 },
  extensions: {
    "company.security": {
      schema_version: 1,
      threat_model_required: true,
    },
  },
});

const workflowInput = () => ({
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
});

const policyInput = () => ({
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
      id: "high-risk-human-review",
      when: { operation: "transition", risk_levels: ["high", "critical"] },
      require: { human_approvals: 1 },
    },
    {
      id: "test-evidence-before-accept",
      when: { operation: "verdict", verdict: "ACCEPT" },
      require: { all_contract_evidence: true },
    },
    {
      id: "credential-security-review",
      when: { operation: "verdict", risk_reasons: ["credentials"] },
      require: {
        evidence_types: ["opencodex.security-scan", "opencodex.security-review"],
      },
    },
  ],
});

describe("Phase 1 identity and actor model", () => {
  test("generates unique, lexically sortable, typed identifiers", () => {
    let now = 1_700_000_000_000;
    const ids = createSortableIdGenerator({
      now: () => now++,
      randomBytes: size => new Uint8Array(size).fill(7),
    });

    const first = ids.next("task");
    const second = ids.next("task");
    const event = ids.next("event");

    expect(first).toStartWith("task:");
    expect(event).toStartWith("event:");
    expect(first < second).toBe(true);
    expect(new Set([first, second, event]).size).toBe(3);
  });

  test("accepts future-ready actors while rejecting missing identity", () => {
    expect(parseActor({
      type: "agent",
      id: "agent:frontend-17",
      model_ref: "model:google/gemini-x",
      runtime_ref: "runtime:opencodex-3",
    })).toEqual({
      type: "agent",
      id: "agent:frontend-17",
      model_ref: "model:google/gemini-x",
      runtime_ref: "runtime:opencodex-3",
    });
    expect(() => parseActor({ type: "human", id: "" })).toThrow();
    expect(() => parseActor({ type: "model", id: "model:x" })).toThrow();
  });

  test("stores credential references rather than secret values", () => {
    expect(parseSecretRef({
      provider: "system-keychain",
      key: "opencodex/provider/account-2",
    })).toEqual({
      provider: "system-keychain",
      key: "opencodex/provider/account-2",
    });
    expect(() => parseSecretRef({ provider: "inline", key: "api_key=abcdefghijklmnop" })).toThrow();
    expect(() => parseSecretRef({ provider: "system-keychain", key: "../outside" })).toThrow();
  });
});

describe("Phase 1 task contract", () => {
  test("validates extensions by namespace and preserves unknown extension data", () => {
    const parsed = parseTaskContractDocument(contractInput());
    expect(parsed.extensions["company.security"]).toEqual({
      schema_version: 1,
      threat_model_required: true,
    });

    const unnamespaced = contractInput();
    unnamespaced.extensions = { security: { schema_version: 1 } };
    expect(() => parseTaskContractDocument(unnamespaced)).toThrow();

    const unversioned = contractInput();
    unversioned.extensions = { "company.security": { threat_model_required: true } } as never;
    expect(() => parseTaskContractDocument(unversioned)).toThrow();
  });

  test("produces the same canonical hash regardless of object key order", () => {
    const first = parseTaskContractDocument(contractInput());
    const reordered = {
      extensions: first.extensions,
      budgets: first.budgets,
      risk: first.risk,
      acceptance_criteria: first.acceptance_criteria,
      constraints: first.constraints,
      scope: first.scope,
      goal: first.goal,
      title: first.title,
      revision: first.revision,
      task_id: first.task_id,
      schema_version: first.schema_version,
    };

    expect(canonicalContractHash(first)).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(canonicalContractHash(reordered)).toBe(canonicalContractHash(first));
  });

  test("rejects duplicate criteria and computes machine-readable revision diffs", () => {
    const duplicate = contractInput();
    duplicate.acceptance_criteria.push({ ...duplicate.acceptance_criteria[0] });
    expect(() => parseTaskContractDocument(duplicate)).toThrow();

    const before = parseTaskContractDocument(contractInput());
    const afterInput = contractInput();
    afterInput.revision = 2;
    afterInput.constraints[0] = "Secrets must not appear in logs, prompts, traces, events, or artifacts.";
    afterInput.acceptance_criteria.shift();
    afterInput.acceptance_criteria.push({
      key: "audit-chain",
      statement: "The event hash chain verifies.",
      required_evidence: ["opencodex.integrity-check"],
    });
    afterInput.risk.level = "critical";
    const diff = diffTaskContracts(before, parseTaskContractDocument(afterInput));

    expect(diff.added_criteria).toEqual(["audit-chain"]);
    expect(diff.removed_criteria).toEqual(["rotation"]);
    expect(diff.modified_constraints).toHaveLength(1);
    expect(diff.risk_changed).toEqual({ from: "high", to: "critical" });
  });
});

describe("Phase 1 workflow engine", () => {
  test("loads versioned data, validates graph references, and enforces guards", () => {
    const workflow = parseWorkflowDefinition(workflowInput());
    expect(evaluateWorkflowTransition({
      workflow,
      from: "specification",
      to: "planning",
      satisfied_guards: [],
    })).toEqual({ allowed: false, reason: "guards-unsatisfied", missing_guards: ["contract.approved"] });
    expect(evaluateWorkflowTransition({
      workflow,
      from: "specification",
      to: "planning",
      satisfied_guards: ["contract.approved"],
    })).toEqual({ allowed: true, reason: "transition-allowed", terminal: false });

    const invalid = workflowInput();
    invalid.transitions.push({ from: "missing", to: "done" });
    expect(() => parseWorkflowDefinition(invalid)).toThrow();
  });

  test("rejects silent transitions from terminal stages", () => {
    const workflow = parseWorkflowDefinition(workflowInput());
    expect(evaluateWorkflowTransition({
      workflow,
      from: "done",
      to: "intake",
      satisfied_guards: [],
    })).toEqual({ allowed: false, reason: "terminal-stage" });
  });
});

describe("Phase 1 declarative policy engine", () => {
  test("denies high-risk planning without contract approval and human approval", () => {
    const pack = parsePolicyPack(policyInput());
    const decision = evaluatePolicy({
      pack,
      operation: { kind: "transition", to: "planning" },
      task: {
        risk_level: "high",
        risk_reasons: ["credentials"],
        contract_status: "PROPOSED",
        required_evidence: [],
      },
      human_approval_count: 0,
      verified_evidence: [],
    });

    expect(decision.allowed).toBe(false);
    expect(decision.denied_by).toEqual([
      "approved-contract-before-planning",
      "high-risk-human-review",
    ]);
    expect(decision.missing_requirements).toContain("contract.status=APPROVED");
    expect(decision.missing_requirements).toContain("human_approvals:1");
    expect(decision.evaluated_policy).toEqual({ id: "safe-default", version: "1.0.0" });
  });

  test("requires complete contract and credential evidence before ACCEPT", () => {
    const pack = parsePolicyPack(policyInput());
    const denied = evaluatePolicy({
      pack,
      operation: { kind: "verdict", decision: "ACCEPT" },
      task: {
        risk_level: "high",
        risk_reasons: ["credentials"],
        contract_status: "APPROVED",
        required_evidence: [
          { criterion_key: "tests", evidence_type: "opencodex.test-result" },
          { criterion_key: "security", evidence_type: "opencodex.security-scan" },
        ],
      },
      human_approval_count: 1,
      verified_evidence: [
        { criterion_key: "tests", evidence_type: "opencodex.test-result" },
        { criterion_key: "security", evidence_type: "opencodex.security-scan" },
      ],
    });
    expect(denied).toMatchObject({
      allowed: false,
      denied_by: ["credential-security-review"],
      missing_requirements: ["evidence:opencodex.security-review"],
    });

    const allowed = evaluatePolicy({
      pack,
      operation: { kind: "verdict", decision: "ACCEPT" },
      task: {
        risk_level: "high",
        risk_reasons: ["credentials"],
        contract_status: "APPROVED",
        required_evidence: [
          { criterion_key: "tests", evidence_type: "opencodex.test-result" },
          { criterion_key: "security", evidence_type: "opencodex.security-scan" },
        ],
      },
      human_approval_count: 1,
      verified_evidence: [
        { criterion_key: "tests", evidence_type: "opencodex.test-result" },
        { criterion_key: "security", evidence_type: "opencodex.security-scan" },
        { criterion_key: "security", evidence_type: "opencodex.security-review" },
      ],
    });
    expect(allowed).toEqual({
      allowed: true,
      decision: "allowed",
      evaluated_policy: { id: "safe-default", version: "1.0.0" },
    });
  });
});
