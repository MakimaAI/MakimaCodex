import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  accountId,
  agentId,
  assertTaskContractRevision,
  decideEvolutionChange,
  decideMemoryWrite,
  decidePermission,
  modelId,
  parseRoleId,
  permissionEnvelopeId,
  providerId,
  roleId,
  runtimeId,
  taskId,
  taskContractSchema,
  validateAgentBinding,
  type AgentProfile,
  type PermissionEnvelope,
  type TaskContract,
} from "../src/oef";

function approvedContract(): TaskContract {
  return taskContractSchema.parse({
    schemaVersion: "oef.task-contract/v1",
    taskId: taskId("oef-phase-0"),
    revision: 1,
    title: "Establish OEF phase-zero boundaries",
    objective: "Make identity and safety boundaries explicit and enforceable.",
    risk: {
      level: "high",
      reasons: ["The future system can propose changes to its own control plane."],
    },
    scope: {
      read: ["src/**", "tests/**", "structure/**", "docs/adr/**"],
      write: ["src/oef/**", "tests/oef-*.test.ts", "structure/oef/**", "docs/adr/000*.md"],
      deny: ["src/server/**", "src/providers/**"],
    },
    constraints: [
      "deterministic-control-kernel",
      "no-live-core-self-modification",
      "no-secret-in-memory",
    ],
    permissionEnvelopeId: permissionEnvelopeId("oef-phase-0"),
    acceptanceCriteria: [
      {
        id: "ac:identity-boundaries",
        statement: "Role, agent, runtime, provider, model, and account identifiers are not interchangeable.",
        verifier: { kind: "test", target: "tests/oef-type-boundaries.test.ts" },
      },
      {
        id: "ac:no-self-modification",
        statement: "An agent cannot write directly to the production core.",
        verifier: { kind: "test", target: "tests/oef-phase0.test.ts" },
      },
    ],
    approval: {
      status: "approved",
      actorId: "human:owner",
      approvedAt: "2026-07-23T09:30:00.000Z",
    },
    createdAt: "2026-07-23T09:00:00.000Z",
  });
}

const memoryIdentity = {
  recordId: "memory:oef-phase-0",
  scope: "task:oef-phase-0",
} as const;

function sha256(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

describe("OEF identity boundaries", () => {
  test("uses distinct, prefixed identifiers at runtime", () => {
    expect(roleId("chief-architect")).toBe("role:chief-architect");
    expect(agentId("architect-01")).toBe("agent:architect-01");
    expect(runtimeId("codex-desktop")).toBe("runtime:codex-desktop");
    expect(providerId("openai")).toBe("provider:openai");
    expect(modelId("openai/gpt-5.6-sol")).toBe("model:openai/gpt-5.6-sol");
    expect(accountId("openai/main")).toBe("account:openai/main");
    expect(() => parseRoleId("model:openai/gpt-5.6-sol")).toThrow("role:");
  });

  test("rejects non-canonical identifiers with whitespace or control characters", () => {
    for (const value of ["role:owner\n", "role:owner ", "role:\towner", " role:owner"]) {
      expect(() => parseRoleId(value), JSON.stringify(value)).toThrow();
    }
  });

  test("rejects an agent binding whose model and account belong to different providers", () => {
    const profile: AgentProfile = {
      id: agentId("implementer-01"),
      roleId: roleId("implementer"),
      runtimeId: runtimeId("codex-cli"),
      allowedModelIds: [modelId("openai/gpt-5.6-terra")],
      toolBundle: ["shell", "apply_patch"],
      memoryScopes: { read: ["project"], write: ["task-episode"] },
      permissionEnvelopeId: permissionEnvelopeId("implementer"),
      workspace: "isolated-worktree",
      verifiers: ["tests", "typecheck"],
      stopConditions: ["budget-exhausted", "permission-denied"],
    };

    expect(validateAgentBinding({
      profile,
      model: {
        id: modelId("openai/gpt-5.6-terra"),
        providerId: providerId("openai"),
        apiModelId: "gpt-5.6-terra",
      },
      account: {
        id: accountId("anthropic/reviewer"),
        providerId: providerId("anthropic"),
      },
    })).toEqual({
      ok: false,
      reason: "model-account-provider-mismatch",
    });
  });
});

describe("versioned task contract", () => {
  test("requires explicit, testable acceptance criteria", () => {
    const contract = approvedContract();
    expect(contract.acceptanceCriteria).toHaveLength(2);

    expect(() => taskContractSchema.parse({
      ...contract,
      acceptanceCriteria: [],
    })).toThrow();
  });

  test("prevents silent scope changes by requiring a monotonic revision and supersedes reference", () => {
    const previous = approvedContract();
    const silentChange = taskContractSchema.parse({
      ...previous,
      scope: { ...previous.scope, write: [...previous.scope.write, "src/server/**"] },
    });

    expect(() => assertTaskContractRevision(previous, silentChange)).toThrow("revision");

    const revisionTwo = taskContractSchema.parse({
      ...silentChange,
      revision: 2,
      supersedes: { taskId: previous.taskId, revision: previous.revision },
      approval: { status: "draft" },
    });
    expect(() => assertTaskContractRevision(previous, revisionTwo)).not.toThrow();
  });

  test("allows approval-only transitions without changing the contract revision", () => {
    const initialDraft = taskContractSchema.parse({
      ...approvedContract(),
      approval: { status: "draft" },
    });
    const initialApproved = taskContractSchema.parse({
      ...initialDraft,
      approval: {
        status: "approved",
        actorId: "human:owner",
        approvedAt: "2026-07-23T09:30:00.000Z",
      },
    });
    expect(() => assertTaskContractRevision(initialDraft, initialApproved)).not.toThrow();

    const revisedDraft = taskContractSchema.parse({
      ...initialApproved,
      revision: 2,
      supersedes: { taskId: initialApproved.taskId, revision: 1 },
      constraints: [...initialApproved.constraints, "candidate-worktree-only"],
      approval: { status: "draft" },
    });
    expect(() => assertTaskContractRevision(initialApproved, revisedDraft)).not.toThrow();

    const revisedApproved = taskContractSchema.parse({
      ...revisedDraft,
      approval: {
        status: "approved",
        actorId: "human:owner",
        approvedAt: "2026-07-23T10:00:00.000Z",
      },
    });
    expect(() => assertTaskContractRevision(revisedDraft, revisedApproved)).not.toThrow();

    expect(() => assertTaskContractRevision(revisedDraft, taskContractSchema.parse({
      ...revisedApproved,
      objective: "Silently changed objective",
    }))).toThrow("revision");
  });

  test("rejects revision gaps, duplicate acceptance ids, and time-travel approvals", () => {
    const previous = approvedContract();
    expect(() => taskContractSchema.parse({
      ...previous,
      revision: 3,
      supersedes: { taskId: previous.taskId, revision: 1 },
      approval: { status: "draft" },
    })).toThrow();

    expect(() => taskContractSchema.parse({
      ...previous,
      acceptanceCriteria: [
        previous.acceptanceCriteria[0],
        previous.acceptanceCriteria[0],
      ],
    })).toThrow();

    expect(() => taskContractSchema.parse({
      ...previous,
      approval: {
        status: "approved",
        actorId: "human:owner",
        approvedAt: "2026-07-23T08:00:00.000Z",
      },
    })).toThrow();

    expect(() => taskContractSchema.parse({
      ...previous,
      acceptanceCriteria: [{
        ...previous.acceptanceCriteria[0],
        id: "ac:identity-boundaries\n",
      }],
    })).toThrow();
  });
});

describe("fail-closed permission model", () => {
  const subject = agentId("implementer-01");
  const envelope: PermissionEnvelope = {
    id: permissionEnvelopeId("implementer"),
    subjectId: subject,
    defaultEffect: "deny",
    grants: [
      {
        capability: "workspace.write",
        resource: "candidate-worktree",
        pathPatterns: ["src/oef/**"],
      },
      {
        capability: "deployment.promote",
        resource: "production",
        requiresHumanApproval: true,
      },
    ],
    denies: [
      { capability: "workspace.write", resource: "production-core" },
      { capability: "credential.read", resource: "credential-store" },
    ],
  };

  test("allows only an explicitly granted operation", () => {
    expect(decidePermission(envelope, {
      subjectId: subject,
      capability: "workspace.write",
      resource: "candidate-worktree",
      path: "src/oef/identity.ts",
      approvalIds: [],
    })).toEqual({ allowed: true, reason: "explicit-grant" });
  });

  test("denies unknown operations and lets explicit deny override grants", () => {
    expect(decidePermission(envelope, {
      subjectId: subject,
      capability: "network.access",
      resource: "internet",
      approvalIds: [],
    })).toEqual({ allowed: false, reason: "default-deny" });

    expect(decidePermission(envelope, {
      subjectId: subject,
      capability: "workspace.write",
      resource: "production-core",
      path: "src/oef/identity.ts",
      approvalIds: ["approval:owner"],
    })).toEqual({ allowed: false, reason: "protected-resource" });
  });

  test("requires concrete human approval for gated grants", () => {
    expect(decidePermission(envelope, {
      subjectId: subject,
      capability: "deployment.promote",
      resource: "production",
      approvalIds: [],
    })).toEqual({ allowed: false, reason: "human-approval-required" });

    expect(decidePermission(envelope, {
      subjectId: subject,
      capability: "deployment.promote",
      resource: "production",
      approvalIds: ["approval:owner"],
    })).toEqual({ allowed: true, reason: "explicit-grant" });

    expect(decidePermission(envelope, {
      subjectId: subject,
      capability: "deployment.promote",
      resource: "production",
      approvalIds: ["   "],
    })).toEqual({ allowed: false, reason: "human-approval-required" });

    expect(decidePermission(envelope, {
      subjectId: subject,
      capability: "deployment.promote",
      resource: "production",
      approvalIds: ["approval:owner\n"],
    })).toEqual({ allowed: false, reason: "human-approval-required" });
  });

  test("canonicalizes path policy safely and treats ** as zero or more segments", () => {
    const pathEnvelope: PermissionEnvelope = {
      id: permissionEnvelopeId("path-test"),
      subjectId: subject,
      defaultEffect: "deny",
      grants: [{ capability: "workspace.write", resource: "candidate-worktree", pathPatterns: ["src/**"] }],
      denies: [{ capability: "workspace.write", resource: "candidate-worktree", pathPatterns: ["src/**/secret.ts"] }],
    };

    expect(decidePermission(pathEnvelope, {
      subjectId: subject,
      capability: "workspace.write",
      resource: "candidate-worktree",
      path: "src/secret.ts",
      approvalIds: [],
    })).toEqual({ allowed: false, reason: "explicit-deny" });

    expect(decidePermission(pathEnvelope, {
      subjectId: subject,
      capability: "workspace.write",
      resource: "candidate-worktree",
      path: "src/oef/./secret.ts",
      approvalIds: [],
    })).toEqual({ allowed: false, reason: "invalid-path" });

    expect(decidePermission(pathEnvelope, {
      subjectId: subject,
      capability: "workspace.write",
      resource: "candidate-worktree",
      path: "../src/other.ts",
      approvalIds: [],
    })).toEqual({ allowed: false, reason: "invalid-path" });
  });

  test("reserves production-core writes even when a malformed envelope grants them", () => {
    const unsafeEnvelope: PermissionEnvelope = {
      id: permissionEnvelopeId("unsafe"),
      subjectId: subject,
      defaultEffect: "deny",
      grants: [{ capability: "workspace.write", resource: "production-core" }],
      denies: [],
    };
    expect(decidePermission(unsafeEnvelope, {
      subjectId: subject,
      capability: "workspace.write",
      resource: "production-core",
      path: "src/oef/identity.ts",
      approvalIds: ["approval:owner"],
    })).toEqual({ allowed: false, reason: "protected-resource" });
  });

  test("fails closed for malformed runtime permission input", () => {
    expect(decidePermission(envelope, {
      subjectId: subject,
      capability: "workspace.destroy",
      resource: "candidate-worktree",
      approvalIds: [],
    } as never)).toEqual({ allowed: false, reason: "invalid-request" });
  });
});

describe("memory security policy", () => {
  test("rejects declared or detected secrets before persistence", () => {
    expect(decideMemoryWrite({
      ...memoryIdentity,
      actor: { kind: "agent", id: agentId("researcher-01") },
      level: "L1",
      requestedStatus: "OBSERVED",
      classification: "secret",
      content: "provider credential",
      provenance: { sourceType: "runtime-observation", evidenceRefs: ["artifact:run-1"] },
    })).toMatchObject({ allowed: false, reason: "secret-content" });

    expect(decideMemoryWrite({
      ...memoryIdentity,
      actor: { kind: "agent", id: agentId("researcher-01") },
      level: "L1",
      requestedStatus: "OBSERVED",
      classification: "internal",
      content: "Authorization: Bearer this-is-a-live-looking-token-1234567890",
      provenance: { sourceType: "runtime-observation", evidenceRefs: ["artifact:run-2"] },
    })).toMatchObject({ allowed: false, reason: "secret-content" });
  });

  test("keeps an unsupported agent assertion at OBSERVED", () => {
    expect(decideMemoryWrite({
      ...memoryIdentity,
      actor: { kind: "agent", id: agentId("researcher-01") },
      level: "L2",
      requestedStatus: "VERIFIED",
      classification: "internal",
      content: "The provider always retries this error.",
      provenance: { sourceType: "agent-assertion", evidenceRefs: [] },
    })).toEqual({ allowed: false, reason: "agent-assertion-must-remain-observed" });
  });

  test("requires human approval for immutable L5 governance memory", () => {
    expect(decideMemoryWrite({
      ...memoryIdentity,
      actor: { kind: "agent", id: agentId("architect-01") },
      level: "L5",
      requestedStatus: "PROMOTED",
      classification: "internal",
      content: "Agents may promote their own policies.",
      provenance: { sourceType: "agent-assertion", evidenceRefs: [] },
    })).toEqual({ allowed: false, reason: "governance-requires-human-approval" });
  });

  test("does not trust agent-declared evidence without a trusted evidence capability", () => {
    const evidenceRef = `artifact:sha256:${"a".repeat(64)}`;
    const content = "Reproduced provider behavior.";
    const actorId = agentId("researcher-01");
    const request = {
      ...memoryIdentity,
      actor: { kind: "agent" as const, id: actorId },
      level: "L2" as const,
      requestedStatus: "VERIFIED" as const,
      classification: "internal" as const,
      content,
      provenance: { sourceType: "deterministic-test" as const, evidenceRefs: [evidenceRef] },
    };
    const binding = {
      sourceType: "deterministic-test" as const,
      recordId: memoryIdentity.recordId,
      scope: memoryIdentity.scope,
      actorId,
      level: "L2" as const,
      status: "VERIFIED" as const,
      contentSha256: sha256(content),
    };
    const previousRecord = {
      recordId: memoryIdentity.recordId,
      scope: memoryIdentity.scope,
      actorId,
      level: "L2" as const,
      status: "OBSERVED" as const,
      contentSha256: sha256(content),
    };

    expect(decideMemoryWrite(request)).toEqual({ allowed: false, reason: "untrusted-evidence" });
    expect(decideMemoryWrite(request, {
      evidence: new Map([[evidenceRef, binding]]),
      approvalIds: new Set(),
      approvals: new Map(),
      previousRecord,
    })).toEqual({ allowed: true, reason: "policy-satisfied", effectiveStatus: "VERIFIED" });

    expect(decideMemoryWrite({
      ...request,
      content: "Unrelated arbitrary claim.",
    }, {
      evidence: new Map([[evidenceRef, binding]]),
      approvalIds: new Set(),
      approvals: new Map(),
      previousRecord,
    })).toEqual({ allowed: false, reason: "untrusted-evidence" });
  });

  test("rejects malformed or secret-bearing evidence references", () => {
    expect(decideMemoryWrite({
      ...memoryIdentity,
      actor: { kind: "agent", id: agentId("researcher-01") },
      level: "L1",
      requestedStatus: "OBSERVED",
      classification: "internal",
      content: "Observation",
      provenance: { sourceType: "runtime-observation", evidenceRefs: [""] },
    })).toEqual({ allowed: false, reason: "invalid-evidence-reference" });

    expect(decideMemoryWrite({
      ...memoryIdentity,
      actor: { kind: "agent", id: agentId("researcher-01") },
      level: "L1",
      requestedStatus: "OBSERVED",
      classification: "internal",
      content: "Observation",
      provenance: {
        sourceType: "runtime-observation",
        evidenceRefs: ["Authorization: Bearer this-is-a-live-looking-token-1234567890"],
      },
    })).toEqual({ allowed: false, reason: "secret-content" });

    expect(decideMemoryWrite({
      ...memoryIdentity,
      actor: { kind: "agent", id: agentId("researcher-01") },
      level: "L1",
      requestedStatus: "OBSERVED",
      classification: "internal",
      content: "Observation",
      provenance: {
        sourceType: "runtime-observation",
        evidenceRefs: [`artifact:sha256:${"c".repeat(64)}\n`],
      },
    })).toEqual({ allowed: false, reason: "invalid-evidence-reference" });
  });

  test("requires a validated nonblank approval capability for L5", () => {
    const evidenceRef = `artifact:sha256:${"b".repeat(64)}`;
    const request = {
      ...memoryIdentity,
      actor: { kind: "human" as const, id: "human:owner", approvalId: "   " },
      level: "L5" as const,
      requestedStatus: "PROMOTED" as const,
      classification: "internal" as const,
      content: "No live core self-modification.",
      provenance: { sourceType: "human-approved" as const, evidenceRefs: [evidenceRef] },
    };
    const context = {
      evidence: new Map([[evidenceRef, {
        sourceType: "human-approved" as const,
        recordId: memoryIdentity.recordId,
        scope: memoryIdentity.scope,
        actorId: "human:owner",
        level: "L5" as const,
        status: "PROMOTED" as const,
        contentSha256: sha256(request.content),
      }]]),
      approvalIds: new Set<string>(),
      approvals: new Map<string, {
        recordId: string;
        scope: string;
        actorId: string;
        level: "L5";
        status: "PROMOTED";
        contentSha256: string;
      }>(),
    };
    expect(decideMemoryWrite(request, context)).toEqual({ allowed: false, reason: "invalid-request" });

    const approvalId = "approval:owner";
    const approvalBinding = {
      recordId: memoryIdentity.recordId,
      scope: memoryIdentity.scope,
      actorId: "human:owner",
      level: "L5" as const,
      status: "PROMOTED" as const,
      contentSha256: sha256(request.content),
    };
    expect(decideMemoryWrite({
      ...request,
      actor: { kind: "human", id: "human:owner", approvalId },
    }, {
      ...context,
      approvalIds: new Set([approvalId]),
      approvals: new Map([[approvalId, approvalBinding]]),
    })).toEqual({ allowed: true, reason: "policy-satisfied", effectiveStatus: "PROMOTED" });

    expect(decideMemoryWrite({
      ...request,
      actor: { kind: "human", id: "human:owner", approvalId: `${approvalId}\n` },
    }, {
      ...context,
      approvalIds: new Set([`${approvalId}\n`]),
      approvals: new Map([[`${approvalId}\n`, approvalBinding]]),
    })).toEqual({ allowed: false, reason: "invalid-request" });
  });

  test("rejects malformed human approval metadata before persistence at every level", () => {
    expect(decideMemoryWrite({
      ...memoryIdentity,
      actor: {
        kind: "human",
        id: "human:owner",
        approvalId: "Authorization: Bearer this-is-a-live-looking-token-1234567890",
      },
      level: "L1",
      requestedStatus: "OBSERVED",
      classification: "internal",
      content: "Observation",
      provenance: { sourceType: "human-approved", evidenceRefs: [] },
    })).toEqual({ allowed: false, reason: "invalid-request" });
  });

  test("fails closed for malformed runtime memory input", () => {
    expect(decideMemoryWrite({
      ...memoryIdentity,
      actor: { kind: "agent", id: agentId("researcher-01") },
      level: "L1",
      requestedStatus: "OBSERVED",
      classification: "top-secret",
      content: "Observation",
      provenance: { sourceType: "runtime-observation", evidenceRefs: [] },
    } as never)).toEqual({ allowed: false, reason: "invalid-request" });
  });

  test("enforces level/status policy and requires trusted previous-record context", () => {
    const content = "A verified lesson.";
    const evidenceRef = `artifact:sha256:${"d".repeat(64)}`;
    const actorId = agentId("researcher-01");
    const base = {
      ...memoryIdentity,
      actor: { kind: "agent" as const, id: actorId },
      classification: "internal" as const,
      content,
      provenance: { sourceType: "deterministic-test" as const, evidenceRefs: [evidenceRef] },
    };

    expect(decideMemoryWrite({
      ...base,
      level: "L2",
      requestedStatus: "PROMOTED",
    })).toEqual({ allowed: false, reason: "invalid-level-status" });

    expect(decideMemoryWrite({
      ...base,
      level: "L2",
      requestedStatus: "DEPRECATED",
    })).toEqual({ allowed: false, reason: "previous-record-required" });
  });

  test("allows an approved L5 record to enter a terminal correction state", () => {
    const content = "No live core self-modification.";
    const actorId = "human:owner";
    const approvalId = "approval:governance-correction";
    const contentSha256 = sha256(content);
    const binding = {
      recordId: memoryIdentity.recordId,
      scope: memoryIdentity.scope,
      actorId,
      level: "L5" as const,
      status: "SUPERSEDED" as const,
      contentSha256,
    };
    expect(decideMemoryWrite({
      ...memoryIdentity,
      actor: { kind: "human", id: actorId, approvalId },
      level: "L5",
      requestedStatus: "SUPERSEDED",
      classification: "internal",
      content,
      provenance: { sourceType: "human-approved", evidenceRefs: [] },
    }, {
      evidence: new Map(),
      approvals: new Map([[approvalId, binding]]),
      previousRecord: {
        ...binding,
        status: "PROMOTED",
      },
    })).toEqual({ allowed: true, reason: "policy-satisfied", effectiveStatus: "SUPERSEDED" });

    expect(decideMemoryWrite({
      ...memoryIdentity,
      actor: { kind: "human", id: actorId, approvalId },
      level: "L5",
      requestedStatus: "SUPERSEDED",
      classification: "internal",
      content,
      provenance: { sourceType: "human-approved", evidenceRefs: [] },
    }, {
      evidence: new Map(),
      approvals: new Map([[approvalId, binding]]),
      previousRecord: {
        ...binding,
        status: "OBSERVED",
      },
    })).toEqual({ allowed: false, reason: "invalid-status-transition" });
  });
});

describe("self-evolution containment", () => {
  test("never permits an agent to modify the production core directly", () => {
    expect(decideEvolutionChange({
      actor: { kind: "agent", id: agentId("evolution-01") },
      sourceZone: "candidate-worktree",
      targetZone: "production-core",
      artifactKind: "control-kernel",
      gates: {
        benchmarkPassed: true,
        securityPassed: true,
        holdoutPassed: true,
        humanApprovalId: "approval:owner",
        rollbackPoint: "git:abc123",
      },
    })).toEqual({ allowed: false, reason: "agent-cannot-modify-production-core" });
  });

  test("allows a promotion service only after every mandatory gate is present", () => {
    expect(decideEvolutionChange({
      actor: { kind: "promotion-service", id: "service:oef-promoter" },
      sourceZone: "canary",
      targetZone: "production-core",
      artifactKind: "control-kernel",
      gates: {
        benchmarkPassed: true,
        securityPassed: true,
        holdoutPassed: true,
        humanApprovalId: "approval:owner",
        rollbackPoint: "git:abc123",
      },
    })).toEqual({ allowed: true, reason: "gated-promotion" });

    expect(decideEvolutionChange({
      actor: { kind: "promotion-service", id: "service:oef-promoter" },
      sourceZone: "canary",
      targetZone: "production-core",
      artifactKind: "control-kernel",
      gates: {
        benchmarkPassed: true,
        securityPassed: false,
        holdoutPassed: true,
        humanApprovalId: "approval:owner",
        rollbackPoint: "git:abc123",
      },
    })).toEqual({ allowed: false, reason: "promotion-gates-incomplete" });

    expect(decideEvolutionChange({
      actor: { kind: "promotion-service", id: "service:oef-promoter" },
      sourceZone: "canary",
      targetZone: "production-core",
      artifactKind: "control-kernel",
      gates: {
        benchmarkPassed: true,
        securityPassed: true,
        holdoutPassed: true,
        humanApprovalId: "approval:owner\n",
        rollbackPoint: "git:abc123\n",
      },
    })).toEqual({ allowed: false, reason: "invalid-request" });
  });

  test("lets agents write only candidate worktrees, never benchmark or canary", () => {
    const base = {
      actor: { kind: "agent" as const, id: agentId("evolution-01") },
      sourceZone: "candidate-worktree" as const,
      artifactKind: "skill" as const,
      gates: {
        benchmarkPassed: false,
        securityPassed: false,
        holdoutPassed: false,
      },
    };
    expect(decideEvolutionChange({ ...base, targetZone: "candidate-worktree" })).toEqual({
      allowed: true,
      reason: "candidate-contained",
    });
    expect(decideEvolutionChange({ ...base, targetZone: "benchmark" })).toEqual({
      allowed: false,
      reason: "agent-transition-forbidden",
    });
    expect(decideEvolutionChange({ ...base, targetZone: "canary" })).toEqual({
      allowed: false,
      reason: "agent-transition-forbidden",
    });
  });

  test("rejects blank gates and malformed runtime evolution input", () => {
    expect(decideEvolutionChange({
      actor: { kind: "promotion-service", id: "service:oef-promoter" },
      sourceZone: "canary",
      targetZone: "production-core",
      artifactKind: "control-kernel",
      gates: {
        benchmarkPassed: true,
        securityPassed: true,
        holdoutPassed: true,
        humanApprovalId: "   ",
        rollbackPoint: "   ",
      },
    })).toEqual({ allowed: false, reason: "invalid-request" });

    expect(decideEvolutionChange({
      actor: { kind: "promotion-service", id: "service:oef-promoter" },
      sourceZone: "canary",
      targetZone: "production-core",
      artifactKind: "control-kernel",
      gates: {
        benchmarkPassed: true,
        securityPassed: true,
        holdoutPassed: true,
        humanApprovalId: "not an approval reference",
        rollbackPoint: "not a rollback reference",
      },
    })).toEqual({ allowed: false, reason: "invalid-request" });

    expect(decideEvolutionChange({
      actor: { kind: "agent", id: agentId("evolution-01") },
      sourceZone: "candidate-worktree",
      targetZone: "production_core",
      artifactKind: "control-kernel",
      gates: { benchmarkPassed: true, securityPassed: true, holdoutPassed: true },
    } as never)).toEqual({ allowed: false, reason: "invalid-request" });

    expect(decideEvolutionChange({
      actor: { kind: "promotion-service", id: "service:oef-promoter\n" },
      sourceZone: "candidate-worktree",
      targetZone: "benchmark",
      artifactKind: "skill",
      gates: { benchmarkPassed: false, securityPassed: false, holdoutPassed: false },
    })).toEqual({ allowed: false, reason: "invalid-request" });

    expect(decideEvolutionChange({
      actor: { kind: "human", id: "owner" },
      sourceZone: "candidate-worktree",
      targetZone: "candidate-worktree",
      artifactKind: "skill",
      gates: { benchmarkPassed: false, securityPassed: false, holdoutPassed: false },
    })).toEqual({ allowed: false, reason: "invalid-request" });

    expect(decideEvolutionChange({
      actor: { kind: "promotion-service", id: "service:oef-promoter" },
      sourceZone: "candidate-worktree",
      targetZone: "benchmark",
      artifactKind: "skill",
      gates: {
        benchmarkPassed: false,
        securityPassed: false,
        holdoutPassed: false,
        humanApprovalId: "not-canonical",
      },
    })).toEqual({ allowed: false, reason: "invalid-request" });
  });

  test("enforces the promotion-service benchmark and canary transition matrix", () => {
    expect(decideEvolutionChange({
      actor: { kind: "promotion-service", id: "service:oef-promoter" },
      sourceZone: "candidate-worktree",
      targetZone: "benchmark",
      artifactKind: "skill",
      gates: { benchmarkPassed: false, securityPassed: false, holdoutPassed: false },
    })).toEqual({ allowed: true, reason: "evaluation-transition" });

    expect(decideEvolutionChange({
      actor: { kind: "promotion-service", id: "service:oef-promoter" },
      sourceZone: "benchmark",
      targetZone: "canary",
      artifactKind: "skill",
      gates: {
        benchmarkPassed: true,
        securityPassed: true,
        holdoutPassed: true,
        rollbackPoint: "git:abc123",
      },
    })).toEqual({ allowed: true, reason: "canary-admission" });

    expect(decideEvolutionChange({
      actor: { kind: "promotion-service", id: "service:oef-promoter" },
      sourceZone: "candidate-worktree",
      targetZone: "canary",
      artifactKind: "skill",
      gates: {
        benchmarkPassed: true,
        securityPassed: true,
        holdoutPassed: true,
        rollbackPoint: "git:abc123",
      },
    })).toEqual({ allowed: false, reason: "invalid-transition" });
  });
});

describe("phase-zero governance artifacts", () => {
  const root = join(import.meta.dir, "..");
  const requiredFiles = [
    "structure/oef/00-overview.md",
    "structure/oef/01-terminology.md",
    "structure/oef/02-task-contract.md",
    "structure/oef/03-permission-model.md",
    "structure/oef/04-memory-security-policy.md",
    "structure/oef/05-self-evolution-threat-model.md",
    "docs/adr/0006-oef-identity-boundaries.md",
    "docs/adr/0007-oef-versioned-task-contract.md",
    "docs/adr/0008-oef-fail-closed-permissions-and-memory.md",
    "docs/adr/0009-oef-gated-self-evolution.md",
  ];

  test("keeps every phase-zero policy in the maintainer source of truth or ADR ledger", () => {
    for (const relativePath of requiredFiles) {
      expect(existsSync(join(root, relativePath)), relativePath).toBe(true);
    }
  });

  test("states both non-negotiable exit gates in the overview", () => {
    const overview = readFileSync(join(root, "structure/oef/00-overview.md"), "utf8");
    expect(overview).toContain("not interchangeable");
    expect(overview).toContain("cannot directly modify the production core");
  });
});
