import { createHash } from "node:crypto";
import { z } from "zod";
import { parseAgentId, type AgentId } from "./identity";
import {
  isApprovalReference,
  isEvidenceReference,
  isHumanId,
  isMemoryRecordId,
  isMemoryScope,
} from "./references";

export const MEMORY_LEVELS = ["L0", "L1", "L2", "L3", "L4", "L5"] as const;
export const MEMORY_STATUSES = [
  "OBSERVED",
  "REPRODUCED",
  "VERIFIED",
  "GENERALIZED",
  "PROMOTED",
  "SUPERSEDED",
  "DEPRECATED",
] as const;
export const MEMORY_CLASSIFICATIONS = ["public", "internal", "confidential", "secret"] as const;
export const MEMORY_SOURCE_TYPES = [
  "agent-assertion",
  "runtime-observation",
  "reproduced-run",
  "deterministic-test",
  "human-approved",
] as const;

export type MemoryLevel = typeof MEMORY_LEVELS[number];
export type MemoryStatus = typeof MEMORY_STATUSES[number];
export type MemoryClassification = typeof MEMORY_CLASSIFICATIONS[number];
export type MemorySourceType = typeof MEMORY_SOURCE_TYPES[number];

const agentIdSchema = z.custom<AgentId>(value => {
  try {
    parseAgentId(value);
    return true;
  } catch {
    return false;
  }
});

export const memoryWriteRequestSchema = z.object({
  recordId: z.string().refine(isMemoryRecordId),
  scope: z.string().refine(isMemoryScope),
  actor: z.discriminatedUnion("kind", [
    z.object({ kind: z.literal("agent"), id: agentIdSchema }).strict(),
    z.object({
      kind: z.literal("human"),
      id: z.string().refine(isHumanId),
      approvalId: z.string().refine(isApprovalReference),
    }).strict(),
  ]),
  level: z.enum(MEMORY_LEVELS),
  requestedStatus: z.enum(MEMORY_STATUSES),
  classification: z.enum(MEMORY_CLASSIFICATIONS),
  content: z.string(),
  provenance: z.object({
    sourceType: z.enum(MEMORY_SOURCE_TYPES),
    evidenceRefs: z.array(z.string()).max(64),
  }).strict(),
}).strict();

export type MemoryWriteRequest = z.infer<typeof memoryWriteRequestSchema>;

interface MemoryClaimBinding {
  recordId: string;
  scope: string;
  actorId: string;
  level: MemoryLevel;
  status: MemoryStatus;
  contentSha256: string;
}

export interface MemoryEvidenceCapability extends MemoryClaimBinding {
  sourceType: Exclude<MemorySourceType, "agent-assertion">;
}

export interface MemoryApprovalCapability extends MemoryClaimBinding {
  level: "L5";
  status: "PROMOTED" | "SUPERSEDED" | "DEPRECATED";
}

export interface TrustedMemoryRecord extends MemoryClaimBinding {}

export interface MemoryPolicyContext {
  evidence: ReadonlyMap<string, MemoryEvidenceCapability>;
  approvals: ReadonlyMap<string, MemoryApprovalCapability>;
  previousRecord?: TrustedMemoryRecord;
}

export type MemoryWriteDecision =
  | { allowed: true; reason: "policy-satisfied"; effectiveStatus: MemoryStatus }
  | {
      allowed: false;
      reason:
        | "invalid-request"
        | "secret-content"
        | "invalid-evidence-reference"
        | "untrusted-evidence"
        | "invalid-approval"
        | "invalid-level-status"
        | "invalid-status-transition"
        | "previous-record-required"
        | "agent-assertion-must-remain-observed"
        | "governance-requires-human-approval"
        | "evidence-required";
    };

const SECRET_PATTERNS = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i,
  /\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/-]{20,}/i,
  /\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)\s*[:=]\s*["']?[A-Za-z0-9._~+/-]{12,}/i,
];

const EMPTY_CONTEXT: MemoryPolicyContext = {
  evidence: new Map(),
  approvals: new Map(),
};

const ALLOWED_STATUSES: Record<MemoryLevel, ReadonlySet<MemoryStatus>> = {
  L0: new Set(["OBSERVED"]),
  L1: new Set(["OBSERVED", "REPRODUCED", "VERIFIED", "SUPERSEDED", "DEPRECATED"]),
  L2: new Set(["OBSERVED", "REPRODUCED", "VERIFIED", "GENERALIZED", "SUPERSEDED", "DEPRECATED"]),
  L3: new Set(["OBSERVED", "VERIFIED", "GENERALIZED", "PROMOTED", "SUPERSEDED", "DEPRECATED"]),
  L4: new Set(["OBSERVED", "VERIFIED", "GENERALIZED", "SUPERSEDED", "DEPRECATED"]),
  L5: new Set(["PROMOTED", "SUPERSEDED", "DEPRECATED"]),
};

const ALLOWED_TRANSITIONS: Partial<Record<MemoryStatus, ReadonlySet<MemoryStatus>>> = {
  OBSERVED: new Set(["REPRODUCED", "VERIFIED"]),
  REPRODUCED: new Set(["VERIFIED"]),
  VERIFIED: new Set(["GENERALIZED"]),
  GENERALIZED: new Set(["PROMOTED"]),
  PROMOTED: new Set(),
};

const TERMINAL_STATUSES = new Set<MemoryStatus>(["SUPERSEDED", "DEPRECATED"]);

export function containsLikelySecret(content: string): boolean {
  return SECRET_PATTERNS.some(pattern => pattern.test(content));
}

export function memoryContentSha256(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

function requestBinding(request: MemoryWriteRequest): MemoryClaimBinding {
  return {
    recordId: request.recordId,
    scope: request.scope,
    actorId: request.actor.id,
    level: request.level,
    status: request.requestedStatus,
    contentSha256: memoryContentSha256(request.content),
  };
}

function bindingMatches(binding: MemoryClaimBinding | undefined, expected: MemoryClaimBinding): boolean {
  return binding !== undefined
    && binding.recordId === expected.recordId
    && binding.scope === expected.scope
    && binding.actorId === expected.actorId
    && binding.level === expected.level
    && binding.status === expected.status
    && binding.contentSha256 === expected.contentSha256;
}

function previousRecordMatches(
  previous: TrustedMemoryRecord | undefined,
  request: MemoryWriteRequest,
): previous is TrustedMemoryRecord {
  return previous !== undefined
    && previous.recordId === request.recordId
    && previous.scope === request.scope
    && previous.actorId === request.actor.id
    && previous.level === request.level
    && previous.contentSha256 === memoryContentSha256(request.content);
}

export function decideMemoryWrite(
  requestInput: unknown,
  context: MemoryPolicyContext = EMPTY_CONTEXT,
): MemoryWriteDecision {
  const result = memoryWriteRequestSchema.safeParse(requestInput);
  if (!result.success) return { allowed: false, reason: "invalid-request" };
  const request = result.data;
  const persistedStrings = [
    request.recordId,
    request.scope,
    request.content,
    request.actor.id,
    ...(request.actor.kind === "human" ? [request.actor.approvalId] : []),
    ...request.provenance.evidenceRefs,
  ];
  if (
    request.classification === "secret"
    || persistedStrings.some(value => containsLikelySecret(value))
  ) {
    return { allowed: false, reason: "secret-content" };
  }
  if (request.provenance.evidenceRefs.some(reference => !isEvidenceReference(reference))) {
    return { allowed: false, reason: "invalid-evidence-reference" };
  }
  if (!ALLOWED_STATUSES[request.level].has(request.requestedStatus)) {
    return { allowed: false, reason: "invalid-level-status" };
  }
  if (request.level === "L5") {
    if (request.actor.kind !== "human" || request.provenance.sourceType !== "human-approved") {
      return { allowed: false, reason: "governance-requires-human-approval" };
    }
    const approval = context.approvals.get(request.actor.approvalId);
    if (
      !isApprovalReference(request.actor.approvalId)
      || !bindingMatches(approval, requestBinding(request))
    ) {
      return { allowed: false, reason: "invalid-approval" };
    }
  }
  if (
    request.provenance.sourceType === "agent-assertion"
    && request.requestedStatus !== "OBSERVED"
  ) {
    return { allowed: false, reason: "agent-assertion-must-remain-observed" };
  }
  if (TERMINAL_STATUSES.has(request.requestedStatus)) {
    if (!previousRecordMatches(context.previousRecord, request)) {
      return { allowed: false, reason: "previous-record-required" };
    }
    if (request.level === "L5" && context.previousRecord.status !== "PROMOTED") {
      return { allowed: false, reason: "invalid-status-transition" };
    }
    if (TERMINAL_STATUSES.has(context.previousRecord.status)) {
      return { allowed: false, reason: "invalid-status-transition" };
    }
    return { allowed: true, reason: "policy-satisfied", effectiveStatus: request.requestedStatus };
  }
  if (request.requestedStatus === "OBSERVED") {
    return { allowed: true, reason: "policy-satisfied", effectiveStatus: "OBSERVED" };
  }
  if (request.provenance.evidenceRefs.length === 0) {
    return { allowed: false, reason: "evidence-required" };
  }
  const expectedBinding = requestBinding(request);
  const evidenceTrusted = request.provenance.evidenceRefs.every(reference => {
    const capability = context.evidence.get(reference);
    return capability?.sourceType === request.provenance.sourceType
      && bindingMatches(capability, expectedBinding);
  });
  if (!evidenceTrusted) return { allowed: false, reason: "untrusted-evidence" };

  const initialL5Promotion = request.level === "L5" && request.requestedStatus === "PROMOTED";
  if (!initialL5Promotion) {
    if (!previousRecordMatches(context.previousRecord, request)) {
      return { allowed: false, reason: "previous-record-required" };
    }
    if (!ALLOWED_TRANSITIONS[context.previousRecord.status]?.has(request.requestedStatus)) {
      return { allowed: false, reason: "invalid-status-transition" };
    }
  }
  return {
    allowed: true,
    reason: "policy-satisfied",
    effectiveStatus: request.requestedStatus,
  };
}
