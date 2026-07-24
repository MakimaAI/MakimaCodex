import { z } from "zod";
import {
  parseAgentId,
  parsePermissionEnvelopeId,
  type AgentId,
  type PermissionEnvelopeId,
} from "./identity";
import { isApprovalReference } from "./references";

export const PERMISSION_CAPABILITIES = [
  "workspace.read",
  "workspace.write",
  "network.access",
  "process.execute",
  "credential.use",
  "credential.read",
  "memory.read",
  "memory.write",
  "deployment.promote",
  "policy.propose",
] as const;

export const PERMISSION_RESOURCES = [
  "candidate-worktree",
  "production-core",
  "production",
  "internet",
  "local-process",
  "credential-store",
  "memory-store",
  "policy-store",
] as const;

export type PermissionCapability = typeof PERMISSION_CAPABILITIES[number];
export type PermissionResource = typeof PERMISSION_RESOURCES[number];

const agentIdSchema = z.custom<AgentId>(value => {
  try {
    parseAgentId(value);
    return true;
  } catch {
    return false;
  }
});

const permissionEnvelopeIdSchema = z.custom<PermissionEnvelopeId>(value => {
  try {
    parsePermissionEnvelopeId(value);
    return true;
  } catch {
    return false;
  }
});

const permissionRuleSchema = z.object({
  capability: z.enum(PERMISSION_CAPABILITIES),
  resource: z.enum(PERMISSION_RESOURCES),
  pathPatterns: z.array(z.string().min(1).max(1_024)).max(64).optional(),
  requiresHumanApproval: z.boolean().optional(),
}).strict();

export const permissionEnvelopeSchema = z.object({
  id: permissionEnvelopeIdSchema,
  subjectId: agentIdSchema,
  defaultEffect: z.literal("deny"),
  grants: z.array(permissionRuleSchema),
  denies: z.array(permissionRuleSchema),
}).strict();

export const permissionRequestSchema = z.object({
  subjectId: agentIdSchema,
  capability: z.enum(PERMISSION_CAPABILITIES),
  resource: z.enum(PERMISSION_RESOURCES),
  path: z.string().max(1_024).optional(),
  approvalIds: z.array(z.string().max(512)).max(64),
}).strict();

export type PermissionRule = z.infer<typeof permissionRuleSchema>;
export type PermissionEnvelope = z.infer<typeof permissionEnvelopeSchema>;
export type PermissionRequest = z.infer<typeof permissionRequestSchema>;

export type PermissionDecision =
  | { allowed: true; reason: "explicit-grant" }
  | {
      allowed: false;
      reason:
        | "invalid-request"
        | "invalid-path"
        | "subject-mismatch"
        | "protected-resource"
        | "explicit-deny"
        | "default-deny"
        | "human-approval-required";
    };

const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;
function canonicalRepositoryValue(value: string, allowGlobs: boolean): string | null {
  if (
    value.length === 0
    || value.length > 1_024
    || value !== value.trim()
    || CONTROL_CHARACTER_PATTERN.test(value)
  ) return null;
  const normalized = value.replaceAll("\\", "/");
  if (
    normalized.startsWith("/")
    || normalized.startsWith("//")
    || /^[A-Za-z]:/.test(normalized)
    || normalized.includes("//")
  ) return null;
  const segments = normalized.split("/");
  if (segments.length > 128) return null;
  if (segments.some(segment => segment === "" || segment === "." || segment === "..")) return null;
  if (!allowGlobs && segments.some(segment => segment.includes("*"))) return null;
  if (
    allowGlobs
    && segments.some(segment => segment.includes("***") || (segment.includes("**") && segment !== "**"))
  ) return null;
  return segments.join("/");
}

function segmentMatches(value: string, pattern: string): boolean {
  const source = pattern
    .split("*")
    .map(part => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("[^/]*");
  return new RegExp(`^${source}$`).test(value);
}

function globMatches(path: string, pattern: string): boolean {
  const pathSegments = path.split("/");
  const patternSegments = pattern.split("/");
  const memo = new Map<string, boolean>();

  function visit(pathIndex: number, patternIndex: number): boolean {
    const key = `${pathIndex}:${patternIndex}`;
    const cached = memo.get(key);
    if (cached !== undefined) return cached;
    if (patternIndex === patternSegments.length) return pathIndex === pathSegments.length;
    const patternSegment = patternSegments[patternIndex]!;
    if (patternSegment === "**") {
      if (patternIndex === patternSegments.length - 1) {
        memo.set(key, true);
        return true;
      }
      for (let nextPathIndex = pathIndex; nextPathIndex <= pathSegments.length; nextPathIndex += 1) {
        if (visit(nextPathIndex, patternIndex + 1)) {
          memo.set(key, true);
          return true;
        }
      }
      memo.set(key, false);
      return false;
    }
    const matched = pathIndex < pathSegments.length
      && segmentMatches(pathSegments[pathIndex]!, patternSegment)
      && visit(pathIndex + 1, patternIndex + 1);
    memo.set(key, matched);
    return matched;
  }

  return visit(0, 0);
}

function ruleMatches(rule: PermissionRule, request: PermissionRequest): boolean {
  if (rule.capability !== request.capability || rule.resource !== request.resource) return false;
  if (!rule.pathPatterns || rule.pathPatterns.length === 0) return true;
  if (request.path === undefined) return false;
  return rule.pathPatterns.some(pattern => globMatches(request.path!, pattern));
}

export function decidePermission(envelopeInput: unknown, requestInput: unknown): PermissionDecision {
  const envelopeResult = permissionEnvelopeSchema.safeParse(envelopeInput);
  const requestResult = permissionRequestSchema.safeParse(requestInput);
  if (!envelopeResult.success || !requestResult.success) {
    return { allowed: false, reason: "invalid-request" };
  }
  const envelope = envelopeResult.data;
  const parsedRequest = requestResult.data;
  const path = parsedRequest.path === undefined
    ? undefined
    : canonicalRepositoryValue(parsedRequest.path, false);
  if (parsedRequest.path !== undefined && path === null) {
    return { allowed: false, reason: "invalid-path" };
  }
  const normalizedRules = [...envelope.denies, ...envelope.grants].map(rule => ({
    ...rule,
    pathPatterns: rule.pathPatterns?.map(pattern => canonicalRepositoryValue(pattern, true)),
  }));
  if (normalizedRules.some(rule => rule.pathPatterns?.some(pattern => pattern === null))) {
    return { allowed: false, reason: "invalid-request" };
  }
  const denyCount = envelope.denies.length;
  const normalizedEnvelope: PermissionEnvelope = {
    ...envelope,
    denies: normalizedRules.slice(0, denyCount).map(rule => ({
      ...rule,
      pathPatterns: rule.pathPatterns as string[] | undefined,
    })),
    grants: normalizedRules.slice(denyCount).map(rule => ({
      ...rule,
      pathPatterns: rule.pathPatterns as string[] | undefined,
    })),
  };
  const request: PermissionRequest = { ...parsedRequest, path: path ?? undefined };

  if (normalizedEnvelope.subjectId !== request.subjectId) {
    return { allowed: false, reason: "subject-mismatch" };
  }
  if (request.capability === "workspace.write" && request.resource === "production-core") {
    return { allowed: false, reason: "protected-resource" };
  }
  if (normalizedEnvelope.denies.some(rule => ruleMatches(rule, request))) {
    return { allowed: false, reason: "explicit-deny" };
  }
  const grant = normalizedEnvelope.grants.find(rule => ruleMatches(rule, request));
  if (!grant) {
    return { allowed: false, reason: "default-deny" };
  }
  const validApprovalPresent = request.approvalIds.some(isApprovalReference);
  if (grant.requiresHumanApproval && !validApprovalPresent) {
    return { allowed: false, reason: "human-approval-required" };
  }
  return { allowed: true, reason: "explicit-grant" };
}
