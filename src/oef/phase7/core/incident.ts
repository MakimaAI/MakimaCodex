import { z } from "zod";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { actorSchema, type Actor } from "../../phase1/core/shared/actor";
import { assertNoPhase1Secret, assertNoStructuredPhase1Secret } from "../../phase1/core/security/secrets";
import { parseFailureObservation, type FailureObservation } from "./failure-observation";
import {
  deepFreezePhase7,
  phase7HashSchema,
  phase7IdentifierSchema,
  phase7ScopeSchema,
  phase7TimestampSchema,
  samePhase7Scope,
} from "./shared";

export const INCIDENT_STATUSES = ["OPEN", "MONITORING", "CLOSED"] as const;
export const INCIDENT_STAGES = ["TRIAGE", "INVESTIGATING", "MITIGATING", "RESOLVED"] as const;
export const INCIDENT_REPRODUCTION_STATES = ["NOT_ATTEMPTED", "REPRODUCIBLE", "INTERMITTENT", "NON_REPRODUCIBLE"] as const;
export const INCIDENT_ROOT_CAUSE_STATES = ["UNCONFIRMED", "PROBABLE", "CONFIRMED"] as const;
export const INCIDENT_CONTAINMENT_STATES = ["NOT_STARTED", "IN_PROGRESS", "CONTAINED", "RELEASED"] as const;
export const INCIDENT_SEVERITIES = ["SEV0", "SEV1", "SEV2", "SEV3", "SEV4"] as const;
export const INCIDENT_PRIORITIES = ["URGENT", "HIGH", "NORMAL", "LOW"] as const;
export const ROOT_CAUSE_CONFIRMATION_CONDITIONS = [
  "FAILURE_REPRODUCED",
  "CAUSAL_MECHANISM_OBSERVED",
  "CONTROLLED_CHANGE_REMOVES_FAILURE",
  "CAUSE_REINTRODUCTION_RESTORES_FAILURE",
  "ALTERNATIVES_DISPROVED",
  "EVIDENCE_MATCHES_INCIDENT_SCOPE",
] as const;

const evidenceRefsSchema = z.array(phase7IdentifierSchema).max(256)
  .refine(values => new Set(values).size === values.length, "Evidence references cannot contain duplicates");

const rootCauseAcceptanceSchema = z.object({
  kind: z.enum(["INDEPENDENT_REVIEW", "EXTERNAL_NON_REPRODUCIBLE_ACCEPTANCE"]),
  accepted_by: actorSchema,
  rationale: z.string().trim().min(1).max(2_000),
  accepted_at: phase7TimestampSchema,
}).strict();

const rootCauseSchema = z.object({
  state: z.enum(INCIDENT_ROOT_CAUSE_STATES),
  statement: z.string().trim().min(1).max(10_000).nullable(),
  evidence_refs: evidenceRefsSchema,
  hypothesis_id: phase7IdentifierSchema.nullable(),
  acceptance: rootCauseAcceptanceSchema.nullable(),
  confirmation_conditions: z.array(z.enum(ROOT_CAUSE_CONFIRMATION_CONDITIONS)).optional(),
}).strict().superRefine((value, context) => {
  if (value.state === "UNCONFIRMED" && (value.statement !== null || value.evidence_refs.length > 0 || value.hypothesis_id !== null || value.acceptance !== null || value.confirmation_conditions !== undefined)) {
    context.addIssue({ code: "custom", message: "Unconfirmed root cause cannot carry an accepted conclusion" });
  }
  if (value.state !== "UNCONFIRMED" && (value.statement === null || value.evidence_refs.length === 0 || value.acceptance === null)) {
    context.addIssue({ code: "custom", message: "Accepted root cause requires a statement, evidence, and acceptance" });
  }
  if (value.state === "CONFIRMED" && value.confirmation_conditions?.length !== ROOT_CAUSE_CONFIRMATION_CONDITIONS.length) {
    context.addIssue({ code: "custom", path: ["confirmation_conditions"], message: "Confirmed root cause requires all global evidence conditions" });
  }
  if (value.state === "PROBABLE" && value.acceptance?.kind !== "EXTERNAL_NON_REPRODUCIBLE_ACCEPTANCE") {
    context.addIssue({ code: "custom", path: ["acceptance"], message: "Probable root cause requires explicit external acceptance" });
  }
});

const incidentHypothesisSchema = z.object({
  hypothesis_id: phase7IdentifierSchema,
  statement: z.string().trim().min(3).max(10_000),
  falsifiable_prediction: z.string().trim().min(3).max(10_000),
  disproof_conditions: z.array(z.string().trim().min(3).max(2_000)).min(1).max(32),
  proposed_by: actorSchema,
  proposed_at: phase7TimestampSchema,
  status: z.enum(["ACTIVE", "SUPPORTED", "REJECTED"]),
  evidence_refs: evidenceRefsSchema,
  resolved_by: actorSchema.nullable(),
  resolved_at: phase7TimestampSchema.nullable(),
}).strict().superRefine((value, context) => {
  const active = value.status === "ACTIVE";
  if (active !== (value.resolved_by === null && value.resolved_at === null)) {
    context.addIssue({ code: "custom", message: "Hypothesis resolution metadata must match status" });
  }
  if (active && value.evidence_refs.length > 0) context.addIssue({ code: "custom", path: ["evidence_refs"], message: "Active hypotheses do not contain resolution evidence" });
});

const incidentRevisionPayloadSchema = z.object({
  schema_version: z.literal(1),
  incident_id: phase7IdentifierSchema,
  revision: z.number().int().positive(),
  previous_revision_hash: phase7HashSchema.nullable(),
  title: z.string().trim().min(3).max(1_000),
  status: z.enum(INCIDENT_STATUSES),
  stage: z.enum(INCIDENT_STAGES),
  reproduction: z.object({ state: z.enum(INCIDENT_REPRODUCTION_STATES), evidence_refs: evidenceRefsSchema }).strict(),
  root_cause: rootCauseSchema,
  containment: z.object({ state: z.enum(INCIDENT_CONTAINMENT_STATES), summary: z.string().trim().min(1).max(5_000).nullable(), evidence_refs: evidenceRefsSchema }).strict(),
  severity: z.enum(INCIDENT_SEVERITIES),
  priority: z.enum(INCIDENT_PRIORITIES),
  confidence: z.number().finite().min(0).max(1),
  owner: actorSchema.nullable(),
  scope: phase7ScopeSchema,
  observation_ids: z.array(phase7IdentifierSchema).min(1).max(10_000)
    .refine(values => new Set(values).size === values.length, "Observation IDs cannot contain duplicates"),
  hypotheses: z.array(incidentHypothesisSchema).max(256),
  created_at: phase7TimestampSchema,
  created_by: actorSchema,
  change: z.object({ reason: z.string().trim().min(1).max(2_000), actor: actorSchema, at: phase7TimestampSchema }).strict(),
}).strict().superRefine((value, context) => {
  if ((value.revision === 1) !== (value.previous_revision_hash === null)) {
    context.addIssue({ code: "custom", path: ["previous_revision_hash"], message: "Incident revision hash link is invalid" });
  }
  if (value.hypotheses.filter(item => item.status === "ACTIVE").length > 5) {
    context.addIssue({ code: "custom", path: ["hypotheses"], message: "INCIDENT_ACTIVE_HYPOTHESIS_LIMIT" });
  }
  if (new Set(value.hypotheses.map(item => item.hypothesis_id)).size !== value.hypotheses.length) {
    context.addIssue({ code: "custom", path: ["hypotheses"], message: "Hypothesis IDs cannot contain duplicates" });
  }
  if (value.status === "CLOSED" && value.stage !== "RESOLVED") {
    context.addIssue({ code: "custom", path: ["stage"], message: "Closed incidents must be resolved" });
  }
});

export const incidentSchema = incidentRevisionPayloadSchema.extend({ revision_hash: phase7HashSchema }).strict();
export type Incident = z.infer<typeof incidentSchema>;
export type IncidentInput = Omit<z.input<typeof incidentRevisionPayloadSchema>, "schema_version" | "revision" | "previous_revision_hash" | "change">;
export type IncidentRevisionPatch = Partial<Pick<Incident,
  "title" | "status" | "stage" | "reproduction" | "root_cause" | "containment" | "severity" | "priority" | "confidence" | "owner" | "observation_ids" | "hypotheses"
>>;

export interface AppendIncidentRevisionOptions {
  expected_revision: number;
  reason: string;
  actor: Actor;
  at: string;
}

export function createIncident(input: IncidentInput): Incident {
  if (input.root_cause.state !== "UNCONFIRMED") throw new Error("ROOT_CAUSE_INITIAL_STATE_FORBIDDEN");
  const payload = incidentRevisionPayloadSchema.parse({
    schema_version: 1,
    ...input,
    revision: 1,
    previous_revision_hash: null,
    change: { reason: "initial incident", actor: input.created_by, at: input.created_at },
  });
  assertIncidentSecretSafe(payload);
  return immutableIncident({ ...payload, revision_hash: canonicalSha256(payload) });
}

export function parseIncident(input: unknown): Incident {
  const value = incidentSchema.parse(input);
  const { revision_hash, ...payload } = value;
  if (canonicalSha256(payload) !== revision_hash) throw new Error("INCIDENT_REVISION_HASH_MISMATCH");
  assertIncidentSecretSafe(value);
  return deepFreezePhase7(value);
}

export function appendIncidentRevision(currentInput: Incident, patch: IncidentRevisionPatch, options: AppendIncidentRevisionOptions): Incident {
  return appendIncidentRevisionInternal(currentInput, patch, options, false);
}

function appendIncidentRevisionInternal(currentInput: Incident, patch: IncidentRevisionPatch, options: AppendIncidentRevisionOptions, rootCauseGatePassed: boolean): Incident {
  const current = parseIncident(currentInput);
  if (current.revision !== options.expected_revision) throw new Error("INCIDENT_REVISION_CONFLICT");
  if (Date.parse(options.at) < Date.parse(current.change.at)) throw new Error("INCIDENT_TIME_CAUSALITY_INVALID");
  if (patch.root_cause?.state === "CONFIRMED" && current.root_cause.state !== "CONFIRMED" && !rootCauseGatePassed) throw new Error("ROOT_CAUSE_CONFIRMATION_GATE_REQUIRED");
  if (patch.root_cause?.state === "PROBABLE" && current.root_cause.state !== "PROBABLE" && !rootCauseGatePassed) throw new Error("ROOT_CAUSE_PROBABLE_GATE_REQUIRED");
  const payload = incidentRevisionPayloadSchema.parse({
    schema_version: 1,
    incident_id: current.incident_id,
    revision: current.revision + 1,
    previous_revision_hash: current.revision_hash,
    title: patch.title ?? current.title,
    status: patch.status ?? current.status,
    stage: patch.stage ?? current.stage,
    reproduction: patch.reproduction ?? current.reproduction,
    root_cause: patch.root_cause ?? current.root_cause,
    containment: patch.containment ?? current.containment,
    severity: patch.severity ?? current.severity,
    priority: patch.priority ?? current.priority,
    confidence: patch.confidence ?? current.confidence,
    owner: patch.owner === undefined ? current.owner : patch.owner,
    scope: current.scope,
    observation_ids: patch.observation_ids ?? current.observation_ids,
    hypotheses: patch.hypotheses ?? current.hypotheses,
    created_at: current.created_at,
    created_by: current.created_by,
    change: { reason: options.reason, actor: options.actor, at: options.at },
  });
  assertIncidentSecretSafe(payload);
  return immutableIncident({ ...payload, revision_hash: canonicalSha256(payload) });
}

export function attachFailureObservation(current: Incident, observationInput: FailureObservation, options: Omit<AppendIncidentRevisionOptions, "reason">): Incident {
  const observation = parseFailureObservation(observationInput);
  const parsedCurrent = parseIncident(current);
  if (!samePhase7Scope(parsedCurrent.scope, observation.scope)) throw new Error("INCIDENT_SCOPE_MISMATCH");
  if (parsedCurrent.observation_ids.includes(observation.observation_id)) throw new Error("INCIDENT_OBSERVATION_ALREADY_ATTACHED");
  return appendIncidentRevisionInternal(parsedCurrent, {
    observation_ids: [...parsedCurrent.observation_ids, observation.observation_id],
    ...(parsedCurrent.status === "CLOSED" ? { status: "OPEN" as const, stage: "INVESTIGATING" as const } : {}),
  }, { ...options, reason: parsedCurrent.status === "CLOSED" ? "new observation reopened incident" : "attached failure observation" }, false);
}

export interface IncidentHypothesisInput {
  hypothesis_id: string;
  statement: string;
  falsifiable_prediction: string;
  disproof_conditions: string[];
  proposed_by: Actor;
}

export function addIncidentHypothesis(currentInput: Incident, hypothesis: IncidentHypothesisInput, options: Omit<AppendIncidentRevisionOptions, "reason">): Incident {
  const current = parseIncident(currentInput);
  if (current.hypotheses.filter(item => item.status === "ACTIVE").length >= 5) throw new Error("INCIDENT_ACTIVE_HYPOTHESIS_LIMIT");
  if (current.hypotheses.some(item => item.hypothesis_id === hypothesis.hypothesis_id)) throw new Error("INCIDENT_HYPOTHESIS_ID_CONFLICT");
  const added = incidentHypothesisSchema.parse({ ...hypothesis, proposed_at: options.at, status: "ACTIVE", evidence_refs: [], resolved_by: null, resolved_at: null });
  return appendIncidentRevisionInternal(current, { hypotheses: [...current.hypotheses, added] }, { ...options, reason: "added falsifiable hypothesis" }, false);
}

export function resolveIncidentHypothesis(
  currentInput: Incident,
  hypothesisId: string,
  resolution: "SUPPORTED" | "REJECTED",
  options: Omit<AppendIncidentRevisionOptions, "reason"> & { evidence_refs: string[] },
): Incident {
  const current = parseIncident(currentInput);
  const hypothesis = current.hypotheses.find(item => item.hypothesis_id === hypothesisId);
  if (!hypothesis || hypothesis.status !== "ACTIVE") throw new Error("INCIDENT_HYPOTHESIS_NOT_ACTIVE");
  if (resolution === "SUPPORTED" && hypothesis.proposed_by.type === options.actor.type && hypothesis.proposed_by.id === options.actor.id) {
    throw new Error("HYPOTHESIS_SELF_CONFIRMATION_FORBIDDEN");
  }
  if (options.evidence_refs.length === 0) throw new Error("HYPOTHESIS_RESOLUTION_EVIDENCE_REQUIRED");
  const hypotheses = current.hypotheses.map(item => item.hypothesis_id === hypothesisId ? incidentHypothesisSchema.parse({
    ...item,
    status: resolution,
    evidence_refs: options.evidence_refs,
    resolved_by: options.actor,
    resolved_at: options.at,
  }) : item);
  return appendIncidentRevisionInternal(current, { hypotheses }, { ...options, reason: `${resolution.toLowerCase()} hypothesis` }, false);
}

type RootCauseCondition = typeof ROOT_CAUSE_CONFIRMATION_CONDITIONS[number];

export interface ConfirmRootCauseInput {
  hypothesis_id: string;
  statement: string;
  conditions: Array<{ condition: RootCauseCondition; evidence_refs: string[] }>;
  authority: { kind: "INDEPENDENT_REVIEW"; actor: Actor };
}

export function confirmIncidentRootCause(currentInput: Incident, input: ConfirmRootCauseInput, options: { expected_revision: number; at: string }): Incident {
  const current = parseIncident(currentInput);
  if (current.reproduction.state !== "REPRODUCIBLE") throw new Error("ROOT_CAUSE_CONFIRMATION_REPRODUCTION_REQUIRED");
  const hypothesis = current.hypotheses.find(item => item.hypothesis_id === input.hypothesis_id);
  if (!hypothesis) throw new Error("ROOT_CAUSE_HYPOTHESIS_NOT_FOUND");
  if (hypothesis.proposed_by.type === input.authority.actor.type && hypothesis.proposed_by.id === input.authority.actor.id) throw new Error("ROOT_CAUSE_SELF_CONFIRMATION_FORBIDDEN");
  if (input.authority.actor.type !== "integration") throw new Error("ROOT_CAUSE_CONFIRMATION_AUTHORITY_REQUIRED");
  const conditionSet = new Set(input.conditions.map(item => item.condition));
  const complete = conditionSet.size === ROOT_CAUSE_CONFIRMATION_CONDITIONS.length
    && ROOT_CAUSE_CONFIRMATION_CONDITIONS.every(condition => conditionSet.has(condition))
    && input.conditions.every(condition => condition.evidence_refs.length > 0 && new Set(condition.evidence_refs).size === condition.evidence_refs.length);
  if (!complete) throw new Error("ROOT_CAUSE_CONFIRMATION_EVIDENCE_INCOMPLETE");
  const evidencePrefix = `artifact:${current.scope.id}:`;
  if (input.conditions.some(condition => condition.evidence_refs.some(reference => !reference.startsWith(evidencePrefix)))) {
    throw new Error("ROOT_CAUSE_EVIDENCE_SCOPE_MISMATCH");
  }
  const evidenceRefs = [...new Set(input.conditions.flatMap(item => item.evidence_refs))];
  const rootCause = rootCauseSchema.parse({
    state: "CONFIRMED",
    statement: input.statement,
    evidence_refs: evidenceRefs,
    hypothesis_id: input.hypothesis_id,
    acceptance: { kind: input.authority.kind, accepted_by: input.authority.actor, rationale: "all global confirmation conditions satisfied", accepted_at: options.at },
    confirmation_conditions: [...ROOT_CAUSE_CONFIRMATION_CONDITIONS],
  });
  return appendIncidentRevisionInternal(current, { root_cause: rootCause }, { ...options, reason: "confirmed root cause", actor: input.authority.actor }, true);
}

export interface ProbableRootCauseInput {
  statement: string;
  external_dependency: true;
  evidence_refs: string[];
  acceptance: { accepted_by: Actor; rationale: string };
}

export function markIncidentRootCauseProbable(currentInput: Incident, input: ProbableRootCauseInput, options: { expected_revision: number; at: string }): Incident {
  const current = parseIncident(currentInput);
  if (current.reproduction.state !== "NON_REPRODUCIBLE" || input.external_dependency !== true || input.acceptance.accepted_by.type !== "human") {
    throw new Error("ROOT_CAUSE_PROBABLE_EXTERNAL_ACCEPTANCE_REQUIRED");
  }
  const evidencePrefix = `artifact:${current.scope.id}:`;
  if (input.evidence_refs.some(reference => !reference.startsWith(evidencePrefix))) throw new Error("ROOT_CAUSE_EVIDENCE_SCOPE_MISMATCH");
  const rootCause = rootCauseSchema.parse({
    state: "PROBABLE",
    statement: input.statement,
    evidence_refs: input.evidence_refs,
    hypothesis_id: null,
    acceptance: { kind: "EXTERNAL_NON_REPRODUCIBLE_ACCEPTANCE", accepted_by: input.acceptance.accepted_by, rationale: input.acceptance.rationale, accepted_at: options.at },
  });
  return appendIncidentRevisionInternal(current, { root_cause: rootCause }, { ...options, reason: "accepted probable external root cause", actor: input.acceptance.accepted_by }, true);
}

function immutableIncident(input: unknown): Incident {
  return deepFreezePhase7(incidentSchema.parse(input));
}

function assertIncidentSecretSafe(value: unknown): void {
  try {
    assertNoStructuredPhase1Secret(value);
    assertNoPhase1Secret(JSON.stringify(value), "incident");
  } catch {
    throw new Error("INCIDENT_SECRET_REJECTED");
  }
}
