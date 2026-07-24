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
  mechanism: z.string().trim().min(1).max(10_000).nullable(),
  evidence_refs: evidenceRefsSchema,
  hypothesis_id: phase7IdentifierSchema.nullable(),
  acceptance: rootCauseAcceptanceSchema.nullable(),
  confirmation_conditions: z.array(z.enum(ROOT_CAUSE_CONFIRMATION_CONDITIONS)).optional(),
  adjudication_id: phase7IdentifierSchema.nullable(),
  supersedes_adjudication_id: phase7IdentifierSchema.nullable(),
}).strict().superRefine((value, context) => {
  if (value.state === "UNCONFIRMED" && (value.statement !== null || value.mechanism !== null || value.evidence_refs.length > 0 || value.hypothesis_id !== null || value.acceptance !== null || value.confirmation_conditions !== undefined || value.adjudication_id !== null || value.supersedes_adjudication_id !== null)) {
    context.addIssue({ code: "custom", message: "Unconfirmed root cause cannot carry an accepted conclusion" });
  }
  if (value.state !== "UNCONFIRMED" && (value.statement === null || value.mechanism === null || value.evidence_refs.length === 0 || value.acceptance === null || value.adjudication_id === null)) {
    context.addIssue({ code: "custom", message: "Accepted root cause requires a statement, mechanism, evidence, acceptance, and adjudication identity" });
  }
  if (value.state === "CONFIRMED" && value.confirmation_conditions?.length !== ROOT_CAUSE_CONFIRMATION_CONDITIONS.length) {
    context.addIssue({ code: "custom", path: ["confirmation_conditions"], message: "Confirmed root cause requires all global evidence conditions" });
  }
  if (value.state === "PROBABLE" && value.acceptance?.kind !== "EXTERNAL_NON_REPRODUCIBLE_ACCEPTANCE") {
    context.addIssue({ code: "custom", path: ["acceptance"], message: "Probable root cause requires explicit external acceptance" });
  }
  if (value.adjudication_id !== null && value.adjudication_id === value.supersedes_adjudication_id) {
    context.addIssue({ code: "custom", path: ["supersedes_adjudication_id"], message: "Root cause cannot supersede itself" });
  }
});

const hypothesisContradictionSchema = z.object({
  contradiction_id: phase7IdentifierSchema,
  statement: z.string().trim().min(3).max(10_000),
  evidence_refs: evidenceRefsSchema,
  status: z.enum(["UNRESOLVED", "RESOLVED"]),
  recorded_by: actorSchema,
  recorded_at: phase7TimestampSchema,
  resolution: z.object({
    rationale: z.string().trim().min(3).max(10_000),
    evidence_refs: evidenceRefsSchema,
    resolved_by: actorSchema,
    resolved_at: phase7TimestampSchema,
  }).strict().nullable(),
}).strict().superRefine((value, context) => {
  if ((value.status === "RESOLVED") !== (value.resolution !== null)) context.addIssue({ code: "custom", path: ["resolution"], message: "Contradiction resolution must match status" });
});

const incidentHypothesisSchema = z.object({
  hypothesis_id: phase7IdentifierSchema,
  statement: z.string().trim().min(3).max(10_000),
  causal_mechanism: z.string().trim().min(3).max(10_000),
  falsifiable_prediction: z.string().trim().min(3).max(10_000),
  disproof_conditions: z.array(z.string().trim().min(3).max(2_000)).min(1).max(32),
  proposed_by: actorSchema,
  proposed_at: phase7TimestampSchema,
  status: z.enum(["ACTIVE", "SUPPORTED", "REJECTED"]),
  evidence_for: evidenceRefsSchema,
  evidence_against: evidenceRefsSchema,
  contradictions: z.array(hypothesisContradictionSchema).max(64),
  resolved_by: actorSchema.nullable(),
  resolved_at: phase7TimestampSchema.nullable(),
}).strict().superRefine((value, context) => {
  const active = value.status === "ACTIVE";
  if (active !== (value.resolved_by === null && value.resolved_at === null)) {
    context.addIssue({ code: "custom", message: "Hypothesis resolution metadata must match status" });
  }
  if (active && (value.evidence_for.length > 0 || value.evidence_against.length > 0)) context.addIssue({ code: "custom", message: "Active hypotheses do not contain resolution evidence" });
  if (new Set(value.contradictions.map(item => item.contradiction_id)).size !== value.contradictions.length) context.addIssue({ code: "custom", path: ["contradictions"], message: "Contradiction IDs cannot contain duplicates" });
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
export type IncidentInput = Omit<z.input<typeof incidentRevisionPayloadSchema>, "schema_version" | "revision" | "previous_revision_hash" | "change" | "observation_ids">;
export type IncidentRevisionPatch = Partial<Pick<Incident,
  "title" | "status" | "stage" | "reproduction" | "containment" | "severity" | "priority" | "confidence" | "owner"
>>;
type InternalIncidentRevisionPatch = IncidentRevisionPatch & Partial<Pick<Incident, "root_cause" | "observation_ids" | "hypotheses">>;

export interface AppendIncidentRevisionOptions {
  expected_revision: number;
  reason: string;
  actor: Actor;
  at: string;
}

export function createIncident(input: IncidentInput, observationInputs: readonly FailureObservation[]): Incident {
  if (input.root_cause.state !== "UNCONFIRMED") throw new Error("ROOT_CAUSE_INITIAL_STATE_FORBIDDEN");
  if (observationInputs.length === 0) throw new Error("INCIDENT_OBSERVATION_REQUIRED");
  const observations = observationInputs.map(parseFailureObservation);
  if (observations.some(observation => !samePhase7Scope(input.scope, observation.scope))) throw new Error("INCIDENT_SCOPE_MISMATCH");
  const payload = incidentRevisionPayloadSchema.parse({
    schema_version: 1,
    ...input,
    revision: 1,
    previous_revision_hash: null,
    observation_ids: observations.map(observation => observation.revision_id),
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
  assertPlainPatch(patch, "INCIDENT_REVISION_PATCH_FORBIDDEN_FIELD");
  const allowed = new Set(["title", "status", "stage", "reproduction", "containment", "severity", "priority", "confidence", "owner"]);
  if (Object.keys(patch).some(key => !allowed.has(key))) throw new Error("INCIDENT_REVISION_PATCH_FORBIDDEN_FIELD");
  return appendIncidentRevisionInternal(currentInput, patch, options, false);
}

function appendIncidentRevisionInternal(currentInput: Incident, patch: InternalIncidentRevisionPatch, options: AppendIncidentRevisionOptions, rootCauseGatePassed: boolean): Incident {
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
  if (parsedCurrent.observation_ids.includes(observation.revision_id)) throw new Error("INCIDENT_OBSERVATION_ALREADY_ATTACHED");
  return appendIncidentRevisionInternal(parsedCurrent, {
    observation_ids: [...parsedCurrent.observation_ids, observation.revision_id],
    ...(parsedCurrent.status === "CLOSED" ? { status: "OPEN" as const, stage: "INVESTIGATING" as const } : {}),
  }, { ...options, reason: parsedCurrent.status === "CLOSED" ? "new observation reopened incident" : "attached failure observation" }, false);
}

export interface IncidentHypothesisInput {
  hypothesis_id: string;
  statement: string;
  causal_mechanism: string;
  falsifiable_prediction: string;
  disproof_conditions: string[];
  proposed_by: Actor;
}

export function addIncidentHypothesis(currentInput: Incident, hypothesis: IncidentHypothesisInput, options: Omit<AppendIncidentRevisionOptions, "reason">): Incident {
  const current = parseIncident(currentInput);
  if (current.hypotheses.filter(item => item.status === "ACTIVE").length >= 5) throw new Error("INCIDENT_ACTIVE_HYPOTHESIS_LIMIT");
  if (current.hypotheses.some(item => item.hypothesis_id === hypothesis.hypothesis_id)) throw new Error("INCIDENT_HYPOTHESIS_ID_CONFLICT");
  const added = incidentHypothesisSchema.parse({ ...hypothesis, proposed_at: options.at, status: "ACTIVE", evidence_for: [], evidence_against: [], contradictions: [], resolved_by: null, resolved_at: null });
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
    evidence_for: resolution === "SUPPORTED" ? options.evidence_refs : item.evidence_for,
    evidence_against: resolution === "REJECTED" ? options.evidence_refs : item.evidence_against,
    resolved_by: options.actor,
    resolved_at: options.at,
  }) : item);
  return appendIncidentRevisionInternal(current, { hypotheses }, { ...options, reason: `${resolution.toLowerCase()} hypothesis` }, false);
}

export interface HypothesisContradictionInput {
  contradiction_id: string;
  statement: string;
  evidence_refs: string[];
}

export function recordIncidentHypothesisContradiction(
  currentInput: Incident,
  hypothesisId: string,
  input: HypothesisContradictionInput,
  options: Omit<AppendIncidentRevisionOptions, "reason">,
): Incident {
  const current = parseIncident(currentInput);
  const hypothesis = current.hypotheses.find(item => item.hypothesis_id === hypothesisId);
  if (!hypothesis) throw new Error("INCIDENT_HYPOTHESIS_NOT_FOUND");
  if (hypothesis.contradictions.some(item => item.contradiction_id === input.contradiction_id)) throw new Error("INCIDENT_CONTRADICTION_ID_CONFLICT");
  assertScopedEvidence(current, input.evidence_refs, "HYPOTHESIS_EVIDENCE_SCOPE_MISMATCH");
  const contradiction = hypothesisContradictionSchema.parse({ ...input, status: "UNRESOLVED", recorded_by: options.actor, recorded_at: options.at, resolution: null });
  const hypotheses = current.hypotheses.map(item => item.hypothesis_id === hypothesisId ? incidentHypothesisSchema.parse({
    ...item,
    evidence_against: [...new Set([...item.evidence_against, ...input.evidence_refs])],
    contradictions: [...item.contradictions, contradiction],
  }) : item);
  return appendIncidentRevisionInternal(current, { hypotheses }, { ...options, reason: "recorded hypothesis contradiction" }, false);
}

export function resolveIncidentHypothesisContradiction(
  currentInput: Incident,
  hypothesisId: string,
  contradictionId: string,
  options: Omit<AppendIncidentRevisionOptions, "reason"> & { rationale: string; evidence_refs: string[] },
): Incident {
  const current = parseIncident(currentInput);
  const hypothesis = current.hypotheses.find(item => item.hypothesis_id === hypothesisId);
  const contradiction = hypothesis?.contradictions.find(item => item.contradiction_id === contradictionId);
  if (!hypothesis || !contradiction || contradiction.status !== "UNRESOLVED") throw new Error("INCIDENT_CONTRADICTION_NOT_UNRESOLVED");
  assertScopedEvidence(current, options.evidence_refs, "HYPOTHESIS_EVIDENCE_SCOPE_MISMATCH");
  const hypotheses = current.hypotheses.map(item => item.hypothesis_id === hypothesisId ? incidentHypothesisSchema.parse({
    ...item,
    contradictions: item.contradictions.map(candidate => candidate.contradiction_id === contradictionId ? hypothesisContradictionSchema.parse({
      ...candidate,
      status: "RESOLVED",
      resolution: { rationale: options.rationale, evidence_refs: options.evidence_refs, resolved_by: options.actor, resolved_at: options.at },
    }) : candidate),
  }) : item);
  return appendIncidentRevisionInternal(current, { hypotheses }, { ...options, reason: "resolved hypothesis contradiction" }, false);
}

type RootCauseCondition = typeof ROOT_CAUSE_CONFIRMATION_CONDITIONS[number];

export interface ConfirmRootCauseInput {
  hypothesis_id: string;
  statement: string;
  mechanism: string;
  conditions: Array<{ condition: RootCauseCondition; evidence_refs: string[] }>;
  authority: { kind: "INDEPENDENT_REVIEW"; actor: Actor };
}

export function confirmIncidentRootCause(currentInput: Incident, input: ConfirmRootCauseInput, options: { expected_revision: number; at: string }): Incident {
  const current = parseIncident(currentInput);
  if (current.root_cause.state !== "UNCONFIRMED") throw new Error("ROOT_CAUSE_SUPERSESSION_REQUIRED");
  return adjudicateConfirmedRootCause(current, input, options, null);
}

export function supersedeIncidentRootCause(currentInput: Incident, input: ConfirmRootCauseInput, options: { expected_revision: number; at: string }): Incident {
  const current = parseIncident(currentInput);
  if (current.root_cause.state === "UNCONFIRMED" || current.root_cause.adjudication_id === null) throw new Error("ROOT_CAUSE_NOT_ADJUDICATED");
  return adjudicateConfirmedRootCause(current, input, options, current.root_cause.adjudication_id);
}

function adjudicateConfirmedRootCause(current: Incident, input: ConfirmRootCauseInput, options: { expected_revision: number; at: string }, supersedesAdjudicationId: string | null): Incident {
  if (current.reproduction.state !== "REPRODUCIBLE") throw new Error("ROOT_CAUSE_CONFIRMATION_REPRODUCTION_REQUIRED");
  const hypothesis = current.hypotheses.find(item => item.hypothesis_id === input.hypothesis_id);
  if (!hypothesis) throw new Error("ROOT_CAUSE_HYPOTHESIS_NOT_FOUND");
  if (hypothesis.status !== "SUPPORTED") throw new Error("ROOT_CAUSE_HYPOTHESIS_NOT_SUPPORTED");
  if (input.statement !== hypothesis.statement || input.mechanism !== hypothesis.causal_mechanism) throw new Error("ROOT_CAUSE_HYPOTHESIS_BINDING_MISMATCH");
  if (hypothesis.contradictions.some(item => item.status === "UNRESOLVED")) throw new Error("ROOT_CAUSE_UNRESOLVED_CONTRADICTION");
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
    mechanism: input.mechanism,
    evidence_refs: evidenceRefs,
    hypothesis_id: input.hypothesis_id,
    acceptance: { kind: input.authority.kind, accepted_by: input.authority.actor, rationale: "all global confirmation conditions satisfied", accepted_at: options.at },
    confirmation_conditions: [...ROOT_CAUSE_CONFIRMATION_CONDITIONS],
    adjudication_id: `root-cause-adjudication:${current.incident_id}:${current.revision + 1}`,
    supersedes_adjudication_id: supersedesAdjudicationId,
  });
  return appendIncidentRevisionInternal(current, { root_cause: rootCause }, { ...options, reason: "confirmed root cause", actor: input.authority.actor }, true);
}

export interface ProbableRootCauseInput {
  statement: string;
  mechanism: string;
  external_dependency: true;
  evidence_refs: string[];
  acceptance: { accepted_by: Actor; rationale: string };
}

export function markIncidentRootCauseProbable(currentInput: Incident, input: ProbableRootCauseInput, options: { expected_revision: number; at: string }): Incident {
  const current = parseIncident(currentInput);
  if (current.root_cause.state !== "UNCONFIRMED") throw new Error("ROOT_CAUSE_SUPERSESSION_REQUIRED");
  if (current.reproduction.state !== "NON_REPRODUCIBLE" || input.external_dependency !== true || input.acceptance.accepted_by.type !== "human") {
    throw new Error("ROOT_CAUSE_PROBABLE_EXTERNAL_ACCEPTANCE_REQUIRED");
  }
  const evidencePrefix = `artifact:${current.scope.id}:`;
  if (input.evidence_refs.some(reference => !reference.startsWith(evidencePrefix))) throw new Error("ROOT_CAUSE_EVIDENCE_SCOPE_MISMATCH");
  const rootCause = rootCauseSchema.parse({
    state: "PROBABLE",
    statement: input.statement,
    mechanism: input.mechanism,
    evidence_refs: input.evidence_refs,
    hypothesis_id: null,
    acceptance: { kind: "EXTERNAL_NON_REPRODUCIBLE_ACCEPTANCE", accepted_by: input.acceptance.accepted_by, rationale: input.acceptance.rationale, accepted_at: options.at },
    adjudication_id: `root-cause-adjudication:${current.incident_id}:${current.revision + 1}`,
    supersedes_adjudication_id: null,
  });
  return appendIncidentRevisionInternal(current, { root_cause: rootCause }, { ...options, reason: "accepted probable external root cause", actor: input.acceptance.accepted_by }, true);
}

function assertScopedEvidence(current: Incident, evidenceRefs: string[], code: string): void {
  const prefix = `artifact:${current.scope.id}:`;
  if (evidenceRefs.some(reference => !reference.startsWith(prefix))) throw new Error(code);
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

function assertPlainPatch(value: unknown, code: string): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype || Object.getOwnPropertySymbols(value).length > 0) throw new Error(code);
  if (Object.keys(value).some(key => !Object.getOwnPropertyDescriptor(value, key) || !("value" in Object.getOwnPropertyDescriptor(value, key)!))) throw new Error(code);
}
