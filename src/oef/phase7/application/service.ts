import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import type { Actor } from "../../phase1/core/shared/actor";
import { createMemoryRecord, type MemoryRecord } from "../../phase6/core/domain";
import type { SqliteOperationsStore } from "../../operations/persistence/sqlite-store";
import {
  ROOT_CAUSE_CONFIRMATION_CONDITIONS,
  addIncidentHypothesis,
  appendIncidentRevision,
  attachFailureObservation,
  confirmIncidentRootCause,
  createIncident,
  resolveIncidentHypothesis,
  type ConfirmRootCauseInput,
  type Incident,
  type IncidentHypothesisInput,
} from "../core/incident";
import { createPlaybookCandidate } from "../core/playbook-candidate";
import type { Phase7Scope } from "../core/shared";
import type { CollectedPhase2Failure } from "../ingestion/phase2-failure-collector";
import {
  type IncidentRelation,
  type IngestionPersistenceResult,
  SqliteIncidentRegistry,
} from "../persistence/sqlite-store";
import { createDeterministicPhase2ReplayAdapter, createReproductionManifest, runPinnedReproduction, type ReproductionResult } from "../reproduction/manifest";
import { regressionResultRecord, remediationProposalRecord, reviewVerdictRecord, type RegressionResultInput, type RemediationProposalInput, type ReviewVerdictInput } from "../remediation/records";

export interface Phase6IncidentMemoryWriter { write(records: readonly MemoryRecord[]): void | Promise<void> }
export interface IncidentIntelligenceServiceOptions {
  registry: SqliteIncidentRegistry;
  operations?: SqliteOperationsStore;
  memoryWriter?: Phase6IncidentMemoryWriter;
}
export type TriageSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type TriagePriority = "P0" | "P1" | "P2" | "P3";

export class IncidentIntelligenceService {
  private readonly registry: SqliteIncidentRegistry;
  private readonly operations: SqliteOperationsStore | undefined;
  private readonly memoryWriter: Phase6IncidentMemoryWriter | undefined;
  constructor(options: IncidentIntelligenceServiceOptions) {
    if (options.memoryWriter && !options.operations) throw new Error("PHASE7_MEMORY_RECOVERY_OPERATIONS_REQUIRED");
    this.registry = options.registry;
    this.operations = options.operations;
    this.memoryWriter = options.memoryWriter;
  }

  ingest(input: CollectedPhase2Failure): IngestionPersistenceResult {
    const risk = classifyRisk(input);
    const candidate = this.registry.findCorrelation({ scope: input.observation.scope, signatures: input.signatures, provider: input.provider, runtime: input.runtime, runtime_major: input.runtime_major });
    let incident: Incident;
    let relation: IncidentRelation | null = null;
    let correlation: IngestionPersistenceResult["correlation"] = "NEW";
    if (candidate && (risk.severity === "HIGH" || risk.severity === "CRITICAL")) {
      incident = initialIncident(input, risk);
      correlation = "POSSIBLE_DUPLICATE";
      relation = {
        relation_id: `incident-relation:${canonicalSha256({ from: incident.incident_id, to: candidate.incident.incident_id, type: correlation }).slice(7, 39)}`,
        incident_id: incident.incident_id,
        related_incident_id: candidate.incident.incident_id,
        relation_type: "POSSIBLE_DUPLICATE",
        reason: "high-risk observations require review before merge",
        created_at: input.observation.observed_at,
      };
    } else if (candidate) {
      incident = attachFailureObservation(candidate.incident, input.observation, {
        expected_revision: candidate.incident.revision,
        actor: { type: "system", id: "system:phase7-correlation" },
        at: input.observation.observed_at,
      });
      correlation = "AUTO_CORRELATED";
    } else {
      incident = initialIncident(input, risk);
    }
    return this.registry.persistIngestion({
      source_event_id: input.source_event_id,
      source_hash: input.source_hash,
      observation: input.observation,
      signatures: input.signatures,
      provider: input.provider,
      runtime: input.runtime,
      runtime_major: input.runtime_major,
      incident,
      relation,
      correlation,
    });
  }

  triage(incidentId: string, input: { severity: TriageSeverity; priority: TriagePriority; confidence: number; actor: Actor; at: string }): Record<string, unknown> {
    const incident = this.requiredIncident(incidentId);
    const observation = this.requiredObservationFor(incident);
    const floor = classifyRiskFromCode(observation.failure.code, observation.failure.summary);
    const severity = severityRank(input.severity) < severityRank(floor.severity) ? floor.severity : input.severity;
    const requiredApproval = floor.a5 ? "A5" : severity === "CRITICAL" ? "A4" : "A3";
    const record = {
      record_id: `triage:${canonicalSha256({ incident_id: incidentId, revision: incident.revision, at: input.at }).slice(7, 39)}`,
      incident_id: incidentId,
      severity,
      priority: input.priority,
      confidence: input.confidence,
      required_approval: requiredApproval,
      actor: input.actor,
      at: input.at,
    };
    if (!Number.isFinite(input.confidence) || input.confidence < 0 || input.confidence > 1) throw new Error("INCIDENT_TRIAGE_CONFIDENCE_INVALID");
    this.registry.saveRecord("TRIAGE", { record_id: record.record_id, incident_id: incidentId, scope_id: incident.scope.id, occurred_at: input.at, payload: record });
    return record;
  }

  proposeContainment(incidentId: string, input: { action_id: string; summary: string; autonomy: "A0" | "A1" | "A2" | "A3" | "A4" | "A5"; reversible: boolean; actor: Actor; at: string }): Record<string, unknown> {
    const incident = this.requiredIncident(incidentId);
    if (!["A0", "A1", "A2", "A3", "A4", "A5"].includes(input.autonomy)) throw new Error("INCIDENT_CONTAINMENT_AUTONOMY_INVALID");
    const automatic = input.reversible && ["A0", "A1", "A2"].includes(input.autonomy);
    const record = {
      record_id: input.action_id,
      incident_id: incidentId,
      summary: input.summary,
      autonomy: input.autonomy,
      reversible: input.reversible,
      state: automatic ? "EXECUTED" : "PROPOSED",
      execution_kind: automatic ? "LOCAL_RECORD_ONLY" : "NONE",
      production_action_performed: false,
      actor: input.actor,
      at: input.at,
    };
    this.registry.saveRecord("CONTAINMENT", { record_id: input.action_id, incident_id: incidentId, scope_id: incident.scope.id, occurred_at: input.at, payload: record });
    return record;
  }

  recordReproduction(incidentId: string, result: ReproductionResult, input: { actor: Actor; at: string }): Incident {
    const incident = this.requiredIncident(incidentId);
    if (result.incident_id !== incidentId || result.scope.id !== incident.scope.id) throw new Error("INCIDENT_REPRODUCTION_SCOPE_MISMATCH");
    const state = result.classification === "REPRODUCIBLE" ? "REPRODUCIBLE" : result.classification === "INTERMITTENT" ? "INTERMITTENT" : "NON_REPRODUCIBLE";
    const next = appendIncidentRevision(incident, { reproduction: { state, evidence_refs: result.attempts.map(item => item.evidence_ref) }, stage: "INVESTIGATING" }, { expected_revision: incident.revision, reason: "recorded pinned Phase 2 reproduction", actor: input.actor, at: input.at });
    return this.registry.transaction(() => {
      this.registry.saveRecord("REPRODUCTION", { record_id: result.result_id, incident_id: incidentId, scope_id: incident.scope.id, occurred_at: input.at, payload: result as unknown as Record<string, unknown> });
      return this.registry.appendIncident(next, "REPRODUCTION_RECORDED", { result_id: result.result_id, classification: result.classification });
    });
  }

  addHypothesis(incidentId: string, hypothesis: IncidentHypothesisInput, input: { actor: Actor; at: string }): Incident {
    const incident = this.requiredIncident(incidentId);
    const next = addIncidentHypothesis(incident, hypothesis, { expected_revision: incident.revision, actor: input.actor, at: input.at });
    return this.registry.appendIncident(next, "HYPOTHESIS_ADDED", { hypothesis_id: hypothesis.hypothesis_id });
  }

  recordExperimentResult(incidentId: string, input: { experiment_id: string; hypothesis_id: string; outcome: "SUPPORTS" | "REJECTS"; evidence_refs: string[]; controlled_intervention: boolean; actor: Actor; at: string }): Incident {
    const incident = this.requiredIncident(incidentId);
    if (!input.controlled_intervention) throw new Error("INCIDENT_EXPERIMENT_CONTROL_REQUIRED");
    const next = resolveIncidentHypothesis(incident, input.hypothesis_id, input.outcome === "SUPPORTS" ? "SUPPORTED" : "REJECTED", { expected_revision: incident.revision, actor: input.actor, at: input.at, evidence_refs: input.evidence_refs });
    return this.registry.transaction(() => {
      this.registry.saveRecord("HYPOTHESIS_EVIDENCE", { record_id: input.experiment_id, incident_id: incidentId, scope_id: incident.scope.id, occurred_at: input.at, payload: { ...input, incident_id: incidentId } });
      return this.registry.appendIncident(next, "EXPERIMENT_RECORDED", { experiment_id: input.experiment_id, outcome: input.outcome });
    });
  }

  confirmRootCause(incidentId: string, claim: ConfirmRootCauseInput, input: { at: string }): Incident {
    const incident = this.requiredIncident(incidentId);
    const next = confirmIncidentRootCause(incident, claim, { expected_revision: incident.revision, at: input.at });
    return this.registry.transaction(() => {
      this.registry.saveRecord("ROOT_CAUSE", { record_id: next.root_cause.adjudication_id!, incident_id: incidentId, scope_id: incident.scope.id, occurred_at: input.at, payload: next.root_cause as unknown as Record<string, unknown> });
      return this.registry.appendIncident(next, "ROOT_CAUSE_CONFIRMED", { adjudication_id: next.root_cause.adjudication_id });
    });
  }

  proposeRemediation(incidentId: string, input: RemediationProposalInput): Record<string, unknown> {
    const incident = this.requiredIncident(incidentId);
    if (input.steps.length === 0) throw new Error("REMEDIATION_STEPS_REQUIRED");
    const record = remediationProposalRecord(incidentId, input);
    this.registry.saveRecord("REMEDIATION", { record_id: input.proposal_id, incident_id: incidentId, scope_id: incident.scope.id, occurred_at: input.at, payload: record });
    return record;
  }

  recordRegression(incidentId: string, input: RegressionResultInput): Record<string, unknown> {
    const incident = this.requiredIncident(incidentId);
    if (!input.evidence_ref.startsWith(`artifact:${incident.scope.id}:`)) throw new Error("REGRESSION_EVIDENCE_SCOPE_MISMATCH");
    const record = regressionResultRecord(incidentId, input);
    this.registry.saveRecord("REGRESSION", { record_id: input.regression_id, incident_id: incidentId, scope_id: incident.scope.id, occurred_at: input.at, payload: record });
    return record;
  }

  recordReview(incidentId: string, input: ReviewVerdictInput): Record<string, unknown> {
    const incident = this.requiredIncident(incidentId);
    const proposal = this.registry.records("REMEDIATION", incidentId).find(item => item.record_id === input.proposal_id)?.payload;
    if (!proposal) throw new Error("REMEDIATION_PROPOSAL_NOT_FOUND");
    const proposer = proposal.proposed_by as Actor;
    if ((input.reviewer.type !== "integration" && input.reviewer.type !== "human") || (proposer.type === input.reviewer.type && proposer.id === input.reviewer.id)) throw new Error("INCIDENT_REVIEW_INDEPENDENCE_REQUIRED");
    const record = reviewVerdictRecord(incidentId, input);
    this.registry.saveRecord("REVIEW", { record_id: input.review_id, incident_id: incidentId, scope_id: incident.scope.id, occurred_at: input.at, payload: record });
    return record;
  }

  async close(incidentId: string, input: { actor: Actor; reason: string; at: string }): Promise<{ incident: Incident; memory: Record<string, unknown>; playbook_candidate_id: string }> {
    const incident = this.requiredIncident(incidentId);
    if (incident.root_cause.state !== "CONFIRMED") throw new Error("INCIDENT_CLOSE_ROOT_CAUSE_REQUIRED");
    if (incident.reproduction.state !== "REPRODUCIBLE") throw new Error("INCIDENT_CLOSE_REPRODUCTION_REQUIRED");
    const proposals = this.registry.records("REMEDIATION", incidentId);
    const regressions = this.registry.records("REGRESSION", incidentId).map(item => item.payload);
    const reviews = this.registry.records("REVIEW", incidentId).map(item => item.payload);
    if (proposals.length === 0) throw new Error("INCIDENT_CLOSE_REMEDIATION_REQUIRED");
    if (!regressions.some(item => item.phase === "BEFORE" && item.result === "FAIL") || !regressions.some(item => item.phase === "AFTER" && item.result === "PASS")) throw new Error("INCIDENT_CLOSE_REGRESSION_GATE_FAILED");
    if (!reviews.some(item => item.verdict === "APPROVED" && item.independent === true)) throw new Error("INCIDENT_CLOSE_REVIEW_REQUIRED");
    const closed = appendIncidentRevision(incident, { status: "CLOSED", stage: "RESOLVED" }, { expected_revision: incident.revision, reason: input.reason, actor: input.actor, at: input.at });
    const proposal = proposals[0]!.payload;
    const playbook = createPlaybookCandidate({
      candidate_id: `playbook-candidate:${canonicalSha256({ incident_id: incidentId }).slice(7, 39)}`,
      source_incident_id: incidentId,
      scope: incident.scope,
      title: String(proposal.summary),
      trigger_signature: closed.revision_hash,
      steps: proposal.steps as string[],
      created_at: input.at,
      created_by: input.actor,
    });
    const persisted = this.registry.transaction(() => {
      const value = this.registry.appendIncident(closed, "INCIDENT_CLOSED", { reason: input.reason, production_repair_claimed: false });
      this.registry.saveRecord("PLAYBOOK", { record_id: playbook.candidate_id, incident_id: incidentId, scope_id: incident.scope.id, occurred_at: input.at, payload: playbook as unknown as Record<string, unknown> });
      return value;
    });
    const memories = closureMemories(persisted, playbook.candidate_id, input.at);
    const memory = await this.writeClosureMemory(persisted, memories, input.at);
    return { incident: persisted, memory, playbook_candidate_id: playbook.candidate_id };
  }

  reopen(incidentId: string, input: { actor: Actor; reason: string; at: string }): Incident {
    const incident = this.requiredIncident(incidentId);
    if (incident.status !== "CLOSED") throw new Error("INCIDENT_REOPEN_REQUIRES_CLOSED");
    const reopened = appendIncidentRevision(incident, { status: "OPEN", stage: "INVESTIGATING" }, { expected_revision: incident.revision, reason: input.reason, actor: input.actor, at: input.at });
    return this.registry.appendIncident(reopened, "INCIDENT_REOPENED", { reason: input.reason });
  }

  explain(incidentId: string): Record<string, unknown> {
    const incident = this.requiredIncident(incidentId);
    return { incident_id: incidentId, status: incident.status, root_cause_state: incident.root_cause.state, reproduction_state: incident.reproduction.state, relations: this.registry.relations(incidentId), audit_events: this.registry.auditEvents(incidentId).length, production_repair_claimed: false };
  }

  async runFoundationResolution(failure: CollectedPhase2Failure, options: { at: string }): Promise<Record<string, unknown>> {
    const ingested = this.ingest(failure);
    const incidentId = ingested.incident_id;
    const times = timeSequence(options.at, 12);
    const system: Actor = { type: "system", id: "system:phase7-demo" };
    const agent: Actor = { type: "agent", id: "agent:phase7-investigator" };
    const reviewer: Actor = { type: "integration", id: "integration:phase3-independent-review" };
    this.triage(incidentId, { severity: "HIGH", priority: "P1", confidence: 0.97, actor: system, at: times[0]! });
    this.proposeContainment(incidentId, { action_id: `containment:${incidentId}`, summary: "Propose bounded account permission isolation", autonomy: "A3", reversible: true, actor: system, at: times[1]! });
    const manifest = createReproductionManifest({
      manifest_id: `reproduction-manifest:${canonicalSha256({ incident_id: incidentId }).slice(7, 39)}`,
      incident_id: incidentId,
      scope: failure.observation.scope,
      source_commit: failure.source_commit,
      image_digest: failure.source_hash,
      seed: 403,
      attempts: 5,
      budgets: { timeout_ms: 30_000, max_output_bytes: 64_000, max_memory_mb: 512 },
      production_access: false,
      secret_refs: [],
      network_access: false,
      phase2_adapter: { id: "phase2-local-replay", version: "1.0.0" },
      created_at: times[2]!,
    });
    const reproduction = await runPinnedReproduction(manifest, createDeterministicPhase2ReplayAdapter({ outcomes: [true, true, true, true, true] }));
    this.recordReproduction(incidentId, reproduction, { actor: system, at: times[3]! });
    const hypothesisId = `hypothesis:${canonicalSha256({ incident_id: incidentId }).slice(7, 39)}`;
    const statement = "Repository permission scope rejects the provider request";
    const mechanism = "The pinned account lacks the repository permission required by the provider";
    this.addHypothesis(incidentId, { hypothesis_id: hypothesisId, statement, causal_mechanism: mechanism, falsifiable_prediction: "A controlled local permission fixture removes the 403", disproof_conditions: ["The same pinned fixture still returns 403"], proposed_by: agent }, { actor: agent, at: times[4]! });
    const controlledEvidence = `artifact:${failure.observation.scope.id}:controlled-intervention`;
    this.recordExperimentResult(incidentId, { experiment_id: `experiment:${canonicalSha256({ incident_id: incidentId }).slice(7, 39)}`, hypothesis_id: hypothesisId, outcome: "SUPPORTS", evidence_refs: [controlledEvidence], controlled_intervention: true, actor: reviewer, at: times[5]! });
    const conditions = ROOT_CAUSE_CONFIRMATION_CONDITIONS.map(condition => ({ condition, evidence_refs: [`artifact:${failure.observation.scope.id}:root-${condition.toLowerCase()}`] }));
    this.confirmRootCause(incidentId, { hypothesis_id: hypothesisId, statement, mechanism, conditions, authority: { kind: "INDEPENDENT_REVIEW", actor: reviewer } }, { at: times[6]! });
    const proposalId = `remediation-proposal:${canonicalSha256({ incident_id: incidentId }).slice(7, 39)}`;
    this.proposeRemediation(incidentId, { proposal_id: proposalId, summary: "Pin and validate a least-privilege permission mapping", steps: ["Validate the local permission fixture", "Propose the scoped mapping change"], proposed_by: agent, at: times[7]! });
    this.recordRegression(incidentId, { regression_id: `regression:${incidentId}:before`, phase: "BEFORE", result: "FAIL", evidence_ref: `artifact:${failure.observation.scope.id}:regression-before`, actor: reviewer, at: times[8]! });
    this.recordRegression(incidentId, { regression_id: `regression:${incidentId}:after`, phase: "AFTER", result: "PASS", evidence_ref: `artifact:${failure.observation.scope.id}:regression-after`, actor: reviewer, at: times[9]! });
    this.recordReview(incidentId, { review_id: `review:${canonicalSha256({ incident_id: incidentId }).slice(7, 39)}`, proposal_id: proposalId, verdict: "APPROVED", reviewer, rationale: "Pinned replay and fail-before/pass-after evidence satisfy the foundation gate", at: times[10]! });
    const closed = await this.close(incidentId, { actor: reviewer, reason: "foundation evidence gates satisfied", at: times[11]! });
    return { incident_id: incidentId, observation_id: ingested.observation_id, correlation: ingested.correlation, reproduction, root_cause: closed.incident.root_cause, memory: closed.memory, playbook_candidate_id: closed.playbook_candidate_id };
  }

  private requiredIncident(incidentId: string): Incident { return this.registry.getIncident(incidentId) ?? fail("PHASE7_INCIDENT_NOT_FOUND"); }
  private requiredObservationFor(incident: Incident) {
    const revisionId = incident.observation_ids[0]!;
    return this.registry.getObservationByRevision(revisionId) ?? fail("PHASE7_OBSERVATION_NOT_FOUND");
  }
  private async writeClosureMemory(incident: Incident, records: readonly MemoryRecord[], at: string): Promise<Record<string, unknown>> {
    if (!this.memoryWriter) return { status: "NOT_CONFIGURED", records: records.length };
    try {
      await this.memoryWriter.write(records);
      return { status: "WRITTEN", records: records.length, memory_ids: records.map(record => record.memory_id) };
    } catch {
      if (!this.operations) throw new Error("PHASE7_MEMORY_RECOVERY_OPERATIONS_REQUIRED");
      const job = this.operations.enqueue({
        scope_id: `repository:${incident.scope.id}`,
        kind: "phase7.memory-write",
        idempotency_key: `closure:${incident.revision_hash}`,
        payload: { incident_id: incident.incident_id, closure_revision_hash: incident.revision_hash, memory_ids: records.map(record => record.memory_id), error_code: "MEMORY_WRITE_FAILED" },
        priority: 90,
        max_attempts: 5,
        retry_policy: { base_backoff_ms: 1_000, max_backoff_ms: 60_000 },
        now: at,
      });
      return { status: "RETRY_QUEUED", records: records.length, job_id: job.job_id };
    }
  }
}

function initialIncident(input: CollectedPhase2Failure, risk: ReturnType<typeof classifyRisk>): Incident {
  return createIncident({
    incident_id: `incident:${canonicalSha256({ source_event_id: input.source_event_id, source_hash: input.source_hash }).slice(7, 39)}`,
    title: input.observation.failure.summary,
    status: "OPEN",
    stage: "TRIAGE",
    reproduction: { state: "NOT_ATTEMPTED", evidence_refs: [] },
    root_cause: { state: "UNCONFIRMED", statement: null, mechanism: null, evidence_refs: [], hypothesis_id: null, acceptance: null, adjudication_id: null, supersedes_adjudication_id: null },
    containment: { state: "NOT_STARTED", summary: null, evidence_refs: [] },
    severity: risk.severity === "CRITICAL" ? "SEV0" : risk.severity === "HIGH" ? "SEV1" : risk.severity === "MEDIUM" ? "SEV2" : "SEV3",
    priority: risk.priority === "P0" ? "URGENT" : risk.priority === "P1" ? "HIGH" : risk.priority === "P2" ? "NORMAL" : "LOW",
    confidence: 0.9,
    owner: { type: "system", id: "system:phase7-triage" },
    scope: input.observation.scope,
    hypotheses: [],
    created_at: input.observation.observed_at,
    created_by: { type: "system", id: "system:phase7-ingestion" },
  }, [input.observation]);
}
function classifyRisk(input: CollectedPhase2Failure): { severity: TriageSeverity; priority: TriagePriority; a5: boolean } {
  return classifyRiskFromCode(input.phase2_failure_type, input.observation.failure.summary, input.http_status);
}
function classifyRiskFromCode(code: string, summary: string, httpStatus?: number | null): { severity: TriageSeverity; priority: TriagePriority; a5: boolean } {
  const normalized = code.toUpperCase().replace(/^OPENCODEX\./, "").replaceAll("-", "_");
  const a5 = normalized === "SECRET_LEAK_DETECTED" || /permission.?bypass/i.test(summary);
  if (a5) return { severity: "HIGH", priority: "P1", a5: true };
  if (normalized === "AUTHORIZATION_FAILED" || httpStatus === 403) return { severity: "HIGH", priority: "P1", a5: false };
  if (["PATH_POLICY_VIOLATION", "AUTHENTICATION_FAILED"].includes(normalized)) return { severity: "MEDIUM", priority: "P2", a5: false };
  return { severity: "LOW", priority: "P3", a5: false };
}
function severityRank(value: TriageSeverity): number { return ["LOW", "MEDIUM", "HIGH", "CRITICAL"].indexOf(value); }
function timeSequence(start: string, count: number): string[] {
  const base = Date.parse(start);
  if (!Number.isFinite(base)) throw new Error("PHASE7_TIME_INVALID");
  return Array.from({ length: count }, (_, index) => new Date(base + index * 1_000).toISOString());
}
function closureMemories(incident: Incident, playbookCandidateId: string, at: string): MemoryRecord[] {
  const scopes = [{ type: "REPOSITORY" as const, id: incident.scope.id }];
  const shared = { scopes, temporal: { observed_at: at, valid_from: at, valid_until: null, last_verified_at: at }, relations: { supersedes: [], contradicts: [], derived_from: [] }, access: { sensitivity: "INTERNAL" as const, read_roles: ["*"] }, retention: { policy: "repository-durable" }, created_at: at };
  return [
    createMemoryRecord({ ...shared, memory_id: `memory:incident-episode-${incident.incident_id.slice(-16)}`, layer: "EPISODE", kind: "opencodex.incident.episode", subject: { type: "incident", key: incident.incident_id }, content: { summary: `Observed incident ${incident.incident_id} closed with preserved evidence.` }, lifecycle: { status: "OBSERVED" }, trust: { level: "HIGH", confidence: incident.confidence }, provenance: { source_refs: [incident.revision_hash], extractor_ref: { id: "phase7-closure", version: "1.0.0" } }, created_by: { type: "system", id: "system:phase7-memory" } }),
    createMemoryRecord({ ...shared, memory_id: `memory:incident-lesson-${incident.incident_id.slice(-16)}`, layer: "LESSON", kind: "opencodex.incident.confirmed-lesson", subject: { type: "root-cause", key: incident.root_cause.adjudication_id! }, content: { summary: incident.root_cause.statement! }, lifecycle: { status: "VERIFIED" }, trust: { level: "AUTHORITATIVE", confidence: 1 }, provenance: { source_refs: [incident.revision_hash, ...incident.root_cause.evidence_refs], extractor_ref: { id: "phase7-root-cause", version: "1.0.0" } }, created_by: { type: "verifier", id: "verifier:phase7-independent-review" } }),
    createMemoryRecord({ ...shared, memory_id: `memory:incident-procedure-${incident.incident_id.slice(-16)}`, layer: "PROCEDURE_CANDIDATE", kind: "opencodex.incident.playbook-candidate", subject: { type: "playbook-candidate", key: playbookCandidateId }, content: { summary: `Candidate procedure derived from ${incident.incident_id}; it is not an active skill.` }, lifecycle: { status: "CANDIDATE" }, trust: { level: "HIGH", confidence: 0.9 }, provenance: { source_refs: [incident.revision_hash, playbookCandidateId], extractor_ref: { id: "phase7-playbook", version: "1.0.0" } }, created_by: { type: "system", id: "system:phase7-memory" } }),
  ];
}
function fail(message: string): never { throw new Error(message); }
