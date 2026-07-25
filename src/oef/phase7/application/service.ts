import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import type { Actor } from "../../phase1/core/shared/actor";
import type { SqliteOperationsStore } from "../../operations/persistence/sqlite-store";
import { createMemoryRecord, type MemoryRecord } from "../../phase6/core/domain";
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
import type { CollectedPhase2Failure } from "../ingestion/phase2-failure-collector";
import {
  getPhase7RegistryWriter,
  type IncidentRelation,
  type IngestionPersistenceResult,
  type Phase7RegistryWriter,
  SqliteIncidentRegistry,
} from "../persistence/sqlite-store";
import type { MemoryWriteBatch } from "../persistence/typed-records";
import {
  createReproductionManifest,
  parseReproductionManifest,
  runPinnedReproduction,
  type Phase2ReproductionAdapter,
  type ReproductionEvidenceResolver,
  type ReproductionManifest,
  type ReproductionResult,
} from "../reproduction/manifest";
import {
  regressionResultRecord,
  remediationProposalRecord,
  reviewVerdictRecord,
  type RegressionResultInput,
  type RemediationProposalInput,
  type RemediationProposalRecord,
  type ReviewVerdictInput,
} from "../remediation/records";

export interface Phase6IncidentMemoryWriter { write(records: readonly MemoryRecord[]): void | Promise<void> }
export interface ContainmentApprovalVerifier {
  verify(input: { credential: string; incident_id: string; action_id: string; scope_id: string; actor: Actor; now: string }): { level: "A5"; actor: Actor; expires_at: string } | null;
}
export interface IncidentIntelligenceServiceOptions {
  registry: SqliteIncidentRegistry;
  operations?: SqliteOperationsStore;
  memoryWriter?: Phase6IncidentMemoryWriter;
  reproductionAdapter?: Phase2ReproductionAdapter;
  evidenceResolver?: ReproductionEvidenceResolver;
  containmentApprovalVerifier?: ContainmentApprovalVerifier;
}
export type TriageSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type TriagePriority = "P0" | "P1" | "P2" | "P3";

export const PHASE7_LOCAL_REPLAY_IMAGE_DIGEST = canonicalSha256({ image: "phase7-local-replay", version: "1.0.0" });

export class IncidentIntelligenceService {
  private readonly registry: SqliteIncidentRegistry;
  private readonly writer: Phase7RegistryWriter;
  private readonly operations: SqliteOperationsStore | undefined;
  private readonly memoryWriter: Phase6IncidentMemoryWriter | undefined;
  private readonly reproductionAdapter: Phase2ReproductionAdapter | undefined;
  private readonly evidenceResolver: ReproductionEvidenceResolver | undefined;
  private readonly containmentApprovalVerifier: ContainmentApprovalVerifier | undefined;

  constructor(options: IncidentIntelligenceServiceOptions) {
    if (options.memoryWriter && !options.operations) throw new Error("PHASE7_MEMORY_RECOVERY_OPERATIONS_REQUIRED");
    if ((options.reproductionAdapter && !options.evidenceResolver) || (!options.reproductionAdapter && options.evidenceResolver)) throw new Error("PHASE7_REPRODUCTION_PORTS_INCOMPLETE");
    this.registry = options.registry;
    this.writer = getPhase7RegistryWriter(options.registry);
    this.operations = options.operations;
    this.memoryWriter = options.memoryWriter;
    this.reproductionAdapter = options.reproductionAdapter;
    this.evidenceResolver = options.evidenceResolver;
    this.containmentApprovalVerifier = options.containmentApprovalVerifier;
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
        scope: incident.scope,
        reason: "high-risk observations require review before merge",
        created_at: input.observation.observed_at,
      };
    } else if (candidate) {
      incident = attachFailureObservation(candidate.incident, input.observation, { expected_revision: candidate.incident.revision, actor: { type: "system", id: "system:phase7-correlation" }, at: input.observation.observed_at });
      correlation = "AUTO_CORRELATED";
    } else incident = initialIncident(input, risk);
    return this.writer.ingest({ source_event_id: input.source_event_id, source_hash: input.source_hash, observation: input.observation, signatures: input.signatures, provider: input.provider, runtime: input.runtime, runtime_major: input.runtime_major, incident, relation, correlation });
  }

  triage(incidentId: string, input: { severity: TriageSeverity; priority: TriagePriority; confidence: number; actor: Actor; at: string }): Record<string, unknown> {
    const incident = this.requiredIncident(incidentId);
    const observation = this.requiredObservationFor(incident);
    const floor = classifyRiskFromCode(observation.failure.code, observation.failure.summary);
    const severity = severityRank(input.severity) < severityRank(floor.severity) ? floor.severity : input.severity;
    if (!Number.isFinite(input.confidence) || input.confidence < 0 || input.confidence > 1) throw new Error("INCIDENT_TRIAGE_CONFIDENCE_INVALID");
    const record = {
      record_id: `triage:${canonicalSha256({ incident_id: incidentId, revision: incident.revision, at: input.at }).slice(7, 39)}`,
      incident_id: incidentId,
      scope: incident.scope,
      severity,
      priority: input.priority,
      confidence: input.confidence,
      required_approval: floor.a5 ? "A5" as const : severity === "CRITICAL" ? "A4" as const : "A3" as const,
      actor: input.actor,
      at: input.at,
    };
    this.writer.saveTriage(record);
    return record;
  }

  proposeContainment(incidentId: string, input: { action_id: string; summary: string; autonomy: "A0" | "A1" | "A2" | "A3" | "A4" | "A5"; reversible: boolean; actor: Actor; at: string; approval?: { credential: string; actor: Actor } }): Record<string, unknown> {
    const incident = this.requiredIncident(incidentId);
    const latestTriage = this.registry.records("TRIAGE", incidentId).at(-1)?.payload;
    const a5Required = latestTriage?.required_approval === "A5";
    let approvedBy: Actor | null = null;
    if (a5Required && input.approval && this.containmentApprovalVerifier) {
      const verified = this.containmentApprovalVerifier.verify({ credential: input.approval.credential, incident_id: incidentId, action_id: input.action_id, scope_id: incident.scope.id, actor: input.approval.actor, now: input.at });
      if (verified?.level === "A5" && verified.actor.id === input.approval.actor.id && verified.actor.type === input.approval.actor.type && (verified.actor.type === "human" || /(^|:)security(?=:|$)/.test(verified.actor.id)) && Date.parse(verified.expires_at) > Date.parse(input.at)) approvedBy = verified.actor;
    }
    const automatic = input.reversible && ["A0", "A1", "A2"].includes(input.autonomy) && (!a5Required || approvedBy !== null);
    const record = {
      record_id: input.action_id,
      incident_id: incidentId,
      scope: incident.scope,
      summary: input.summary,
      autonomy: input.autonomy,
      reversible: input.reversible,
      state: automatic ? "EXECUTED" as const : "PROPOSED" as const,
      execution_kind: automatic ? "LOCAL_RECORD_ONLY" as const : "NONE" as const,
      required_approval: a5Required ? "A5" as const : automatic ? null : input.autonomy === "A5" ? "A5" as const : input.autonomy === "A4" ? "A4" as const : "A3" as const,
      approved_by: approvedBy,
      production_action_performed: false as const,
      actor: input.actor,
      at: input.at,
    };
    this.writer.saveContainment(record);
    return record;
  }

  async reproduce(incidentId: string, manifestInput: unknown, input: { actor: Actor; at: string }): Promise<Incident> {
    if (!this.reproductionAdapter || !this.evidenceResolver) throw new Error("PHASE7_REPRODUCTION_PORTS_REQUIRED");
    const incident = this.requiredIncident(incidentId);
    const manifest = manifestInput && typeof manifestInput === "object" && "manifest_hash" in manifestInput
      ? parseReproductionManifest(manifestInput)
      : createReproductionManifest(manifestInput);
    if (manifest.incident_id !== incidentId) throw new Error("INCIDENT_REPRODUCTION_SCOPE_MISMATCH");
    this.writer.persistReproductionManifest(manifest);
    const result = await runPinnedReproduction(manifest, this.reproductionAdapter, this.evidenceResolver);
    const state = result.classification === "REPRODUCIBLE" ? "REPRODUCIBLE" : result.classification === "INTERMITTENT" ? "INTERMITTENT" : "NON_REPRODUCIBLE";
    const next = appendIncidentRevision(incident, { reproduction: { state, evidence_refs: result.attempts.map(item => item.evidence_ref) }, stage: "INVESTIGATING" }, { expected_revision: incident.revision, reason: "recorded trusted pinned Phase 2 reproduction", actor: input.actor, at: input.at });
    return this.writer.recordReproduction(result, next, { at: input.at });
  }

  addHypothesis(incidentId: string, hypothesis: IncidentHypothesisInput, input: { actor: Actor; at: string }): Incident {
    const incident = this.requiredIncident(incidentId);
    const next = addIncidentHypothesis(incident, hypothesis, { expected_revision: incident.revision, actor: input.actor, at: input.at });
    return this.writer.appendHypothesis(next, hypothesis.hypothesis_id);
  }

  recordExperimentResult(incidentId: string, input: { experiment_id: string; hypothesis_id: string; outcome: "SUPPORTS" | "REJECTS"; evidence_refs: string[]; controlled_intervention: boolean; actor: Actor; at: string }): Incident {
    const incident = this.requiredIncident(incidentId);
    if (!input.controlled_intervention) throw new Error("INCIDENT_EXPERIMENT_CONTROL_REQUIRED");
    const next = resolveIncidentHypothesis(incident, input.hypothesis_id, input.outcome === "SUPPORTS" ? "SUPPORTED" : "REJECTED", { expected_revision: incident.revision, actor: input.actor, at: input.at, evidence_refs: input.evidence_refs });
    return this.writer.recordExperiment({ ...input, incident_id: incidentId, scope: incident.scope, controlled_intervention: true }, next);
  }

  confirmRootCause(incidentId: string, claim: ConfirmRootCauseInput, input: { at: string }): Incident {
    const incident = this.requiredIncident(incidentId);
    const next = confirmIncidentRootCause(incident, claim, { expected_revision: incident.revision, at: input.at });
    return this.writer.recordRootCause({ incident_id: incidentId, scope: incident.scope, adjudication_id: next.root_cause.adjudication_id!, root_cause: next.root_cause, at: input.at }, next);
  }

  proposeRemediation(incidentId: string, input: RemediationProposalInput): Record<string, unknown> {
    const incident = this.requiredIncident(incidentId);
    const record = remediationProposalRecord(incidentId, incident.scope, input);
    this.writer.saveRemediation(record);
    return record;
  }

  recordRegression(incidentId: string, input: RegressionResultInput): Record<string, unknown> {
    const incident = this.requiredIncident(incidentId);
    const record = regressionResultRecord(incidentId, incident.scope, input);
    this.writer.saveRegression(record);
    return record;
  }

  recordReview(incidentId: string, input: ReviewVerdictInput): Record<string, unknown> {
    const incident = this.requiredIncident(incidentId);
    const proposal = this.registry.records("REMEDIATION", incidentId).find(item => item.record_id === input.proposal_id)?.payload;
    if (!proposal) throw new Error("REMEDIATION_PROPOSAL_NOT_FOUND");
    const proposer = proposal.proposed_by as Actor;
    if ((input.reviewer.type !== "integration" && input.reviewer.type !== "human") || (proposer.type === input.reviewer.type && proposer.id === input.reviewer.id)) throw new Error("INCIDENT_REVIEW_INDEPENDENCE_REQUIRED");
    const record = reviewVerdictRecord(incidentId, incident.scope, input);
    this.writer.saveReview(record);
    return record;
  }

  async close(incidentId: string, input: { actor: Actor; reason: string; at: string }): Promise<{ incident: Incident; memory: Record<string, unknown>; playbook_candidate_id: string }> {
    const incident = this.requiredIncident(incidentId);
    if (incident.root_cause.state !== "CONFIRMED") throw new Error("INCIDENT_CLOSE_ROOT_CAUSE_REQUIRED");
    if (incident.reproduction.state !== "REPRODUCIBLE") throw new Error("INCIDENT_CLOSE_REPRODUCTION_REQUIRED");
    const proposals = this.registry.records("REMEDIATION", incidentId).map(item => item.payload as unknown as RemediationProposalRecord);
    if (proposals.length === 0) throw new Error("INCIDENT_CLOSE_REMEDIATION_REQUIRED");
    const regressions = this.registry.records("REGRESSION", incidentId).map(item => item.payload);
    const reviews = this.registry.records("REVIEW", incidentId).map(item => item.payload);
    const proposal = proposals.find(candidate =>
      regressions.some(item => item.remediation_id === candidate.proposal_id && item.plan_hash === candidate.plan_hash && item.patch_hash === candidate.patch_hash && item.phase === "BEFORE" && item.result === "FAIL") &&
      regressions.some(item => item.remediation_id === candidate.proposal_id && item.plan_hash === candidate.plan_hash && item.patch_hash === candidate.patch_hash && item.phase === "AFTER" && item.result === "PASS") &&
      reviews.some(item => item.proposal_id === candidate.proposal_id && item.plan_hash === candidate.plan_hash && item.patch_hash === candidate.patch_hash && item.verdict === "APPROVED" && item.independent === true));
    if (!proposal) throw new Error("INCIDENT_CLOSE_REMEDIATION_LINEAGE_REQUIRED");
    const closed = appendIncidentRevision(incident, { status: "CLOSED", stage: "RESOLVED" }, { expected_revision: incident.revision, reason: input.reason, actor: input.actor, at: input.at });
    const playbook = createPlaybookCandidate({
      candidate_id: `playbook-candidate:${canonicalSha256({ incident_id: incidentId, closure_revision_hash: closed.revision_hash }).slice(7, 39)}`,
      source_incident_id: incidentId,
      scope: incident.scope,
      title: proposal.summary,
      trigger_signature: closed.revision_hash,
      steps: proposal.steps,
      created_at: input.at,
      created_by: input.actor,
    });
    const persisted = this.writer.closeIncident(closed, playbook, proposal.proposal_id);
    const memories = closureMemories(persisted, playbook.candidate_id, input.at);
    const batch = createMemoryWriteBatch(persisted, memories, input.at);
    this.writer.saveMemoryWriteBatch(batch);
    const memory = await this.writeClosureMemory(persisted, batch, input.at);
    return { incident: persisted, memory, playbook_candidate_id: playbook.candidate_id };
  }

  reopen(incidentId: string, input: { actor: Actor; reason: string; at: string }): Incident {
    const incident = this.requiredIncident(incidentId);
    if (incident.status !== "CLOSED") throw new Error("INCIDENT_REOPEN_REQUIRES_CLOSED");
    const reopened = appendIncidentRevision(incident, { status: "OPEN", stage: "INVESTIGATING" }, { expected_revision: incident.revision, reason: input.reason, actor: input.actor, at: input.at });
    return this.writer.reopenIncident(reopened);
  }

  async processNextMemoryWrite(input: { scope_id: string; owner: string; now: string; lease_ms: number }): Promise<Record<string, unknown>> {
    if (!this.operations || !this.memoryWriter) throw new Error("PHASE7_MEMORY_RECOVERY_NOT_CONFIGURED");
    const job = this.operations.claim(input);
    if (!job) return { status: "IDLE" };
    this.operations.start({ scope_id: input.scope_id, job_id: job.job_id, owner: input.owner, now: input.now });
    try {
      if (job.kind !== "phase7.memory-write" || Object.keys(job.payload).sort().join(",") !== "batch_hash,batch_id" || typeof job.payload.batch_id !== "string" || typeof job.payload.batch_hash !== "string") throw new Error("PHASE7_MEMORY_JOB_PAYLOAD_INVALID");
      const batch = this.registry.getMemoryWriteBatch(job.payload.batch_id, job.payload.batch_hash);
      if (!batch) throw new Error("PHASE7_MEMORY_BATCH_NOT_FOUND");
      await this.memoryWriter.write(batch.records);
      this.operations.succeed({ scope_id: input.scope_id, job_id: job.job_id, owner: input.owner, effect: { batch_id: batch.batch_id, batch_hash: batch.batch_hash, records: batch.records.length }, now: input.now });
      return { status: "SUCCEEDED", records: batch.records.length, incident_id: batch.incident_id, batch_id: batch.batch_id };
    } catch {
      this.operations.fail({ scope_id: input.scope_id, job_id: job.job_id, owner: input.owner, failure: { code: "PHASE7_MEMORY_WRITE_FAILED", summary: "Phase 7 memory batch write did not complete", artifact_ref: null }, retryable: true, now: input.now });
      return { status: "RETRY_PENDING", job_id: job.job_id };
    }
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
    const manifest: ReproductionManifest = createReproductionManifest({
      manifest_id: `reproduction-manifest:${canonicalSha256({ incident_id: incidentId, revision: this.requiredIncident(incidentId).revision }).slice(7, 39)}`,
      incident_id: incidentId,
      scope: failure.observation.scope,
      source_commit: failure.source_commit,
      image_digest: PHASE7_LOCAL_REPLAY_IMAGE_DIGEST,
      expected_signature: failure.signatures.normalized_signature,
      seed: 403,
      attempts: 5,
      budgets: { timeout_ms: 30_000, max_output_bytes: 64_000, max_memory_mb: 512 },
      production_access: false,
      secret_refs: [],
      network_access: false,
      phase2_adapter: { id: "phase2-local-replay", version: "1.0.0" },
      created_at: times[2]!,
    });
    await this.reproduce(incidentId, manifest, { actor: system, at: times[3]! });
    const reproduction = this.registry.records("REPRODUCTION", incidentId).at(-1)!.payload as unknown as ReproductionResult;
    const hypothesisId = `hypothesis:${canonicalSha256({ incident_id: incidentId }).slice(7, 39)}`;
    const statement = "Repository permission scope rejects the provider request";
    const mechanism = "The pinned account lacks the repository permission required by the provider";
    this.addHypothesis(incidentId, { hypothesis_id: hypothesisId, statement, causal_mechanism: mechanism, falsifiable_prediction: "A controlled local permission fixture removes the 403", disproof_conditions: ["The same pinned fixture still returns 403"], proposed_by: agent }, { actor: agent, at: times[4]! });
    const controlledEvidence = `artifact:${failure.observation.scope.id}:controlled-intervention`;
    this.recordExperimentResult(incidentId, { experiment_id: `experiment:${canonicalSha256({ incident_id: incidentId }).slice(7, 39)}`, hypothesis_id: hypothesisId, outcome: "SUPPORTS", evidence_refs: [controlledEvidence], controlled_intervention: true, actor: reviewer, at: times[5]! });
    const conditions = ROOT_CAUSE_CONFIRMATION_CONDITIONS.map(condition => ({ condition, evidence_refs: [`artifact:${failure.observation.scope.id}:root-${condition.toLowerCase()}`] }));
    this.confirmRootCause(incidentId, { hypothesis_id: hypothesisId, statement, mechanism, conditions, authority: { kind: "INDEPENDENT_REVIEW", actor: reviewer } }, { at: times[6]! });
    const proposalId = `remediation-proposal:${canonicalSha256({ incident_id: incidentId }).slice(7, 39)}`;
    const planHash = canonicalSha256({ incident_id: incidentId, plan: "least-privilege-permission-mapping" });
    const patchHash = canonicalSha256({ incident_id: incidentId, patch: "bounded-local-fixture" });
    this.proposeRemediation(incidentId, { proposal_id: proposalId, summary: "Pin and validate a least-privilege permission mapping", steps: ["Validate the local permission fixture", "Propose the scoped mapping change"], plan_hash: planHash, patch_hash: patchHash, evidence_refs: [`artifact:${failure.observation.scope.id}:remediation-plan`], proposed_by: agent, at: times[7]! });
    this.recordRegression(incidentId, { regression_id: `regression:${incidentId}:before`, remediation_id: proposalId, plan_hash: planHash, patch_hash: patchHash, phase: "BEFORE", result: "FAIL", evidence_ref: `artifact:${failure.observation.scope.id}:regression-before`, actor: reviewer, at: times[8]! });
    this.recordRegression(incidentId, { regression_id: `regression:${incidentId}:after`, remediation_id: proposalId, plan_hash: planHash, patch_hash: patchHash, phase: "AFTER", result: "PASS", evidence_ref: `artifact:${failure.observation.scope.id}:regression-after`, actor: reviewer, at: times[9]! });
    this.recordReview(incidentId, { review_id: `review:${canonicalSha256({ incident_id: incidentId }).slice(7, 39)}`, proposal_id: proposalId, plan_hash: planHash, patch_hash: patchHash, verdict: "APPROVED", reviewer, rationale: "Pinned replay and fail-before/pass-after evidence satisfy the foundation gate", evidence_refs: [`artifact:${failure.observation.scope.id}:remediation-plan`, `artifact:${failure.observation.scope.id}:independent-review`], at: times[10]! });
    const closed = await this.close(incidentId, { actor: reviewer, reason: "foundation evidence gates satisfied", at: times[11]! });
    return { incident_id: incidentId, observation_id: ingested.observation_id, correlation: ingested.correlation, reproduction, root_cause: closed.incident.root_cause, memory: closed.memory, playbook_candidate_id: closed.playbook_candidate_id };
  }

  private requiredIncident(incidentId: string): Incident { return this.registry.getIncident(incidentId) ?? fail("PHASE7_INCIDENT_NOT_FOUND"); }
  private requiredObservationFor(incident: Incident) { return this.registry.getObservationByRevision(incident.observation_ids[0]!) ?? fail("PHASE7_OBSERVATION_NOT_FOUND"); }
  private async writeClosureMemory(incident: Incident, batch: MemoryWriteBatch, at: string): Promise<Record<string, unknown>> {
    if (!this.memoryWriter) return { status: "NOT_CONFIGURED", records: batch.records.length, batch_id: batch.batch_id };
    try {
      await this.memoryWriter.write(batch.records);
      return { status: "WRITTEN", records: batch.records.length, memory_ids: batch.records.map(record => record.memory_id), batch_id: batch.batch_id };
    } catch {
      if (!this.operations) throw new Error("PHASE7_MEMORY_RECOVERY_OPERATIONS_REQUIRED");
      const job = this.operations.enqueue({ scope_id: `repository:${incident.scope.id}`, kind: "phase7.memory-write", idempotency_key: `closure:${incident.revision_hash}`, payload: { batch_id: batch.batch_id, batch_hash: batch.batch_hash }, priority: 90, max_attempts: 5, retry_policy: { base_backoff_ms: 1_000, max_backoff_ms: 60_000 }, now: at });
      return { status: "RETRY_QUEUED", records: batch.records.length, job_id: job.job_id, batch_id: batch.batch_id };
    }
  }
}

function initialIncident(input: CollectedPhase2Failure, risk: ReturnType<typeof classifyRisk>): Incident {
  return createIncident({ incident_id: `incident:${canonicalSha256({ source_event_id: input.source_event_id, source_hash: input.source_hash }).slice(7, 39)}`, title: input.observation.failure.summary, status: "OPEN", stage: "TRIAGE", reproduction: { state: "NOT_ATTEMPTED", evidence_refs: [] }, root_cause: { state: "UNCONFIRMED", statement: null, mechanism: null, evidence_refs: [], hypothesis_id: null, acceptance: null, adjudication_id: null, supersedes_adjudication_id: null }, containment: { state: "NOT_STARTED", summary: null, evidence_refs: [] }, severity: risk.severity === "CRITICAL" ? "SEV0" : risk.severity === "HIGH" ? "SEV1" : risk.severity === "MEDIUM" ? "SEV2" : "SEV3", priority: risk.priority === "P0" ? "URGENT" : risk.priority === "P1" ? "HIGH" : risk.priority === "P2" ? "NORMAL" : "LOW", confidence: 0.9, owner: { type: "system", id: "system:phase7-triage" }, scope: input.observation.scope, hypotheses: [], created_at: input.observation.observed_at, created_by: { type: "system", id: "system:phase7-ingestion" } }, [input.observation]);
}
function classifyRisk(input: CollectedPhase2Failure): { severity: TriageSeverity; priority: TriagePriority; a5: boolean } { return classifyRiskFromCode(input.phase2_failure_type, input.observation.failure.summary, input.http_status); }
function classifyRiskFromCode(code: string, summary: string, httpStatus?: number | null): { severity: TriageSeverity; priority: TriagePriority; a5: boolean } {
  const normalized = code.toUpperCase().replace(/^OPENCODEX\./, "").replaceAll("-", "_");
  const a5 = normalized === "SECRET_LEAK_DETECTED" || /permission.?bypass/i.test(summary);
  if (a5) return { severity: "HIGH", priority: "P1", a5: true };
  if (normalized === "AUTHORIZATION_FAILED" || httpStatus === 403) return { severity: "HIGH", priority: "P1", a5: false };
  if (["PATH_POLICY_VIOLATION", "AUTHENTICATION_FAILED"].includes(normalized)) return { severity: "MEDIUM", priority: "P2", a5: false };
  return { severity: "LOW", priority: "P3", a5: false };
}
function severityRank(value: TriageSeverity): number { return ["LOW", "MEDIUM", "HIGH", "CRITICAL"].indexOf(value); }
function timeSequence(start: string, count: number): string[] { const base = Date.parse(start); if (!Number.isFinite(base)) throw new Error("PHASE7_TIME_INVALID"); return Array.from({ length: count }, (_, index) => new Date(base + index * 1_000).toISOString()); }
function closureMemories(incident: Incident, playbookCandidateId: string, at: string): MemoryRecord[] {
  const suffix = incident.revision_hash.slice(7, 23);
  const scopes = [{ type: "REPOSITORY" as const, id: incident.scope.id }];
  const shared = { scopes, temporal: { observed_at: at, valid_from: at, valid_until: null, last_verified_at: at }, relations: { supersedes: [], contradicts: [], derived_from: [] }, access: { sensitivity: "INTERNAL" as const, read_roles: ["*"] }, retention: { policy: "repository-durable" }, created_at: at };
  return [
    createMemoryRecord({ ...shared, memory_id: `memory:incident-episode-${suffix}`, layer: "EPISODE", kind: "opencodex.incident.episode", subject: { type: "incident", key: incident.incident_id }, content: { summary: `Observed incident ${incident.incident_id} closed with preserved evidence.` }, lifecycle: { status: "OBSERVED" }, trust: { level: "HIGH", confidence: incident.confidence }, provenance: { source_refs: [incident.revision_hash], extractor_ref: { id: "phase7-closure", version: "1.0.0" } }, created_by: { type: "system", id: "system:phase7-memory" } }),
    createMemoryRecord({ ...shared, memory_id: `memory:incident-lesson-${suffix}`, layer: "LESSON", kind: "opencodex.incident.confirmed-lesson", subject: { type: "root-cause", key: incident.root_cause.adjudication_id! }, content: { summary: incident.root_cause.statement! }, lifecycle: { status: "VERIFIED" }, trust: { level: "AUTHORITATIVE", confidence: 1 }, provenance: { source_refs: [incident.revision_hash, ...incident.root_cause.evidence_refs], extractor_ref: { id: "phase7-root-cause", version: "1.0.0" } }, created_by: { type: "verifier", id: "verifier:phase7-independent-review" } }),
    createMemoryRecord({ ...shared, memory_id: `memory:incident-procedure-${suffix}`, layer: "PROCEDURE_CANDIDATE", kind: "opencodex.incident.playbook-candidate", subject: { type: "playbook-candidate", key: playbookCandidateId }, content: { summary: `Candidate procedure derived from ${incident.incident_id}; it is not an active skill.` }, lifecycle: { status: "CANDIDATE" }, trust: { level: "HIGH", confidence: 0.9 }, provenance: { source_refs: [incident.revision_hash, playbookCandidateId], extractor_ref: { id: "phase7-playbook", version: "1.0.0" } }, created_by: { type: "system", id: "system:phase7-memory" } }),
  ];
}
function createMemoryWriteBatch(incident: Incident, records: MemoryRecord[], at: string): MemoryWriteBatch {
  const payload = { schema_version: 1 as const, batch_id: `memory-batch:${incident.revision_hash.slice(7, 39)}`, incident_id: incident.incident_id, scope: incident.scope, closure_revision_hash: incident.revision_hash, records, created_at: at };
  return { ...payload, batch_hash: canonicalSha256(payload) };
}
function fail(message: string): never { throw new Error(message); }
