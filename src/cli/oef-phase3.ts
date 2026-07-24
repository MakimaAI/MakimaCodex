import { createHash, randomBytes } from "node:crypto";
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, unlinkSync, writeFileSync, writeSync } from "node:fs";
import { extname, join, resolve } from "node:path";
import {
  SqlitePhase3Store,
  compileReviewPlan,
  createBuiltInReviewTypeRegistry,
  createGovernanceAuditEvent,
  assertGovernanceAuditEventStream,
  createHumanReviewApproval,
  createReviewLaunchPolicyId,
  createReviewSnapshot,
  createRepairProposal,
  createWaiver,
  hashReviewPlan,
  parseReviewPlanState,
  parseReviewRequest,
  reviewProfileSchema,
  runPhase3AcceptanceDemo,
  ReadOnlyReviewEnvironment,
  computeReviewDependencyHash,
  computeReviewTreeHash,
  createReviewSnapshotFileIndex,
  ReviewCoordinator,
  InMemoryReviewEffectPort,
  RunnerReviewExecutor,
  parseReviewerBinding,
  parseReviewFinding,
  parseFindingValidation,
  parseReviewExecutionRecord,
  reviewValidityInputsSchema,
  transitionFinding,
  transitionReviewPlan,
  type GovernanceAuditEvent,
  type ReviewCoordinatorOutcome,
  type ReviewFinding,
  type ReviewPlan,
  type ReviewPlanState,
  type ReviewProfile,
  type ReviewAuditEventType,
  type ReviewArtifactPort,
  type ReviewAuditPort,
  type ReviewCoordinatorDataPort,
  type ReviewCoordinatorExecutorPort,
  type ReviewCommandRunner,
  type ReviewIdentityAuthorityClient,
  verifyRunnerIdentityAttestation,
} from "../oef/phase3";
import { canonicalSha256 } from "../oef/phase1/core/contract/task-contract";
import { createPhase2Runtime, evidencePackageSchema, GitWorktreeWorkspaceManager, runnerClientFromHome, type Phase2Runtime } from "../oef/phase2";

interface ParsedArgs { positionals: string[]; options: Map<string, string | true>; json: boolean }
interface ReviewRunnerClient extends ReviewCommandRunner, ReviewIdentityAuthorityClient { cancelExecution(executionId: string): Promise<void> }
export interface LiveReviewInputs {
  source: string;
  evidence: string;
  artifacts: string;
  current_snapshot: unknown;
  mechanical_evidence: { passed: boolean; evidence_hash: string; artifact_refs: string[] };
  current_validity: unknown;
  validation_authority: {
    contract_revision_id: string;
    contract_refs: string[];
    evidence_refs: string[];
  };
  context_authority: Record<string, unknown>;
}
export interface OefPhase3CliDependencies {
  reviewRunnerFactory?: (home: string) => ReviewRunnerClient;
  resolveLiveReviewInputs?: (input: { store: SqlitePhase3Store; plan: ReviewPlan; run: ConfiguredRun }) => Promise<LiveReviewInputs>;
  afterDecidedReceipt?: (input: { review_plan_id: string; revision: number }) => Promise<void> | void;
}

const REVIEW_COMMANDS = [
  "plan", "bind", "show-plan", "start", "watch", "findings", "finding show", "finding dismiss",
  "waiver create", "approval create", "repair create", "rerun", "cancel", "pause-all",
] as const;

export async function cmdOefPhase3(group: string, args: string[], dependencies: OefPhase3CliDependencies = {}): Promise<number> {
  const parsed = parseArgs(args);
  try {
    let value: unknown;
    if (group === "oef-phase3-demo") value = await runPhase3AcceptanceDemo({ root: resolve(required(parsed, "root")) });
    else if (group === "review") value = await reviewCommand(parsed, dependencies);
    else throw new Error(`Unknown Phase 3 command group: ${group}`);
    console.log(JSON.stringify(value, null, parsed.json ? 0 : 2));
    return 0;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    return 1;
  }
}

async function reviewCommand(parsed: ParsedArgs, dependencies: OefPhase3CliDependencies): Promise<unknown> {
  const command = parsed.positionals[0];
  if (command === "help" || !command) return { commands: [...REVIEW_COMMANDS], json_supported: true };
  const home = reviewHome(parsed);
  mkdirSync(home, { recursive: true });
  const store = new SqlitePhase3Store({ databasePath: join(home, "oef.sqlite") });
  try {
    if (command === "plan") return planCommand(store, parsed);
    if (command === "bind") return await bindCommand(store, home, positional(parsed, 1, "review plan id"), required(parsed, "file"), dependencies);
    if (command === "show-plan") {
      const id = positional(parsed, 1, "review plan id");
      const plan = store.getReviewPlan(id);
      if (!plan) throw new Error(`Review plan not found: ${id}`);
      return { plan, state: store.getReviewPlanState(id), plan_hash: hashReviewPlan(plan) };
    }
    if (command === "watch") {
      const id = positional(parsed, 1, "review plan id");
      const plan = store.getReviewPlan(id);
      if (!plan) throw new Error(`Review plan not found: ${id}`);
      return { plan, state: store.getReviewPlanState(id), findings: store.listFindings(id), events: store.listEvents(id), decision: store.getLatestReviewDecision(id) };
    }
    if (command === "findings") return store.listFindings(positional(parsed, 1, "review plan id"));
    if (command === "finding") return findingCommand(store, parsed);
    if (command === "waiver") return waiverCommand(store, parsed);
    if (command === "approval") return approvalCommand(store, parsed);
    if (command === "repair") return repairCommand(store, home, parsed);
    if (command === "cancel") return await cancelCommand(store, home, positional(parsed, 1, "review plan id"));
    if (command === "pause-all") return pauseAll(home, option(parsed, "reason") ?? "operator pause");
    if (command === "start") return await startCommand(store, home, positional(parsed, 1, "review plan id"), required(parsed, "run-file"), dependencies);
    if (command === "rerun") {
      const planId = positional(parsed, 1, "review plan id");
      const plan = store.getReviewPlan(planId);
      if (!plan || plan.revision < 2) throw new Error("REVIEW_RERUN_REQUIRES_NEW_PLAN_REVISION");
      const previous = store.getReviewPlan(planId, plan.revision - 1);
      if (!previous) throw new Error("REVIEW_RERUN_PREVIOUS_REVISION_MISSING");
      if (previous.snapshot.snapshot_hash === plan.snapshot.snapshot_hash
        && store.listWaivers(planId).length === 0 && !store.getLatestHumanApproval(planId)) {
        throw new Error("REVIEW_RERUN_REQUIRES_NEW_SNAPSHOT_OR_GOVERNANCE_CHANGE");
      }
      return await startCommand(store, home, planId, required(parsed, "run-file"), dependencies);
    }
    throw new Error(`Unknown review command: ${command}`);
  } finally { store.close(); }
}

function planCommand(store: SqlitePhase3Store, parsed: ParsedArgs): unknown {
  const raw = readDataFile(required(parsed, "file")) as Record<string, unknown>;
  const request = parseReviewRequest(raw.review_request);
  const rawProfiles = raw.profiles as Record<string, unknown>;
  if (!rawProfiles || typeof rawProfiles !== "object") throw new Error("Review plan input requires profiles");
  const profiles = Object.fromEntries(Object.entries(rawProfiles).map(([type, profile]) => [type, reviewProfileSchema.parse(profile)])) as Record<string, ReviewProfile>;
  const registry = createBuiltInReviewTypeRegistry(Object.fromEntries(Object.entries(profiles).map(([type, profile]) => [type, {
    id: profile.review_profile_id, version: profile.version, hash: profile.content_hash,
  }])));
  const plan = compileReviewPlan({
    ...(raw.compiler_input as Omit<Parameters<typeof compileReviewPlan>[0], "registry" | "profiles" | "review_request_id" | "task_id">),
    review_request_id: request.review_request_id,
    task_id: request.task_id,
    registry,
    profiles,
  });
  const previousPlan = plan.revision > 1 ? store.getReviewPlan(plan.review_plan_id, plan.revision - 1) : null;
  const previousState = plan.revision > 1 ? store.getReviewPlanState(plan.review_plan_id) : null;
  if (plan.revision > 1 && !previousState) throw new Error("REVIEW_PLAN_PREVIOUS_REVISION_STATE_MISSING");
  if (previousPlan?.snapshot.snapshot_hash === plan.snapshot.snapshot_hash
    && store.listWaivers(plan.review_plan_id).length === 0 && !store.getLatestHumanApproval(plan.review_plan_id)) {
    throw new Error("REVIEW_PLAN_REVISION_REQUIRES_NEW_SNAPSHOT_OR_GOVERNANCE_CHANGE");
  }
  const supersedeRequired = previousState !== null && previousState.status !== "SUPERSEDED";
  const state = parseReviewPlanState({
    schema_version: 1,
    review_plan_id: plan.review_plan_id,
    snapshot_hash: plan.snapshot.snapshot_hash,
    status: "CREATED",
    unit_states: plan.review_units.map(unit => ({ review_unit_id: unit.review_unit_id, status: "CREATED", review_execution_id: null, result_artifact_id: null })),
    counters: { review_rounds: 0, repair_rounds: 0, evidence_requests: 0, adjudication_rounds: 0, total_cost_units: 0 },
    aggregate_version: previousState ? previousState.aggregate_version + (supersedeRequired ? 2 : 1) : 1,
    created_at: plan.created_at,
    updated_at: plan.created_at,
  });
  const validityBaseline = reviewValidityInputsSchema.parse(raw.validity_baseline);
  store.transaction(() => {
    if (previousState && supersedeRequired) {
      transitionReviewPlan(previousState.status, "SUPERSEDED");
      const superseded = parseReviewPlanState({
        ...previousState,
        status: "SUPERSEDED",
        aggregate_version: previousState.aggregate_version + 1,
        updated_at: plan.created_at,
      });
      if (!store.updateReviewPlanState(superseded, previousState.aggregate_version)) throw new Error("REVIEW_PLAN_SUPERSEDE_CONFLICT");
    }
    for (const profile of Object.values(profiles)) if (!store.getReviewProfile(profile.review_profile_id, profile.version)) store.insertReviewProfile(profile);
    store.insertReviewRequest(request);
    store.insertReviewPlan(plan, hashReviewPlan(plan), state);
    store.insertReviewValidityBaseline(plan.review_plan_id, plan.revision, validityBaseline, plan.created_at);
  });
  ensurePlanCreatedAudit(store, plan.review_plan_id);
  return { plan, state, plan_hash: hashReviewPlan(plan) };
}

async function bindCommand(store: SqlitePhase3Store, home: string, planId: string, file: string, dependencies: OefPhase3CliDependencies): Promise<unknown> {
  const plan = store.getReviewPlan(planId);
  if (!plan) throw new Error(`Review plan not found: ${planId}`);
  const raw = readDataFile(file);
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("REVIEW_BINDING_FILE_INVALID");
  const value = raw as Record<string, unknown>;
  if (typeof value.runner_home !== "string" || resolve(value.runner_home) !== resolve(home)) throw new Error("REVIEW_BINDING_RUNNER_HOME_MISMATCH");
  const binding = parseReviewerBinding(value.reviewer_binding);
  const policy = value.launch_policy as { docker_image?: unknown; executable?: unknown; arguments?: unknown } | undefined;
  if (!policy || typeof policy.docker_image !== "string" || typeof policy.executable !== "string" || !Array.isArray(policy.arguments)
    || policy.arguments.some(argument => typeof argument !== "string")) throw new Error("REVIEW_BINDING_LAUNCH_POLICY_INVALID");
  const launchPolicyId = createReviewLaunchPolicyId({ docker_image: policy.docker_image, executable: policy.executable, arguments: policy.arguments as string[] });
  const unit = plan.review_units.find(candidate => candidate.review_unit_id === binding.review_unit_id);
  if (!unit || canonicalSha256(binding.reviewer_profile_ref) !== canonicalSha256(unit.profile_ref)
    || binding.risk_level !== plan.risk.level || binding.independence.source_access !== "read-only"
    || binding.runtime_ref.id !== launchPolicyId) {
    throw new Error("REVIEW_BINDING_PLAN_MISMATCH");
  }
  const runner = dependencies.reviewRunnerFactory?.(resolve(value.runner_home)) ?? runnerClientFromHome(resolve(value.runner_home));
  const trustedPolicy = await runner.getReviewLaunchPolicy(launchPolicyId);
  if (canonicalSha256(trustedPolicy.reviewer) !== canonicalSha256(binding.independence.reviewer)) throw new Error("REVIEW_BINDING_RUNNER_IDENTITY_MISMATCH");
  store.insertReviewerBinding(binding);
  return { review_plan_id: planId, reviewer_binding: binding };
}

function findingCommand(store: SqlitePhase3Store, parsed: ParsedArgs): unknown {
  const subcommand = parsed.positionals[1];
  const findingId = positional(parsed, 2, "finding id");
  const finding = store.getFinding(findingId);
  if (!finding) throw new Error(`Finding not found: ${findingId}`);
  if (subcommand === "show") return finding;
  if (subcommand === "dismiss") {
    ensurePlanCreatedAudit(store, finding.review_plan_id);
    const rationale = required(parsed, "rationale");
    transitionFinding(finding.status, "DISMISSED");
    const updated = { ...finding, status: "DISMISSED" as const, effective_severity: null, updated_at: new Date().toISOString() };
    store.transaction(() => {
      if (!store.updateFinding(updated, finding.status)) throw new Error("Finding update conflict");
      appendStoreAuditEvent(store, finding.review_plan_id, "finding.dismissed", {
        finding_id: finding.finding_id,
        finding_key: finding.finding_key,
        severity: finding.proposed_severity,
        rationale,
      });
    });
    return { finding: updated, rationale };
  }
  throw new Error("Usage: ocx review finding <show|dismiss> <finding-id> [--rationale ...] --json");
}

function waiverCommand(store: SqlitePhase3Store, parsed: ParsedArgs): unknown {
  if (parsed.positionals[1] !== "create") throw new Error("Usage: ocx review waiver create --finding <id> --rationale <text> [--expires <date>] --json");
  const finding = store.getFinding(required(parsed, "finding"));
  if (!finding) throw new Error("Finding not found");
  ensurePlanCreatedAudit(store, finding.review_plan_id);
  requireInteractiveHumanConfirmation(parsed, finding.scope.snapshot_hash);
  const expires = option(parsed, "expires");
  const waiver = createWaiver({
    waiver_id: `review-waiver:${digest(`${finding.finding_id}:${required(parsed, "rationale")}:${expires ?? "never"}`).slice(0, 24)}`,
    finding,
    decision: "ACCEPTED_RISK",
    rationale: required(parsed, "rationale"),
    approved_by: authenticatedLocalHuman(parsed),
    expires_at: expires ? normalizeDate(expires) : null,
    conditions: (option(parsed, "conditions") ?? "no-severity-increase").split(",").map(value => value.trim()).filter(Boolean),
    snapshot_hash: finding.scope.snapshot_hash,
    created_at: new Date().toISOString(),
  });
  store.transaction(() => {
    store.insertWaiver(waiver);
    appendStoreAuditEvent(store, finding.review_plan_id, "finding.waived", {
      finding_id: finding.finding_id,
      finding_key: finding.finding_key,
      severity: finding.effective_severity ?? undefined,
      waiver_id: waiver.waiver_id,
    });
  });
  return waiver;
}

function approvalCommand(store: SqlitePhase3Store, parsed: ParsedArgs): unknown {
  if (parsed.positionals[1] !== "create") throw new Error("Usage: ocx review approval create <review-plan-id> --rationale <text> --json");
  const planId = positional(parsed, 2, "review plan id");
  const plan = store.getReviewPlan(planId);
  if (!plan) throw new Error(`Review plan not found: ${planId}`);
  const state = store.getReviewPlanState(planId);
  const reviewDecision = store.getLatestReviewDecision(planId);
  if (state?.status !== "NEEDS_HUMAN" || reviewDecision?.decision !== "NEEDS_HUMAN") throw new Error("REVIEW_HUMAN_APPROVAL_REQUIRES_NEEDS_HUMAN_DECISION");
  requireInteractiveHumanConfirmation(parsed, plan.snapshot.snapshot_hash);
  if (required(parsed, "confirm-decision") !== canonicalSha256(reviewDecision)) throw new Error("REVIEW_HUMAN_APPROVAL_DECISION_CONFIRMATION_MISMATCH");
  ensurePlanCreatedAudit(store, planId);
  const approvedAt = new Date().toISOString();
  const approval = createHumanReviewApproval({
    approval_id: `review-approval:${digest(`${planId}:${required(parsed, "rationale")}:${approvedAt}`).slice(0, 24)}`,
    review_plan_id: planId,
    snapshot_hash: plan.snapshot.snapshot_hash,
    review_decision_id: reviewDecision.review_decision_id,
    review_decision_hash: canonicalSha256(reviewDecision),
    finding_ids: [...new Set([...reviewDecision.accepted_findings, ...reviewDecision.unresolved_findings])].sort(),
    decision: "APPROVE",
    rationale: required(parsed, "rationale"),
    approved_by: authenticatedLocalHuman(parsed),
    approval_artifact_ref: option(parsed, "artifact") ?? `artifact:human-approval-${digest(planId).slice(0, 24)}`,
    approved_at: approvedAt,
  });
  store.transaction(() => {
    store.insertHumanApproval(approval);
    appendStoreAuditEvent(store, planId, "review.human-approved", {
      human_approval_id: approval.approval_id,
      snapshot_hash: approval.snapshot_hash,
      review_decision_id: approval.review_decision_id,
      review_decision_hash: approval.review_decision_hash,
      finding_ids: approval.finding_ids,
      artifact_refs: [{ artifact_id: approval.approval_artifact_ref, artifact_hash: approval.approval_hash, kind: "human-decision" }],
    });
  });
  return approval;
}

function appendStoreAuditEvent(
  store: SqlitePhase3Store,
  planId: string,
  eventType: ReviewAuditEventType,
  payload: Record<string, unknown>,
  actor: { type: "human" | "system"; id: string } = { type: "human", id: "human:local-owner" },
): void {
  const eventId = storeAuditEventId(planId, eventType, payload);
  const existing = store.listEvents(planId).find(candidate => candidate.event_id === eventId);
  if (existing) {
    if (existing.event_type !== eventType || canonicalSha256(existing.payload) !== canonicalSha256(payload)
      || canonicalSha256(existing.actor) !== canonicalSha256(actor)) throw new Error("REVIEW_AUDIT_EVENT_IDEMPOTENCY_CONFLICT");
    return;
  }
  const event = buildStoreAuditEvent(store, planId, eventType, payload, actor);
  store.appendEvent(event);
}

function buildStoreAuditEvent(
  store: SqlitePhase3Store,
  planId: string,
  eventType: ReviewAuditEventType,
  payload: Record<string, unknown>,
  actor: { type: "human" | "system"; id: string } = { type: "human", id: "human:local-owner" },
): GovernanceAuditEvent {
  const plan = store.getReviewPlan(planId);
  if (!plan) throw new Error(`Review plan not found: ${planId}`);
  const events = store.listEvents(planId);
  const event = createGovernanceAuditEvent({
    event_id: storeAuditEventId(planId, eventType, payload),
    event_type: eventType,
    aggregate_type: "review-plan",
    aggregate_id: planId,
    aggregate_version: events.length + 1,
    task_id: plan.task_id,
    occurred_at: new Date().toISOString(),
    actor,
    payload,
    previous_event_hash: events.at(-1)?.event_hash ?? null,
  });
  return event;
}

function storeAuditEventId(planId: string, eventType: ReviewAuditEventType, payload: Record<string, unknown>): string {
  return `review-event:${digest(`${planId}:${eventType}:${JSON.stringify(payload)}`).slice(0, 32)}`;
}

function repairCommand(store: SqlitePhase3Store, home: string, parsed: ParsedArgs): unknown {
  if (parsed.positionals[1] !== "create") throw new Error("Usage: ocx review repair create <review-plan-id> --json");
  const planId = positional(parsed, 2, "review plan id");
  const plan = store.getReviewPlan(planId);
  if (!plan) throw new Error(`Review plan not found: ${planId}`);
  ensurePlanCreatedAudit(store, planId);
  const decision = store.getLatestReviewDecision(planId);
  if (!decision || decision.decision !== "CHANGES_REQUESTED") throw new Error("REVIEW_REPAIR_REQUIRES_CHANGES_REQUESTED_DECISION");
  const blockerIds = [...new Set(decision.accepted_findings)].sort();
  const findings = store.listFindings(planId)
    .filter(finding => finding.status === "CONFIRMED" && blockerIds.includes(finding.finding_id))
    .sort((left, right) => left.finding_id.localeCompare(right.finding_id));
  if (canonicalSha256(findings.map(finding => finding.finding_id)) !== canonicalSha256(blockerIds)) throw new Error("REVIEW_REPAIR_FINDING_LINEAGE_MISMATCH");
  const proposal = createRepairProposal({
    repair_proposal_id: `repair-proposal:${digest(`${planId}:${findings.map(item => item.finding_id).sort().join(",")}`).slice(0, 24)}`,
    task_id: plan.task_id,
    source_review_plan_id: planId,
    findings,
    constraints: ["Preserve all verified behavior outside the target findings."],
    required_evidence: [...new Set(findings.flatMap(finding => finding.evidence_refs))],
    created_at: decision.issued_at,
  });
  const proposalAuditPayload = {
    repair_proposal_id: proposal.repair_proposal_id,
    finding_ids: blockerIds,
    artifact_refs: [{ artifact_id: `artifact:${digest(proposal.repair_proposal_id).slice(0, 32)}`, artifact_hash: canonicalSha256(proposal), kind: "finding-report" as const }],
  };
  store.transaction(() => {
    store.insertRepairProposal(proposal);
    appendStoreAuditEvent(store, planId, "repair.proposed", proposalAuditPayload);
  });
  const runtime = createPhase2Runtime({ home });
  try {
    const task = runtime.phase1.store.getTask(plan.task_id);
    if (!task?.active_contract_revision_id) throw new Error("REPAIR_PHASE1_ACTIVE_CONTRACT_REQUIRED");
    const contract = runtime.phase1.store.getContractRevision(task.active_contract_revision_id);
    if (!contract || contract.canonical_hash !== plan.snapshot.contract.hash) throw new Error("REPAIR_CONTRACT_SNAPSHOT_MISMATCH");
    const assignmentId = `assignment:repair-${digest(proposal.repair_proposal_id).slice(0, 24)}`;
    const assignmentAuditPayload = { repair_assignment_id: assignmentId, repair_proposal_id: proposal.repair_proposal_id };
    assertGovernanceAuditEventStream([...store.listEvents(planId), buildStoreAuditEvent(store, planId, "repair.assignment.created", assignmentAuditPayload)]);
    const assignment = phase2Command(runtime, plan.task_id, assignmentId, {
      contract_ref: { revision_id: contract.revision_id, hash: contract.canonical_hash },
      objective: proposal.objective,
      role: "backend-repairer",
      scope: { allowed_paths: proposal.scope.allowed_paths, denied_paths: [".github/**", ".git/**"] },
      required_capabilities: ["repository-read", "repository-write", "shell", "git", "structured-output"],
      preferred_capabilities: [],
      verification: { commands: [] },
      required_evidence: proposal.required_evidence.map(value => value.toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-|-$/g, "")),
      budgets: { max_wall_time_seconds: 3_600, max_idle_seconds: 300, max_attempts: 3, max_output_bytes: 10_000_000 },
    }, `command:repair-${digest(proposal.repair_proposal_id).slice(0, 24)}`);
    appendStoreAuditEvent(store, planId, "repair.assignment.created", assignmentAuditPayload);
    return { proposal, assignment, lineage: { source_review_plan_id: planId, repair_proposal_id: proposal.repair_proposal_id } };
  } finally { runtime.close(); }
}

function phase2Command(runtime: Phase2Runtime, taskId: string, assignmentId: string, payload: unknown, commandId = runtime.ids.next("command")) {
  const result = runtime.bus.execute({
    schema_version: 1,
    command_id: commandId,
    command_type: "CreateAssignment",
    task_id: taskId,
    aggregate_id: assignmentId,
    expected_aggregate_version: 0,
    actor: { type: "human", id: "human:local-owner" },
    idempotency_key: commandId,
    payload,
  });
  if (!result.ok || !result.value.assignment) throw new Error(result.ok ? "REPAIR_ASSIGNMENT_NOT_CREATED" : JSON.stringify(result.error));
  return result.value.assignment;
}

async function cancelCommand(store: SqlitePhase3Store, home: string, planId: string): Promise<unknown> {
  const plan = store.getReviewPlan(planId);
  if (!plan) throw new Error(`Review plan not found: ${planId}`);
  const state = store.getReviewPlanState(planId);
  if (!state) throw new Error(`Review plan state not found: ${planId}`);
  transitionReviewPlan(state.status, "CANCELLED");
  const runPath = reviewRunPath(home, planId, plan.revision);
  let runner_signalled = false;
  if (existsSync(runPath)) {
    const run = readReviewRunReceipt(runPath) as { runner_home?: unknown; status?: unknown; execution_ids?: unknown };
    if (run.status === "RUNNING" && typeof run.runner_home === "string" && Array.isArray(run.execution_ids)) {
      const client = runnerClientFromHome(run.runner_home);
      for (const executionId of run.execution_ids) {
        if (typeof executionId !== "string" || !executionId.startsWith("execution:review-")) throw new Error("REVIEW_RUN_RECEIPT_INVALID");
        await client.cancelExecution(executionId);
      }
      runner_signalled = true;
    }
    writeReviewRunReceipt(runPath, { ...run, receipt_hash: undefined, status: "CANCELLED", cancelled_at: new Date().toISOString() });
  }
  const next = { ...state, status: "CANCELLED" as const, aggregate_version: state.aggregate_version + 1, updated_at: new Date().toISOString() };
  if (!store.updateReviewPlanState(next, state.aggregate_version)) throw new Error("Review cancellation update conflict");
  return { state: next, runner_signalled };
}

interface ConfiguredRun {
  review_plan_id: string;
  snapshot_hash: string;
  runner_home: string;
  source: string;
  docker_image: string;
  satisfied_prerequisites: Record<string, string[]>;
  reviewer_commands: Array<{
    review_type: string;
    executable: string;
    arguments?: string[];
    reviewer_binding_id: string;
  }>;
  timeout_seconds?: number;
  output_limit_bytes?: number;
}

/** Runs the durable Phase 3 lifecycle: isolated review, validation, adjudication and persistence. */
async function startCommand(store: SqlitePhase3Store, home: string, planId: string, runFile: string, dependencies: OefPhase3CliDependencies): Promise<unknown> {
  const plan = store.getReviewPlan(planId);
  if (!plan) throw new Error(`Review plan not found: ${planId}`);
  const run = configuredRun(runFile, planId);
  if (resolve(run.runner_home) !== resolve(home)) throw new Error("REVIEW_RUNNER_HOME_CONTROL_PLANE_MISMATCH");
  if (run.snapshot_hash !== plan.snapshot.snapshot_hash) throw new Error("REVIEW_RUN_SNAPSHOT_MISMATCH");
  const baseline = store.getReviewValidityBaseline(planId, plan.revision);
  if (!baseline) throw new Error("REVIEW_VALIDITY_BASELINE_MISSING");
  const resolveCurrentInputs = () => dependencies.resolveLiveReviewInputs?.({ store, plan, run }) ?? resolveLiveReviewInputs(store, plan, run);
  const live = await resolveCurrentInputs();
  const replayFingerprint = reviewReplayFingerprint(store, planId, baseline, live, new Date().toISOString());
  const runPath = reviewRunPath(home, planId, plan.revision);
  let decidedReceipt: Record<string, unknown> | null = null;
  if (existsSync(runPath)) {
    const receipt = readReviewRunReceipt(runPath) as { snapshot_hash?: unknown; status?: unknown; outcome?: unknown; replay_fingerprint?: unknown };
    if (receipt.snapshot_hash === run.snapshot_hash && receipt.status === "TERMINAL" && receipt.outcome) {
      assertTerminalRunReceipt(store, plan, receipt);
      if (receipt.replay_fingerprint !== replayFingerprint) {
        supersedeTerminalReview(store, planId);
        throw new Error("REVIEW_TERMINAL_RESULT_STALE_NEW_REVISION_REQUIRED");
      }
      return receipt;
    }
    if (receipt.snapshot_hash === run.snapshot_hash && receipt.status === "DECIDED" && receipt.outcome) decidedReceipt = receipt;
  }
  if (!decidedReceipt) assertReviewStartAllowed(home);
  const releaseRunLock = acquireReviewRunLock(runPath);
  if (decidedReceipt) {
    try { return recoverDecidedReview(store, plan, runPath, decidedReceipt, replayFingerprint); }
    finally { releaseRunLock(); }
  }
  const executionIds = plan.review_units.map(unit => phase2ReviewExecutionId(planId, plan.revision, unit.review_unit_id));
  const started = { schema_version: 1, review_plan_id: planId, review_plan_revision: plan.revision, runner_home: run.runner_home, snapshot_hash: run.snapshot_hash, execution_ids: executionIds, status: "RUNNING", started_at: new Date().toISOString() };
  mkdirSync(join(home, "phase3", "runs"), { recursive: true });
  const environment = new ReadOnlyReviewEnvironment({ root: join(home, "phase3", "prepared") });
  let prepared: ReturnType<ReadOnlyReviewEnvironment["prepare"]> | null = null;
  try {
    ensurePlanCreatedAudit(store, planId);
    advanceToRunning(store, planId);
    writeReviewRunReceipt(runPath, started);
    prepared = environment.prepare({ source: live.source, evidence: live.evidence, artifacts: live.artifacts });
    const expectedPreparedTree = reviewValidityInputsSchema.parse(live.current_validity).source_tree_hash;
    if (prepared.source_manifest_hash !== expectedPreparedTree) throw new Error("REVIEW_PREPARED_SOURCE_SNAPSHOT_MISMATCH");
    const trustedSnapshotFiles = createReviewSnapshotFileIndex(prepared.source);
    const runner = dependencies.reviewRunnerFactory?.(run.runner_home) ?? runnerClientFromHome(run.runner_home);
    const identityAuthority = await runner.getReviewIdentityAuthority();
    const isolated = new RunnerReviewExecutor({
      runner, environment, sandbox: { image: run.docker_image }, identity_authority: runner,
    });
    const commandFor = (reviewType: string) => {
      const command = run.reviewer_commands.find(value => value.review_type === reviewType);
      if (!command) throw new Error(`REVIEW_RUN_COMMAND_MISSING: ${reviewType}`);
      return command;
    };
    const artifacts = new DurableReviewArtifactPort(join(home, "phase3", "artifacts"));
    const audit = new StoreReviewAuditPort(store, planId, plan.task_id);
    const executionEvidence: Array<{
      review_execution_id: string; review_unit_id: string; reviewer_binding_id: string;
      status: "COMPLETED" | "FAILED" | "CANCELLED"; output_hash: string; artifact_ref: string; occurred_at: string;
      runtime_attestation_hash: string; runtime_attestation_key_id: string; runtime_attestation_signature: string;
    }> = [];
    let snapshotReads = 0;
    let mechanicalReads = 0;
    let validityReads = 0;
    const data: ReviewCoordinatorDataPort = {
      async loadPlan(id) { const value = store.getReviewPlan(id); if (!value) throw new Error("REVIEW_PLAN_NOT_FOUND"); return value; },
      async loadPlanState(id) { const value = store.getReviewPlanState(id); if (!value) throw new Error("REVIEW_PLAN_STATE_NOT_FOUND"); return value; },
      async loadCurrentSnapshot() { return snapshotReads++ === 0 ? live.current_snapshot : (await resolveCurrentInputs()).current_snapshot; },
      async loadMechanicalEvidence() { return mechanicalReads++ === 0 ? live.mechanical_evidence : (await resolveCurrentInputs()).mechanical_evidence; },
      async loadSatisfiedPrerequisites(unitId) { return run.satisfied_prerequisites[unitId] ?? []; },
      async loadReviewerBinding(unitId) {
        const unit = plan.review_units.find(candidate => candidate.review_unit_id === unitId);
        if (!unit) throw new Error("REVIEW_UNIT_NOT_FOUND");
        const binding = store.getReviewerBinding(commandFor(unit.review_type).reviewer_binding_id);
        if (!binding) throw new Error("REVIEW_RUN_TRUSTED_BINDING_MISSING");
        return binding;
      },
      async buildContextInput(unit, priorFindings) {
        const raw = live.context_authority[unit.review_unit_id];
        if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("REVIEW_RUN_CONTEXT_INVALID");
        return { ...(raw as Record<string, unknown>), previous_findings: priorFindings };
      },
      async loadResultValidationContext(unitId) {
        if (!plan.review_units.some(candidate => candidate.review_unit_id === unitId)) throw new Error("REVIEW_UNIT_NOT_FOUND");
        return { review_unit_id: unitId, snapshot_hash: plan.snapshot.snapshot_hash, snapshot_files: trustedSnapshotFiles, evidence_refs: live.validation_authority.evidence_refs };
      },
      async loadFindingValidationContext() {
        return {
          snapshot_hash: plan.snapshot.snapshot_hash,
          contract_revision_id: live.validation_authority.contract_revision_id,
          files: trustedSnapshotFiles.map(file => ({ path: file.path, hash: file.file_hash, line_count: file.line_count })),
          contract_refs: live.validation_authority.contract_refs,
          evidence_refs: live.validation_authority.evidence_refs,
        };
      },
      async loadWaivers(id) { return store.listWaivers(id); },
      async loadReviewValidityBaseline() { return baseline; },
      async loadCurrentReviewValidity() {
        return reviewValidityInputsSchema.parse(validityReads++ === 0 ? live.current_validity : (await resolveCurrentInputs()).current_validity);
      },
      async loadHumanApproval(id) { return store.getLatestHumanApproval(id); },
      async loadLatestReviewDecision(id) { return store.getLatestReviewDecision(id); },
      async verifyRuntimeIdentityAttestation(attestation) {
        return verifyRunnerIdentityAttestation(attestation as Parameters<typeof verifyRunnerIdentityAttestation>[0], identityAuthority);
      },
    };
    const executor: ReviewCoordinatorExecutorPort = {
      async execute(input) {
        const command = commandFor(input.unit.review_type);
        const binding = store.getReviewerBinding(command.reviewer_binding_id);
        if (!binding) throw new Error("REVIEW_RUN_TRUSTED_BINDING_MISSING");
        const promptHash = canonicalSha256(input.context);
        const renderedPromptArtifactRef = `artifact:${canonicalSha256({ executionId: input.review_execution_id, type: "rendered-prompt" }).slice(7, 39)}`;
        await artifacts.putJson({
          idempotency_key: `${input.review_execution_id}:rendered-prompt`,
          artifact_ref: renderedPromptArtifactRef,
          value: {
            schema_version: 1,
            review_execution_id: input.review_execution_id,
            media_type: "application/json",
            transport: "stdin-json",
            prompt_hash: promptHash,
            rendered_context: JSON.stringify(input.context),
          },
        });
        const persisted = store.getReviewExecution(input.review_execution_id);
        if (persisted?.status === "COMPLETED") {
          const recovered = artifacts.getJson(`${input.review_execution_id}:attested-result`) as {
            raw_output?: unknown; output_hash?: unknown; runtime_attestation?: unknown; isolation?: unknown; cost_units?: unknown;
          };
          if (typeof recovered.raw_output !== "string" || recovered.output_hash !== persisted.output_hash
            || canonicalSha256(recovered.raw_output) !== persisted.output_hash
            || !recovered.runtime_attestation || typeof recovered.runtime_attestation !== "object"
            || (recovered.runtime_attestation as { attestation_hash?: unknown }).attestation_hash !== persisted.runtime_attestation_hash) {
            throw new Error("REVIEW_PERSISTED_EXECUTION_ATTESTATION_MISMATCH");
          }
          return {
            status: "COMPLETED", raw_output: recovered.raw_output, output_hash: persisted.output_hash!,
            cost_units: typeof recovered.cost_units === "number" ? recovered.cost_units : 0,
            runtime_attestation: recovered.runtime_attestation as never,
          };
        }
        const launchPolicyId = createReviewLaunchPolicyId({
          docker_image: run.docker_image, executable: command.executable, arguments: command.arguments ?? [],
        });
        if (binding.runtime_ref.id !== launchPolicyId) throw new Error("REVIEW_RUN_LAUNCH_POLICY_MISMATCH");
        const trustedPolicy = await runner.getReviewLaunchPolicy(launchPolicyId);
        if (canonicalSha256(trustedPolicy.reviewer) !== canonicalSha256(binding.independence.reviewer)) throw new Error("REVIEW_RUN_RUNNER_IDENTITY_MISMATCH");
        const outcome = await isolated.execute({
          review_execution_id: input.review_execution_id,
          attempt_id: `attempt:review-${digest(`${planId}:${input.unit.review_unit_id}`).slice(0, 24)}`,
          environment_id: prepared!.environment_id,
          executable: command.executable,
          arguments: command.arguments ?? [],
          context: input.context as Record<string, unknown>,
          prompt_hash: promptHash,
          inherited_environment: ["PATH", "SYSTEMROOT", "TEMP", "TMP"],
          timeout_seconds: run.timeout_seconds ?? 300,
          output_limit_bytes: run.output_limit_bytes ?? 1_000_000,
          launch_policy_id: launchPolicyId,
          reviewer_identity: binding.independence.reviewer,
        });
        const outputHash = canonicalSha256(outcome.raw_output);
        const attestationArtifactRef = `artifact:${canonicalSha256({ execution: input.review_execution_id, type: "attested-result" }).slice(7, 39)}`;
        await artifacts.putJson({
          idempotency_key: `${input.review_execution_id}:attested-result`, artifact_ref: attestationArtifactRef,
          value: { raw_output: outcome.raw_output, output_hash: outputHash, cost_units: 1, runtime_attestation: outcome.runtime_identity, isolation: outcome.isolation },
        });
        const durableExecution = {
          review_execution_id: input.review_execution_id,
          review_unit_id: input.unit.review_unit_id,
          reviewer_binding_id: binding.reviewer_binding_id,
          status: outcome.status,
          output_hash: outputHash,
          artifact_ref: attestationArtifactRef,
          runtime_attestation_hash: outcome.runtime_identity.attestation_hash,
          runtime_attestation_key_id: outcome.runtime_identity.attestation_key_id,
          runtime_attestation_signature: outcome.runtime_identity.attestation_signature,
          occurred_at: new Date().toISOString(),
        };
        persistReviewExecutions(store, plan, [durableExecution]);
        executionEvidence.push(durableExecution);
        return {
          status: outcome.status,
          raw_output: outcome.raw_output,
          output_hash: outputHash,
          cost_units: 1,
          runtime_attestation: {
            ...outcome.runtime_identity,
            isolation: {
              mechanism: "docker" as const,
              network: "denied" as const,
              credentials: "unmounted" as const,
              source: "read-only" as const,
              image_digest: outcome.isolation.image_digest,
              attested_by: "runner-review-executor",
            },
          },
        };
      },
      async cancelPlan() {
        for (const executionId of executionIds) await runner.cancelExecution(executionId);
      },
    };
    const coordinator = new ReviewCoordinator({
      data, executor, artifacts, audit, effects: new InMemoryReviewEffectPort(),
      cancellation: { async isCancellationRequested() { return runCancellationRequested(home, planId, plan.revision); } },
      clock: () => new Date().toISOString(),
    });
    const outcome = await coordinator.run({ review_plan_id: planId });
    persistReviewExecutions(store, plan, executionEvidence);
    const decided = { ...started, status: "DECIDED", decided_at: new Date().toISOString(), replay_fingerprint: replayFingerprint, outcome };
    writeReviewRunReceipt(runPath, decided);
    await dependencies.afterDecidedReceipt?.({ review_plan_id: planId, revision: plan.revision });
    store.transaction(() => {
      persistCoordinatorOutcome(store, planId, outcome);
      advanceToTerminal(store, planId, outcome);
    });
    const completed = { ...decided, status: "TERMINAL", completed_at: new Date().toISOString() };
    writeReviewRunReceipt(runPath, completed);
    return completed;
  } catch (error) {
    const current = existsSync(runPath) ? readReviewRunReceipt(runPath) : null;
    if (current?.status !== "DECIDED") writeReviewRunReceipt(runPath, { ...started, status: "FAILED", failed_at: new Date().toISOString() });
    throw error;
  } finally {
    if (prepared) environment.release(prepared.environment_id);
    releaseRunLock();
  }
}

function recoverDecidedReview(
  store: SqlitePhase3Store,
  plan: ReviewPlan,
  runPath: string,
  receipt: Record<string, unknown>,
  replayFingerprint: string,
): Record<string, unknown> {
  const outcome = receipt.outcome as ReviewCoordinatorOutcome | undefined;
  if (!outcome || outcome.decision.review_plan_id !== plan.review_plan_id
    || outcome.decision.snapshot_hash !== plan.snapshot.snapshot_hash
    || receipt.review_plan_revision !== plan.revision) throw new Error("REVIEW_DECIDED_RECEIPT_BINDING_INVALID");
  if (receipt.replay_fingerprint !== replayFingerprint) throw new Error("REVIEW_DECIDED_RESULT_STALE_NEW_REVISION_REQUIRED");
  store.transaction(() => {
    persistCoordinatorOutcome(store, plan.review_plan_id, outcome);
    const state = requiredPlanState(store, plan.review_plan_id);
    if (state.status === "RUNNING") advanceToTerminal(store, plan.review_plan_id, outcome);
    else if (!["PASSED", "CHANGES_REQUESTED", "BLOCKED", "NEEDS_HUMAN", "INCONCLUSIVE", "CANCELLED"].includes(state.status)) {
      throw new Error(`REVIEW_DECIDED_RECOVERY_STATE_INVALID: ${state.status}`);
    }
  });
  const completed = { ...receipt, status: "TERMINAL", completed_at: new Date().toISOString() };
  writeReviewRunReceipt(runPath, completed);
  assertTerminalRunReceipt(store, plan, completed);
  return completed;
}

function configuredRun(pathInput: string, planId: string): ConfiguredRun {
  const raw = readDataFile(pathInput);
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("REVIEW_RUN_FILE_INVALID");
  const value = raw as Record<string, unknown>;
  const requiredStrings = ["review_plan_id", "snapshot_hash", "runner_home", "source", "docker_image"] as const;
  for (const key of requiredStrings) if (typeof value[key] !== "string" || !(value[key] as string).trim()) throw new Error(`REVIEW_RUN_FILE_${key.toUpperCase()}_REQUIRED`);
  if (value.review_plan_id !== planId) throw new Error("REVIEW_RUN_PLAN_MISMATCH");
  if (!value.satisfied_prerequisites || typeof value.satisfied_prerequisites !== "object" || Array.isArray(value.satisfied_prerequisites)) throw new Error("REVIEW_RUN_FILE_SATISFIED_PREREQUISITES_REQUIRED");
  const satisfied_prerequisites = Object.fromEntries(Object.entries(value.satisfied_prerequisites as Record<string, unknown>).map(([unitId, items]) => {
    if (!Array.isArray(items) || items.some(item => typeof item !== "string")) throw new Error("REVIEW_RUN_FILE_SATISFIED_PREREQUISITES_INVALID");
    return [unitId, items as string[]];
  }));
  if (!Array.isArray(value.reviewer_commands)) throw new Error("REVIEW_RUN_FILE_REVIEWER_COMMANDS_REQUIRED");
  const reviewer_commands = value.reviewer_commands.map(item => {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error("REVIEW_RUN_COMMAND_INVALID");
    const command = item as Record<string, unknown>;
    if (typeof command.review_type !== "string" || typeof command.executable !== "string" || (command.arguments !== undefined && (!Array.isArray(command.arguments) || command.arguments.some(value => typeof value !== "string")))
      || typeof command.reviewer_binding_id !== "string") throw new Error("REVIEW_RUN_COMMAND_INVALID");
    return {
      review_type: command.review_type,
      executable: command.executable,
      arguments: command.arguments as string[] | undefined,
      reviewer_binding_id: command.reviewer_binding_id,
    };
  });
  return {
    review_plan_id: value.review_plan_id as string, snapshot_hash: value.snapshot_hash as string,
    runner_home: resolve(value.runner_home as string), source: resolve(value.source as string),
    docker_image: value.docker_image as string, satisfied_prerequisites,
    reviewer_commands, timeout_seconds: typeof value.timeout_seconds === "number" ? value.timeout_seconds : undefined,
    output_limit_bytes: typeof value.output_limit_bytes === "number" ? value.output_limit_bytes : undefined,
  };
}

async function resolveLiveReviewInputs(store: SqlitePhase3Store, plan: ReviewPlan, run: ConfiguredRun): Promise<LiveReviewInputs> {
  const request = store.getReviewRequest(plan.review_request_id);
  if (!request) throw new Error("REVIEW_LIVE_REQUEST_MISSING");
  const runtime = createPhase2Runtime({ home: run.runner_home });
  try {
    const execution = runtime.store.getExecution(request.execution_id);
    const saga = runtime.store.getCompletionSaga(request.execution_id);
    if (!execution || execution.status !== "COMPLETED" || !execution.current_attempt_id
      || !saga || saga.status !== "DONE" || saga.outcome !== "COMPLETED" || saga.mechanical_verification !== "PASSED" || !saga.package_artifact) {
      throw new Error("REVIEW_LIVE_PHASE2_EVIDENCE_NOT_COMPLETE");
    }
    const attempt = runtime.store.getAttempt(execution.current_attempt_id);
    if (!attempt?.workspace_root || attempt.status !== "SUCCEEDED") throw new Error("REVIEW_LIVE_WORKSPACE_NOT_SEALED");
    const workspaceManager = new GitWorktreeWorkspaceManager({ root: attempt.workspace_root });
    const workspace = await workspaceManager.inspect(attempt.workspace_id);
    if (!workspace.workspace.sealed_snapshot_hash) throw new Error("REVIEW_LIVE_WORKSPACE_NOT_SEALED");
    await workspaceManager.assertSeal(attempt.workspace_id, workspace.workspace.sealed_snapshot_hash);
    const source = resolve(workspace.workspace.worktree_path);
    if (source !== resolve(run.source)) throw new Error("REVIEW_RUN_SOURCE_NOT_PHASE2_WORKSPACE");

    const packageArtifact = saga.package_artifact;
    const integrity = runtime.phase1.artifacts.verify(packageArtifact);
    if (!integrity.valid || integrity.content_hash !== packageArtifact.content_hash) throw new Error("REVIEW_LIVE_EVIDENCE_INTEGRITY_INVALID");
    const evidencePackage = evidencePackageSchema.parse(JSON.parse(new TextDecoder().decode(runtime.phase1.artifacts.get(packageArtifact))));
    if (evidencePackage.evidence_package_id !== request.evidence_package_id
      || evidencePackage.result.mechanical_verification !== "PASSED"
      || evidencePackage.contract_revision_id !== request.contract_revision_id
      || evidencePackage.assignment_id !== request.assignment_id) throw new Error("REVIEW_LIVE_EVIDENCE_BINDING_INVALID");
    const trustedInputs = materializeTrustedReviewInputs(runtime, run.runner_home, plan, packageArtifact, evidencePackage);

    const task = runtime.phase1.store.getTask(plan.task_id);
    if (!task?.active_contract_revision_id) throw new Error("REVIEW_LIVE_ACTIVE_CONTRACT_MISSING");
    const contract = runtime.phase1.store.getContractRevision(task.active_contract_revision_id);
    if (!contract) throw new Error("REVIEW_LIVE_ACTIVE_CONTRACT_MISSING");
    const assignment = runtime.store.getAssignment(request.assignment_id);
    if (!assignment || assignment.contract_ref.revision_id !== contract.revision_id || assignment.contract_ref.hash !== contract.canonical_hash) {
      throw new Error("REVIEW_LIVE_ASSIGNMENT_BINDING_INVALID");
    }
    const patch = await workspaceManager.exportPatch(attempt.workspace_id);
    const sourceTreeHash = computeReviewTreeHash(source);
    const currentSnapshot = createReviewSnapshot({
      review_snapshot_id: plan.snapshot.review_snapshot_id,
      contract: { revision_id: contract.revision_id, revision: contract.revision_number, hash: contract.canonical_hash },
      source: { base_commit: attempt.base_commit, result_tree_hash: sourceTreeHash, diff_hash: patch.hash },
      evidence: { package_id: evidencePackage.evidence_package_id, package_hash: packageArtifact.content_hash },
      workflow: task.workflow_ref,
      policy: task.policy_pack_ref,
      created_at: plan.snapshot.created_at,
    });
    const profilesByUnit = new Map(plan.review_units.map(unit => {
      const profile = store.getReviewProfile(unit.profile_ref.id, unit.profile_ref.version);
      if (!profile) throw new Error("REVIEW_LIVE_PROFILE_MISSING");
      return [unit.review_unit_id, profile] as const;
    }));
    const profileHashes = [...profilesByUnit.values()].map(profile => profile.content_hash);
    const contractRefs = contract.document.acceptance_criteria.map(criterion => criterion.key).sort();
    const evidenceRefs = [...new Set([
      packageArtifact.artifact_id,
      ...evidencePackage.evidence.flatMap(evidence => [evidence.artifact_id, evidence.type, `evidence:${evidence.type}`]),
      ...contract.document.acceptance_criteria.flatMap(criterion => criterion.required_evidence.flatMap(reference => [reference, `evidence:${reference}`])),
    ])].sort();
    const contextAuthority = Object.fromEntries(plan.review_units.map(unit => {
      const profile = profilesByUnit.get(unit.review_unit_id)!;
      return [unit.review_unit_id, {
        context_bundle_id: `review-context-bundle:${canonicalSha256({ plan: plan.review_plan_id, revision: plan.revision, unit: unit.review_unit_id }).slice(7, 31)}`,
        snapshot_hash: plan.snapshot.snapshot_hash,
        review_unit: { id: unit.review_unit_id, objective: profile.objective, profile_ref: unit.profile_ref },
        task_contract: {
          revision_id: contract.revision_id,
          revision: contract.revision_number,
          hash: contract.canonical_hash,
          goal: contract.document.goal.summary,
          constraints: contract.document.constraints,
          acceptance_criteria: contract.document.acceptance_criteria.map(criterion => `${criterion.key}: ${criterion.statement}`),
        },
        review_plan: { id: plan.review_plan_id, revision: plan.revision, hash: hashReviewPlan(plan) },
        policy_pack: plan.adjudication_policy_ref,
        assignment: { objective: assignment.objective, allowed_paths: patch.changed_files },
        source: {
          base_commit: attempt.base_commit,
          changed_files: patch.changed_files,
          diff_artifact_ref: packageArtifact.artifact_id,
          relevant_file_refs: [],
        },
        evidence: { mechanical_verification: evidenceRefs, baseline: [], secret_scan: evidenceRefs, dependency_changes: [] },
        repository_rules: [],
        implementer_summary: { content: "No trusted implementer narrative is used as review evidence." },
        previous_findings: [],
        generated_at: plan.created_at,
      }];
    }));
    return {
      source,
      evidence: trustedInputs.evidence,
      artifacts: trustedInputs.artifacts,
      current_snapshot: currentSnapshot,
      mechanical_evidence: { passed: true, evidence_hash: packageArtifact.content_hash, artifact_refs: [packageArtifact.artifact_id] },
      current_validity: {
        contract_hash: contract.canonical_hash,
        source_tree_hash: sourceTreeHash,
        diff_hash: patch.hash,
        evidence_package_hash: packageArtifact.content_hash,
        policy_hash: task.policy_pack_ref.hash,
        profile_hashes: [...new Set(profileHashes)].sort(),
        required_evidence_hashes: [packageArtifact.content_hash],
        dependency_hash: computeReviewDependencyHash(source),
      },
      validation_authority: {
        contract_revision_id: contract.revision_id,
        contract_refs: contractRefs,
        evidence_refs: evidenceRefs,
      },
      context_authority: contextAuthority,
    };
  } finally { runtime.close(); }
}

function materializeTrustedReviewInputs(
  runtime: Phase2Runtime,
  runnerHome: string,
  plan: ReviewPlan,
  packageArtifact: NonNullable<ReturnType<Phase2Runtime["phase1"]["store"]["getArtifact"]>>,
  evidencePackage: ReturnType<typeof evidencePackageSchema.parse>,
): { evidence: string; artifacts: string } {
  const root = join(runnerHome, "phase3", "live-inputs", digest(`${plan.review_plan_id}:revision-${plan.revision}:${packageArtifact.content_hash}`));
  const evidence = join(root, "evidence");
  const artifacts = join(root, "artifacts");
  mkdirSync(evidence, { recursive: true });
  mkdirSync(artifacts, { recursive: true });
  const packageBytes = runtime.phase1.artifacts.get(packageArtifact);
  writeTrustedReviewInput(join(evidence, "evidence-package.json"), packageBytes);
  const references = [evidencePackage.manifest_ref, ...evidencePackage.evidence];
  const index = references.map(reference => {
    const stored = runtime.phase1.store.getArtifact(reference.artifact_id);
    if (!stored || stored.content_hash !== reference.content_hash) throw new Error("REVIEW_LIVE_EVIDENCE_ARTIFACT_BINDING_INVALID");
    const integrity = runtime.phase1.artifacts.verify(stored);
    if (!integrity.valid || integrity.content_hash !== reference.content_hash) throw new Error("REVIEW_LIVE_EVIDENCE_ARTIFACT_INTEGRITY_INVALID");
    const filename = `${digest(reference.artifact_id).slice(0, 24)}-${reference.content_hash.slice(7, 23)}.artifact`;
    writeTrustedReviewInput(join(artifacts, filename), runtime.phase1.artifacts.get(stored));
    return { artifact_id: reference.artifact_id, content_hash: reference.content_hash, type: "type" in reference ? reference.type : "execution-manifest", path: `/review/artifacts/${filename}` };
  }).sort((left, right) => left.artifact_id.localeCompare(right.artifact_id));
  writeTrustedReviewInput(join(evidence, "artifact-index.json"), new TextEncoder().encode(JSON.stringify({ schema_version: 1, evidence_package_id: evidencePackage.evidence_package_id, artifacts: index }, null, 2)));
  const expectedEvidence = ["artifact-index.json", "evidence-package.json"];
  const expectedArtifacts = index.map(item => item.path.slice("/review/artifacts/".length)).sort();
  if (canonicalSha256(readdirSync(evidence).sort()) !== canonicalSha256(expectedEvidence)
    || canonicalSha256(readdirSync(artifacts).sort()) !== canonicalSha256(expectedArtifacts)) {
    throw new Error("REVIEW_LIVE_INPUT_DIRECTORY_NOT_AUTHORITATIVE");
  }
  return { evidence, artifacts };
}

function writeTrustedReviewInput(path: string, content: Uint8Array): void {
  if (existsSync(path)) {
    if (!Buffer.from(readFileSync(path)).equals(Buffer.from(content))) throw new Error("REVIEW_LIVE_INPUT_CONTENT_CONFLICT");
    return;
  }
  writeFileSync(path, content, { flag: "wx" });
}

function reviewReplayFingerprint(
  store: SqlitePhase3Store,
  planId: string,
  baseline: ReturnType<typeof reviewValidityInputsSchema.parse>,
  live: LiveReviewInputs,
  evaluatedAt: string,
): string {
  const waivers = store.listWaivers(planId).map(waiver => ({
    hash: canonicalSha256(waiver),
    expired: waiver.expires_at !== null && Date.parse(evaluatedAt) >= Date.parse(waiver.expires_at),
  })).sort((left, right) => left.hash.localeCompare(right.hash));
  const approval = store.getLatestHumanApproval(planId);
  return canonicalSha256({
    baseline,
    current_snapshot: live.current_snapshot,
    mechanical_evidence: live.mechanical_evidence,
    current_validity: reviewValidityInputsSchema.parse(live.current_validity),
    waivers,
    human_approval: approval ? canonicalSha256(approval) : null,
  });
}

function supersedeTerminalReview(store: SqlitePhase3Store, planId: string): void {
  const state = requiredPlanState(store, planId);
  transitionReviewPlan(state.status, "SUPERSEDED");
  const superseded = parseReviewPlanState({
    ...state,
    status: "SUPERSEDED",
    aggregate_version: state.aggregate_version + 1,
    updated_at: new Date().toISOString(),
  });
  store.transaction(() => {
    if (!store.updateReviewPlanState(superseded, state.aggregate_version)) throw new Error("REVIEW_PLAN_SUPERSEDE_CONFLICT");
    appendStoreAuditEvent(store, planId, "review.decision.superseded", { snapshot_hash: state.snapshot_hash }, { type: "system", id: "system:review-coordinator" });
  });
}

class DurableReviewArtifactPort implements ReviewArtifactPort {
  constructor(private readonly directory: string) { mkdirSync(directory, { recursive: true }); }

  async putJson(input: { idempotency_key: string; artifact_ref: string; value: unknown }) {
    const path = join(this.directory, `${digest(input.idempotency_key)}.json`);
    const contentHash = canonicalSha256(input.value);
    if (existsSync(path)) {
      const existing = JSON.parse(readFileSync(path, "utf8")) as { idempotency_key?: unknown; artifact_ref?: unknown; content_hash?: unknown };
      if (existing.idempotency_key !== input.idempotency_key || existing.artifact_ref !== input.artifact_ref || existing.content_hash !== contentHash) {
        throw new Error("REVIEW_ARTIFACT_IDEMPOTENCY_CONFLICT");
      }
      return { artifact_ref: input.artifact_ref, replayed: true };
    }
    atomicWriteJson(path, { schema_version: 1, idempotency_key: input.idempotency_key, artifact_ref: input.artifact_ref, content_hash: contentHash, value: input.value });
    return { artifact_ref: input.artifact_ref, replayed: false };
  }

  getJson(idempotencyKey: string): unknown {
    const path = join(this.directory, `${digest(idempotencyKey)}.json`);
    if (!existsSync(path)) throw new Error("REVIEW_ARTIFACT_NOT_FOUND");
    const artifact = JSON.parse(readFileSync(path, "utf8")) as { idempotency_key?: unknown; content_hash?: unknown; value?: unknown };
    if (artifact.idempotency_key !== idempotencyKey || artifact.content_hash !== canonicalSha256(artifact.value)) throw new Error("REVIEW_ARTIFACT_INTEGRITY_INVALID");
    return artifact.value;
  }
}

class StoreReviewAuditPort implements ReviewAuditPort {
  constructor(private readonly store: SqlitePhase3Store, private readonly aggregateId: string, private readonly taskId: string) {}

  async append(input: { idempotency_key: string; event_id: string; event_type: string; aggregate_id: string; occurred_at: string; payload: unknown }) {
    if (input.aggregate_id !== this.aggregateId) throw new Error("REVIEW_AUDIT_AGGREGATE_MISMATCH");
    const existing = this.store.listEvents(this.aggregateId).find(event => event.event_id === input.event_id);
    if (existing) {
      if (existing.event_type !== input.event_type || canonicalSha256(existing.payload) !== canonicalSha256(input.payload)) throw new Error("REVIEW_AUDIT_IDEMPOTENCY_CONFLICT");
      return { replayed: true };
    }
    const events = this.store.listEvents(this.aggregateId);
    const event = createGovernanceAuditEvent({
      event_id: input.event_id,
      event_type: input.event_type as GovernanceAuditEvent["event_type"],
      aggregate_type: "review-plan",
      aggregate_id: this.aggregateId,
      aggregate_version: events.length + 1,
      task_id: this.taskId,
      occurred_at: input.occurred_at,
      actor: { type: "system", id: "system:review-coordinator" },
      payload: input.payload,
      previous_event_hash: events.at(-1)?.event_hash ?? null,
    });
    const result = this.store.appendEvent(event);
    return { replayed: result.status === "DUPLICATE" };
  }

  async assertIntegrity(aggregateId: string): Promise<void> {
    if (aggregateId !== this.aggregateId || !this.store.verifyEventChain(aggregateId).valid) throw new Error("REVIEW_AUDIT_CHAIN_INVALID");
    assertGovernanceAuditEventStream(this.store.listEvents(aggregateId));
  }
}

function ensurePlanCreatedAudit(store: SqlitePhase3Store, planId: string): void {
  const plan = store.getReviewPlan(planId);
  if (!plan) throw new Error("REVIEW_PLAN_NOT_FOUND");
  const events = store.listEvents(planId);
  if (events.some(event => event.event_type === "review.plan.created" && event.payload.plan_revision === plan.revision)) return;
  const event = createGovernanceAuditEvent({
    event_id: `review-event:${digest(`${planId}:revision-${plan.revision}:created`).slice(0, 32)}`,
    event_type: "review.plan.created",
    aggregate_type: "review-plan",
    aggregate_id: planId,
    aggregate_version: events.length + 1,
    task_id: plan.task_id,
    occurred_at: new Date().toISOString(),
    actor: { type: "system", id: "system:review-coordinator" },
    payload: {
      source_tree_hash: plan.snapshot.source.result_tree_hash,
      contract_revision: plan.snapshot.contract.revision,
      plan_revision: plan.revision,
      snapshot_hash: plan.snapshot.snapshot_hash,
      required_unit_ids: plan.review_units.filter(unit => unit.required).map(unit => unit.review_unit_id).sort(),
    },
    previous_event_hash: events.at(-1)?.event_hash ?? null,
  });
  store.appendEvent(event);
}

function advanceToRunning(store: SqlitePhase3Store, planId: string): void {
  const plan = store.getReviewPlan(planId);
  if (!plan) throw new Error("REVIEW_PLAN_NOT_FOUND");
  let state = requiredPlanState(store, planId);
  if (state.status === "CREATED") state = updatePlanState(store, state, "WAITING_PREREQUISITES", unit => ({ ...unit, status: "WAITING_PREREQUISITES", review_execution_id: null, result_artifact_id: null }));
  if (state.status === "WAITING_PREREQUISITES") state = updatePlanState(store, state, "READY", unit => ({ ...unit, status: "READY", review_execution_id: null, result_artifact_id: null }));
  if (state.status === "READY") state = updatePlanState(store, state, "RUNNING", unit => ({
    ...unit,
    status: "RUNNING",
    review_execution_id: coordinatorReviewExecutionId(planId, plan.revision, unit.review_unit_id),
    result_artifact_id: null,
  }));
  if (state.status !== "RUNNING") throw new Error(`REVIEW_PLAN_NOT_STARTABLE: ${state.status}`);
}

function advanceToTerminal(store: SqlitePhase3Store, planId: string, outcome: ReviewCoordinatorOutcome): void {
  const plan = store.getReviewPlan(planId);
  if (!plan) throw new Error("REVIEW_PLAN_NOT_FOUND");
  const completed = new Set(outcome.completed_review_units);
  const settle = (unit: ReviewPlanState["unit_states"][number]) => completed.has(unit.review_unit_id)
    ? { ...unit, status: "COMPLETED" as const, review_execution_id: null, result_artifact_id: coordinatorResultArtifactId(planId, plan.revision, unit.review_unit_id) }
    : { ...unit, status: outcome.decision.decision === "CANCELLED" ? "CANCELLED" as const : "FAILED" as const, review_execution_id: null, result_artifact_id: null };
  let state = requiredPlanState(store, planId);
  if (state.status !== "RUNNING") throw new Error(`REVIEW_PLAN_TERMINAL_STATE_INVALID: ${state.status}`);
  if (outcome.decision.decision === "INCONCLUSIVE" || outcome.decision.decision === "CANCELLED") {
    updatePlanState(store, state, outcome.decision.decision, settle);
    return;
  }
  state = updatePlanState(store, state, "COLLECTING", settle, { review_rounds: state.counters.review_rounds + 1 });
  state = updatePlanState(store, state, "VALIDATING_FINDINGS");
  if (outcome.decision.decision === "NEEDS_HUMAN") {
    updatePlanState(store, state, "NEEDS_HUMAN");
    return;
  }
  state = updatePlanState(store, state, "ADJUDICATING", undefined, { adjudication_rounds: state.counters.adjudication_rounds + 1 });
  state = updatePlanState(store, state, "COMPLETED");
  const terminal = outcome.decision.decision === "PASS" || outcome.decision.decision === "PASS_WITH_NOTES" ? "PASSED" : outcome.decision.decision;
  updatePlanState(store, state, terminal);
}

function requiredPlanState(store: SqlitePhase3Store, planId: string): ReviewPlanState {
  const state = store.getReviewPlanState(planId);
  if (!state) throw new Error("REVIEW_PLAN_STATE_NOT_FOUND");
  return state;
}

function updatePlanState(
  store: SqlitePhase3Store,
  current: ReviewPlanState,
  nextStatus: ReviewPlanState["status"],
  updateUnit: ((unit: ReviewPlanState["unit_states"][number]) => ReviewPlanState["unit_states"][number]) | undefined = undefined,
  counterPatch: Partial<ReviewPlanState["counters"]> = {},
): ReviewPlanState {
  transitionReviewPlan(current.status, nextStatus);
  const next = {
    ...current,
    status: nextStatus,
    unit_states: updateUnit ? current.unit_states.map(updateUnit) : current.unit_states,
    counters: { ...current.counters, ...counterPatch },
    aggregate_version: current.aggregate_version + 1,
    updated_at: new Date().toISOString(),
  } as ReviewPlanState;
  if (!store.updateReviewPlanState(next, current.aggregate_version)) throw new Error("REVIEW_PLAN_STATE_CONFLICT");
  return next;
}

function persistCoordinatorOutcome(store: SqlitePhase3Store, planId: string, outcome: ReviewCoordinatorOutcome): void {
  for (const finalFinding of outcome.findings) persistCoordinatorFinding(store, finalFinding);
  const current = store.getLatestReviewDecision(planId);
  if (!current || current.review_decision_id !== outcome.decision.review_decision_id) store.insertReviewDecision(outcome.decision);
}

function persistReviewExecutions(
  store: SqlitePhase3Store,
  plan: ReviewPlan,
  records: ReadonlyArray<{
    review_execution_id: string; review_unit_id: string; reviewer_binding_id: string;
    status: "COMPLETED" | "FAILED" | "CANCELLED"; output_hash: string; artifact_ref: string; occurred_at: string;
    runtime_attestation_hash: string; runtime_attestation_key_id: string; runtime_attestation_signature: string;
  }>,
): void {
  for (const record of records) {
    if (store.getReviewExecution(record.review_execution_id)) continue;
    const completed = record.status === "COMPLETED";
    store.insertReviewExecution(parseReviewExecutionRecord({
      schema_version: 1,
      review_execution_id: record.review_execution_id,
      review_plan_id: plan.review_plan_id,
      review_unit_id: record.review_unit_id,
      reviewer_binding_id: record.reviewer_binding_id,
      snapshot_hash: plan.snapshot.snapshot_hash,
      status: record.status,
      attempt_number: 1,
      context_artifact_ref: `artifact:${canonicalSha256({ executionId: record.review_execution_id, type: "context" }).slice(7, 39)}`,
      rendered_prompt_artifact_ref: `artifact:${canonicalSha256({ executionId: record.review_execution_id, type: "rendered-prompt" }).slice(7, 39)}`,
      result_artifact_ref: completed ? record.artifact_ref : null,
      output_hash: completed ? record.output_hash : null,
      runtime_attestation_hash: completed ? record.runtime_attestation_hash : null,
      runtime_attestation_key_id: completed ? record.runtime_attestation_key_id : null,
      runtime_attestation_signature: completed ? record.runtime_attestation_signature : null,
      protocol_errors: 0,
      aggregate_version: 1,
      created_at: record.occurred_at,
      updated_at: record.occurred_at,
    }));
  }
}

function persistCoordinatorFinding(store: SqlitePhase3Store, finalFinding: ReviewFinding): void {
  let current = store.getFinding(finalFinding.finding_id);
  if (!current) {
    current = parseReviewFinding({ ...finalFinding, status: "PROPOSED", effective_severity: null, duplicate_of: null });
    store.insertFinding(current);
  }
  const path = findingPersistencePath(current.status, finalFinding.status);
  for (const status of path) {
    const next = parseReviewFinding({
      ...finalFinding,
      status,
      effective_severity: status === "CONFIRMED" || status === "WAIVED" ? finalFinding.effective_severity : null,
      duplicate_of: status === "DUPLICATE" ? finalFinding.duplicate_of : null,
    });
    if (!store.updateFinding(next, current.status)) throw new Error("REVIEW_FINDING_STATE_CONFLICT");
    current = next;
  }
  const validationStatus = finalFinding.status === "WAIVED" ? "CONFIRMED" : finalFinding.status;
  if (!["CONFIRMED", "DISMISSED", "DUPLICATE", "STALE"].includes(validationStatus)) return;
  if (store.listFindingValidations(finalFinding.review_plan_id).some(value => value.finding_id === finalFinding.finding_id)) return;
  store.insertFindingValidation(parseFindingValidation({
    schema_version: 1,
    finding_validation_id: `finding-validation:${digest(finalFinding.finding_id).slice(0, 32)}`,
    finding_id: finalFinding.finding_id,
    review_plan_id: finalFinding.review_plan_id,
    snapshot_hash: finalFinding.scope.snapshot_hash,
    status: validationStatus,
    effective_severity: validationStatus === "CONFIRMED" ? finalFinding.effective_severity : null,
    evidence_strength: finalFinding.evidence_strength,
    validated_by: ["deterministic-policy", "snapshot", "evidence"],
    validator_binding_id: finalFinding.proposed_by.reviewer_binding_id,
    validation_artifact_ref: `artifact:${digest(`${finalFinding.finding_id}:validation`).slice(0, 32)}`,
    created_at: finalFinding.updated_at,
  }));
}

function findingPersistencePath(current: ReviewFinding["status"], target: ReviewFinding["status"]): ReviewFinding["status"][] {
  if (current === target) return [];
  if (current === "CONFIRMED" && target === "WAIVED") return ["WAIVED"];
  if (current !== "PROPOSED") throw new Error(`REVIEW_FINDING_ALREADY_TERMINAL: ${current}`);
  if (target === "CONFIRMED") return ["VALIDATING", "CONFIRMED"];
  if (target === "WAIVED") return ["VALIDATING", "CONFIRMED", "WAIVED"];
  if (["DISMISSED", "DUPLICATE", "STALE"].includes(target)) return [target];
  if (target === "VALIDATING") return ["VALIDATING"];
  return [];
}

function assertReviewStartAllowed(home: string): void {
  const path = join(home, "phase3", "control.json");
  if (!existsSync(path)) return;
  const control = JSON.parse(readFileSync(path, "utf8")) as { state?: unknown };
  if (control.state === "PAUSE_NEW_REVIEWS") throw new Error("REVIEW_START_PAUSED");
}

function runCancellationRequested(home: string, planId: string, revision: number): boolean {
  const path = reviewRunPath(home, planId, revision);
  if (!existsSync(path)) return false;
  const receipt = readReviewRunReceipt(path) as { status?: unknown };
  return receipt.status === "CANCELLED";
}

function writeReviewRunReceipt(path: string, input: Record<string, unknown>): void {
  const { receipt_hash: ignored, ...content } = input;
  atomicWriteJson(path, { ...content, receipt_hash: canonicalSha256(content) });
}

function atomicWriteJson(path: string, value: unknown): void {
  const temporary = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  let descriptor: number | null = null;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    writeSync(descriptor, JSON.stringify(value, null, 2), undefined, "utf8");
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = null;
    renameSync(temporary, path);
  } catch (error) {
    if (descriptor !== null) try { closeSync(descriptor); } catch { /* best effort */ }
    try { unlinkSync(temporary); } catch { /* best effort */ }
    throw error;
  }
}

function readReviewRunReceipt(path: string): Record<string, unknown> {
  const receipt = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  const { receipt_hash: receiptHash, ...content } = receipt;
  if (typeof receiptHash !== "string" || canonicalSha256(content) !== receiptHash) throw new Error("REVIEW_RUN_RECEIPT_INTEGRITY_INVALID");
  return receipt;
}

function assertTerminalRunReceipt(store: SqlitePhase3Store, plan: ReviewPlan, receipt: Record<string, unknown>): void {
  const state = store.getReviewPlanState(plan.review_plan_id);
  const decision = store.getLatestReviewDecision(plan.review_plan_id);
  const outcome = receipt.outcome;
  const receiptDecision = outcome && typeof outcome === "object" && !Array.isArray(outcome)
    ? (outcome as Record<string, unknown>).decision
    : null;
  if (receipt.review_plan_revision !== plan.revision || !state || !["PASSED", "CHANGES_REQUESTED", "BLOCKED", "NEEDS_HUMAN", "INCONCLUSIVE", "CANCELLED"].includes(state.status)
    || !decision || !receiptDecision || canonicalSha256(receiptDecision) !== canonicalSha256(decision)) {
    throw new Error("REVIEW_RUN_TERMINAL_RECEIPT_MISMATCH");
  }
}

function acquireReviewRunLock(runPath: string): () => void {
  const lockPath = `${runPath}.lock`;
  mkdirSync(resolve(runPath, ".."), { recursive: true });
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      writeFileSync(lockPath, JSON.stringify({ pid: process.pid, acquired_at: new Date().toISOString() }), { encoding: "utf8", flag: "wx" });
      let released = false;
      return () => {
        if (released) return;
        released = true;
        try { unlinkSync(lockPath); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const lock = JSON.parse(readFileSync(lockPath, "utf8")) as { pid?: unknown };
      if (typeof lock.pid === "number" && processIsAlive(lock.pid)) throw new Error("REVIEW_RUN_ALREADY_ACTIVE");
      try { unlinkSync(lockPath); } catch (unlinkError) { if ((unlinkError as NodeJS.ErrnoException).code !== "ENOENT") throw unlinkError; }
    }
  }
  throw new Error("REVIEW_RUN_LOCK_UNAVAILABLE");
}

function processIsAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; }
  catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM"; }
}

function coordinatorReviewExecutionId(planId: string, revision: number, unitId: string): string {
  return `review-execution:${canonicalSha256({ plan: planId, revision, unit: unitId }).slice(7, 39)}`;
}

function phase2ReviewExecutionId(planId: string, revision: number, unitId: string): string {
  return `execution:review-${coordinatorReviewExecutionId(planId, revision, unitId).slice("review-execution:".length)}`;
}

function coordinatorResultArtifactId(planId: string, revision: number, unitId: string): string {
  const executionId = coordinatorReviewExecutionId(planId, revision, unitId);
  return `artifact:${canonicalSha256({ executionId, type: "result" }).slice(7, 39)}`;
}

function reviewRunPath(home: string, planId: string, revision: number): string {
  return join(home, "phase3", "runs", `${digest(`${planId}:revision-${revision}`)}.json`);
}

function pauseAll(home: string, reason: string): unknown {
  const control = { schema_version: 1, state: "PAUSE_NEW_REVIEWS", reason, changed_at: new Date().toISOString() };
  const directory = join(home, "phase3");
  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, "control.json"), JSON.stringify(control, null, 2), "utf8");
  return control;
}

function parseArgs(args: string[]): ParsedArgs {
  const positionals: string[] = [];
  const options = new Map<string, string | true>();
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index]!;
    if (!value.startsWith("--")) { positionals.push(value); continue; }
    const key = value.slice(2);
    if (key === "json") { options.set(key, true); continue; }
    const next = args[index + 1];
    if (!next || next.startsWith("--")) throw new Error(`Missing value for --${key}`);
    options.set(key, next); index += 1;
  }
  return { positionals, options, json: options.has("json") };
}

function reviewHome(parsed: ParsedArgs): string { return resolve(option(parsed, "home") ?? process.env.OPENCODEX_OEF_HOME ?? join(process.cwd(), ".opencodex")); }
function option(parsed: ParsedArgs, name: string): string | undefined { const value = parsed.options.get(name); return typeof value === "string" ? value : undefined; }
function authenticatedLocalHuman(parsed: ParsedArgs): { type: "human"; id: "human:local-owner" } {
  const claimed = option(parsed, "approved-by");
  if (claimed !== undefined && claimed !== "human:local-owner") throw new Error("REVIEW_HUMAN_PRINCIPAL_NOT_AUTHENTICATED");
  return { type: "human", id: "human:local-owner" };
}
function requireInteractiveHumanConfirmation(parsed: ParsedArgs, snapshotHash: string): void {
  if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error("REVIEW_HUMAN_APPROVAL_REQUIRES_INTERACTIVE_TERMINAL");
  if (required(parsed, "confirm-snapshot") !== snapshotHash) throw new Error("REVIEW_HUMAN_APPROVAL_SNAPSHOT_CONFIRMATION_MISMATCH");
}
function required(parsed: ParsedArgs, name: string): string { const value = option(parsed, name); if (!value) throw new Error(`Missing required option --${name}`); return value; }
function positional(parsed: ParsedArgs, index: number, label: string): string { const value = parsed.positionals[index]; if (!value) throw new Error(`Missing ${label}`); return value; }
function readDataFile(pathInput: string): unknown { const path = resolve(pathInput); const source = readFileSync(path, "utf8"); return extname(path).toLowerCase() === ".json" ? JSON.parse(source) : Bun.YAML.parse(source); }
function digest(value: string): string { return createHash("sha256").update(value).digest("hex"); }
function normalizeDate(value: string): string { const normalized = /^\d{4}-\d{2}-\d{2}$/.test(value) ? `${value}T00:00:00.000Z` : value; if (!Number.isFinite(Date.parse(normalized))) throw new Error("Invalid waiver expiration"); return new Date(normalized).toISOString(); }
