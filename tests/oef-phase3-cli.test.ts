import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cmdOefPhase3, type OefPhase3CliDependencies } from "../src/cli/oef-phase3";
import { createPhase2Runtime, type Phase2Runtime } from "../src/oef/phase2";
import {
  SqlitePhase3Store, computeReviewTreeHash, createGovernanceAuditEvent, createReviewLaunchPolicyId, createReviewProfile, createReviewSnapshot, createReviewSnapshotFileIndex, createWaiver, hashReviewPlan, parseReviewDecisionRecord, parseReviewFinding,
  parseReviewerBinding, parseReviewPlan, parseReviewPlanState, parseReviewRequest,
} from "../src/oef/phase3";
import { TestReviewIdentityAuthority } from "./fixtures/phase3-review-identity-authority";
import { canonicalSha256 } from "../src/oef/phase1/core/contract/task-contract";

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0)) {
    for (let attempt = 0; attempt < 80; attempt += 1) {
      try { rmSync(root, { recursive: true, force: true }); break; }
      catch (error) { if (attempt === 79) throw error; await Bun.sleep(Math.min(250, 25 + attempt * 5)); }
    }
  }
});
const NOW = "2026-07-23T15:00:00.000Z";
const hash = (value: string) => `sha256:${value.repeat(64)}`;

describe("Phase 3 minimal CLI", () => {
  test("publishes the complete review governance command surface with JSON support", async () => {
    const output: string[] = [];
    const original = console.log;
    console.log = (...values: unknown[]) => output.push(values.map(String).join(" "));
    try {
      expect(await cmdOefPhase3("review", ["help", "--json"])).toBe(0);
    } finally { console.log = original; }
    const value = JSON.parse(output.join("\n"));
    expect(value.commands).toEqual([
      "plan", "bind", "show-plan", "start", "watch", "findings", "finding show", "finding dismiss",
      "waiver create", "approval create", "repair create", "rerun", "cancel", "pause-all",
    ]);
    expect(value.json_supported).toBeTrue();
  });

  test("fails closed when a review run is started without its durable manifest", async () => {
    const errors: string[] = [];
    const original = console.error;
    console.error = (...values: unknown[]) => errors.push(values.map(String).join(" "));
    try {
      expect(await cmdOefPhase3("review", ["start", "review-plan:missing", "--json"])).toBe(1);
    } finally { console.error = original; }
    expect(errors.join("\n")).toContain("Missing required option --run-file");
  });

  test("creates a real Phase 2 repair assignment linked to confirmed findings", async () => {
    const root = mkdtempSync(join(tmpdir(), "oef-phase3-cli-repair-"));
    roots.push(root);
    const home = join(root, "home");
    const seeded = seedRepairableReview(home);
    const result = await invoke(["repair", "create", seeded.planId, "--home", home, "--json"]);
    expect(result.code).toBe(0);
    expect(result.value).toMatchObject({
      proposal: { source_review_plan_id: seeded.planId, target_findings: [seeded.findingId] },
      assignment: { task_id: seeded.taskId, role: "backend-repairer" },
      lineage: { source_review_plan_id: seeded.planId },
    });
    const runtime = createPhase2Runtime({ home });
    try {
      const assignmentId = (result.value as { assignment: { assignment_id: string } }).assignment.assignment_id;
      expect(runtime.store.getAssignment(assignmentId)).toMatchObject({ assignment_id: assignmentId, task_id: seeded.taskId });
    } finally { runtime.close(); }
    const governance = new SqlitePhase3Store({ databasePath: join(home, "oef.sqlite") });
    try {
      expect(governance.listEvents(seeded.planId).map(event => event.event_type)).toEqual([
        "review.plan.created", "finding.confirmed", "review.decision.issued", "repair.proposed", "repair.assignment.created",
      ]);
      expect(governance.verifyEventChain(seeded.planId)).toMatchObject({ valid: true, event_count: 5 });
    } finally { governance.close(); }
  });

  test("runs the durable coordinator lifecycle and persists a terminal PASS without duplicate dispatch", async () => {
    const root = mkdtempSync(join(tmpdir(), "oef-phase3-cli-start-"));
    roots.push(root);
    const seeded = seedStartableReview(root);
    const identityAuthority = new TestReviewIdentityAuthority();
    registerSeededPolicy(identityAuthority, seeded);
    const trustedManifest = JSON.parse(readFileSync(seeded.runFile, "utf8"));
    const trustedEvidence = trustedManifest.evidence as string;
    const trustedArtifacts = trustedManifest.artifacts as string;
    trustedManifest.evidence = join(root, "attacker-controlled-evidence-does-not-exist");
    trustedManifest.artifacts = join(root, "attacker-controlled-artifacts-does-not-exist");
    writeFileSync(seeded.runFile, JSON.stringify(trustedManifest, null, 2), "utf8");
    let executions = 0;
    let crashAfterDecision = true;
    const dependencies: OefPhase3CliDependencies = {
      afterDecidedReceipt() {
        if (!crashAfterDecision) return;
        crashAfterDecision = false;
        throw new Error("SIMULATED_POST_DECISION_CRASH");
      },
      async resolveLiveReviewInputs() {
        const manifest = JSON.parse(readFileSync(seeded.runFile, "utf8"));
        return {
          source: manifest.source,
          evidence: trustedEvidence,
          artifacts: trustedArtifacts,
          current_snapshot: manifest.current_snapshot,
          mechanical_evidence: manifest.mechanical_evidence,
          current_validity: manifest.current_validity,
          validation_authority: { contract_revision_id: manifest.current_snapshot.contract.revision_id, contract_refs: [], evidence_refs: [] },
          context_authority: Object.fromEntries(manifest.reviewer_commands.map((command: { context: { review_unit: { id: string } } }) => [command.context.review_unit.id, command.context])),
        };
      },
      reviewRunnerFactory: () => ({
        getReviewIdentityAuthority: () => identityAuthority.getReviewIdentityAuthority(),
        getReviewLaunchPolicy: id => identityAuthority.getReviewLaunchPolicy(id),
        async cancelExecution() {},
        async runVerificationCommand(request) {
          executions += 1;
          const stdout = join(root, "review-stdout.json");
          const stderr = join(root, "review-stderr.txt");
          const output = JSON.stringify({
            schema_version: 1,
            review_unit_id: seeded.unitId,
            snapshot_hash: seeded.snapshotHash,
            decision: { recommendation: "pass" },
            summary: "No supported issue found.",
            findings: [],
            unanswered_questions: [],
            requested_evidence: [],
          });
          writeFileSync(stdout, output, "utf8");
          writeFileSync(stderr, "", "utf8");
          return identityAuthority.createAtomicReviewResult(request, { process_id: "supervised-process:cli-review", exit_code: 0, failure_type: null, timed_out: null, stdout_path: stdout, stderr_path: stderr, output_bytes: output.length, redaction_count: 0 } as never);
        },
      }),
    };
    const args = ["start", seeded.planId, "--home", seeded.home, "--run-file", seeded.runFile, "--json"];
    const interrupted = await invokeCode(args, dependencies);
    expect(interrupted.code).toBe(1);
    expect(interrupted.error).toContain("SIMULATED_POST_DECISION_CRASH");
    const decidedReceipt = readdirSync(join(seeded.home, "phase3", "runs")).map(file =>
      JSON.parse(readFileSync(join(seeded.home, "phase3", "runs", file), "utf8")) as { status?: string });
    expect(decidedReceipt).toEqual([expect.objectContaining({ status: "DECIDED" })]);
    const staleDecidedManifest = JSON.parse(readFileSync(seeded.runFile, "utf8"));
    const originalDependencyHash = staleDecidedManifest.current_validity.dependency_hash;
    staleDecidedManifest.current_validity.dependency_hash = hash("0");
    writeFileSync(seeded.runFile, JSON.stringify(staleDecidedManifest, null, 2), "utf8");
    const staleDecided = await invokeCode(args, dependencies);
    expect(staleDecided.code).toBe(1);
    expect(staleDecided.error).toContain("REVIEW_DECIDED_RESULT_STALE_NEW_REVISION_REQUIRED");
    staleDecidedManifest.current_validity.dependency_hash = originalDependencyHash;
    writeFileSync(seeded.runFile, JSON.stringify(staleDecidedManifest, null, 2), "utf8");
    const first = await invoke(args, dependencies);
    expect(first.value).toMatchObject({ status: "TERMINAL", outcome: { decision: { decision: "PASS" }, replayed: false } });
    const replay = await invoke(args, dependencies);
    expect(replay.value).toMatchObject({ status: "TERMINAL", outcome: { decision: { decision: "PASS" } } });
    expect(executions).toBe(1);

    const store = new SqlitePhase3Store({ databasePath: join(seeded.home, "oef.sqlite") });
    try {
      expect(store.getReviewPlanState(seeded.planId)?.status).toBe("PASSED");
      expect(store.getLatestReviewDecision(seeded.planId)?.decision).toBe("PASS");
      expect(store.verifyEventChain(seeded.planId)).toMatchObject({ valid: true, event_count: 3 });
      expect(store.listFindings(seeded.planId)).toEqual([]);
      const executionId = `review-execution:${canonicalSha256({ plan: seeded.planId, revision: 1, unit: seeded.unitId }).slice(7, 39)}`;
      const execution = store.getReviewExecution(executionId);
      expect(execution).toMatchObject({ status: "COMPLETED", reviewer_binding_id: "reviewer-binding:cli-start" });
      expect(execution?.result_artifact_ref).toMatch(/^artifact:/);
      expect(execution?.runtime_attestation_hash).toMatch(/^sha256:/);
      expect(execution?.runtime_attestation_key_id).toMatch(/^sha256:/);
      expect(execution?.runtime_attestation_signature).toMatch(/^[A-Za-z0-9_-]+$/);
      const durableArtifacts = readdirSync(join(seeded.home, "phase3", "artifacts")).map(file =>
        JSON.parse(readFileSync(join(seeded.home, "phase3", "artifacts", file), "utf8")) as Record<string, unknown>);
      const attested = durableArtifacts.find(artifact => artifact.artifact_ref === execution?.result_artifact_ref) as { value?: Record<string, unknown> } | undefined;
      expect(attested?.value).toMatchObject({
        output_hash: execution?.output_hash,
        runtime_attestation: { attested_by: "phase2-runner-host", attestation_algorithm: "Ed25519", output_hash: execution?.output_hash },
      });
      const renderedPrompt = durableArtifacts.find(artifact => artifact.artifact_ref === execution?.rendered_prompt_artifact_ref) as { value?: Record<string, unknown> } | undefined;
      expect(renderedPrompt?.value).toMatchObject({
        review_execution_id: executionId,
        transport: "stdin-json",
        media_type: "application/json",
      });
      expect(renderedPrompt?.value?.prompt_hash).toBe(canonicalSha256(JSON.parse(String(renderedPrompt?.value?.rendered_context))));
    } finally { store.close(); }

    const drifted = JSON.parse(readFileSync(seeded.runFile, "utf8"));
    drifted.current_validity.dependency_hash = hash("0");
    writeFileSync(seeded.runFile, JSON.stringify(drifted, null, 2), "utf8");
    const staleReplay = await invokeCode(args, dependencies);
    expect(staleReplay.code).toBe(1);
    expect(staleReplay.error).toContain("REVIEW_TERMINAL_RESULT_STALE_NEW_REVISION_REQUIRED");
    expect(executions).toBe(1);
    const superseded = new SqlitePhase3Store({ databasePath: join(seeded.home, "oef.sqlite") });
    try { expect(superseded.getReviewPlanState(seeded.planId)?.status).toBe("SUPERSEDED"); }
    finally { superseded.close(); }
  });

  test("binds a reviewer through the public CLI to its immutable launch policy", async () => {
    const root = mkdtempSync(join(tmpdir(), "oef-phase3-cli-bind-"));
    roots.push(root);
    const seeded = seedStartableReview(root);
    const manifest = JSON.parse(readFileSync(seeded.runFile, "utf8"));
    const original = manifest.reviewer_commands[0].reviewer_binding_id as string;
    const store = new SqlitePhase3Store({ databasePath: join(seeded.home, "oef.sqlite") });
    const existing = store.getReviewerBinding(original)!;
    store.close();
    const bindFile = join(root, "reviewer-binding.json");
    writeFileSync(bindFile, JSON.stringify({
      runner_home: seeded.home,
      reviewer_binding: { ...existing, reviewer_binding_id: "reviewer-binding:cli-public-bind" },
      launch_policy: { docker_image: manifest.docker_image, executable: "reviewer", arguments: [] },
    }), "utf8");
    const identityAuthority = new TestReviewIdentityAuthority();
    identityAuthority.registerReviewLaunchPolicy({ launch_policy_id: existing.runtime_ref.id, reviewer: existing.independence.reviewer });
    const result = await invoke(["bind", seeded.planId, "--home", seeded.home, "--file", bindFile, "--json"], {
      reviewRunnerFactory: () => ({
        getReviewIdentityAuthority: () => identityAuthority.getReviewIdentityAuthority(),
        getReviewLaunchPolicy: id => identityAuthority.getReviewLaunchPolicy(id),
        async cancelExecution() {},
        async runVerificationCommand() { throw new Error("must not run"); },
      }),
    });
    expect(result.value).toMatchObject({ reviewer_binding: { reviewer_binding_id: "reviewer-binding:cli-public-bind" } });
    const reopened = new SqlitePhase3Store({ databasePath: join(seeded.home, "oef.sqlite") });
    try { expect(reopened.getReviewerBinding("reviewer-binding:cli-public-bind")?.runtime_ref.id).toBe(existing.runtime_ref.id); }
    finally { reopened.close(); }
    writeFileSync(bindFile, JSON.stringify({
      runner_home: seeded.home,
      reviewer_binding: {
        ...existing,
        reviewer_binding_id: "reviewer-binding:cli-forged-provider",
        model_ref: { ...existing.model_ref, provider: "provider-forged" },
        independence: { ...existing.independence, reviewer: { ...existing.independence.reviewer, provider: "provider-forged" } },
      },
      launch_policy: { docker_image: manifest.docker_image, executable: "reviewer", arguments: [] },
    }), "utf8");
    const forged = await invokeCode(["bind", seeded.planId, "--home", seeded.home, "--file", bindFile, "--json"], {
      reviewRunnerFactory: () => ({
        getReviewIdentityAuthority: () => identityAuthority.getReviewIdentityAuthority(),
        getReviewLaunchPolicy: id => identityAuthority.getReviewLaunchPolicy(id),
        async cancelExecution() {}, async runVerificationCommand() { throw new Error("must not run"); },
      }),
    });
    expect(forged.code).toBe(1);
    expect(forged.error).toContain("REVIEW_BINDING_RUNNER_IDENTITY_MISMATCH");
  });

  test("fails closed when the live source changes after the immutable review copy is prepared", async () => {
    const root = mkdtempSync(join(tmpdir(), "oef-phase3-cli-toctou-"));
    roots.push(root);
    const seeded = seedStartableReview(root);
    const manifest = JSON.parse(readFileSync(seeded.runFile, "utf8"));
    const identityAuthority = new TestReviewIdentityAuthority();
    registerSeededPolicy(identityAuthority, seeded);
    const sourceFile = join(manifest.source, "classifier.ts");
    const dependencies: OefPhase3CliDependencies = {
      async resolveLiveReviewInputs() {
        const current = JSON.parse(readFileSync(seeded.runFile, "utf8"));
        return {
          source: current.source,
          evidence: current.evidence,
          artifacts: current.artifacts,
          current_snapshot: current.current_snapshot,
          mechanical_evidence: current.mechanical_evidence,
          current_validity: { ...current.current_validity, source_tree_hash: computeReviewTreeHash(current.source) },
          validation_authority: { contract_revision_id: current.current_snapshot.contract.revision_id, contract_refs: [], evidence_refs: [] },
          context_authority: Object.fromEntries(current.reviewer_commands.map((command: { context: { review_unit: { id: string } } }) => [command.context.review_unit.id, command.context])),
        };
      },
      reviewRunnerFactory: () => ({
        getReviewIdentityAuthority: () => identityAuthority.getReviewIdentityAuthority(),
        getReviewLaunchPolicy: id => identityAuthority.getReviewLaunchPolicy(id),
        async cancelExecution() {},
        async runVerificationCommand(request) {
          writeFileSync(sourceFile, "export const classify = () => 'changed-after-copy';\n", "utf8");
          const stdout = join(root, "toctou-stdout.json");
          const stderr = join(root, "toctou-stderr.txt");
          const output = JSON.stringify({ schema_version: 1, review_unit_id: seeded.unitId, snapshot_hash: seeded.snapshotHash, decision: { recommendation: "pass" }, summary: "No issue.", findings: [], unanswered_questions: [], requested_evidence: [] });
          writeFileSync(stdout, output); writeFileSync(stderr, "");
          return identityAuthority.createAtomicReviewResult(request, { process_id: "supervised-process:cli-toctou", exit_code: 0, failure_type: null, timed_out: null, stdout_path: stdout, stderr_path: stderr, output_bytes: output.length, redaction_count: 0 } as never);
        },
      }),
    };
    const result = await invoke(["start", seeded.planId, "--home", seeded.home, "--run-file", seeded.runFile, "--json"], dependencies);
    expect(result.value).toMatchObject({ status: "TERMINAL", outcome: { decision: { decision: "INCONCLUSIVE" } } });
    expect((result.value as { outcome: { decision: { reason_codes: string[] } } }).outcome.decision.reason_codes).toContain("source-tree-changed");
  });

  test("reruns the same snapshot after a waiver without receipt, artifact, or audit collisions", async () => {
    const root = mkdtempSync(join(tmpdir(), "oef-phase3-cli-waiver-rerun-"));
    roots.push(root);
    const seeded = seedStartableReview(root);
    const identityAuthority = new TestReviewIdentityAuthority();
    registerSeededPolicy(identityAuthority, seeded);
    let executions = 0;
    const dependencies: OefPhase3CliDependencies = {
      async resolveLiveReviewInputs() {
        const manifest = JSON.parse(readFileSync(seeded.runFile, "utf8"));
        return {
          source: manifest.source,
          evidence: manifest.evidence,
          artifacts: manifest.artifacts,
          current_snapshot: manifest.current_snapshot,
          mechanical_evidence: manifest.mechanical_evidence,
          current_validity: manifest.current_validity,
          validation_authority: { contract_revision_id: manifest.current_snapshot.contract.revision_id, contract_refs: ["AC-1"], evidence_refs: ["evidence:test"] },
          context_authority: Object.fromEntries(manifest.reviewer_commands.map((command: { context: { review_unit: { id: string } } }) => [command.context.review_unit.id, command.context])),
        };
      },
      reviewRunnerFactory: () => ({
        getReviewIdentityAuthority: () => identityAuthority.getReviewIdentityAuthority(),
        getReviewLaunchPolicy: id => identityAuthority.getReviewLaunchPolicy(id),
        async cancelExecution() {},
        async runVerificationCommand(request) {
          executions += 1;
          const manifest = JSON.parse(readFileSync(seeded.runFile, "utf8"));
          const file = createReviewSnapshotFileIndex(manifest.source).find(item => item.path === "classifier.ts")!;
          const stdout = join(root, `waiver-stdout-${executions}.json`);
          const stderr = join(root, `waiver-stderr-${executions}.txt`);
          const output = JSON.stringify({
            schema_version: 1, review_unit_id: seeded.unitId, snapshot_hash: seeded.snapshotHash,
            decision: { recommendation: "changes-requested" }, summary: "A bounded high-severity issue remains.",
            findings: [{
              finding_key: "FIND-WAIVER-RERUN", category: "correctness", proposed_severity: "HIGH", confidence: 0.95,
              claim: "The bounded behavior needs explicit risk acceptance.", impact: "The known behavior remains for this snapshot.",
              contract_refs: ["AC-1"], code_locations: [{ path: file.path, start_line: 1, end_line: 1, file_hash: file.file_hash }],
              evidence_refs: ["evidence:test"], verification: { reproducible: true, reproduction_steps: ["Inspect classifier.ts."] },
              recommendation: "Accept or repair the bounded behavior.",
            }], unanswered_questions: [], requested_evidence: [],
          });
          writeFileSync(stdout, output); writeFileSync(stderr, "");
          return identityAuthority.createAtomicReviewResult(request, { process_id: `supervised-process:waiver-${executions}`, exit_code: 0, failure_type: null, timed_out: null, stdout_path: stdout, stderr_path: stderr, output_bytes: output.length, redaction_count: 0 } as never);
        },
      }),
    };
    const first = await invoke(["start", seeded.planId, "--home", seeded.home, "--run-file", seeded.runFile, "--json"], dependencies);
    expect(first.value).toMatchObject({ outcome: { decision: { decision: "CHANGES_REQUESTED" } } });
    const store = new SqlitePhase3Store({ databasePath: join(seeded.home, "oef.sqlite") });
    try {
      const planOne = store.getReviewPlan(seeded.planId)!;
      const stateOne = store.getReviewPlanState(seeded.planId)!;
      const finding = store.listFindings(seeded.planId).find(candidate => candidate.status === "CONFIRMED")!;
      store.insertWaiver(createWaiver({
        waiver_id: "review-waiver:cli-same-snapshot", finding, decision: "ACCEPTED_RISK",
        rationale: "The accountable owner accepts this exact bounded high-severity finding.", approved_by: { type: "human", id: "human:local-owner" },
        expires_at: null, conditions: ["no-severity-increase"], snapshot_hash: planOne.snapshot.snapshot_hash, created_at: "2026-07-23T16:00:00.000Z",
      }));
      const superseded = parseReviewPlanState({ ...stateOne, status: "SUPERSEDED", aggregate_version: stateOne.aggregate_version + 1, updated_at: "2026-07-23T16:00:01.000Z" });
      expect(store.updateReviewPlanState(superseded, stateOne.aggregate_version)).toBeTrue();
      const planTwo = parseReviewPlan({ ...planOne, revision: 2, previous_revision_hash: hashReviewPlan(planOne), created_at: "2026-07-23T16:00:02.000Z" });
      const stateTwo = parseReviewPlanState({
        schema_version: 1, review_plan_id: seeded.planId, snapshot_hash: planTwo.snapshot.snapshot_hash, status: "CREATED",
        unit_states: planTwo.review_units.map(unit => ({ review_unit_id: unit.review_unit_id, status: "CREATED", review_execution_id: null, result_artifact_id: null })),
        counters: { review_rounds: 0, repair_rounds: 0, evidence_requests: 0, adjudication_rounds: 0, total_cost_units: 0 },
        aggregate_version: superseded.aggregate_version + 1, created_at: planTwo.created_at, updated_at: planTwo.created_at,
      });
      const baseline = store.getReviewValidityBaseline(seeded.planId, 1)!;
      store.insertReviewPlan(planTwo, hashReviewPlan(planTwo), stateTwo);
      store.insertReviewValidityBaseline(seeded.planId, 2, baseline, planTwo.created_at);
      const manifest = JSON.parse(readFileSync(seeded.runFile, "utf8"));
      manifest.reviewer_commands[0].context.review_plan = { id: seeded.planId, revision: 2, hash: hashReviewPlan(planTwo) };
      writeFileSync(seeded.runFile, JSON.stringify(manifest, null, 2));
    } finally { store.close(); }
    const rerun = await invoke(["rerun", seeded.planId, "--home", seeded.home, "--run-file", seeded.runFile, "--json"], dependencies);
    expect(rerun.value).toMatchObject({ review_plan_revision: 2, outcome: { decision: { decision: "PASS" } } });
    expect(executions).toBe(2);
    const reopened = new SqlitePhase3Store({ databasePath: join(seeded.home, "oef.sqlite") });
    try {
      expect(reopened.getReviewPlanState(seeded.planId)?.status).toBe("PASSED");
      expect(reopened.verifyEventChain(seeded.planId).valid).toBeTrue();
      expect(reopened.listEvents(seeded.planId).filter(event => event.event_type === "review.plan.created").map(event => event.payload.plan_revision)).toEqual([1, 2]);
    } finally { reopened.close(); }
  });
});

function registerSeededPolicy(authority: TestReviewIdentityAuthority, seeded: { home: string; runFile: string }): void {
  const manifest = JSON.parse(readFileSync(seeded.runFile, "utf8"));
  const store = new SqlitePhase3Store({ databasePath: join(seeded.home, "oef.sqlite") });
  try {
    const binding = store.getReviewerBinding(manifest.reviewer_commands[0].reviewer_binding_id)!;
    authority.registerReviewLaunchPolicy({ launch_policy_id: binding.runtime_ref.id, reviewer: binding.independence.reviewer });
  } finally { store.close(); }
}

function seedStartableReview(root: string): { home: string; runFile: string; planId: string; unitId: string; snapshotHash: string } {
  const home = join(root, "home");
  const source = join(root, "source");
  const evidence = join(root, "evidence");
  const artifacts = join(root, "artifacts");
  for (const directory of [home, source, evidence, artifacts]) mkdirSync(directory, { recursive: true });
  writeFileSync(join(source, "classifier.ts"), "export const classify = () => 'ok';\n", "utf8");
  const profile = createReviewProfile({
    review_profile_id: "spec-compliance", version: "1.0.0", objective: "Review the approved contract independently.",
    required_inputs: ["task-contract", "diff"], required_capabilities: ["diff-analysis", "structured-findings"], preferred_capabilities: [],
    workspace: { source_mode: "read-only", temp_write: "allowed", network: "denied" }, checks: { correctness: true },
    output_schema_ref: { id: "review-result", version: 1 }, renderer_ref: { id: "generic", version: "1.0.0" },
    budgets: { max_wall_time_seconds: 300, max_output_tokens: 4_000 }, independence: { different_session: "required", different_context: "required", different_provider: "preferred" },
    extensions: {}, created_at: NOW,
  });
  const snapshot = createReviewSnapshot({
    review_snapshot_id: "review-snapshot:cli-start",
    contract: { revision_id: "contract-revision:cli-start", revision: 1, hash: hash("a") },
    source: { base_commit: "abc123", result_tree_hash: computeReviewTreeHash(source), diff_hash: hash("c") },
    evidence: { package_id: `evidence-package:${"d".repeat(64)}`, package_hash: hash("d") },
    workflow: { id: "software-development", version: "1.0.0", hash: hash("e") }, policy: { id: "safe-default", version: "1.0.0", hash: hash("f") }, created_at: NOW,
  });
  const request = parseReviewRequest({
    schema_version: 1, review_request_id: "review-request:cli-start", task_id: "task:cli-start", contract_revision_id: snapshot.contract.revision_id,
    assignment_id: "assignment:cli-start", execution_id: "execution:cli-start", evidence_package_id: snapshot.evidence.package_id,
    requested_scope: ["opencodex.spec-compliance"], trigger: { type: "workflow-stage", stage: "review" }, created_by: { type: "system", id: "system:test" }, created_at: NOW,
  });
  const planId = "review-plan:cli-start";
  const unitId = "review-unit:cli-start";
  const plan = parseReviewPlan({
    schema_version: 1, review_plan_id: planId, revision: 1, previous_revision_hash: null, review_request_id: request.review_request_id, task_id: request.task_id, snapshot,
    risk: { level: "high", reasons: ["authentication"] },
    review_units: [{ review_unit_id: unitId, review_type: "opencodex.spec-compliance", profile_ref: { id: profile.review_profile_id, version: profile.version, hash: profile.content_hash }, required: true, required_capabilities: ["diff-analysis", "structured-findings"], preferred_capabilities: [], depends_on: [], prerequisites: ["mechanical-verification.passed"] }],
    execution_strategy: { parallel_groups: [[unitId]] }, adjudication_policy_ref: { id: "safe-default", version: "1.0.0", hash: hash("1") },
    quorum: { required_review_types: ["opencodex.spec-compliance"], minimum_independent_providers: 1, minimum_independence_score: 6, human_approval: "not-required" },
    budget: { max_wall_time_seconds: 600, max_total_output_tokens: 10_000, max_review_units: 2, max_parallel_units: 1 }, limits: { max_review_rounds: 3, max_repair_rounds: 3, max_evidence_requests: 3, max_adjudication_rounds: 1, max_total_cost_units: 100 }, created_at: NOW,
  });
  const state = parseReviewPlanState({
    schema_version: 1, review_plan_id: planId, snapshot_hash: snapshot.snapshot_hash, status: "CREATED",
    unit_states: [{ review_unit_id: unitId, status: "CREATED", review_execution_id: null, result_artifact_id: null }],
    counters: { review_rounds: 0, repair_rounds: 0, evidence_requests: 0, adjudication_rounds: 0, total_cost_units: 0 }, aggregate_version: 1, created_at: NOW, updated_at: NOW,
  });
  const validity = {
    contract_hash: snapshot.contract.hash, source_tree_hash: snapshot.source.result_tree_hash, diff_hash: snapshot.source.diff_hash,
    evidence_package_hash: snapshot.evidence.package_hash, policy_hash: snapshot.policy.hash, profile_hashes: [profile.content_hash],
    required_evidence_hashes: [hash("7")], dependency_hash: hash("8"),
  };
  const store = new SqlitePhase3Store({ databasePath: join(home, "oef.sqlite") });
  try {
    store.insertReviewProfile(profile); store.insertReviewRequest(request); store.insertReviewPlan(plan, hashReviewPlan(plan), state);
    store.insertReviewValidityBaseline(planId, 1, validity, NOW);
  } finally { store.close(); }
  const reviewer = { agent_id: "agent:cli-reviewer", provider: "provider-b", model_class: "review-spec", session_id: "session:cli-reviewer", context_id: "context:cli-reviewer" };
  const dockerImage = `example.invalid/reviewer@sha256:${"9".repeat(64)}`;
  const binding = {
    schema_version: 1, reviewer_binding_id: "reviewer-binding:cli-start", review_unit_id: unitId,
    reviewer_profile_ref: plan.review_units[0]!.profile_ref,
    runtime_ref: { id: createReviewLaunchPolicyId({ docker_image: dockerImage, executable: "reviewer", arguments: [] }), adapter_version: "1.0.0" },
    model_ref: { provider: reviewer.provider, model_class: reviewer.model_class, resolved_model: "provider-b/review-spec" },
    reviewer_capabilities: ["diff-analysis", "structured-findings"], risk_level: "high",
    independence: {
      implementer: { agent_id: "agent:cli-implementer", provider: "provider-a", model_class: "coding", session_id: "session:cli-implementer", context_id: "context:cli-implementer" },
      reviewer, source_access: "read-only", human_approval_required: false,
    },
    created_by: { type: "system", id: "system:review-router" }, created_at: NOW,
  };
  const bindingStore = new SqlitePhase3Store({ databasePath: join(home, "oef.sqlite") });
  try { bindingStore.insertReviewerBinding(parseReviewerBinding(binding)); }
  finally { bindingStore.close(); }
  const runFile = join(root, "review-run.json");
  writeFileSync(runFile, JSON.stringify({
    review_plan_id: planId, snapshot_hash: snapshot.snapshot_hash, runner_home: home, source, evidence, artifacts,
    docker_image: dockerImage,
    current_snapshot: snapshot,
    mechanical_evidence: { passed: true, evidence_hash: hash("7"), artifact_refs: ["evidence:mechanical"] },
    current_validity: validity,
    finding_validation_context: { snapshot_hash: snapshot.snapshot_hash, contract_revision_id: snapshot.contract.revision_id, files: [], contract_refs: [], evidence_refs: [] },
    satisfied_prerequisites: { [unitId]: ["mechanical-verification.passed"] },
    reviewer_commands: [{
      review_type: "opencodex.spec-compliance", executable: "reviewer", arguments: [], reviewer_binding_id: binding.reviewer_binding_id,
      context: {
        context_bundle_id: "review-context-bundle:cli-start", snapshot_hash: snapshot.snapshot_hash,
        review_unit: { id: unitId, objective: profile.objective, profile_ref: plan.review_units[0]!.profile_ref },
        task_contract: { revision_id: snapshot.contract.revision_id, revision: 1, hash: snapshot.contract.hash, goal: "Keep classification correct.", constraints: [], acceptance_criteria: [] },
        review_plan: { id: planId, revision: 1, hash: hashReviewPlan(plan) }, policy_pack: plan.adjudication_policy_ref,
        assignment: { objective: "Review classifier.", allowed_paths: ["classifier.ts"] },
        source: { base_commit: "abc123", changed_files: ["classifier.ts"], diff_artifact_ref: "artifact:diff", relevant_file_refs: [] },
        evidence: { mechanical_verification: ["evidence:mechanical"], baseline: [], secret_scan: [], dependency_changes: [] },
        repository_rules: [], implementer_summary: { content: "Implementation claims completion." }, previous_findings: [], generated_at: NOW,
      },
      result_validation_context: { review_unit_id: unitId, snapshot_hash: snapshot.snapshot_hash, snapshot_files: [], evidence_refs: [] },
    }],
  }, null, 2), "utf8");
  return { home, runFile, planId, unitId, snapshotHash: snapshot.snapshot_hash };
}

function seedRepairableReview(home: string): { taskId: string; planId: string; findingId: string } {
  const runtime = createPhase2Runtime({ home });
  let taskId: string;
  let revision: ReturnType<Phase2Runtime["phase1"]["store"]["getContractRevision"]>;
  try {
    taskId = runtime.phase1.ids.next("task");
    phase1(runtime, taskId, "CreateTask", {
      title: "Phase 3 CLI repair", workflow: { id: "software-development", version: "1.0.0" },
      policy: { id: "safe-default", version: "1.0.0" }, risk: { level: "high", reasons: ["authentication"] },
    });
    phase1(runtime, taskId, "CreateContractRevision", {
      parent_revision_id: null,
      document: {
        schema_version: 1, task_id: taskId, revision: 1, title: "Phase 3 CLI repair",
        goal: { summary: "Keep HTTP 403 authentication behavior correct." },
        scope: { included: ["src/classifier.ts"], excluded: ["Everything else"] },
        constraints: ["Preserve 429 behavior."],
        acceptance_criteria: [{ key: "AC-403", statement: "403 remains an authentication failure.", required_evidence: ["opencodex.regression-test-403"] }],
        risk: { level: "high", reasons: ["authentication"] }, budgets: { max_attempts: 3, max_parallel_writers: 1, max_cost_units: 20 },
        extensions: { "opencodex.plan": { schema_version: 1, exists: true } },
      },
    });
    revision = runtime.phase1.store.listContractRevisions(taskId)[0]!;
    phase1(runtime, taskId, "ProposeContractRevision", { revision_id: revision.revision_id });
    phase1(runtime, taskId, "ApproveContractRevision", { revision_id: revision.revision_id, rationale: "Approved for repair test." });
    for (const to of ["specification", "planning", "execution"] as const) {
      const task = runtime.phase1.store.getTask(taskId)!;
      phase1(runtime, taskId, "TransitionTaskStage", { from_stage: task.stage, to_stage: to });
    }
  } finally { runtime.close(); }
  if (!revision) throw new Error("Contract revision was not created");

  const store = new SqlitePhase3Store({ databasePath: join(home, "oef.sqlite") });
  const planId = "review-plan:cli-repair";
  const findingId = "review-finding:cli-repair";
  try {
    const profile = createReviewProfile({
      review_profile_id: "spec-compliance", version: "1.0.0", objective: "Review the approved contract.",
      required_inputs: ["task-contract", "diff"], required_capabilities: ["diff-analysis", "structured-findings"], preferred_capabilities: [],
      workspace: { source_mode: "read-only", temp_write: "allowed", network: "denied" }, checks: { correctness: true },
      output_schema_ref: { id: "review-result", version: 1 }, renderer_ref: { id: "generic", version: "1.0.0" },
      budgets: { max_wall_time_seconds: 300, max_output_tokens: 4_000 }, independence: { different_session: "required", different_context: "required", different_provider: "preferred" },
      extensions: {}, created_at: NOW,
    });
    const snapshot = createReviewSnapshot({
      review_snapshot_id: "review-snapshot:cli-repair",
      contract: { revision_id: revision.revision_id, revision: revision.revision_number, hash: revision.canonical_hash },
      source: { base_commit: "abc123", result_tree_hash: hash("b"), diff_hash: hash("c") },
      evidence: { package_id: `evidence-package:${"d".repeat(64)}`, package_hash: hash("d") },
      workflow: { id: "software-development", version: "1.0.0", hash: hash("e") }, policy: { id: "safe-default", version: "1.0.0", hash: hash("f") }, created_at: NOW,
    });
    const request = parseReviewRequest({
      schema_version: 1, review_request_id: "review-request:cli-repair", task_id: taskId, contract_revision_id: revision.revision_id,
      assignment_id: "assignment:source", execution_id: "execution:source", evidence_package_id: `evidence-package:${"d".repeat(64)}`,
      requested_scope: ["opencodex.spec-compliance"], trigger: { type: "workflow-stage", stage: "review" }, created_by: { type: "system", id: "system:test" }, created_at: NOW,
    });
    const plan = parseReviewPlan({
      schema_version: 1, review_plan_id: planId, revision: 1, previous_revision_hash: null, review_request_id: request.review_request_id, task_id: taskId, snapshot,
      risk: { level: "high", reasons: ["authentication"] }, review_units: [{ review_unit_id: "review-unit:cli-repair", review_type: "opencodex.spec-compliance", profile_ref: { id: profile.review_profile_id, version: profile.version, hash: profile.content_hash }, required: true, required_capabilities: ["diff-analysis", "structured-findings"], preferred_capabilities: [], depends_on: [], prerequisites: ["mechanical-verification.passed"] }],
      execution_strategy: { parallel_groups: [["review-unit:cli-repair"]] }, adjudication_policy_ref: { id: "safe-default", version: "1.0.0", hash: hash("a") },
      quorum: { required_review_types: ["opencodex.spec-compliance"], minimum_independent_providers: 1, minimum_independence_score: 3, human_approval: "not-required" },
      budget: { max_wall_time_seconds: 600, max_total_output_tokens: 10_000, max_review_units: 2, max_parallel_units: 1 }, limits: { max_review_rounds: 3, max_repair_rounds: 3, max_evidence_requests: 3, max_adjudication_rounds: 1, max_total_cost_units: 100 }, created_at: NOW,
    });
    const state = parseReviewPlanState({ schema_version: 1, review_plan_id: planId, snapshot_hash: snapshot.snapshot_hash, status: "CHANGES_REQUESTED", unit_states: [{ review_unit_id: "review-unit:cli-repair", status: "COMPLETED", review_execution_id: null, result_artifact_id: "artifact:result" }], counters: { review_rounds: 1, repair_rounds: 0, evidence_requests: 0, adjudication_rounds: 1, total_cost_units: 1 }, aggregate_version: 1, created_at: NOW, updated_at: NOW });
    const proposed = parseReviewFinding({ schema_version: 1, finding_id: findingId, finding_key: "FIND-CLI-403", review_plan_id: planId, review_unit_id: "review-unit:cli-repair", category: "correctness", proposed_severity: "HIGH", effective_severity: null, confidence: 0.95, status: "PROPOSED", claim: "HTTP 403 is classified as a rate limit.", impact: "Invalid credentials rotate accounts.", scope: { snapshot_hash: snapshot.snapshot_hash, contract_revision_id: revision.revision_id, source_tree_hash: snapshot.source.result_tree_hash, diff_hash: snapshot.source.diff_hash }, anchors: [{ type: "code", path: "src/classifier.ts", line_start: 1, line_end: 4, file_hash: hash("1"), symbol: null, snippet_hash: hash("2") }], contract_refs: ["AC-403"], evidence_refs: ["opencodex.regression-test-403"], evidence_strength: "STRONG", proposed_by: { reviewer_binding_id: "reviewer-binding:cli" }, created_at: NOW, updated_at: NOW, duplicate_of: null });
    store.insertReviewProfile(profile); store.insertReviewRequest(request); store.insertReviewPlan(plan, hashReviewPlan(plan), state); store.insertFinding(proposed);
    const validating = parseReviewFinding({ ...proposed, status: "VALIDATING" });
    store.updateFinding(validating, "PROPOSED");
    store.updateFinding(parseReviewFinding({ ...validating, status: "CONFIRMED", effective_severity: "HIGH" }), "VALIDATING");
    const decision = parseReviewDecisionRecord({
      schema_version: 1, review_decision_id: "review-decision:cli-repair", review_plan_id: planId, snapshot_hash: snapshot.snapshot_hash,
      decision: "CHANGES_REQUESTED", decision_source: "deterministic-policy", current_snapshot: true, quorum_satisfied: true,
      mechanical_verification_passed: true, accepted_findings: [findingId], dismissed_findings: [], unresolved_findings: [], waived_findings: [],
      waiver_ids: [], human_approval: null, severity_counts: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
      reason_codes: ["confirmed-repairable-finding"], rationale: "The confirmed finding requires repair.", next_action: { type: "repair" },
      decision_artifact_ref: "artifact:cli-repair-decision", issued_at: NOW,
    });
    store.insertReviewDecision(decision);
    let previous: string | null = null;
    for (const [index, definition] of [
      { event_type: "review.plan.created" as const, payload: { source_tree_hash: snapshot.source.result_tree_hash, contract_revision: snapshot.contract.revision, plan_revision: plan.revision, snapshot_hash: snapshot.snapshot_hash, required_unit_ids: plan.review_units.map(unit => unit.review_unit_id) } },
      { event_type: "finding.confirmed" as const, payload: { finding_id: findingId, finding_key: "FIND-CLI-403", severity: "HIGH" as const } },
      { event_type: "review.decision.issued" as const, payload: { decision: "repair" as const, blocker_ids: [findingId] } },
    ].entries()) {
      const event = createGovernanceAuditEvent({
        event_id: `review-event:cli-repair-${index + 1}`, event_type: definition.event_type, aggregate_type: "review-plan", aggregate_id: planId,
        aggregate_version: index + 1, task_id: taskId, occurred_at: NOW, actor: { type: "system", id: "system:test" }, payload: definition.payload,
        previous_event_hash: previous,
      });
      store.appendEvent(event); previous = event.event_hash;
    }
  } finally { store.close(); }
  return { taskId, planId, findingId };
}

function phase1(runtime: Phase2Runtime, taskId: string, commandType: string, payload: unknown): void {
  const commandId = runtime.phase1.ids.next("command");
  const result = runtime.phase1.bus.execute({ schema_version: 1, command_id: commandId, command_type: commandType, task_id: taskId, expected_aggregate_version: runtime.phase1.store.getTask(taskId)?.aggregate_version ?? 0, actor: { type: "human", id: "human:local-owner" }, idempotency_key: commandId, payload });
  if (!result.ok) throw new Error(JSON.stringify(result.error));
}

async function invoke(args: string[], dependencies: OefPhase3CliDependencies = {}): Promise<{ code: number; value: unknown }> {
  const result = await invokeCode(args, dependencies);
  if (result.code !== 0) throw new Error(result.error);
  return { code: result.code, value: JSON.parse(result.output.at(-1) ?? "null") };
}

async function invokeCode(args: string[], dependencies: OefPhase3CliDependencies = {}): Promise<{ code: number; output: string[]; error: string }> {
  const output: string[] = []; const errors: string[] = [];
  const originalLog = console.log; const originalError = console.error;
  console.log = (...values: unknown[]) => output.push(values.join(" "));
  console.error = (...values: unknown[]) => errors.push(values.join(" "));
  try {
    const code = await cmdOefPhase3("review", args, dependencies);
    return { code, output, error: errors.join("\n") };
  } finally { console.log = originalLog; console.error = originalError; }
}
