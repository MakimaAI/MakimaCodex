import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AuthenticatedRunnerHttpServer,
  CodexPromptRenderer,
  CompletionSagaService,
  StartupReconciliationWorker,
  ContextBundleCompiler,
  FakeRuntimeAdapter,
  GitWorktreeWorkspaceManager,
  HttpRunnerClient,
  LocalProcessSupervisor,
  LocalRunnerHost,
  MechanicalVerifier,
  readRequiredEvidenceLog,
  SingleAgentExecutionCoordinator,
  createPhase2Runtime,
  type Phase2Runtime,
} from "../src/oef/phase2";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* Git/runner handles may linger briefly on Windows */ }
  }
});

const git = process.platform === "win32" ? "C:\\Program Files\\Git\\cmd\\git.exe" : "git";
function root(): string { const value = mkdtempSync(join(tmpdir(), "oef-phase2-e2e-")); roots.push(value); return value; }
function gitRun(cwd: string, args: string[]): string {
  const result = Bun.spawnSync([git, ...args], { cwd, stdout: "pipe", stderr: "pipe", env: process.env });
  if (result.exitCode !== 0) throw new Error(new TextDecoder().decode(result.stderr));
  return new TextDecoder().decode(result.stdout).trim();
}

function repository(base: string): { path: string; head: string } {
  const path = join(base, "repository");
  mkdirSync(join(path, "src"), { recursive: true });
  mkdirSync(join(path, "tests"), { recursive: true });
  writeFileSync(join(path, "src", "agent-target.ts"), "export const value = 1;\n");
  writeFileSync(join(path, "tests", "agent-target.test.ts"), "import { expect, test } from 'bun:test';\nimport { value } from '../src/agent-target';\ntest('value', () => expect(value).toBe(1));\n");
  writeFileSync(join(path, "package.json"), JSON.stringify({ name: "phase2-e2e", private: true, type: "module" }, null, 2));
  gitRun(path, ["init", "-b", "main"]);
  gitRun(path, ["config", "user.email", "phase2@example.invalid"]);
  gitRun(path, ["config", "user.name", "Phase 2 E2E"]);
  gitRun(path, ["add", "."]);
  gitRun(path, ["commit", "-m", "baseline"]);
  return { path, head: gitRun(path, ["rev-parse", "HEAD"]) };
}

function phase1(runtime: Phase2Runtime, taskId: string, commandType: string, payload: unknown, actor = { type: "human", id: "human:local-owner" }) {
  const commandId = runtime.phase1.ids.next("command");
  const result = runtime.phase1.bus.execute({
    schema_version: 1,
    command_id: commandId,
    command_type: commandType,
    task_id: taskId,
    expected_aggregate_version: runtime.phase1.store.getTask(taskId)?.aggregate_version ?? 0,
    actor,
    idempotency_key: commandId,
    payload,
  });
  if (!result.ok) throw new Error(JSON.stringify(result.error));
  return result.value;
}

function approvedExecutionTask(runtime: Phase2Runtime): string {
  const taskId = runtime.phase1.ids.next("task");
  phase1(runtime, taskId, "CreateTask", {
    title: "Phase 2 end to end",
    workflow: { id: "software-development", version: "1.0.0" },
    policy: { id: "safe-default", version: "1.0.0" },
    risk: { level: "low", reasons: [] },
  });
  phase1(runtime, taskId, "CreateContractRevision", {
    parent_revision_id: null,
    document: {
      schema_version: 1, task_id: taskId, revision: 1, title: "Phase 2 E2E",
      goal: { summary: "Safely update the target implementation and test." },
      scope: { included: ["src/agent-target.ts", "tests/agent-target.test.ts"], excluded: ["Everything else"] },
      constraints: ["Do not merge or push."],
      acceptance_criteria: [{ key: "execution", statement: "The bounded execution package is verified.", required_evidence: ["opencodex.execution-package"] }],
      risk: { level: "low", reasons: [] },
      budgets: { max_attempts: 2, max_parallel_writers: 1, max_cost_units: 10 },
      extensions: { "opencodex.plan": { schema_version: 1, exists: true } },
    },
  });
  const revision = runtime.phase1.store.listContractRevisions(taskId)[0]!;
  phase1(runtime, taskId, "ProposeContractRevision", { revision_id: revision.revision_id });
  phase1(runtime, taskId, "ApproveContractRevision", { revision_id: revision.revision_id, rationale: "Approved." });
  for (const to of ["specification", "planning", "execution"]) {
    const task = runtime.phase1.store.getTask(taskId)!;
    phase1(runtime, taskId, "TransitionTaskStage", { from_stage: task.stage, to_stage: to });
  }
  return taskId;
}

describe("Phase 2 safe single-agent end-to-end", () => {
  test("accepts a legitimate empty evidence log but rejects missing advertised logs", () => {
    const base = root();
    const empty = join(base, "empty.log");
    writeFileSync(empty, "");
    expect(readRequiredEvidenceLog(empty)).toBe("");
    expect(() => readRequiredEvidenceLog(join(base, "missing.log"))).toThrow("EVIDENCE_LOG_MISSING_OR_UNREADABLE");
  });

  test("completes the required 23-step demo and keeps main unchanged across restart", async () => {
    const base = root();
    const repo = repository(base);
    const home = join(base, "oef-home");
    const runtime = createPhase2Runtime({ home });
    const taskId = approvedExecutionTask(runtime);
    const adapter = new FakeRuntimeAdapter();
    const host = new LocalRunnerHost({
      root: join(base, "runner"), runner_id: "runner:e2e", adapters: [adapter],
      supervisor: new LocalProcessSupervisor({ root: join(base, "processes") }), heartbeat_interval_ms: 50, lease_ttl_ms: 500,
    });
    const ipc = new AuthenticatedRunnerHttpServer({ host, token: "e".repeat(64) });
    const endpoint = ipc.start();
    const coordinator = new SingleAgentExecutionCoordinator({
      runtime,
      adapter,
      runner: new HttpRunnerClient({ endpoint, token: "e".repeat(64) }),
      workspaceManager: new GitWorktreeWorkspaceManager({ root: join(base, "workspaces"), git_executable: git, stability_window_ms: 20 }),
      contextCompiler: new ContextBundleCompiler(),
      promptRenderer: new CodexPromptRenderer(),
      verifier: new MechanicalVerifier({ command_runner: new HttpRunnerClient({ endpoint, token: "e".repeat(64) }) }),
      runRoot: join(base, "runs"),
    });
    let report;
    try {
      report = await coordinator.run({
        task_id: taskId,
        repository_id: "repo:e2e",
        repository_path: repo.path,
        base_commit: repo.head,
        assignment: {
          objective: "Change value from 1 to 2 and update its test.",
          role: "backend-implementer",
          scope: { allowed_paths: ["src/agent-target.ts", "tests/agent-target.test.ts"], denied_paths: [".github/**"] },
          required_capabilities: ["repository-read", "repository-write", "shell", "git", "structured-output"],
          preferred_capabilities: ["tool-events"],
          verification: {
            commands: [
              { executable: process.execPath, args: ["test", "tests/agent-target.test.ts"], timeout_seconds: 10 },
              { executable: process.execPath, args: ["-e", "console.log('lint passed')"], timeout_seconds: 10 },
              { executable: process.execPath, args: ["-e", "console.log('typecheck passed')"], timeout_seconds: 10 },
            ],
          },
          required_evidence: ["code-diff", "changed-files", "test-result", "lint-result", "typecheck-result", "secret-scan"],
          budgets: { max_wall_time_seconds: 60, max_idle_seconds: 10, max_attempts: 2, max_output_bytes: 1_000_000 },
        },
        binding: {
          agent_profile_ref: { id: "coding-primary", version: "1.0.0" },
          model_ref: { provider: "fake", model_class: "deterministic-test", resolved_model: null },
          environment_ref: { type: "local-worktree", version: 1 },
          account_ref: { id: "none" },
        },
        expected_changed_files: ["src/agent-target.ts", "tests/agent-target.test.ts"],
      });
    } finally {
      ipc.stop();
      await host.close();
    }

    expect(report.steps).toEqual([
      "task-read", "contract-approved", "assignment-created", "binding-created", "runtime-healthy", "worktree-created",
      "baseline-passed", "context-compiled", "runner-started", "events-streamed", "two-files-edited", "runtime-exited",
      "workspace-sealed", "path-policy-passed", "diff-created", "mechanical-verification-passed", "secret-scan-passed",
      "execution-completed", "evidence-package-created", "task-ready-for-review", "control-plane-restarted", "timeline-persisted",
      "main-branch-unchanged",
    ]);
    expect(report.result).toBe("READY_FOR_REVIEW");
    expect(report.changed_files).toEqual(["src/agent-target.ts", "tests/agent-target.test.ts"]);
    expect(gitRun(repo.path, ["rev-parse", "HEAD"])).toBe(repo.head);
    expect(readFileSync(join(repo.path, "src", "agent-target.ts"), "utf8")).toContain("value = 1");
    const executionId = report.execution_id;
    const registeredArtifacts = runtime.phase1.store.listArtifacts(taskId);
    const packageRef = registeredArtifacts.find(artifact => artifact.artifact_id === report.evidence_package_artifact_id)!;
    const evidencePackage = JSON.parse(new TextDecoder().decode(runtime.phase1.artifacts.get(packageRef))) as {
      manifest_ref: { artifact_id: string };
      evidence: Array<{ artifact_id: string }>;
    };
    const registeredIds = new Set(registeredArtifacts.map(artifact => artifact.artifact_id));
    expect(registeredIds.has(evidencePackage.manifest_ref.artifact_id)).toBeTrue();
    expect(evidencePackage.evidence.every(item => registeredIds.has(item.artifact_id))).toBeTrue();
    const artifactCount = runtime.phase1.store.listArtifacts(taskId).length;
    const evidenceCount = runtime.phase1.store.listEvidence(taskId).length;
    const completedSaga = runtime.store.getCompletionSaga(executionId)!;
    expect(completedSaga.status).toBe("DONE");
    runtime.store.saveCompletionSaga({ ...completedSaga, status: "EXECUTION_COMPLETED" });
    expect(new CompletionSagaService(runtime).resumePending()).toEqual([{ execution_id: executionId, completed: true }]);
    expect(runtime.store.getCompletionSaga(executionId)?.status).toBe("DONE");
    expect(runtime.phase1.store.listEvidence(taskId)).toHaveLength(evidenceCount);
    runtime.store.saveCompletionSaga({
      ...completedSaga,
      status: "EXECUTION_COMPLETED",
      outcome: "PENDING",
      package_artifact: null,
      manifest_artifact: { ...completedSaga.manifest_artifact, content_hash: `sha256:${"0".repeat(64)}` },
    });
    await expect(new StartupReconciliationWorker(runtime).run()).rejects.toThrow("COMPLETION_SAGA_RESUME_FAILED");
    expect(runtime.store.getCompletionSaga(executionId)).toMatchObject({ status: "EXECUTION_COMPLETED", outcome: "PENDING" });
    runtime.store.saveCompletionSaga(completedSaga);
    const eventCount = runtime.store.listEvents(executionId).length;
    runtime.close();

    const reopened = createPhase2Runtime({ home });
    try {
      expect(reopened.store.getExecution(executionId)?.status).toBe("COMPLETED");
      expect(reopened.store.listEvents(executionId)).toHaveLength(eventCount);
      expect(reopened.phase1.store.listArtifacts(taskId)).toHaveLength(artifactCount);
      expect(reopened.phase1.store.getTask(taskId)?.stage).toBe("review");
    } finally {
      reopened.close();
    }
  }, 30_000);

  test("terminalizes, quarantines, and packages a runtime failure instead of leaving RUNNING state", async () => {
    const base = root();
    const repo = repository(base);
    const runtime = createPhase2Runtime({ home: join(base, "oef-home") });
    const taskId = approvedExecutionTask(runtime);
    const adapter = new FakeRuntimeAdapter();
    const host = new LocalRunnerHost({
      root: join(base, "runner"), runner_id: "runner:failure", adapters: [adapter],
      supervisor: new LocalProcessSupervisor({ root: join(base, "processes") }), heartbeat_interval_ms: 50, lease_ttl_ms: 500,
    });
    const ipc = new AuthenticatedRunnerHttpServer({ host, token: "f".repeat(64) });
    const endpoint = ipc.start();
    let report;
    try {
      report = await new SingleAgentExecutionCoordinator({
        runtime, adapter, runner: new HttpRunnerClient({ endpoint, token: "f".repeat(64) }),
        workspaceManager: new GitWorktreeWorkspaceManager({ root: join(base, "workspaces"), git_executable: git, stability_window_ms: 20 }),
        contextCompiler: new ContextBundleCompiler(), promptRenderer: new CodexPromptRenderer(),
        verifier: new MechanicalVerifier({ command_runner: new HttpRunnerClient({ endpoint, token: "f".repeat(64) }) }), runRoot: join(base, "runs"),
      }).run({
        task_id: taskId, repository_id: "repo:failure", repository_path: repo.path, base_commit: repo.head,
        assignment: {
          objective: "Exercise safe failure handling.", role: "backend-implementer",
          scope: { allowed_paths: ["src/agent-target.ts", "tests/agent-target.test.ts"], denied_paths: [".github/**"] },
          required_capabilities: ["repository-read", "repository-write", "shell", "git", "structured-output"], preferred_capabilities: [],
          verification: { commands: [{ executable: process.execPath, args: ["test", "tests/agent-target.test.ts"], timeout_seconds: 10 }] },
          required_evidence: ["runtime-events", "failure"],
          budgets: { max_wall_time_seconds: 1, max_idle_seconds: 1, max_attempts: 2, max_output_bytes: 1_000_000 },
        },
        binding: {
          agent_profile_ref: { id: "coding-primary", version: "1.0.0" },
          model_ref: { provider: "fake", model_class: "deterministic-test", resolved_model: null },
          environment_ref: { type: "local-worktree", version: 1 }, account_ref: { id: "none" },
        },
        runtime_scenario: "startup-timeout",
      });
    } finally {
      ipc.stop();
      await host.close();
    }
    expect(report.result).toBe("BLOCKED");
    expect(runtime.store.getExecution(report.execution_id)?.status).toBe("FAILED");
    expect(runtime.store.getAttempt(report.attempt_id)?.status).toBe("FAILED");
    expect(runtime.store.listAttempts(report.execution_id)).toHaveLength(2);
    expect(report.steps).toContain("fresh-attempt-scheduled");
    expect((await new GitWorktreeWorkspaceManager({ root: join(base, "workspaces"), git_executable: git }).inspect(report.workspace_id)).workspace.cleanup_status).toBe("QUARANTINED");
    expect(report.steps).toContain("execution-terminal");
    expect(runtime.phase1.store.listArtifacts(taskId).some(artifact => artifact.artifact_id === report.evidence_package_artifact_id)).toBeTrue();
    expect(gitRun(repo.path, ["rev-parse", "HEAD"])).toBe(repo.head);
    runtime.close();
  }, 30_000);
});
