import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cmdOefPhase2 } from "../src/cli/oef-phase2";
import { acquireRunnerDaemonLock, createPhase2Runtime, runnerClientFromHome, runnerDaemonPaths, type Phase2Runtime } from "../src/oef/phase2";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* CLI child handles may linger briefly */ }
  }
});

describe("Phase 2 JSON CLI", () => {
  test("enforces a home-scoped singleton lock and recovers after the owner releases it", () => {
    const root = mkdtempSync(join(tmpdir(), "oef-phase2-daemon-lock-"));
    roots.push(root);
    const paths = runnerDaemonPaths(join(root, "home"));
    const first = acquireRunnerDaemonLock(paths.root);
    try {
      expect(() => acquireRunnerDaemonLock(paths.root)).toThrow("RUNNER_DAEMON_ALREADY_RUNNING");
    } finally { first.release(); }
    const recovered = acquireRunnerDaemonLock(paths.root);
    recovered.release();
  });

  test("supports runtime discovery and persistent runner controls", async () => {
    const root = mkdtempSync(join(tmpdir(), "oef-phase2-cli-"));
    roots.push(root);
    const home = join(root, "home");
    const scan = await invoke("runtimes", ["scan", "--home", home, "--json"]);
    expect(scan.code).toBe(0);
    expect(scan.value).toBeArray();
    expect((scan.value as Array<{ runtime_id: string }>).some(value => value.runtime_id === "codex-local")).toBeTrue();

    const started = await invoke("runner", ["start", "--home", home, "--json"]);
    expect(started.value).toMatchObject({ status: "READY", pid: expect.any(Number), endpoint: expect.stringMatching(/^http:\/\/127\.0\.0\.1:/) });
    try {
      expect((await invoke("runner", ["pause", "--home", home, "--json"])).value).toMatchObject({ kill_switch: { state: "PAUSE_NEW_EXECUTIONS" } });
      expect((await invoke("runner", ["resume", "--home", home, "--json"])).value).toMatchObject({ kill_switch: { state: "RUNNING" } });
      expect((await invoke("runner", ["status", "--home", home, "--json"])).value).toMatchObject({ runner: { status: "READY" }, kill_switch: { state: "RUNNING" } });
    } finally {
      await invoke("runner", ["stop", "--home", home, "--json"]);
    }
    expect((await invoke("runner", ["status", "--home", home, "--json"])).value).toMatchObject({ runner: { status: "STOPPED" }, reachable: false });
  });

  test("runs a fake execution and exposes assignment, execution, workspace, and verification commands", async () => {
    const root = mkdtempSync(join(tmpdir(), "oef-phase2-cli-e2e-"));
    roots.push(root);
    const demoRoot = join(root, "demo");
    const started = await invoke("oef-phase2-demo", ["--runtime", "fake", "--root", demoRoot, "--json"]);
    expect(started.code).toBe(0);
    const demo = started.value as {
      home: string;
      report: { task_id: string; assignment_id: string; execution_id: string; workspace_id: string; result: string };
    };
    expect(demo.report.result).toBe("READY_FOR_REVIEW");

    const assignment = await invoke("assignment", ["show", demo.report.assignment_id, "--home", demo.home, "--json"]);
    expect(assignment.value).toMatchObject({ assignment_id: demo.report.assignment_id });
    const execution = await invoke("execution", ["status", demo.report.execution_id, "--home", demo.home, "--json"]);
    expect(execution.value).toMatchObject({ execution_id: demo.report.execution_id, status: "COMPLETED" });
    const events = await invoke("execution", ["events", demo.report.execution_id, "--home", demo.home, "--json"]);
    expect((events.value as unknown[]).length).toBeGreaterThan(0);
    const artifacts = await invoke("execution", ["artifacts", demo.report.execution_id, "--home", demo.home, "--json"]);
    expect((artifacts.value as unknown[]).length).toBeGreaterThan(0);

    const workspaceRoot = join(demoRoot, "workspaces");
    const workspaces = await invoke("workspace", ["list", "--workspace-root", workspaceRoot, "--json"]);
    expect(workspaces.value).toEqual([expect.objectContaining({ workspace_id: demo.report.workspace_id })]);
    const inspected = await invoke("workspace", ["inspect", demo.report.workspace_id, "--workspace-root", workspaceRoot, "--json"]);
    expect(inspected.value).toMatchObject({ workspace: { workspace_id: demo.report.workspace_id } });
    const diff = await invoke("workspace", ["diff", demo.report.workspace_id, "--workspace-root", workspaceRoot, "--json"]);
    expect(diff.value).toMatchObject({ hash: expect.stringMatching(/^sha256:/) });

    const planPath = join(root, "verification-plan.json");
    writeFileSync(planPath, JSON.stringify({
      schema_version: 1,
      verification_plan_id: "verification:cli",
      steps: [{ id: "smoke", type: "command", command: { executable: process.execPath, arguments: ["-e", "console.log('ok')"] }, timeout_seconds: 10, required: true }],
    }));
    const verified = await invoke("verify", [
      "run", "--workspace", demo.report.workspace_id, "--plan", planPath,
      "--workspace-root", workspaceRoot, "--home", demo.home, "--json",
    ]);
    expect(verified.value).toMatchObject({ status: "PASSED" });
    const shown = await invoke("verify", ["show", "verification:cli", "--home", demo.home, "--json"]);
    expect(shown.value).toMatchObject({ verification_plan_id: "verification:cli", status: "PASSED" });

    const mutatingPlanPath = join(root, "mutating-verification-plan.json");
    writeFileSync(mutatingPlanPath, JSON.stringify({
      schema_version: 1,
      verification_plan_id: "verification:mutating-cli",
      steps: [{
        id: "mutate", type: "command",
        command: { executable: process.execPath, arguments: ["-e", "require('node:fs').appendFileSync('src/agent-target.ts', '\\n// verifier mutation\\n')"] },
        timeout_seconds: 10, required: true,
      }],
    }));
    await expect(invoke("verify", [
      "run", "--workspace", demo.report.workspace_id, "--plan", mutatingPlanPath,
      "--workspace-root", workspaceRoot, "--home", demo.home, "--json",
    ])).rejects.toThrow("WORKSPACE_SEAL_BROKEN");

    const assignmentId = seedApprovedAssignment(demo.home);
    await invoke("runner", ["start", "--home", demo.home, "--json"]);
    try {
      const general = await invoke("execution", [
        "start", "--assignment", assignmentId, "--runtime", "fake-local", "--repository", (started.value as { repository_path: string }).repository_path,
        "--workspace-root", join(root, "general-workspaces"), "--home", demo.home, "--json",
      ]);
      expect(general.value).toMatchObject({ assignment_id: assignmentId, result: "READY_FOR_REVIEW" });
    } finally {
      await invoke("runner", ["stop", "--home", demo.home, "--json"]);
    }
  }, 30_000);

  test("cancels a live daemon execution before reporting durable cancellation", async () => {
    const root = mkdtempSync(join(tmpdir(), "oef-phase2-cli-cancel-"));
    roots.push(root);
    const home = join(root, "home");
    const workspace = join(root, "workspace");
    mkdirSync(workspace, { recursive: true });
    await invoke("runner", ["start", "--home", home, "--json"]);
    try {
      const seeded = seedRunningExecution(home);
      const client = runnerClientFromHome(home);
      await client.startExecution({
        adapter_id: "fake-runtime",
        runtime_request: {
          execution_id: seeded.executionId, attempt_id: seeded.attemptId, workspace_path: workspace, prompt_path: join(workspace, "prompt.md"),
          prompt_hash: `sha256:${"8".repeat(64)}`, inherited_environment: ["PATH", "SYSTEMROOT", "WINDIR", "TEMP"], injected_secret_refs: [],
          timeouts: { startup_seconds: 2, idle_seconds: 10, tool_seconds: 10, total_seconds: 30, graceful_shutdown_seconds: 0.05 },
          output_limit_bytes: 1_000_000, scenario: "child-process-hang",
        },
      });
      await waitUntil(async () => (await client.getStatus(seeded.executionId)).status === "RUNNING", 3_000);
      const cancelled = await invoke("execution", ["cancel", seeded.executionId, "--home", home, "--json"]);
      expect(cancelled.value).toMatchObject({ execution: { status: "CANCELLED" }, cancellation_requested: true, runner_status: { status: "EXITED" } });
      expect((await client.getStatus(seeded.executionId)).exit?.cancelled).toBeTrue();
      const runtime = createPhase2Runtime({ home });
      try {
        expect(runtime.store.getExecution(seeded.executionId)?.status).toBe("CANCELLED");
        expect(runtime.store.getAttempt(seeded.attemptId)?.status).toBe("CANCELLED");
      } finally { runtime.close(); }
    } finally {
      await invoke("runner", ["stop", "--home", home, "--json"]);
    }
  }, 30_000);
});

function seedApprovedAssignment(home: string): string {
  const runtime = createPhase2Runtime({ home });
  try {
    const taskId = runtime.phase1.ids.next("task");
    phase1(runtime, taskId, "CreateTask", {
      title: "CLI general execution", workflow: { id: "software-development", version: "1.0.0" },
      policy: { id: "safe-default", version: "1.0.0" }, risk: { level: "low", reasons: [] },
    });
    phase1(runtime, taskId, "CreateContractRevision", {
      parent_revision_id: null,
      document: {
        schema_version: 1, task_id: taskId, revision: 1, title: "CLI general execution",
        goal: { summary: "Run an existing assignment through the persistent runner." },
        scope: { included: ["src/agent-target.ts", "tests/agent-target.test.ts"], excluded: ["Everything else"] },
        constraints: ["Do not merge or push."],
        acceptance_criteria: [{ key: "execution", statement: "Verified package exists.", required_evidence: ["opencodex.execution-package"] }],
        risk: { level: "low", reasons: [] }, budgets: { max_attempts: 2, max_parallel_writers: 1, max_cost_units: 10 },
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
    const assignmentId = runtime.ids.next("assignment");
    const commandId = runtime.ids.next("command");
    const result = runtime.bus.execute({
      schema_version: 1, command_id: commandId, command_type: "CreateAssignment", task_id: taskId,
      aggregate_id: assignmentId, expected_aggregate_version: 0, actor: { type: "human", id: "human:local-owner" },
      idempotency_key: commandId,
      payload: {
        contract_ref: { revision_id: revision.revision_id, hash: revision.canonical_hash },
        objective: "Change value from 1 to 2 and update its regression test.", role: "backend-implementer",
        scope: { allowed_paths: ["src/agent-target.ts", "tests/agent-target.test.ts"], denied_paths: [".github/**"] },
        required_capabilities: ["repository-read", "repository-write", "shell", "git", "structured-output"], preferred_capabilities: [],
        verification: { commands: [{ executable: process.execPath, args: ["test", "tests/agent-target.test.ts"], timeout_seconds: 10 }] },
        required_evidence: ["code-diff", "test-result"],
        budgets: { max_wall_time_seconds: 30, max_idle_seconds: 5, max_attempts: 2, max_output_bytes: 1_000_000 },
      },
    });
    if (!result.ok) throw new Error(JSON.stringify(result.error));
    return assignmentId;
  } finally { runtime.close(); }
}

function phase1(runtime: Phase2Runtime, taskId: string, commandType: string, payload: unknown): void {
  const commandId = runtime.phase1.ids.next("command");
  const result = runtime.phase1.bus.execute({
    schema_version: 1, command_id: commandId, command_type: commandType, task_id: taskId,
    expected_aggregate_version: runtime.phase1.store.getTask(taskId)?.aggregate_version ?? 0,
    actor: { type: "human", id: "human:local-owner" }, idempotency_key: commandId, payload,
  });
  if (!result.ok) throw new Error(JSON.stringify(result.error));
}

function seedRunningExecution(home: string): { executionId: string; attemptId: string } {
  const assignmentId = seedApprovedAssignment(home);
  const runtime = createPhase2Runtime({ home });
  try {
    const assignment = runtime.store.getAssignment(assignmentId)!;
    const bindingId = runtime.ids.next("binding");
    phase2(runtime, "CreateExecutionBinding", assignment.task_id, bindingId, 0, {
      assignment_id: assignmentId, assignment_revision: assignment.revision,
      agent_profile_ref: { id: "coding-primary", version: "1.0.0" }, runtime_ref: { id: "fake-local", adapter_version: "1.0.0" },
      model_ref: { provider: "fake", model_class: "test", resolved_model: null }, environment_ref: { type: "local-worktree", version: 1 }, account_ref: { id: "none" },
    });
    const executionId = runtime.ids.next("execution");
    phase2(runtime, "CreateExecution", assignment.task_id, executionId, 0, { assignment_id: assignmentId, assignment_revision: 1, binding_id: bindingId });
    let execution = runtime.store.getExecution(executionId)!;
    for (const status of ["QUEUED", "PREPARING"] as const) {
      phase2(runtime, "TransitionExecution", assignment.task_id, executionId, execution.aggregate_version, { to_status: status });
      execution = runtime.store.getExecution(executionId)!;
    }
    const attemptId = runtime.ids.next("attempt");
    phase2(runtime, "CreateExecutionAttempt", assignment.task_id, executionId, execution.aggregate_version, {
      attempt_id: attemptId, base_commit: "abc123", workspace_id: runtime.ids.next("workspace"),
      context_bundle_hash: `sha256:${"6".repeat(64)}`, binding_hash: `sha256:${"7".repeat(64)}`, failure_of_previous_attempt: null,
    });
    for (const status of ["LEASED", "WORKSPACE_PREPARING", "CONTEXT_PREPARING", "STARTING", "RUNNING"] as const) {
      execution = runtime.store.getExecution(executionId)!;
      phase2(runtime, "TransitionExecutionAttempt", assignment.task_id, attemptId, execution.aggregate_version, { to_status: status }, { type: "system", id: "system:local-runner" });
    }
    execution = runtime.store.getExecution(executionId)!;
    phase2(runtime, "TransitionExecution", assignment.task_id, executionId, execution.aggregate_version, { to_status: "RUNNING" });
    return { executionId, attemptId };
  } finally { runtime.close(); }
}

function phase2(runtime: Phase2Runtime, type: string, taskId: string, aggregateId: string, version: number, payload: unknown, actor: { type: "human" | "system"; id: string } = { type: "human", id: "human:local-owner" }): void {
  const commandId = runtime.ids.next("command");
  const result = runtime.bus.execute({ schema_version: 1, command_id: commandId, command_type: type, task_id: taskId, aggregate_id: aggregateId,
    expected_aggregate_version: version, actor, idempotency_key: commandId, payload });
  if (!result.ok) throw new Error(JSON.stringify(result.error));
}

async function waitUntil(predicate: () => boolean | Promise<boolean>, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!(await predicate())) {
    if (Date.now() >= deadline) throw new Error("Condition was not met before timeout");
    await Bun.sleep(20);
  }
}

async function invoke(group: string, args: string[]): Promise<{ code: number; value: unknown }> {
  const output: string[] = [];
  const errors: string[] = [];
  const originalLog = console.log;
  const originalError = console.error;
  console.log = (...values: unknown[]) => output.push(values.join(" "));
  console.error = (...values: unknown[]) => errors.push(values.join(" "));
  try {
    const code = await cmdOefPhase2(group, args);
    if (code !== 0) throw new Error(errors.join("\n"));
    return { code, value: JSON.parse(output.at(-1) ?? "null") };
  } finally {
    console.log = originalLog;
    console.error = originalError;
  }
}
