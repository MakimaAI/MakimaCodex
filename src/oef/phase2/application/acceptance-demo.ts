import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { AuthenticatedRunnerHttpServer, HttpRunnerClient } from "../runner/http-ipc";
import { LocalRunnerHost } from "../runner/local-runner-host";
import { LocalProcessSupervisor } from "../runner/process-supervisor";
import { FakeRuntimeAdapter } from "../runtime/adapters/fake";
import { CodexRuntimeAdapter } from "../runtime/adapters/codex";
import type { RuntimeAdapter } from "../runtime/protocol";
import { GitWorktreeWorkspaceManager } from "../workspace/git-worktree-manager";
import { ContextBundleCompiler } from "../context/context-bundle";
import { CodexPromptRenderer } from "../context/prompt-renderer";
import { MechanicalVerifier } from "../verification/mechanical-verifier";
import { createPhase2Runtime, type Phase2Runtime } from "./runtime";
import { SingleAgentExecutionCoordinator, type SingleAgentRunReport } from "./single-agent-coordinator";

export interface Phase2AcceptanceDemoResult {
  runtime: "fake" | "codex";
  root: string;
  home: string;
  repository_path: string;
  report_path: string;
  report: SingleAgentRunReport;
  main_branch_unchanged: boolean;
  persisted_execution_status: string;
  persisted_task_stage: string;
}

export async function runPhase2AcceptanceDemo(options: { root: string; runtime: "fake" | "codex" }): Promise<Phase2AcceptanceDemoResult> {
  const root = resolve(options.root);
  mkdirSync(root, { recursive: true });
  const reportPath = join(root, "acceptance-report.json");
  if (existsSync(reportPath)) throw new Error("Acceptance demo root already contains a report");
  const git = defaultGitExecutable();
  const repository = createRepository(join(root, "repository"), git);
  const home = join(root, "oef-home");
  const runtime = createPhase2Runtime({ home });
  const taskId = createApprovedExecutionTask(runtime);
  const adapter: RuntimeAdapter = options.runtime === "fake" ? new FakeRuntimeAdapter() : new CodexRuntimeAdapter();
  const host = new LocalRunnerHost({
    root: join(root, "runner"),
    runner_id: `runner:acceptance-${options.runtime}`,
    adapters: [adapter],
    supervisor: new LocalProcessSupervisor({ root: join(root, "processes") }),
    heartbeat_interval_ms: 1_000,
    lease_ttl_ms: 5_000,
  });
  const token = randomBytes(32).toString("base64url");
  const server = new AuthenticatedRunnerHttpServer({ host, token });
  const endpoint = server.start();
  let report: SingleAgentRunReport;
  try {
    report = await new SingleAgentExecutionCoordinator({
      runtime,
      adapter,
      runner: new HttpRunnerClient({ endpoint, token }),
      workspaceManager: new GitWorktreeWorkspaceManager({ root: join(root, "workspaces"), git_executable: git, stability_window_ms: 50 }),
      contextCompiler: new ContextBundleCompiler(),
      promptRenderer: new CodexPromptRenderer(),
      verifier: new MechanicalVerifier({ command_runner: new HttpRunnerClient({ endpoint, token }) }),
      runRoot: join(root, "runs"),
    }).run({
      task_id: taskId,
      repository_id: "repo:phase2-acceptance",
      repository_path: repository.path,
      base_commit: repository.head,
      assignment: {
        objective: "Change the exported value from 1 to 2 and update exactly its matching test expectation from 1 to 2.",
        role: "backend-implementer",
        scope: { allowed_paths: ["src/agent-target.ts", "tests/agent-target.test.ts"], denied_paths: [".github/**"] },
        required_capabilities: ["repository-read", "repository-write", "shell", "git", "structured-output"],
        preferred_capabilities: ["tool-events"],
        verification: {
          commands: [
            { executable: process.execPath, args: ["test", "tests/agent-target.test.ts"], timeout_seconds: 30 },
            { executable: process.execPath, args: [join(repository.path, "scripts", "lint.mjs")], timeout_seconds: 30 },
            { executable: process.execPath, args: [phase2AcceptanceTypeScriptExecutable(), "--noEmit", "--project", "tsconfig.json"], timeout_seconds: 30 },
          ],
        },
        required_evidence: ["code-diff", "changed-files", "test-result", "lint-result", "typecheck-result", "secret-scan"],
        budgets: {
          max_wall_time_seconds: options.runtime === "codex" ? 600 : 60,
          max_idle_seconds: options.runtime === "codex" ? 180 : 10,
          max_attempts: 2,
          max_output_bytes: 5_000_000,
        },
      },
      binding: {
        agent_profile_ref: { id: "coding-primary", version: "1.0.0" },
        model_ref: { provider: options.runtime === "codex" ? "openai" : "fake", model_class: "coding-high", resolved_model: null },
        environment_ref: { type: "local-worktree", version: 1 },
        account_ref: { id: options.runtime === "codex" ? "codex-local-auth" : "none" },
      },
      expected_changed_files: ["src/agent-target.ts", "tests/agent-target.test.ts"],
    });
  } finally {
    server.stop();
    await host.close();
  }
  const mainBranchUnchanged = gitRun(repository.path, ["rev-parse", "HEAD"], git) === repository.head
    && readFileSync(join(repository.path, "src", "agent-target.ts"), "utf8").includes("value = 1");
  const persistedExecutionStatus = runtime.store.getExecution(report.execution_id)?.status ?? "MISSING";
  const persistedTaskStage = runtime.phase1.store.getTask(taskId)?.stage ?? "MISSING";
  const result: Phase2AcceptanceDemoResult = {
    runtime: options.runtime,
    root,
    home,
    repository_path: repository.path,
    report_path: reportPath,
    report,
    main_branch_unchanged: mainBranchUnchanged,
    persisted_execution_status: persistedExecutionStatus,
    persisted_task_stage: persistedTaskStage,
  };
  writeFileSync(reportPath, JSON.stringify(result, null, 2), "utf8");
  runtime.close();
  const reopened = createPhase2Runtime({ home });
  try {
    if (reopened.store.getExecution(report.execution_id)?.status !== "COMPLETED") throw new Error("Acceptance demo restart lost execution state");
    if (reopened.phase1.store.getTask(taskId)?.stage !== "review") throw new Error("Acceptance demo restart lost task stage");
  } finally { reopened.close(); }
  return result;
}

function createRepository(path: string, git: string): { path: string; head: string } {
  if (existsSync(path)) throw new Error("Acceptance demo repository path already exists");
  mkdirSync(join(path, "src"), { recursive: true });
  mkdirSync(join(path, "tests"), { recursive: true });
  writeFileSync(join(path, "src", "agent-target.ts"), "export const value = 1;\n", "utf8");
  writeFileSync(join(path, "tests", "agent-target.test.ts"), "import { expect, test } from 'bun:test';\nimport { value } from '../src/agent-target';\ntest('value', () => expect(value).toBe(1));\n", "utf8");
  writeFileSync(join(path, "package.json"), JSON.stringify({ name: "phase2-acceptance", private: true, type: "module" }, null, 2), "utf8");
  writeFileSync(join(path, "tsconfig.json"), JSON.stringify({
    compilerOptions: { strict: true, noEmit: true, target: "ESNext", module: "ESNext", moduleResolution: "Bundler" },
    include: ["src/**/*.ts"],
  }, null, 2), "utf8");
  mkdirSync(join(path, "scripts"), { recursive: true });
  writeFileSync(join(path, "scripts", "lint.mjs"), [
    "import { readFileSync } from 'node:fs';",
    "for (const file of ['src/agent-target.ts', 'tests/agent-target.test.ts']) {",
    "  const source = readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');",
    "  if (/\\t|[ \\t]+$/m.test(source)) throw new Error(`lint failed: ${file}`);",
    "}",
    "console.log('lint passed');",
    "",
  ].join("\n"), "utf8");
  gitRun(path, ["init", "-b", "main"], git);
  gitRun(path, ["config", "user.email", "phase2@example.invalid"], git);
  gitRun(path, ["config", "user.name", "Phase 2 Acceptance"], git);
  gitRun(path, ["add", "."], git);
  gitRun(path, ["commit", "-m", "baseline"], git);
  return { path, head: gitRun(path, ["rev-parse", "HEAD"], git) };
}

function createApprovedExecutionTask(runtime: Phase2Runtime): string {
  const taskId = runtime.phase1.ids.next("task");
  phase1(runtime, taskId, "CreateTask", {
    title: "Phase 2 acceptance demo",
    workflow: { id: "software-development", version: "1.0.0" },
    policy: { id: "safe-default", version: "1.0.0" },
    risk: { level: "low", reasons: [] },
  });
  phase1(runtime, taskId, "CreateContractRevision", {
    parent_revision_id: null,
    document: {
      schema_version: 1,
      task_id: taskId,
      revision: 1,
      title: "Phase 2 acceptance demo",
      goal: { summary: "Update one implementation file and its test through the safe execution layer." },
      scope: { included: ["src/agent-target.ts", "tests/agent-target.test.ts"], excluded: ["Every other path"] },
      constraints: ["Do not merge or push.", "Change exactly two files."],
      acceptance_criteria: [{ key: "execution", statement: "A verified execution package is recorded.", required_evidence: ["opencodex.execution-package"] }],
      risk: { level: "low", reasons: [] },
      budgets: { max_attempts: 2, max_parallel_writers: 1, max_cost_units: 20 },
      extensions: { "opencodex.plan": { schema_version: 1, exists: true } },
    },
  });
  const revision = runtime.phase1.store.listContractRevisions(taskId)[0]!;
  phase1(runtime, taskId, "ProposeContractRevision", { revision_id: revision.revision_id });
  phase1(runtime, taskId, "ApproveContractRevision", { revision_id: revision.revision_id, rationale: "Acceptance demo approved." });
  for (const to of ["specification", "planning", "execution"]) {
    const task = runtime.phase1.store.getTask(taskId)!;
    phase1(runtime, taskId, "TransitionTaskStage", { from_stage: task.stage, to_stage: to });
  }
  return taskId;
}

function phase1(runtime: Phase2Runtime, taskId: string, type: string, payload: unknown): void {
  const commandId = runtime.phase1.ids.next("command");
  const result = runtime.phase1.bus.execute({
    schema_version: 1,
    command_id: commandId,
    command_type: type,
    task_id: taskId,
    expected_aggregate_version: runtime.phase1.store.getTask(taskId)?.aggregate_version ?? 0,
    actor: { type: "human", id: "human:local-owner" },
    idempotency_key: commandId,
    payload,
  });
  if (!result.ok) throw new Error(`Acceptance demo Phase 1 command failed: ${JSON.stringify(result.error)}`);
}

function gitRun(cwd: string, args: string[], git: string): string {
  const result = Bun.spawnSync([git, ...args], { cwd, stdin: "ignore", stdout: "pipe", stderr: "pipe", env: process.env, windowsHide: true });
  if (result.exitCode !== 0) throw new Error(`Git command failed: ${new TextDecoder().decode(result.stderr).slice(0, 4_000)}`);
  return new TextDecoder().decode(result.stdout).trim();
}
function defaultGitExecutable(): string { return process.platform === "win32" ? "C:\\Program Files\\Git\\cmd\\git.exe" : "git"; }
export function phase2AcceptanceTypeScriptExecutable(): string {
  return fileURLToPath(new URL("../../../../node_modules/typescript/bin/tsc", import.meta.url));
}
