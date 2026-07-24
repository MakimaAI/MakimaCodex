import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { extname, join, resolve } from "node:path";
import {
  CodexRuntimeAdapter,
  CodexPromptRenderer,
  ContextBundleCompiler,
  FakeRuntimeAdapter,
  GitWorktreeWorkspaceManager,
  LocalRuntimeDiscovery,
  MechanicalVerifier,
  SafeRuntimeProbeExecutor,
  SingleAgentExecutionCoordinator,
  createPhase2Runtime,
  parseVerificationPlan,
  readRunnerDaemonStatus,
  runnerClientFromHome,
  runnerDaemonPaths,
  runPhase2AcceptanceDemo,
  type Phase2Runtime,
} from "../oef/phase2";

interface ParsedArgs { positionals: string[]; options: Map<string, string | true>; json: boolean }

export async function cmdOefPhase2(group: string, args: string[]): Promise<number> {
  const parsed = parseArgs(args);
  try {
    let value: unknown;
    if (group === "runtimes") value = await runtimesCommand(parsed);
    else if (group === "runner") value = await runnerCommand(parsed);
    else if (group === "assignment") value = assignmentCommand(parsed);
    else if (group === "execution") value = await executionCommand(parsed);
    else if (group === "workspace") value = await workspaceCommand(parsed);
    else if (group === "verify") value = await verifyCommand(parsed);
    else if (group === "oef-phase2-demo") {
      value = await runPhase2AcceptanceDemo({ root: resolve(required(parsed, "root")), runtime: runtimeOption(parsed) });
    } else throw new Error(`Unknown Phase 2 command group: ${group}`);
    console.log(JSON.stringify(value));
    return 0;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    return 1;
  }
}

async function runtimesCommand(parsed: ParsedArgs): Promise<unknown> {
  const subcommand = parsed.positionals[0];
  const home = phase2Home(parsed);
  const registryPath = join(home, "phase2", "runtime-registry.json");
  if (subcommand === "scan" || subcommand === "health" || !existsSync(registryPath)) {
    const adapters = [new CodexRuntimeAdapter(), new FakeRuntimeAdapter()];
    const snapshots = await new LocalRuntimeDiscovery({ probeExecutor: new SafeRuntimeProbeExecutor({ timeoutMs: 5_000 }) }).scan(adapters);
    mkdirSync(join(home, "phase2"), { recursive: true });
    writeFileSync(registryPath, JSON.stringify({ schema_version: 1, scanned_at: new Date().toISOString(), snapshots }, null, 2), "utf8");
    if (subcommand === "scan") return snapshots;
    if (subcommand === "health") {
      const id = parsed.positionals[1];
      return id ? requireSnapshot(snapshots, id) : snapshots;
    }
  }
  const registry = JSON.parse(readFileSync(registryPath, "utf8")) as { snapshots: Array<{ runtime_id: string; adapter_id: string }> };
  if (subcommand === "status") return registry.snapshots;
  if (subcommand === "inspect") return requireSnapshot(registry.snapshots, positional(parsed, 1, "runtime id"));
  if (subcommand === "health") return registry.snapshots;
  throw new Error("Usage: ocx runtimes <scan|status|inspect|health> [runtime-id] --json");
}

async function runnerCommand(parsed: ParsedArgs): Promise<unknown> {
  const subcommand = parsed.positionals[0];
  const home = phase2Home(parsed);
  if (subcommand === "start") {
    await ensureRunnerDaemon(home);
    return readRunnerDaemonStatus(home);
  }
  if (subcommand === "status") {
    const status = readRunnerDaemonStatus(home) ?? { status: "STOPPED" };
    try { return { runner: status, ...(await runnerClientFromHome(home).getControl()) }; }
    catch { return { runner: status, reachable: false }; }
  }
  const client = runnerClientFromHome(home);
  if (subcommand === "pause") return client.applyControl("PAUSE_NEW_EXECUTIONS", "operator pause");
  if (subcommand === "resume") return client.applyControl("RUNNING", "operator resume");
  if (subcommand === "kill-all") {
    const result = await client.applyControl("CANCEL_ALL", option(parsed, "reason") ?? "operator kill-all");
    const runtime = createPhase2Runtime({ home });
    try {
      for (const status of result.executions) terminalizeCancelledExecution(runtime, status.execution_id);
    } finally { runtime.close(); }
    return result;
  }
  if (subcommand === "stop") {
    const result = await client.shutdown();
    const deadline = Date.now() + 10_000;
    const paths = runnerDaemonPaths(home);
    while (Date.now() < deadline) {
      if (readRunnerDaemonStatus(home)?.status === "STOPPED" && !existsSync(paths.lock)) return result;
      await Bun.sleep(25);
    }
    throw new Error("RUNNER_DAEMON_STOP_TIMEOUT");
  }
  throw new Error("Usage: ocx runner <start|status|pause|resume|kill-all|stop> --json");
}

function assignmentCommand(parsed: ParsedArgs): unknown {
  const runtime = createPhase2Runtime({ home: phase2Home(parsed) });
  try {
    const subcommand = parsed.positionals[0];
    if (subcommand === "show") {
      const id = positional(parsed, 1, "assignment id");
      const revision = option(parsed, "revision");
      const assignment = runtime.store.getAssignment(id, revision ? positiveInteger(revision, "revision") : undefined);
      if (!assignment) throw new Error(`Assignment not found: ${id}`);
      return assignment;
    }
    if (subcommand === "create") {
      const taskId = required(parsed, "task");
      const task = runtime.phase1.store.getTask(taskId);
      if (!task?.active_contract_revision_id) throw new Error("Task has no active contract");
      const contract = runtime.phase1.store.getContractRevision(task.active_contract_revision_id);
      if (!contract) throw new Error("Active contract revision is missing");
      const payload = readDataFile(required(parsed, "file")) as Record<string, unknown>;
      const id = runtime.ids.next("assignment");
      return command(runtime, "CreateAssignment", taskId, id, 0, {
        contract_ref: { revision_id: contract.revision_id, hash: contract.canonical_hash },
        ...payload,
      }).assignment;
    }
    throw new Error("Usage: ocx assignment <create|show> ... --json");
  } finally { runtime.close(); }
}

async function executionCommand(parsed: ParsedArgs): Promise<unknown> {
  const subcommand = parsed.positionals[0];
  if (subcommand === "start") {
    const home = phase2Home(parsed);
    const runtime = createPhase2Runtime({ home });
    try {
      const assignmentId = required(parsed, "assignment");
      const assignment = runtime.store.getAssignment(assignmentId);
      if (!assignment) throw new Error("ASSIGNMENT_NOT_FOUND");
      const runtimeKind = runtimeOption(parsed);
      const adapter = runtimeKind === "fake" ? new FakeRuntimeAdapter() : new CodexRuntimeAdapter();
      let bindingId = option(parsed, "binding");
      let binding = bindingId ? runtime.store.getBinding(bindingId) : null;
      if (bindingId && !binding) throw new Error("BINDING_NOT_FOUND");
      if (!binding) {
        bindingId = runtime.ids.next("binding");
        binding = command(runtime, "CreateExecutionBinding", assignment.task_id, bindingId, 0, {
          assignment_id: assignment.assignment_id,
          assignment_revision: assignment.revision,
          agent_profile_ref: { id: option(parsed, "profile") ?? "coding-primary", version: "1.0.0" },
          runtime_ref: { id: adapter.manifest.runtime_id, adapter_version: adapter.manifest.adapter.version },
          model_ref: {
            provider: option(parsed, "model-provider") ?? runtimeKind,
            model_class: option(parsed, "model-class") ?? "coding-high",
            resolved_model: option(parsed, "model") ?? null,
          },
          environment_ref: { type: "local-worktree", version: 1 },
          account_ref: { id: option(parsed, "account") ?? "local-default" },
        }).binding!;
      }
      if (binding.runtime_ref.id !== adapter.manifest.runtime_id || binding.runtime_ref.adapter_version !== adapter.manifest.adapter.version) {
        throw new Error("BINDING_RUNTIME_MISMATCH");
      }
      const repositoryPath = resolve(required(parsed, "repository"));
      const baseCommit = option(parsed, "base") ?? gitHead(repositoryPath);
      const report = await new SingleAgentExecutionCoordinator({
        runtime,
        adapter,
        runner: runnerClientFromHome(home),
        workspaceManager: new GitWorktreeWorkspaceManager({ root: resolve(option(parsed, "workspace-root") ?? join(home, "phase2", "workspaces")), git_executable: defaultGit() }),
        contextCompiler: new ContextBundleCompiler(),
        promptRenderer: new CodexPromptRenderer(),
        verifier: new MechanicalVerifier({ command_runner: runnerClientFromHome(home) }),
        runRoot: join(home, "phase2", "runs"),
      }).run({
        task_id: assignment.task_id,
        repository_id: option(parsed, "repository-id") ?? `repo:${digest(repositoryPath).slice(0, 24)}`,
        repository_path: repositoryPath,
        base_commit: baseCommit,
        existing_assignment_id: assignmentId,
        existing_binding_id: bindingId!,
      });
      return report;
    } finally { runtime.close(); }
  }
  const runtime = createPhase2Runtime({ home: phase2Home(parsed) });
  try {
    const executionId = positional(parsed, 1, "execution id");
    const execution = runtime.store.getExecution(executionId);
    if (!execution) throw new Error(`Execution not found: ${executionId}`);
    if (subcommand === "status") return execution;
    if (subcommand === "events") return runtime.store.listEvents(executionId);
    if (subcommand === "watch") return { execution, events: runtime.store.listEvents(executionId) };
    if (subcommand === "artifacts") {
      const taskId = runtime.store.listEvents(executionId)[0]?.task_id;
      return taskId ? runtime.phase1.store.listArtifacts(taskId) : [];
    }
    if (subcommand === "cancel") {
      if (["COMPLETED", "FAILED", "INTERRUPTED", "CANCELLED"].includes(execution.status)) return { execution, cancellation_requested: false, reason: "terminal" };
      const taskId = runtime.store.getExecutionTaskId(executionId);
      if (!taskId) throw new Error("EXECUTION_TASK_NOT_FOUND");
      if (execution.status !== "CANCELLING") command(runtime, "TransitionExecution", taskId, executionId, execution.aggregate_version, { to_status: "CANCELLING" });
      const client = runnerClientFromHome(phase2Home(parsed));
      await client.cancelExecution(executionId);
      const deadline = Date.now() + 30_000;
      let runnerStatus;
      while (Date.now() < deadline) {
        runnerStatus = await client.getStatus(executionId);
        if (runnerStatus.status === "EXITED" || runnerStatus.status === "INTERRUPTED") break;
        await Bun.sleep(25);
      }
      if (!runnerStatus || (runnerStatus.status !== "EXITED" && runnerStatus.status !== "INTERRUPTED")) throw new Error("RUNNER_CANCELLATION_NOT_CONFIRMED");
      const terminal = terminalizeCancelledExecution(runtime, executionId);
      return { execution: terminal, cancellation_requested: true, runner_status: runnerStatus };
    }
    throw new Error("Usage: ocx execution <start|watch|status|cancel|events|artifacts> ... --json");
  } finally { runtime.close(); }
}

async function workspaceCommand(parsed: ParsedArgs): Promise<unknown> {
  const manager = new GitWorktreeWorkspaceManager({ root: resolve(required(parsed, "workspace-root")), git_executable: defaultGit() });
  const subcommand = parsed.positionals[0];
  if (subcommand === "list") return manager.list();
  const id = positional(parsed, 1, "workspace id");
  if (subcommand === "inspect") return manager.inspect(id);
  if (subcommand === "diff") return manager.exportPatch(id);
  if (subcommand === "cleanup") return manager.cleanup(id, { action: "QUARANTINE", reason: required(parsed, "reason") });
  throw new Error("Usage: ocx workspace <list|inspect|diff|cleanup> ... --json");
}

async function verifyCommand(parsed: ParsedArgs): Promise<unknown> {
  const subcommand = parsed.positionals[0];
  const home = phase2Home(parsed);
  const resultRoot = join(home, "phase2", "verifications");
  mkdirSync(resultRoot, { recursive: true });
  if (subcommand === "show") {
    const id = positional(parsed, 1, "verification id");
    const path = join(resultRoot, `${digest(id)}.json`);
    if (!existsSync(path)) throw new Error(`Verification not found: ${id}`);
    return JSON.parse(readFileSync(path, "utf8"));
  }
  if (subcommand !== "run") throw new Error("Usage: ocx verify <run|show> ... --json");
  const manager = new GitWorktreeWorkspaceManager({ root: resolve(required(parsed, "workspace-root")), git_executable: defaultGit() });
  const workspaceId = required(parsed, "workspace");
  const status = await manager.inspect(workspaceId);
  if (!status.workspace.sealed_at) throw new Error("Workspace must be sealed before verification");
  const patch = await manager.exportPatch(workspaceId);
  const plan = parseVerificationPlan(readDataFile(required(parsed, "plan")));
  const phase2 = createPhase2Runtime({ home });
  const attempt = phase2.store.getAttempt(status.workspace.attempt_id);
  const execution = attempt ? phase2.store.getExecution(attempt.execution_id) : null;
  phase2.close();
  if (!attempt || !execution || execution.current_attempt_id !== attempt.attempt_id) throw new Error("VERIFIER_CURRENT_EXECUTION_ATTEMPT_REQUIRED");
  const result = await new MechanicalVerifier({ command_runner: await ensureRunnerDaemon(home) }).run(plan, {
    workspace_id: workspaceId,
    path: status.workspace.worktree_path,
    base_commit: status.workspace.base_commit,
    environment_hash: status.workspace.baseline_hash,
    sealed: true,
    changed_files: status.changed_files.map(file => ({ path: file.path, dependency_file: file.dependency_file })),
    path_policy: status.path_policy,
    patch: patch.content,
  }, {
    execution_id: execution.execution_id,
    attempt_id: attempt.attempt_id,
    workspace_path: status.workspace.worktree_path,
  });
  const postVerificationSeal = await manager.assertSeal(workspaceId, status.workspace.sealed_snapshot_hash!);
  if (!postVerificationSeal.main_branch_unchanged || !postVerificationSeal.main_worktree_status_unchanged) {
    throw new Error("MAIN_BRANCH_CHANGED");
  }
  writeFileSync(join(resultRoot, `${digest(plan.verification_plan_id)}.json`), JSON.stringify(result, null, 2), "utf8");
  return result;
}

async function ensureRunnerDaemon(home: string) {
  try {
    const client = runnerClientFromHome(home);
    await client.getCapabilities();
    return client;
  } catch { /* stale or absent daemon status */ }
  const paths = runnerDaemonPaths(home);
  mkdirSync(paths.root, { recursive: true });
  const child = Bun.spawn([process.execPath, paths.launcher, "--home", home], {
    cwd: process.cwd(), stdin: "ignore", stdout: "ignore", stderr: "ignore", windowsHide: true, detached: true,
    env: minimumDaemonEnvironment(),
  });
  child.unref();
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const status = readRunnerDaemonStatus(home);
    if (status?.status === "READY") {
      const client = runnerClientFromHome(home);
      await client.getCapabilities();
      return client;
    }
    if (child.exitCode !== null && status?.status !== "STARTING") throw new Error(`RUNNER_DAEMON_START_FAILED:${child.exitCode}`);
    await Bun.sleep(25);
  }
  throw new Error("RUNNER_DAEMON_START_TIMEOUT");
}

function command(
  runtime: Phase2Runtime,
  type: string,
  taskId: string,
  aggregateId: string,
  expectedVersion: number,
  payload: unknown,
  actor: { type: "human" | "system"; id: string } = { type: "human", id: "human:local-owner" },
) {
  const commandId = runtime.ids.next("command");
  const result = runtime.bus.execute({
    schema_version: 1,
    command_id: commandId,
    command_type: type,
    task_id: taskId,
    aggregate_id: aggregateId,
    expected_aggregate_version: expectedVersion,
    actor,
    idempotency_key: commandId,
    payload,
  });
  if (!result.ok) throw new Error(JSON.stringify(result.error));
  return result.value;
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
    options.set(key, next);
    index += 1;
  }
  return { positionals, options, json: options.has("json") };
}

function phase2Home(parsed: ParsedArgs): string { return resolve(option(parsed, "home") ?? process.env.OPENCODEX_OEF_HOME ?? join(process.cwd(), ".opencodex")); }
function option(parsed: ParsedArgs, name: string): string | undefined { const value = parsed.options.get(name); return typeof value === "string" ? value : undefined; }
function required(parsed: ParsedArgs, name: string): string { const value = option(parsed, name); if (!value) throw new Error(`Missing required option --${name}`); return value; }
function positional(parsed: ParsedArgs, index: number, label: string): string { const value = parsed.positionals[index]; if (!value) throw new Error(`Missing ${label}`); return value; }
function runtimeOption(parsed: ParsedArgs): "fake" | "codex" {
  const value = required(parsed, "runtime");
  if (value === "fake" || value === "fake-local") return "fake";
  if (value === "codex" || value === "codex-local") return "codex";
  throw new Error("--runtime must be fake, fake-local, codex, or codex-local");
}
function positiveInteger(value: string, label: string): number { const number = Number(value); if (!Number.isInteger(number) || number <= 0) throw new Error(`${label} must be a positive integer`); return number; }
function readDataFile(pathInput: string): unknown { const path = resolve(pathInput); const source = readFileSync(path, "utf8"); return extname(path).toLowerCase() === ".json" ? JSON.parse(source) : Bun.YAML.parse(source); }
function digest(value: string): string { return createHash("sha256").update(value).digest("hex"); }
function defaultGit(): string { return process.platform === "win32" ? "C:\\Program Files\\Git\\cmd\\git.exe" : "git"; }
function gitHead(repositoryPath: string): string {
  const result = Bun.spawnSync([defaultGit(), "rev-parse", "HEAD"], { cwd: repositoryPath, stdin: "ignore", stdout: "pipe", stderr: "pipe", windowsHide: true });
  if (result.exitCode !== 0) throw new Error("REPOSITORY_HEAD_UNAVAILABLE");
  return new TextDecoder().decode(result.stdout).trim();
}
function requireSnapshot<T extends { runtime_id: string; adapter_id: string }>(snapshots: T[], id: string): T { const value = snapshots.find(item => item.runtime_id === id || item.adapter_id === id); if (!value) throw new Error(`Runtime not found: ${id}`); return value; }
function minimumDaemonEnvironment(): Record<string, string> {
  const environment: Record<string, string> = {};
  for (const name of ["PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE", "CODEX_HOME"]) {
    const value = process.env[name];
    if (value) environment[name] = value;
  }
  return environment;
}
function terminalizeCancelledExecution(runtime: Phase2Runtime, executionId: string) {
  let execution = runtime.store.getExecution(executionId);
  if (!execution) return null;
  const taskId = runtime.store.getExecutionTaskId(executionId);
  if (!taskId) throw new Error("EXECUTION_TASK_NOT_FOUND");
  const attempt = execution.current_attempt_id ? runtime.store.getAttempt(execution.current_attempt_id) : null;
  if (attempt && !["SUCCEEDED", "FAILED", "CANCELLED", "ORPHANED"].includes(attempt.status)) {
    command(runtime, "TransitionExecutionAttempt", taskId, attempt.attempt_id, execution.aggregate_version, { to_status: "CANCELLED" }, { type: "system", id: "system:local-runner" });
    execution = runtime.store.getExecution(executionId)!;
  }
  if (!["COMPLETED", "FAILED", "INTERRUPTED", "CANCELLED"].includes(execution.status)) {
    if (execution.status !== "CANCELLING") {
      execution = command(runtime, "TransitionExecution", taskId, executionId, execution.aggregate_version, { to_status: "CANCELLING" }).execution!;
    }
    execution = command(runtime, "TransitionExecution", taskId, executionId, execution.aggregate_version, { to_status: "CANCELLED" }).execution!;
  }
  return execution;
}
