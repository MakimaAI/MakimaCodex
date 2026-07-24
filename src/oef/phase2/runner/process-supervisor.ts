import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseRuntimeLaunchPlan, type RuntimeLaunchPlan } from "../runtime/protocol";
import { EmptySecretResolver, StreamingSecretRedactor, type MaterializedSecrets, type SecretResolver } from "./secrets";
import { attachWindowsKillOnCloseJob, type WindowsJobController } from "./windows-job-object";
import { executableHash, inspectProcessIdentity, type PersistedProcessIdentity, type ProcessRecoveryIdentity } from "./process-identity";

export interface ProcessOutputChunk {
  process_id: string;
  stream: "stdout" | "stderr";
  text: string;
  received_at: string;
}

export interface ProcessSupervisorHooks {
  onOutput?(chunk: ProcessOutputChunk): void | Promise<void>;
}

export interface SupervisedProcessRef {
  process_id: string;
  pid: number;
  identity: PersistedProcessIdentity;
}

export interface SupervisedProcessExit {
  process_id: string;
  pid: number;
  exit_code: number | null;
  signal: string | null;
  timed_out: "startup" | "idle" | "tool" | "total" | null;
  failure_type: "STARTUP_TIMEOUT" | "IDLE_TIMEOUT" | "TOOL_TIMEOUT" | "TOTAL_TIMEOUT" | "OUTPUT_LIMIT_EXCEEDED" | "PROTOCOL_ERROR" | null;
  cancelled: boolean;
  cancel_requests: number;
  started_at: string;
  ended_at: string;
  duration_ms: number;
  stdout_path: string;
  stderr_path: string;
  output_bytes: number;
  output_truncated: boolean;
  line_truncations: number;
  binary_chunks: number;
  redaction_count: number;
}

type ManagedChild = Bun.Subprocess<"ignore" | "pipe", "pipe", "pipe">;

interface ProcessRecord {
  ref: SupervisedProcessRef;
  child: ManagedChild;
  windowsJob: WindowsJobController | null;
  plan: RuntimeLaunchPlan;
  hooks: ProcessSupervisorHooks;
  secrets: MaterializedSecrets;
  redactors: Record<"stdout" | "stderr", StreamingSecretRedactor>;
  lineLimiters: Record<"stdout" | "stderr", LineLimiter>;
  stdoutPath: string;
  stderrPath: string;
  startedAtMs: number;
  startedEventSeen: boolean;
  ended: boolean;
  cancelled: boolean;
  cancelRequests: number;
  terminationStarted: boolean;
  terminationPromise: Promise<void> | null;
  backgroundTerminationPromise: Promise<void> | null;
  residualProcessGroup: boolean;
  timedOut: SupervisedProcessExit["timed_out"];
  outputLimitExceeded: boolean;
  protocolError: boolean;
  rawOutputBytes: number;
  outputBytes: number;
  outputTruncated: boolean;
  lineTruncations: number;
  binaryChunks: number;
  live: string;
  startupTimer?: ReturnType<typeof setTimeout>;
  idleTimer?: ReturnType<typeof setTimeout>;
  toolTimer?: ReturnType<typeof setTimeout>;
  totalTimer?: ReturnType<typeof setTimeout>;
  resolveExit: (exit: SupervisedProcessExit) => void;
  rejectExit: (error: Error) => void;
  exitSettled: boolean;
  exitPromise: Promise<SupervisedProcessExit>;
  resolveMonitorDone: () => void;
  monitorDonePromise: Promise<void>;
}

interface PendingProcessStart {
  processId: string;
  child: ManagedChild;
  windowsJob: WindowsJobController | null;
  graceMs: number;
}

export class LocalProcessSupervisor {
  private readonly root: string;
  private readonly secretResolver: SecretResolver;
  private readonly maxLineBytes: number;
  private readonly maxLiveBufferBytes: number;
  private readonly records = new Map<string, ProcessRecord>();
  private readonly pendingStarts = new Map<string, PendingProcessStart>();
  private containmentGeneration = 0;

  constructor(options: { root: string; secretResolver?: SecretResolver; maxLineBytes?: number; maxLiveBufferBytes?: number }) {
    this.root = options.root;
    this.secretResolver = options.secretResolver ?? new EmptySecretResolver();
    this.maxLineBytes = options.maxLineBytes ?? 100_000;
    this.maxLiveBufferBytes = options.maxLiveBufferBytes ?? 1_000_000;
    if (this.maxLineBytes <= 0 || this.maxLiveBufferBytes <= 0) throw new Error("Supervisor output limits must be positive");
    mkdirSync(this.root, { recursive: true });
  }

  async start(
    planInput: RuntimeLaunchPlan,
    hooks: ProcessSupervisorHooks = {},
    recoveryIdentity?: ProcessRecoveryIdentity,
    input: { stdin_bytes?: Uint8Array } = {},
  ): Promise<SupervisedProcessRef> {
    const startGeneration = this.containmentGeneration;
    const plan = parseRuntimeLaunchPlan(planInput);
    const processId = `supervised-process:${randomBytes(12).toString("hex")}`;
    const startedAt = new Date().toISOString();
    const runnerNonce = randomBytes(16).toString("hex");
    const secrets = await this.secretResolver.materialize(plan.environment.injected_secret_refs, { process_id: processId });
    let cleanupOwnedByStart = true;
    try {
    if (startGeneration !== this.containmentGeneration) throw new Error("PROCESS_START_REVOKED");
    const environment = buildEnvironment(plan.environment.inherited, secrets.environment, plan.environment.path_prepend ?? []);
    const directory = join(this.root, processId.replace(/:/g, "_"));
    mkdirSync(directory, { recursive: false });
    const stdoutPath = join(directory, "stdout.log");
    const stderrPath = join(directory, "stderr.log");
    writeFileSync(stdoutPath, "", { encoding: "utf8", flag: "wx" });
    writeFileSync(stderrPath, "", { encoding: "utf8", flag: "wx" });
    if (input.stdin_bytes && plan.stdin.mode !== "file") throw new Error("RUNTIME_STDIN_BYTES_REQUIRE_FILE_MODE");
    const stdinBytes = plan.stdin.mode === "file" ? (input.stdin_bytes ?? readFileSync(plan.stdin.path)) : null;
    const needsInput = plan.stdin.mode !== "closed" && process.platform !== "win32";
    const windowsGatePath = join(directory, "job-assigned.gate");
    const windowsShutdownPath = join(directory, "graceful-shutdown.request");
    const windowsPlanPath = join(directory, "launch-plan.json");
    const unixPlanPath = join(directory, "unix-watchdog-plan.json");
    if (process.platform === "win32") {
      const windowsStdin = plan.stdin.mode === "file"
        ? { mode: "bytes", content_base64: Buffer.from(stdinBytes!).toString("base64") }
        : plan.stdin;
      writeFileSync(windowsPlanPath, JSON.stringify({ executable: plan.executable, arguments: plan.arguments, stdin: windowsStdin }), "utf8");
    } else if (process.platform === "linux") {
      writeFileSync(unixPlanPath, JSON.stringify({
        executable: plan.executable,
        arguments: plan.arguments,
        owner_pid: process.pid,
        graceful_shutdown_ms: seconds(plan.timeouts.graceful_shutdown_seconds),
      }), { encoding: "utf8", flag: "wx" });
    }
    let launchCommand: string[];
    if (process.platform === "win32") {
      launchCommand = [
        process.execPath,
        fileURLToPath(new URL("./windows-job-bootstrap.ts", import.meta.url)),
        "--gate", windowsGatePath,
        "--shutdown", windowsShutdownPath,
        "--grace-ms", String(seconds(plan.timeouts.graceful_shutdown_seconds)),
        "--plan", windowsPlanPath,
      ];
    } else if (process.platform === "linux") {
      launchCommand = [
        resolveLinuxSetpriv(),
        "--pdeathsig", "SIGTERM",
        process.execPath,
        fileURLToPath(new URL("./unix-pdeathsig-watchdog.ts", import.meta.url)),
        "--plan", unixPlanPath,
      ];
    } else {
      throw new Error("UNIX_CRASH_CONTAINMENT_UNAVAILABLE");
    }
    let child: ManagedChild;
    try {
      child = Bun.spawn(launchCommand, {
        cwd: plan.working_directory,
        env: environment,
        stdin: needsInput ? "pipe" : "ignore",
        stdout: "pipe",
        stderr: "pipe",
        windowsHide: true,
        detached: true,
      }) as ManagedChild;
    } catch (error) { throw error; }
    const pending: PendingProcessStart = {
      processId,
      child,
      windowsJob: null,
      graceMs: seconds(plan.timeouts.graceful_shutdown_seconds),
    };
    this.pendingStarts.set(processId, pending);
    if (startGeneration !== this.containmentGeneration) {
      const cleanupConfirmed = await this.cleanupPendingStart(pending);
      if (!cleanupConfirmed) throw new Error("PROCESS_START_CLEANUP_UNCONFIRMED");
      throw new Error("PROCESS_START_REVOKED");
    }
    let windowsJob: WindowsJobController | null = null;
    let identity!: PersistedProcessIdentity;
    try {
      windowsJob = await attachWindowsKillOnCloseJob(child.pid);
      pending.windowsJob = windowsJob;
      const observedIdentity = await waitForProcessIdentity(child.pid, 2_000);
      if (!observedIdentity) throw new Error("PROCESS_IDENTITY_ATTESTATION_FAILED");
      if (startGeneration !== this.containmentGeneration) throw new Error("PROCESS_START_REVOKED");
      const attestationPath = join(directory, "process-identity.json");
      identity = {
        ...observedIdentity,
        started_at: startedAt,
        target_executable_hash: executableHash(plan.executable),
        runner_nonce: runnerNonce,
        attestation_path: attestationPath,
        recovery_identity: recoveryIdentity,
      };
      writeFileSync(attestationPath, JSON.stringify(identity), { encoding: "utf8", flag: "wx" });
      if (process.platform === "win32") writeFileSync(windowsGatePath, "assigned\n", { encoding: "utf8", flag: "wx" });
      else if (plan.stdin.mode === "file") {
        const sink = child.stdin;
        if (!sink || typeof sink === "number") throw new Error("Runtime stdin pipe was not created");
        sink.write(stdinBytes!);
        sink.end();
      } else if (plan.stdin.mode === "pipe") {
        const sink = child.stdin;
        if (sink && typeof sink !== "number") sink.end();
      }
    } catch (error) {
      const cleanupConfirmed = await this.cleanupPendingStart(pending);
      if (!cleanupConfirmed) throw new Error("PROCESS_START_CLEANUP_UNCONFIRMED", { cause: error });
      throw error;
    }
    let resolveExit!: (exit: SupervisedProcessExit) => void;
    let rejectExit!: (error: Error) => void;
    const exitPromise = new Promise<SupervisedProcessExit>((resolve, reject) => { resolveExit = resolve; rejectExit = reject; });
    let resolveMonitorDone!: () => void;
    const monitorDonePromise = new Promise<void>(resolve => { resolveMonitorDone = resolve; });
    const ref: SupervisedProcessRef = {
      process_id: processId,
      pid: child.pid,
      identity,
    };
    const record: ProcessRecord = {
      ref,
      child,
      windowsJob,
      plan,
      hooks,
      secrets,
      redactors: {
        stdout: new StreamingSecretRedactor(secrets.redaction_values),
        stderr: new StreamingSecretRedactor(secrets.redaction_values),
      },
      lineLimiters: {
        stdout: new LineLimiter(this.maxLineBytes),
        stderr: new LineLimiter(this.maxLineBytes),
      },
      stdoutPath,
      stderrPath,
      startedAtMs: Date.now(),
      startedEventSeen: false,
      ended: false,
      cancelled: false,
      cancelRequests: 0,
      terminationStarted: false,
      terminationPromise: null,
      backgroundTerminationPromise: null,
      residualProcessGroup: false,
      timedOut: null,
      outputLimitExceeded: false,
      protocolError: false,
      rawOutputBytes: 0,
      outputBytes: 0,
      outputTruncated: false,
      lineTruncations: 0,
      binaryChunks: 0,
      live: "",
      resolveExit,
      rejectExit,
      exitSettled: false,
      exitPromise,
      resolveMonitorDone,
      monitorDonePromise,
    };
    this.records.set(processId, record);
    this.pendingStarts.delete(processId);
    record.startupTimer = setTimeout(() => this.timeout(record, "startup"), seconds(plan.timeouts.startup_seconds));
    record.totalTimer = setTimeout(() => this.timeout(record, "total"), seconds(plan.timeouts.total_seconds));
    const stdoutPump = this.pump(record, "stdout", child.stdout);
    const stderrPump = this.pump(record, "stderr", child.stderr);
    void this.monitor(record, stdoutPump, stderrPump);
    cleanupOwnedByStart = false;
    return ref;
    } finally {
      if (cleanupOwnedByStart) await secrets.cleanup();
    }
  }

  notifyStarted(processId: string): void {
    const record = this.requireRecord(processId);
    if (record.ended || record.startedEventSeen) return;
    record.startedEventSeen = true;
    if (record.startupTimer) clearTimeout(record.startupTimer);
    this.resetIdle(record);
  }

  notifyActivity(processId: string): void {
    const record = this.requireRecord(processId);
    if (!record.ended && record.startedEventSeen) this.resetIdle(record);
  }

  notifyToolStarted(processId: string): void {
    const record = this.requireRecord(processId);
    if (record.ended) return;
    if (record.toolTimer) clearTimeout(record.toolTimer);
    record.toolTimer = setTimeout(() => this.timeout(record, "tool"), seconds(record.plan.timeouts.tool_seconds));
  }

  notifyToolCompleted(processId: string): void {
    const record = this.requireRecord(processId);
    if (record.toolTimer) clearTimeout(record.toolTimer);
    record.toolTimer = undefined;
    this.notifyActivity(processId);
  }

  async cancel(processId: string, _reason: string): Promise<void> {
    const record = this.requireRecord(processId);
    if (record.ended && !record.residualProcessGroup) return;
    if (!record.cancelled) {
      record.cancelled = true;
      record.cancelRequests += 1;
    }
    await this.terminateTree(record);
  }

  async wait(processId: string): Promise<SupervisedProcessExit> { return this.requireRecord(processId).exitPromise; }

  async waitForTermination(processId: string): Promise<void> {
    const record = this.requireRecord(processId);
    const settled = await settlesWithin(
      record.monitorDonePromise,
      seconds(record.plan.timeouts.graceful_shutdown_seconds) + 3_000,
    );
    if (!settled || !record.ended || record.residualProcessGroup) {
      throw new Error("PROCESS_TREE_TERMINATION_UNCONFIRMED");
    }
  }

  inspect(processId: string): { state: "RUNNING" | "EXITED"; pid: number; started: boolean; output_bytes: number } {
    const record = this.requireRecord(processId);
    return { state: record.ended ? "EXITED" : "RUNNING", pid: record.ref.pid, started: record.startedEventSeen, output_bytes: record.outputBytes };
  }

  liveOutput(processId: string): string { return this.requireRecord(processId).live; }

  async killAll(reason: string): Promise<void> {
    this.containmentGeneration += 1;
    const targets = new Set<ProcessRecord>();
    for (let pass = 0; pass < 2; pass += 1) {
      const suffix = pass === 0 ? reason : `${reason} (bounded retry)`;
      const currentTargets = [...this.records.values()].filter(record => !record.ended || record.residualProcessGroup);
      for (const record of currentTargets) targets.add(record);
      await Promise.allSettled(currentTargets.map(async record => {
        if (!record.ended) await this.cancel(record.ref.process_id, suffix);
        else await this.retryResidualUnixGroup(record);
      }));
      const pending = [...this.pendingStarts.values()];
      await Promise.allSettled(pending.map(start => this.cleanupPendingStart(start)));
    }
    const completion = await Promise.all([...targets].map(record => settlesWithin(
      record.monitorDonePromise,
      seconds(record.plan.timeouts.graceful_shutdown_seconds) + 3_000,
    )));
    if (completion.some(settled => !settled)
      || [...this.records.values()].some(record => !record.ended || record.residualProcessGroup)
      || this.pendingStarts.size > 0) {
      throw new Error("PROCESS_TREE_TERMINATION_UNCONFIRMED");
    }
  }

  private async monitor(record: ProcessRecord, stdoutPump: Promise<void>, stderrPump: Promise<void>): Promise<void> {
    try {
      await record.child.exited;
      if (process.platform !== "win32") {
        const residualDescendants = await terminateUnixProcessGroup(record.ref.pid, seconds(record.plan.timeouts.graceful_shutdown_seconds));
        record.residualProcessGroup = residualDescendants.found && !residualDescendants.terminated;
        if ((residualDescendants.found && !record.terminationStarted) || !residualDescendants.terminated) record.protocolError = true;
      }
      await Promise.allSettled([stdoutPump, stderrPump]);
    } finally {
      if (process.platform !== "win32") {
        const finalCleanup = await terminateUnixProcessGroup(record.ref.pid, 0);
        record.residualProcessGroup = finalCleanup.found && !finalCleanup.terminated;
        if (!finalCleanup.terminated) record.protocolError = true;
      }
      record.windowsJob?.close();
      record.windowsJob = null;
      if (record.ended) { record.resolveMonitorDone(); return; }
      record.ended = true;
      this.clearTimers(record);
      try { await record.secrets.cleanup(); } catch { record.protocolError = true; }
      const endedAtMs = Date.now();
      const timedOutFailure = record.timedOut ? `${record.timedOut.toUpperCase()}_TIMEOUT` as SupervisedProcessExit["failure_type"] : null;
      const exit: SupervisedProcessExit = {
        process_id: record.ref.process_id,
        pid: record.ref.pid,
        exit_code: record.child.exitCode,
        signal: record.child.signalCode,
        timed_out: record.timedOut,
        failure_type: record.protocolError ? "PROTOCOL_ERROR" : record.outputLimitExceeded ? "OUTPUT_LIMIT_EXCEEDED" : timedOutFailure,
        cancelled: record.cancelled,
        cancel_requests: record.cancelRequests,
        started_at: record.ref.identity.started_at,
        ended_at: new Date(endedAtMs).toISOString(),
        duration_ms: endedAtMs - record.startedAtMs,
        stdout_path: record.stdoutPath,
        stderr_path: record.stderrPath,
        output_bytes: record.outputBytes,
        output_truncated: record.outputTruncated,
        line_truncations: record.lineTruncations,
        binary_chunks: record.binaryChunks,
        redaction_count: record.redactors.stdout.count + record.redactors.stderr.count,
      };
      if (!record.exitSettled) {
        record.exitSettled = true;
        record.resolveExit(exit);
      }
      record.resolveMonitorDone();
    }
  }

  private async pump(record: ProcessRecord, stream: "stdout" | "stderr", readable: ReadableStream<Uint8Array>): Promise<void> {
    const reader = readable.getReader();
    const decoder = new TextDecoder("utf-8", { fatal: false });
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        record.rawOutputBytes += value.byteLength;
        if (record.rawOutputBytes > record.plan.output_limit_bytes) {
          record.outputLimitExceeded = true;
          record.outputTruncated = true;
          this.scheduleBackgroundTermination(record);
        }
        const binary = value.includes(0);
        const decoded = binary ? "[BINARY OUTPUT REDACTED]\n" : decoder.decode(value, { stream: true });
        if (binary) record.binaryChunks += 1;
        const redacted = record.redactors[stream].push(decoded);
        await this.consume(record, stream, redacted, false);
      }
      const remainder = decoder.decode() + record.redactors[stream].flush();
      await this.consume(record, stream, remainder, true);
    } catch {
      record.protocolError = true;
      this.scheduleBackgroundTermination(record);
    } finally {
      reader.releaseLock();
    }
  }

  private async consume(record: ProcessRecord, stream: "stdout" | "stderr", text: string, final: boolean): Promise<void> {
    const limited = record.lineLimiters[stream].push(text, final);
    record.lineTruncations += limited.truncations;
    if (!limited.text) return;
    const incomingBytes = Buffer.byteLength(limited.text);
    const remaining = Math.max(0, record.plan.output_limit_bytes - record.outputBytes);
    let accepted = limited.text;
    if (incomingBytes > remaining) {
      accepted = truncateUtf8(limited.text, remaining) + (record.outputTruncated ? "" : "\n[OUTPUT TRUNCATED]\n");
      record.outputTruncated = true;
      record.outputLimitExceeded = true;
    }
    if (accepted) {
      const path = stream === "stdout" ? record.stdoutPath : record.stderrPath;
      appendFileSync(path, accepted, "utf8");
      record.outputBytes += Buffer.byteLength(accepted);
      record.live = keepTailUtf8(record.live + accepted, this.maxLiveBufferBytes);
      await record.hooks.onOutput?.({ process_id: record.ref.process_id, stream, text: accepted, received_at: new Date().toISOString() });
    }
    if (record.outputLimitExceeded) this.scheduleBackgroundTermination(record);
  }

  private timeout(record: ProcessRecord, kind: NonNullable<SupervisedProcessExit["timed_out"]>): void {
    if (record.ended || record.timedOut) return;
    record.timedOut = kind;
    this.scheduleBackgroundTermination(record);
  }

  private resetIdle(record: ProcessRecord): void {
    if (record.idleTimer) clearTimeout(record.idleTimer);
    record.idleTimer = setTimeout(() => this.timeout(record, "idle"), seconds(record.plan.timeouts.idle_seconds));
  }

  private scheduleBackgroundTermination(record: ProcessRecord): void {
    if (record.ended || record.backgroundTerminationPromise) return;
    const operation = (async () => {
      let lastError: unknown = null;
      for (let attempt = 0; attempt < 2 && !record.ended; attempt += 1) {
        try {
          await this.terminateTree(record);
          const deadline = Date.now() + seconds(record.plan.timeouts.graceful_shutdown_seconds) + 3_000;
          while (!record.ended && Date.now() < deadline) await delay(20);
          if (record.ended) return;
          lastError = new Error("PROCESS_EXIT_BARRIER_TIMEOUT");
        } catch (error) { lastError = error; }
        if (!record.ended) await delay(50);
      }
      if (!record.ended && !record.exitSettled) {
        record.protocolError = true;
        record.exitSettled = true;
        record.rejectExit(new Error("PROCESS_TREE_TERMINATION_UNCONFIRMED", { cause: lastError }));
      }
    })();
    record.backgroundTerminationPromise = operation;
    void operation.finally(() => {
      if (record.backgroundTerminationPromise === operation) record.backgroundTerminationPromise = null;
    });
  }

  private async terminateTree(record: ProcessRecord): Promise<void> {
    if (record.ended && !record.residualProcessGroup) return;
    if (record.terminationPromise) return record.terminationPromise;
    record.terminationStarted = true;
    const operation = this.performTreeTermination(record);
    record.terminationPromise = operation;
    try { await operation; }
    finally { if (record.terminationPromise === operation) record.terminationPromise = null; }
  }

  private async performTreeTermination(record: ProcessRecord): Promise<void> {
    if (process.platform === "win32") {
      const shutdownPath = join(this.root, record.ref.process_id.replace(/:/g, "_"), "graceful-shutdown.request");
      try { writeFileSync(shutdownPath, `${new Date().toISOString()}\n`, { encoding: "utf8", flag: "wx" }); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") record.protocolError = true; }
      await delay(seconds(record.plan.timeouts.graceful_shutdown_seconds));
      if (!record.ended) record.windowsJob?.terminate(1);
    } else {
      const result = await terminateUnixProcessGroup(record.ref.pid, seconds(record.plan.timeouts.graceful_shutdown_seconds));
      record.residualProcessGroup = result.found && !result.terminated;
      if (!result.found) try { record.child.kill("SIGTERM"); } catch {}
      if (!result.terminated) {
        record.protocolError = true;
        throw new Error("PROCESS_GROUP_TERMINATION_FAILED");
      }
    }
  }

  private async retryResidualUnixGroup(record: ProcessRecord): Promise<void> {
    if (!record.residualProcessGroup) return;
    const result = await terminateUnixProcessGroup(record.ref.pid, seconds(record.plan.timeouts.graceful_shutdown_seconds));
    record.residualProcessGroup = result.found && !result.terminated;
    if (!result.terminated) throw new Error("PROCESS_GROUP_TERMINATION_FAILED");
  }

  private async cleanupPendingStart(pending: PendingProcessStart): Promise<boolean> {
    const job = pending.windowsJob;
    pending.windowsJob = null;
    const confirmed = await cleanupUnregisteredChild(pending.child, job, pending.graceMs);
    if (confirmed) this.pendingStarts.delete(pending.processId);
    return confirmed;
  }

  private clearTimers(record: ProcessRecord): void {
    for (const timer of [record.startupTimer, record.idleTimer, record.toolTimer, record.totalTimer]) if (timer) clearTimeout(timer);
  }

  private requireRecord(processId: string): ProcessRecord {
    const record = this.records.get(processId);
    if (!record) throw new Error(`Supervised process not found: ${processId}`);
    return record;
  }
}

async function cleanupUnregisteredChild(
  child: ManagedChild,
  windowsJob: WindowsJobController | null,
  graceMs: number,
): Promise<boolean> {
  if (process.platform === "win32" && child.exitCode !== null) {
    windowsJob?.close();
    return true;
  }
  let terminationConfirmed = true;
  if (process.platform === "win32") {
    try {
      if (windowsJob) windowsJob.terminate(1);
      else child.kill("SIGKILL");
    } catch { terminationConfirmed = child.exitCode !== null; }
    windowsJob?.close();
  } else {
    const group = await terminateUnixProcessGroup(child.pid, graceMs);
    terminationConfirmed = group.terminated;
    if (!group.found) {
      try { child.kill("SIGKILL"); } catch { /* child may already be gone */ }
    }
  }
  const childExited = await settlesWithin(child.exited, graceMs + 3_000);
  return childExited && (terminationConfirmed || (process.platform === "win32" && child.exitCode !== null));
}

function resolveLinuxSetpriv(): string {
  for (const path of ["/usr/bin/setpriv", "/bin/setpriv"]) if (existsSync(path)) return path;
  throw new Error("LINUX_PDEATHSIG_HELPER_UNAVAILABLE");
}

async function terminateUnixProcessGroup(pid: number, graceMs: number): Promise<{ found: boolean; terminated: boolean }> {
  if (process.platform === "win32") return { found: false, terminated: true };
  const initial = unixProcessGroupState(pid);
  if (initial === "MISSING") return { found: false, terminated: true };
  if (initial === "UNCONFIRMED") return { found: true, terminated: false };
  try { process.kill(-pid, "SIGTERM"); }
  catch (error) {
    return (error as NodeJS.ErrnoException).code === "ESRCH"
      ? { found: true, terminated: true }
      : { found: true, terminated: false };
  }
  const graceDeadline = Date.now() + Math.max(0, graceMs);
  while (unixProcessGroupState(pid) === "ALIVE" && Date.now() < graceDeadline) await delay(20);
  const afterGrace = unixProcessGroupState(pid);
  if (afterGrace === "UNCONFIRMED") return { found: true, terminated: false };
  if (afterGrace === "ALIVE") {
    try { process.kill(-pid, "SIGKILL"); }
    catch (error) {
      return (error as NodeJS.ErrnoException).code === "ESRCH"
        ? { found: true, terminated: true }
        : { found: true, terminated: false };
    }
    const killDeadline = Date.now() + 2_000;
    while (unixProcessGroupState(pid) === "ALIVE" && Date.now() < killDeadline) await delay(20);
  }
  return { found: true, terminated: unixProcessGroupState(pid) === "MISSING" };
}

function unixProcessGroupState(pid: number): "ALIVE" | "MISSING" | "UNCONFIRMED" {
  try { process.kill(-pid, 0); return "ALIVE"; }
  catch (error) { return (error as NodeJS.ErrnoException).code === "ESRCH" ? "MISSING" : "UNCONFIRMED"; }
}

async function settlesWithin<T>(promise: Promise<T>, timeoutMs: number): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise.then(() => true, () => true),
      new Promise<boolean>(resolve => { timer = setTimeout(() => resolve(false), Math.max(1, timeoutMs)); }),
    ]);
  } finally { if (timer) clearTimeout(timer); }
}

class LineLimiter {
  private buffer = "";
  private discarding = false;
  constructor(private readonly maxBytes: number) {}

  push(input: string, final: boolean): { text: string; truncations: number } {
    this.buffer += input;
    let output = "";
    let truncations = 0;
    while (true) {
      const newline = this.buffer.indexOf("\n");
      if (newline < 0) break;
      const line = this.buffer.slice(0, newline + 1);
      this.buffer = this.buffer.slice(newline + 1);
      if (this.discarding) {
        this.discarding = false;
        continue;
      }
      if (Buffer.byteLength(line) > this.maxBytes) {
        output += `${truncateUtf8(line, this.maxBytes)}[LINE TRUNCATED]\n`;
        truncations += 1;
      } else output += line;
    }
    if (Buffer.byteLength(this.buffer) > this.maxBytes) {
      output += `${truncateUtf8(this.buffer, this.maxBytes)}[LINE TRUNCATED]\n`;
      this.buffer = "";
      this.discarding = true;
      truncations += 1;
    }
    if (final && this.buffer) {
      output += this.buffer;
      this.buffer = "";
      this.discarding = false;
    }
    return { text: output, truncations };
  }
}

function buildEnvironment(inherited: readonly string[], injected: Readonly<Record<string, string>>, pathPrepend: readonly string[]): Record<string, string> {
  const environment: Record<string, string> = {};
  for (const name of inherited) {
    const value = process.env[name];
    if (value !== undefined) environment[name] = value;
  }
  for (const [name, value] of Object.entries(injected)) environment[name] = value;
  if (pathPrepend.length > 0) {
    const pathName = Object.keys(environment).find(name => name.toUpperCase() === "PATH") ?? "PATH";
    environment[pathName] = [...pathPrepend, environment[pathName]].filter(Boolean).join(delimiter);
  }
  return environment;
}

function seconds(value: number): number { return Math.max(1, Math.ceil(value * 1_000)); }
async function waitForProcessIdentity(pid: number, timeoutMs: number): Promise<ReturnType<typeof inspectProcessIdentity>> {
  const deadline = Date.now() + timeoutMs;
  do {
    const identity = inspectProcessIdentity(pid);
    if (identity) return identity;
    await delay(20);
  } while (Date.now() < deadline);
  return null;
}
function delay(milliseconds: number): Promise<void> { return new Promise(resolve => setTimeout(resolve, milliseconds)); }
function truncateUtf8(value: string, maxBytes: number): string {
  if (maxBytes <= 0) return "";
  const bytes = Buffer.from(value, "utf8");
  return bytes.length <= maxBytes ? value : bytes.subarray(0, maxBytes).toString("utf8").replace(/\uFFFD$/g, "");
}
function keepTailUtf8(value: string, maxBytes: number): string {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length <= maxBytes) return value;
  return bytes.subarray(bytes.length - maxBytes).toString("utf8").replace(/^\uFFFD+/g, "");
}
