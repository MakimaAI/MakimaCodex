import { randomBytes } from "node:crypto";
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync, writeSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { hardenSecretPath } from "../../../lib/windows-secret-acl";
import { CodexRuntimeAdapter } from "../runtime/adapters/codex";
import { FakeRuntimeAdapter } from "../runtime/adapters/fake";
import { AuthenticatedRunnerHttpServer, HttpRunnerClient } from "./http-ipc";
import { LocalRunnerHost, type RunnerReviewLaunchPolicy } from "./local-runner-host";
import { LocalProcessSupervisor } from "./process-supervisor";
import { createPhase2Runtime } from "../application/runtime";
import { StartupReconciliationWorker } from "../application/reconciliation-worker";

export interface RunnerDaemonStatus {
  schema_version: 1;
  status: "STARTING" | "READY" | "STOPPED" | "DEGRADED";
  pid: number;
  endpoint: string | null;
  token_path: string;
  started_at: string;
  stopped_at: string | null;
  last_error: string | null;
}

export function runnerDaemonPaths(homeInput: string): { root: string; status: string; token: string; lock: string; launcher: string; review_policies: string } {
  const root = join(resolve(homeInput), "phase2", "runner");
  return {
    root,
    status: join(root, "daemon-status.json"),
    token: join(root, "ipc-token"),
    lock: join(root, "daemon.lock"),
    launcher: fileURLToPath(new URL("./daemon-entry.ts", import.meta.url)),
    review_policies: join(root, "review-launch-policies.json"),
  };
}

export function readRunnerDaemonStatus(home: string): RunnerDaemonStatus | null {
  const path = runnerDaemonPaths(home).status;
  if (!existsSync(path)) return null;
  const value = JSON.parse(readFileSync(path, "utf8")) as RunnerDaemonStatus;
  if (value.schema_version !== 1 || !Number.isInteger(value.pid) || !["STARTING", "READY", "STOPPED", "DEGRADED"].includes(value.status)) {
    throw new Error("RUNNER_DAEMON_STATUS_CORRUPT");
  }
  return value;
}

export function runnerClientFromHome(home: string): HttpRunnerClient {
  const paths = runnerDaemonPaths(home);
  const status = readRunnerDaemonStatus(home);
  if (!status || status.status !== "READY" || !status.endpoint) throw new Error("RUNNER_DAEMON_NOT_READY");
  if (!existsSync(paths.token)) throw new Error("RUNNER_DAEMON_TOKEN_MISSING");
  return new HttpRunnerClient({ endpoint: status.endpoint, token: readFileSync(paths.token, "utf8").trim() });
}

export async function runLocalRunnerDaemon(options: { home: string }): Promise<void> {
  const paths = runnerDaemonPaths(options.home);
  mkdirSync(paths.root, { recursive: true });
  const lock = acquireRunnerDaemonLock(paths.root);
  const startedAt = new Date().toISOString();
  const writeStatus = (status: RunnerDaemonStatus) => atomicWriteJson(paths.status, status);
  try {
    const token = randomBytes(32).toString("base64url");
    writeFileSync(paths.token, `${token}\n`, { encoding: "utf8", mode: 0o600 });
    if (process.platform === "win32") hardenSecretPath(paths.token, { required: true, verifyIsolation: true });
    writeStatus({ schema_version: 1, status: "STARTING", pid: process.pid, endpoint: null, token_path: paths.token, started_at: startedAt, stopped_at: null, last_error: null });

    const reconciliationRuntime = createPhase2Runtime({ home: options.home });
    try { await new StartupReconciliationWorker(reconciliationRuntime, { runner_root: paths.root }).run(); }
    finally { reconciliationRuntime.close(); }

    const policies = existsSync(paths.review_policies)
      ? parseReviewLaunchPolicies(JSON.parse(readFileSync(paths.review_policies, "utf8")))
      : [];
    const host = new LocalRunnerHost({
      root: paths.root,
      runner_id: `runner:daemon-${process.pid}`,
      adapters: [new CodexRuntimeAdapter(), new FakeRuntimeAdapter()],
      supervisor: new LocalProcessSupervisor({ root: join(paths.root, "processes") }),
      review_launch_policies: policies,
    });
    let requestStop!: () => void;
    const stopped = new Promise<void>(resolveStop => { requestStop = resolveStop; });
    const server = new AuthenticatedRunnerHttpServer({ host, token, onShutdown: () => setTimeout(requestStop, 25) });
    const endpoint = server.start();
    writeStatus({ schema_version: 1, status: "READY", pid: process.pid, endpoint, token_path: paths.token, started_at: startedAt, stopped_at: null, last_error: null });
    const stop = () => requestStop();
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
    process.once("SIGHUP", stop);
    try {
      await stopped;
    } finally {
      server.stop();
      await host.close();
      writeStatus({ schema_version: 1, status: "STOPPED", pid: process.pid, endpoint: null, token_path: paths.token, started_at: startedAt, stopped_at: new Date().toISOString(), last_error: null });
    }
  } catch (error) {
    writeStatus({
      schema_version: 1,
      status: "DEGRADED",
      pid: process.pid,
      endpoint: null,
      token_path: paths.token,
      started_at: startedAt,
      stopped_at: new Date().toISOString(),
      last_error: (error instanceof Error ? error.message : String(error)).slice(0, 4_000),
    });
    throw error;
  } finally {
    lock.release();
  }
}

function parseReviewLaunchPolicies(input: unknown): RunnerReviewLaunchPolicy[] {
  if (!Array.isArray(input)) throw new Error("RUNNER_REVIEW_LAUNCH_POLICIES_INVALID");
  return input as RunnerReviewLaunchPolicy[];
}

export interface RunnerDaemonLock {
  path: string;
  nonce: string;
  release(): void;
}

export function acquireRunnerDaemonLock(root: string): RunnerDaemonLock {
  mkdirSync(root, { recursive: true });
  const path = join(root, "daemon.lock");
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const nonce = randomBytes(16).toString("hex");
    try {
      const descriptor = openSync(path, "wx", 0o600);
      try {
        writeFileSync(descriptor, JSON.stringify({
          schema_version: 1,
          pid: process.pid,
          started_at: new Date().toISOString(),
          process_start_identity: processStartIdentity(process.pid),
          nonce,
        }), "utf8");
      } finally { closeSync(descriptor); }
      return {
        path,
        nonce,
        release: () => {
          try {
            const current = JSON.parse(readFileSync(path, "utf8")) as { nonce?: string };
            if (current.nonce === nonce) unlinkSync(path);
          } catch { /* another owner or already released */ }
        },
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      let owner: { pid?: number; process_start_identity?: string | null; nonce?: string } = {};
      try { owner = JSON.parse(readFileSync(path, "utf8")) as typeof owner; }
      catch { throw new Error("RUNNER_DAEMON_LOCK_OWNER_UNVERIFIED"); }
      if (typeof owner.pid === "number" && processIsAlive(owner.pid)) {
        const actualIdentity = processStartIdentity(owner.pid);
        if (!actualIdentity || !owner.process_start_identity) throw new Error("RUNNER_DAEMON_LOCK_OWNER_UNVERIFIED");
        if (actualIdentity === owner.process_start_identity) throw new Error(`RUNNER_DAEMON_ALREADY_RUNNING:${owner.pid}`);
      }
      const quarantine = join(root, "quarantine");
      mkdirSync(quarantine, { recursive: true });
      try { renameSync(path, join(quarantine, `stale-daemon-lock-${Date.now()}-${randomBytes(4).toString("hex")}.json`)); }
      catch (renameError) { if ((renameError as NodeJS.ErrnoException).code !== "ENOENT") throw renameError; }
    }
  }
  throw new Error("RUNNER_DAEMON_LOCK_UNAVAILABLE");
}

function processIsAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch { return false; }
}

function processStartIdentity(pid: number): string | null {
  if (!Number.isInteger(pid) || pid <= 0) return null;
  try {
    if (process.platform === "win32") {
      const result = Bun.spawnSync([
        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
        `$p=Get-Process -Id ${pid} -ErrorAction Stop; [Console]::Out.Write($p.StartTime.ToUniversalTime().ToString('o'))`,
      ], { stdin: "ignore", stdout: "pipe", stderr: "ignore", windowsHide: true });
      if (result.exitCode !== 0) return null;
      const timestamp = new TextDecoder().decode(result.stdout).trim();
      return Number.isNaN(Date.parse(timestamp)) ? null : new Date(timestamp).toISOString();
    }
    if (process.platform === "linux") {
      const source = readFileSync(`/proc/${pid}/stat`, "utf8").trim();
      const fieldsAfterCommand = source.slice(source.lastIndexOf(")") + 2).split(/\s+/);
      const startTicks = fieldsAfterCommand[19];
      return startTicks ? `linux-proc-start:${startTicks}` : null;
    }
    return null;
  } catch { return null; }
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
