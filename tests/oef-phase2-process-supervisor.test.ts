import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  LocalProcessSupervisor,
  StaticSecretResolver,
  StreamingSecretRedactor,
  verifyPersistedProcessIdentity,
  type ProcessOutputChunk,
  type RuntimeLaunchPlan,
} from "../src/oef/phase2";

const roots: string[] = [];
afterEach(() => {
  delete process.env.UNLISTED_PHASE2_SECRET;
  for (const root of roots.splice(0)) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* Windows can retain process log handles briefly */ }
  }
});

function root(): string {
  const value = mkdtempSync(join(tmpdir(), "oef-phase2-supervisor-"));
  roots.push(value);
  return value;
}

const worker = new URL("./fixtures/oef-phase2-process-worker.ts", import.meta.url).pathname.replace(/^\/(.:)/, "$1");
const HASH = `sha256:${"d".repeat(64)}`;

function plan(workspace: string, mode: string, options: Partial<RuntimeLaunchPlan> = {}): RuntimeLaunchPlan {
  return {
    executable: process.execPath,
    arguments: [worker, mode],
    working_directory: workspace,
    environment: { inherited: ["PATH", "SYSTEMROOT", "WINDIR", "TEMP"], injected_secret_refs: [] },
    stdin: { mode: "closed" },
    output_protocol: { type: "jsonl", version: 1 },
    timeouts: { startup_seconds: 1, idle_seconds: 5, tool_seconds: 5, total_seconds: 10, graceful_shutdown_seconds: 0.05 },
    output_limit_bytes: 1_000_000,
    prompt_hash: HASH,
    ...options,
  };
}

describe("Phase 2 local process supervisor", () => {
  test("holds a multiline private key until the complete block can be redacted", () => {
    const redactor = new StreamingSecretRedactor([]);
    const first = redactor.push("safe-before\n-----BEGIN PRIVATE KEY-----\nabc123\n");
    const second = redactor.push("def456\n-----END PRIVATE KEY-----\nsafe-after\n");
    const output = first + second + redactor.flush();
    expect(first).toBe("safe-before\n");
    expect(output).toContain("[REDACTED]");
    expect(output).not.toContain("abc123");
    expect(output).not.toContain("def456");
    expect(output).toContain("safe-after");
  });

  test("bounds an unterminated private-key quarantine and resumes after its closing marker", () => {
    const redactor = new StreamingSecretRedactor([], { max_private_key_bytes: 128 });
    const first = redactor.push("safe-before\n-----BEGIN PRIVATE KEY-----\n" + "x".repeat(512));
    const second = redactor.push("y".repeat(512));
    const third = redactor.push("-----END PRIVATE KEY-----\nsafe-after\n");
    const output = first + second + third + redactor.flush();
    expect(output).toContain("safe-before");
    expect(output).toContain("[REDACTED PRIVATE KEY BLOCK]");
    expect(output).not.toContain("x".repeat(32));
    expect(output).not.toContain("y".repeat(32));
    expect(output).toContain("safe-after");
    expect(redactor.bufferedBytes()).toBeLessThanOrEqual(128);
  });

  test("distinguishes startup, idle, and total timeouts", async () => {
    const workspace = root();
    const supervisor = new LocalProcessSupervisor({ root: join(workspace, "supervisor") });

    const silent = await supervisor.start(plan(workspace, "silent", {
      timeouts: { startup_seconds: 0.1, idle_seconds: 1, tool_seconds: 1, total_seconds: 2, graceful_shutdown_seconds: 0.05 },
    }));
    expect((await supervisor.wait(silent.process_id)).timed_out).toBe("startup");

    const idle = await supervisor.start(plan(workspace, "idle", {
      timeouts: { startup_seconds: 0.5, idle_seconds: 0.15, tool_seconds: 0.15, total_seconds: 1, graceful_shutdown_seconds: 0.05 },
    }), {
      onOutput: chunk => startedOnFirstOutput(supervisor, chunk),
    });
    expect((await supervisor.wait(idle.process_id)).timed_out).toBe("idle");

    const heartbeat = await supervisor.start(plan(workspace, "heartbeat", {
      timeouts: { startup_seconds: 0.5, idle_seconds: 0.1, tool_seconds: 0.1, total_seconds: 0.25, graceful_shutdown_seconds: 0.05 },
    }), {
      onOutput: chunk => {
        supervisor.notifyStarted(chunk.process_id);
        supervisor.notifyActivity(chunk.process_id);
      },
    });
    expect((await supervisor.wait(heartbeat.process_id)).timed_out).toBe("total");
  });

  test("uses an environment allowlist and redacts secrets before live or disk output", async () => {
    const workspace = root();
    process.env.UNLISTED_PHASE2_SECRET = "ambient-must-not-pass";
    const resolver = new StaticSecretResolver({
      "secret-ref:test": { environment: { TEST_PHASE2_SECRET: "exact-secret-value" } },
    });
    const seen: string[] = [];
    const supervisor = new LocalProcessSupervisor({ root: join(workspace, "supervisor"), secretResolver: resolver });
    const ref = await supervisor.start(plan(workspace, "echo-env", {
      environment: { inherited: ["PATH", "SYSTEMROOT", "WINDIR", "TEMP"], injected_secret_refs: ["secret-ref:test"] },
    }), { onOutput: chunk => { seen.push(chunk.text); supervisor.notifyStarted(chunk.process_id); } });
    const exit = await supervisor.wait(ref.process_id);
    expect(exit.exit_code).toBe(0);
    expect(seen.join("")).toContain("[REDACTED]");
    expect(seen.join("")).not.toContain("exact-secret-value");
    expect(seen.join("")).not.toContain("ambient-must-not-pass");
    expect(readFileSync(exit.stdout_path, "utf8")).not.toContain("exact-secret-value");
    expect(exit.redaction_count).toBeGreaterThan(0);
  });

  test("enforces total output and line limits with explicit evidence", async () => {
    const workspace = root();
    const supervisor = new LocalProcessSupervisor({ root: join(workspace, "supervisor"), maxLineBytes: 512, maxLiveBufferBytes: 1_024 });
    const limited = await supervisor.start(plan(workspace, "output-limit", { output_limit_bytes: 2_000 }), {
      onOutput: chunk => startedOnFirstOutput(supervisor, chunk),
    });
    const limitedExit = await supervisor.wait(limited.process_id);
    expect(limitedExit.failure_type).toBe("OUTPUT_LIMIT_EXCEEDED");
    expect(limitedExit.output_truncated).toBeTrue();
    expect(supervisor.liveOutput(limited.process_id).length).toBeLessThanOrEqual(1_024);

    const longLine = await supervisor.start(plan(workspace, "long-line"), {
      onOutput: chunk => startedOnFirstOutput(supervisor, chunk),
    });
    const longExit = await supervisor.wait(longLine.process_id);
    expect(longExit.line_truncations).toBeGreaterThan(0);
    expect(readFileSync(longExit.stdout_path, "utf8")).toContain("[LINE TRUNCATED]");
  });

  test("classifies output hook failures and always resolves process completion", async () => {
    const workspace = root();
    const supervisor = new LocalProcessSupervisor({ root: join(workspace, "supervisor") });
    const ref = await supervisor.start(plan(workspace, "heartbeat", {
      timeouts: { startup_seconds: 1, idle_seconds: 1, tool_seconds: 1, total_seconds: 2, graceful_shutdown_seconds: 0.01 },
    }), {
      onOutput: chunk => {
        supervisor.notifyStarted(chunk.process_id);
        throw new Error("parser exploded");
      },
    });
    const exit = await Promise.race([
      supervisor.wait(ref.process_id),
      Bun.sleep(2_000).then(() => { throw new Error("supervisor wait stranded"); }),
    ]);
    expect(exit.failure_type).toBe("PROTOCOL_ERROR");
    expect(existsSync(exit.stdout_path)).toBeTrue();
    expect(existsSync(exit.stderr_path)).toBeTrue();
  });

  test("validates file stdin before spawning a process or allocating a Job", async () => {
    const workspace = root();
    let cleanups = 0;
    const supervisor = new LocalProcessSupervisor({
      root: join(workspace, "supervisor"),
      secretResolver: {
        materialize: async () => ({ environment: {}, redaction_values: [], cleanup: async () => { cleanups += 1; } }),
      },
    });
    await expect(supervisor.start(plan(workspace, "heartbeat", {
      stdin: { mode: "file", path: join(workspace, "missing-prompt.md") },
    }))).rejects.toThrow();
    expect(cleanups).toBe(1);
    await supervisor.killAll("test cleanup");
  });

  test("cancellation is idempotent and terminates the full child process tree", async () => {
    const workspace = root();
    const pidFile = join(workspace, "child.pid");
    const supervisor = new LocalProcessSupervisor({ root: join(workspace, "supervisor") });
    const ref = await supervisor.start({
      ...plan(workspace, "child-hang", { timeouts: { startup_seconds: 1, idle_seconds: 5, tool_seconds: 5, total_seconds: 10, graceful_shutdown_seconds: 0.05 } }),
      arguments: [worker, "child-hang", "--pid-file", pidFile],
    }, {
      onOutput: chunk => startedOnFirstOutput(supervisor, chunk),
    });
    await waitUntil(() => existsSync(pidFile), 2_000);
    const childPid = Number(readFileSync(pidFile, "utf8"));
    expect(isAlive(childPid)).toBeTrue();
    expect(verifyPersistedProcessIdentity(ref.identity)).toBeTrue();
    const cancellationStarted = Date.now();
    await supervisor.cancel(ref.process_id, "test cancellation");
    await supervisor.cancel(ref.process_id, "duplicate cancellation");
    const exit = await supervisor.wait(ref.process_id);
    expect(exit.cancelled).toBeTrue();
    await waitUntil(() => !isAlive(childPid), 2_000);
    expect(isAlive(childPid)).toBeFalse();
    expect(exit.cancel_requests).toBe(1);
    if (process.platform === "win32") expect(Date.now() - cancellationStarted).toBeGreaterThanOrEqual(40);
  });

  test("contains descendants when the runtime parent exits first", async () => {
    const workspace = root();
    const pidFile = join(workspace, "orphan.pid");
    const supervisor = new LocalProcessSupervisor({ root: join(workspace, "supervisor") });
    const ref = await supervisor.start({
      ...plan(workspace, "parent-exits-first", { timeouts: { startup_seconds: 1, idle_seconds: 1, tool_seconds: 1, total_seconds: 5, graceful_shutdown_seconds: 0.05 } }),
      arguments: [worker, "parent-exits-first", "--pid-file", pidFile],
    }, {
      onOutput: chunk => startedOnFirstOutput(supervisor, chunk),
    });
    await supervisor.wait(ref.process_id);
    const childPid = Number(readFileSync(pidFile, "utf8"));
    try {
      await waitUntil(() => !isAlive(childPid), 2_000);
      expect(isAlive(childPid)).toBeFalse();
    } finally {
      if (isAlive(childPid)) try { process.kill(childPid); } catch { /* best-effort test cleanup */ }
    }
  });
});

function startedOnFirstOutput(supervisor: LocalProcessSupervisor, chunk: ProcessOutputChunk): void {
  supervisor.notifyStarted(chunk.process_id);
  supervisor.notifyActivity(chunk.process_id);
}

function isAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch { return false; }
}

async function waitUntil(predicate: () => boolean, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("Condition was not met before timeout");
    await Bun.sleep(20);
  }
}
