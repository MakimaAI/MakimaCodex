import { afterEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  FakeRuntimeAdapter,
  LocalProcessSupervisor,
  LocalRunnerHost,
  RunnerEventSpool,
  RunnerKillSwitchStore,
  RunnerLeaseStore,
  type NormalizedRuntimeEvent,
  type RuntimeExecutionRequest,
} from "../src/oef/phase2";
import { inspectSecretPathAcl } from "../src/lib/windows-secret-acl";

const roots: string[] = [];
setDefaultTimeout(30_000);
afterEach(() => {
  for (const root of roots.splice(0)) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* process/WAL fixture handles can linger on Windows */ }
  }
});

function root(): string {
  const value = mkdtempSync(join(tmpdir(), "oef-phase2-runner-"));
  roots.push(value);
  return value;
}

const HASH = `sha256:${"e".repeat(64)}`;
function runtimeRequest(workspace: string, scenario: RuntimeExecutionRequest["scenario"] = "successful-edit"): RuntimeExecutionRequest {
  return {
    execution_id: "execution:runner",
    attempt_id: "attempt:runner-1",
    workspace_path: workspace,
    prompt_path: join(workspace, "prompt.md"),
    prompt_hash: HASH,
    inherited_environment: ["PATH", "SYSTEMROOT", "WINDIR", "TEMP"],
    injected_secret_refs: [],
    timeouts: { startup_seconds: 1, idle_seconds: 1, tool_seconds: 1, total_seconds: 3, graceful_shutdown_seconds: 0.05 },
    output_limit_bytes: 1_000_000,
    scenario,
  };
}

function event(sequence: number, type: NormalizedRuntimeEvent["type"] = "runtime.observation"): NormalizedRuntimeEvent {
  return {
    schema_version: 1,
    event_id: `runtime-event:test-${sequence}`,
    sequence,
    execution_id: "execution:runner",
    attempt_id: "attempt:runner-1",
    type,
    correlation: { call_id: null },
    payload: {},
    source: { runtime: "fake-local", adapter: "fake-runtime@1.0.0" },
    confidence: "AUTHORITATIVE",
    occurred_at: "2026-07-23T10:00:00.000Z",
  };
}

describe("durable runner event spool", () => {
  test("delivers at least once while duplicate ingestion has zero additional effect", () => {
    const spoolRoot = join(root(), "events");
    const spool = new RunnerEventSpool({ root: spoolRoot });
    expect(spool.append(event(1))).toEqual({ status: "APPENDED" });
    expect(spool.append(event(2))).toEqual({ status: "APPENDED" });
    expect(spool.append(event(2))).toEqual({ status: "DUPLICATE" });
    expect(spool.read("execution:runner", 1)).toHaveLength(2);
    expect(spool.read("execution:runner", 2).map(value => value.sequence)).toEqual([2]);

    const reopened = new RunnerEventSpool({ root: spoolRoot });
    expect(reopened.read("execution:runner", 1).map(value => value.sequence)).toEqual([1, 2]);
    expect(reopened.integrity("execution:runner", "attempt:runner-1")).toEqual({
      complete: true,
      next_expected_sequence: 3,
      missing_sequences: [],
    });
  });

  test("records and exposes sequence gaps instead of silently accepting them", () => {
    const spool = new RunnerEventSpool({ root: join(root(), "events") });
    expect(spool.append(event(1))).toEqual({ status: "APPENDED" });
    expect(spool.append(event(3))).toEqual({ status: "GAP", missing_sequences: [2] });
    expect(spool.integrity("execution:runner", "attempt:runner-1")).toEqual({
      complete: false,
      next_expected_sequence: 2,
      missing_sequences: [2],
    });
  });
});

describe("runner lease, kill switch, and local host", () => {
  test("persists the review signing authority across restart and resolves only bootstrap launch policies", async () => {
    const runnerRoot = join(root(), "review-authority-runner");
    const policy = {
      launch_policy_id: `review-launch-policy:${"a".repeat(32)}`,
      reviewer: { agent_id: "agent:reviewer", provider: "provider-b", model_class: "reviewer", session_id: "session:reviewer", context_id: "context:reviewer" },
    };
    const first = new LocalRunnerHost({
      root: runnerRoot, runner_id: "runner:authority-one", adapters: [],
      supervisor: new LocalProcessSupervisor({ root: join(runnerRoot, "processes-one") }), review_launch_policies: [policy],
    });
    const authority = first.getReviewIdentityAuthority();
    if (process.platform === "win32") expect(inspectSecretPathAcl(join(runnerRoot, "state", "review-identity-key.pem"), 15_000)).toEqual({ secure: true });
    expect(first.getReviewLaunchPolicy(policy.launch_policy_id)).toEqual(policy);
    await first.close();
    const restarted = new LocalRunnerHost({
      root: runnerRoot, runner_id: "runner:authority-two", adapters: [],
      supervisor: new LocalProcessSupervisor({ root: join(runnerRoot, "processes-two") }), review_launch_policies: [policy],
    });
    try {
      expect(restarted.getReviewIdentityAuthority()).toEqual(authority);
      expect(() => restarted.getReviewLaunchPolicy(`review-launch-policy:${"b".repeat(32)}`)).toThrow("RUNNER_REVIEW_LAUNCH_POLICY_NOT_FOUND");
    } finally { await restarted.close(); }
  }, 30_000);

  test("rejects an existing review signing key whose ACL was exposed before restart", async () => {
    if (process.platform !== "win32") return;
    const runnerRoot = join(root(), "review-authority-exposed");
    const first = new LocalRunnerHost({
      root: runnerRoot, runner_id: "runner:acl-one", adapters: [],
      supervisor: new LocalProcessSupervisor({ root: join(runnerRoot, "processes-one") }),
    });
    await first.close();
    const keyPath = join(runnerRoot, "state", "review-identity-key.pem");
    const exposed = Bun.spawnSync(["icacls.exe", keyPath, "/grant", "*S-1-1-0:(F)"], { stdout: "pipe", stderr: "pipe", windowsHide: true });
    expect(exposed.exitCode).toBe(0);
    expect(() => new LocalRunnerHost({
      root: runnerRoot, runner_id: "runner:acl-two", adapters: [],
      supervisor: new LocalProcessSupervisor({ root: join(runnerRoot, "processes-two") }),
    })).toThrow("RUNNER_REVIEW_IDENTITY_ACL_ISOLATION_INVALID");
  }, 30_000);

  test("prevents two runner nonces from leasing one execution and detects heartbeat expiry", () => {
    let now = Date.parse("2026-07-23T10:00:00.000Z");
    const leases = new RunnerLeaseStore({ root: join(root(), "leases"), now: () => now });
    const first = leases.acquire({ execution_id: "execution:runner", runner_id: "runner:one", runner_instance_nonce: "nonce-one", ttl_ms: 10_000 });
    expect(first.ok).toBeTrue();
    expect(leases.acquire({ execution_id: "execution:runner", runner_id: "runner:two", runner_instance_nonce: "nonce-two", ttl_ms: 10_000 }))
      .toMatchObject({ ok: false, reason: "LEASE_HELD" });
    now += 11_000;
    expect(leases.inspect("execution:runner").status).toBe("EXPIRED");
    expect(leases.acquire({ execution_id: "execution:runner", runner_id: "runner:two", runner_instance_nonce: "nonce-two", ttl_ms: 10_000 }).ok)
      .toBeTrue();
  });

  test("persists pause/resume state and an audit trail", () => {
    const switchRoot = join(root(), "kill-switch");
    const first = new RunnerKillSwitchStore({ root: switchRoot, actor: "system:test" });
    first.set("PAUSE_NEW_EXECUTIONS", "maintenance");
    expect(first.canStart()).toEqual({ allowed: false, reason: "PAUSE_NEW_EXECUTIONS" });
    const reopened = new RunnerKillSwitchStore({ root: switchRoot, actor: "system:test" });
    expect(reopened.canStart().allowed).toBeFalse();
    reopened.set("RUNNING", "maintenance complete");
    expect(reopened.canStart()).toEqual({ allowed: true });
    expect(reopened.audit()).toHaveLength(2);
  });

  test("runs an adapter through the supervisor, spools events, and survives control-plane reconnect", async () => {
    const runnerRoot = root();
    const adapter = new FakeRuntimeAdapter();
    const host = new LocalRunnerHost({
      root: join(runnerRoot, "runner"),
      runner_id: "runner:local-1",
      adapters: [adapter],
      supervisor: new LocalProcessSupervisor({ root: join(runnerRoot, "processes") }),
      heartbeat_interval_ms: 50,
      lease_ttl_ms: 500,
    });
    try {
      const lease = await host.startExecution({
        adapter_id: adapter.manifest.adapter.id,
        runtime_request: runtimeRequest(runnerRoot),
      });
      expect(lease.execution_id).toBe("execution:runner");
      await waitUntil(async () => (await host.getStatus("execution:runner")).status === "EXITED", 4_000);
      const status = await host.getStatus("execution:runner");
      expect(status.exit?.exit_code).toBe(0);
      expect(status.process_identity.recovery_identity).toEqual({
        execution_id: "execution:runner",
        attempt_id: "attempt:runner-1",
        workspace_path: runtimeRequest(runnerRoot).workspace_path,
      });
      expect(status.event_integrity.complete).toBeTrue();
      const streamed: NormalizedRuntimeEvent[] = [];
      for await (const value of host.streamEvents("execution:runner", 2)) streamed.push(value);
      expect(streamed.map(value => value.sequence)).toEqual([2, 3]);
      const artifacts = await host.collectArtifacts("execution:runner");
      expect(artifacts.stdout_path).toContain("stdout.log");
    } finally {
      await host.close();
    }

    const spool = new RunnerEventSpool({ root: join(runnerRoot, "runner", "events") });
    expect(spool.read("execution:runner", 1).map(value => value.sequence)).toEqual([1, 2, 3]);
  });

  test("cancels idempotently and blocks new starts while paused", async () => {
    const runnerRoot = root();
    const adapter = new FakeRuntimeAdapter();
    const host = new LocalRunnerHost({
      root: join(runnerRoot, "runner"), runner_id: "runner:local-1", adapters: [adapter],
      supervisor: new LocalProcessSupervisor({ root: join(runnerRoot, "processes") }), heartbeat_interval_ms: 50, lease_ttl_ms: 500,
    });
    try {
      await host.startExecution({ adapter_id: adapter.manifest.adapter.id, runtime_request: runtimeRequest(runnerRoot, "idle-timeout") });
      await waitUntil(async () => (await host.getStatus("execution:runner")).status === "RUNNING", 1_000);
      await host.cancelExecution("execution:runner");
      expect((await host.getStatus("execution:runner")).status).toBe("EXITED");
      await host.cancelExecution("execution:runner");
      expect((await host.getStatus("execution:runner")).exit?.cancelled).toBeTrue();
      host.killSwitch.set("PAUSE_NEW_EXECUTIONS", "security pause");
      await expect(host.startExecution({
        adapter_id: adapter.manifest.adapter.id,
        runtime_request: { ...runtimeRequest(runnerRoot), execution_id: "execution:runner-2", attempt_id: "attempt:runner-2" },
      })).rejects.toThrow("PAUSE_NEW_EXECUTIONS");
    } finally {
      await host.close();
    }
  });

  test("CANCEL_ALL waits for a delayed admitted start and then terminates it", async () => {
    const runnerRoot = root();
    const adapter = new FakeRuntimeAdapter();
    const originalPrepare = adapter.prepareLaunch.bind(adapter);
    let markEntered!: () => void;
    let releasePrepare!: () => void;
    const entered = new Promise<void>(resolve => { markEntered = resolve; });
    const release = new Promise<void>(resolve => { releasePrepare = resolve; });
    adapter.prepareLaunch = async request => {
      markEntered();
      await release;
      return originalPrepare({ ...request, scenario: "child-process-hang" });
    };
    const host = new LocalRunnerHost({
      root: join(runnerRoot, "runner"), runner_id: "runner:admission", adapters: [adapter],
      supervisor: new LocalProcessSupervisor({ root: join(runnerRoot, "processes") }), heartbeat_interval_ms: 50, lease_ttl_ms: 500,
    });
    try {
      const starting = host.startExecution({ adapter_id: adapter.manifest.adapter.id, runtime_request: runtimeRequest(runnerRoot, "child-process-hang") });
      await entered;
      let cancelSettled = false;
      const cancellation = host.applyControlState("CANCEL_ALL", "admission race").finally(() => { cancelSettled = true; });
      await Bun.sleep(50);
      expect(cancelSettled).toBeFalse();
      releasePrepare();
      await expect(starting).rejects.toThrow("RUNNER_ADMISSION_REVOKED");
      await cancellation;
      await expect(host.getStatus("execution:runner")).rejects.toThrow("RUNNER_EXECUTION_NOT_FOUND");
    } finally {
      releasePrepare();
      await host.close();
    }
  });

  test("CANCEL_ALL kills known work before a bounded admission timeout and revokes the delayed start", async () => {
    const runnerRoot = root();
    const adapter = new FakeRuntimeAdapter();
    const originalPrepare = adapter.prepareLaunch.bind(adapter);
    let markEntered!: () => void;
    let releasePrepare!: () => void;
    const entered = new Promise<void>(resolve => { markEntered = resolve; });
    const release = new Promise<void>(resolve => { releasePrepare = resolve; });
    adapter.prepareLaunch = async request => {
      if (request.execution_id === "execution:pending") {
        markEntered();
        await release;
      }
      return originalPrepare({ ...request, scenario: "child-process-hang" });
    };
    const host = new LocalRunnerHost({
      root: join(runnerRoot, "runner"), runner_id: "runner:bounded-admission", adapters: [adapter],
      supervisor: new LocalProcessSupervisor({ root: join(runnerRoot, "processes") }), heartbeat_interval_ms: 50,
      lease_ttl_ms: 500, admission_timeout_ms: 100,
    });
    try {
      await host.startExecution({
        adapter_id: adapter.manifest.adapter.id,
        runtime_request: { ...runtimeRequest(runnerRoot, "child-process-hang"), execution_id: "execution:active", attempt_id: "attempt:active" },
      });
      await waitUntil(async () => (await host.getStatus("execution:active")).status === "RUNNING", 1_000);
      const pending = host.startExecution({
        adapter_id: adapter.manifest.adapter.id,
        runtime_request: { ...runtimeRequest(runnerRoot), execution_id: "execution:pending", attempt_id: "attempt:pending" },
      });
      await entered;

      await expect(host.applyControlState("CANCEL_ALL", "bounded admission race"))
        .rejects.toThrow("RUNNER_ADMISSION_BARRIER_TIMEOUT");
      expect(host.killSwitch.current().state).toBe("CANCEL_ALL");
      expect((await host.getStatus("execution:active"))).toMatchObject({ status: "EXITED", exit: { cancelled: true } });

      releasePrepare();
      await expect(pending).rejects.toThrow("RUNNER_ADMISSION_REVOKED");
    } finally {
      releasePrepare();
      await host.close();
    }
  }, 10_000);

  test("host shutdown terminates active work and persists the verified process identity", async () => {
    const runnerRoot = root();
    const adapter = new FakeRuntimeAdapter();
    const host = new LocalRunnerHost({
      root: join(runnerRoot, "runner"), runner_id: "runner:local-1", adapters: [adapter],
      supervisor: new LocalProcessSupervisor({ root: join(runnerRoot, "processes") }), heartbeat_interval_ms: 50, lease_ttl_ms: 500,
    });
    await host.startExecution({ adapter_id: adapter.manifest.adapter.id, runtime_request: runtimeRequest(runnerRoot, "child-process-hang") });
    await waitUntil(async () => (await host.getStatus("execution:runner")).status === "RUNNING", 1_000);

    await host.close();

    const status = await host.getStatus("execution:runner");
    expect(status.status).toBe("EXITED");
    expect(status.exit?.cancelled).toBeTrue();
    expect(status.process_identity).toMatchObject({ pid: status.exit?.pid });
    expect(status.process_identity.executable_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(status.process_identity.runner_nonce).toHaveLength(32);
  });

  test("heartbeat storage failure still contains the process and disables new admissions", async () => {
    const runnerRoot = root();
    const hostRoot = join(runnerRoot, "runner");
    const adapter = new FakeRuntimeAdapter();
    const supervisor = new LocalProcessSupervisor({ root: join(runnerRoot, "processes") });
    const host = new LocalRunnerHost({
      root: hostRoot, runner_id: "runner:heartbeat-containment", adapters: [adapter], supervisor,
      heartbeat_interval_ms: 50, lease_ttl_ms: 500,
    });
    try {
      await host.startExecution({ adapter_id: adapter.manifest.adapter.id, runtime_request: runtimeRequest(runnerRoot, "child-process-hang") });
      await waitUntil(async () => (await host.getStatus("execution:runner")).status === "RUNNING", 1_000);
      const processId = (await host.getStatus("execution:runner")).process_id;
      rmSync(join(hostRoot, "leases"), { recursive: true, force: true });
      rmSync(join(hostRoot, "kill-switch"), { recursive: true, force: true });

      await waitUntil(() => supervisor.inspect(processId).state === "EXITED", 3_000);
      await expect(host.startExecution({
        adapter_id: adapter.manifest.adapter.id,
        runtime_request: { ...runtimeRequest(runnerRoot), execution_id: "execution:after-heartbeat", attempt_id: "attempt:after-heartbeat" },
      })).rejects.toThrow("RUNNER_HOST_DEGRADED");
    } finally {
      mkdirSync(join(hostRoot, "leases"), { recursive: true });
      mkdirSync(join(hostRoot, "kill-switch"), { recursive: true });
      await host.close();
    }
  }, 10_000);

  test("re-cancelling an interrupted execution preserves its terminal status while retrying containment", async () => {
    const runnerRoot = root();
    const adapter = new FakeRuntimeAdapter();
    const startedAt = "2026-07-23T10:00:00.000Z";
    let cancelCalls = 0;
    const interruptedSupervisor = {
      async start() {
        return {
          process_id: "supervised-process:interrupted", pid: 4343,
          identity: { pid: 4343, started_at: startedAt, executable_hash: HASH, runner_nonce: "b".repeat(32) },
        };
      },
      async wait() { throw new Error("PROCESS_TREE_TERMINATION_UNCONFIRMED"); },
      async cancel() { cancelCalls += 1; },
      async waitForTermination() {},
      async killAll() {},
      notifyStarted() {}, notifyActivity() {}, notifyToolStarted() {}, notifyToolCompleted() {},
    } as unknown as LocalProcessSupervisor;
    const host = new LocalRunnerHost({
      root: join(runnerRoot, "runner"), runner_id: "runner:interrupted", adapters: [adapter], supervisor: interruptedSupervisor,
      heartbeat_interval_ms: 50, lease_ttl_ms: 500,
    });
    try {
      await host.startExecution({ adapter_id: adapter.manifest.adapter.id, runtime_request: runtimeRequest(runnerRoot) });
      await waitUntil(async () => (await host.getStatus("execution:runner")).status === "INTERRUPTED", 1_000);
      await host.cancelExecution("execution:runner");
      expect((await host.getStatus("execution:runner")).status).toBe("INTERRUPTED");
      expect(cancelCalls).toBeGreaterThanOrEqual(2);
    } finally {
      await host.close();
    }
  });

  test("buffers runtime output emitted before supervisor start returns", async () => {
    const runnerRoot = root();
    const adapter = new FakeRuntimeAdapter();
    const startedAt = "2026-07-23T10:00:00.000Z";
    const immediateSupervisor = {
      async start(_plan: unknown, hooks: { onOutput?: (chunk: { process_id: string; stream: "stdout"; text: string; received_at: string }) => void | Promise<void> }) {
        await hooks.onOutput?.({
          process_id: "supervised-process:immediate",
          stream: "stdout",
          text: '{"sequence":1,"type":"execution.started","payload":{}}\n',
          received_at: startedAt,
        });
        return {
          process_id: "supervised-process:immediate",
          pid: 4242,
          identity: { pid: 4242, started_at: startedAt, executable_hash: HASH, runner_nonce: "a".repeat(32) },
        };
      },
      async wait() {
        return {
          process_id: "supervised-process:immediate", pid: 4242, exit_code: 0, signal: null, timed_out: null,
          failure_type: null, cancelled: false, cancel_requests: 0, started_at: startedAt, ended_at: startedAt,
          duration_ms: 0, stdout_path: join(runnerRoot, "missing-stdout"), stderr_path: join(runnerRoot, "missing-stderr"),
          output_bytes: 0, output_truncated: false, line_truncations: 0, binary_chunks: 0, redaction_count: 0,
        };
      },
      notifyStarted() {}, notifyActivity() {}, notifyToolStarted() {}, notifyToolCompleted() {}, async cancel() {}, async killAll() {},
    } as unknown as LocalProcessSupervisor;
    const host = new LocalRunnerHost({
      root: join(runnerRoot, "runner"), runner_id: "runner:immediate", adapters: [adapter], supervisor: immediateSupervisor,
      heartbeat_interval_ms: 50, lease_ttl_ms: 500,
    });
    try {
      await host.startExecution({ adapter_id: adapter.manifest.adapter.id, runtime_request: runtimeRequest(runnerRoot) });
      await waitUntil(async () => (await host.getStatus("execution:runner")).status === "EXITED", 1_000);
      expect((await host.getStatus("execution:runner")).event_integrity).toEqual({
        complete: true, next_expected_sequence: 2, missing_sequences: [],
      });
      const events: NormalizedRuntimeEvent[] = [];
      for await (const value of host.streamEvents("execution:runner")) events.push(value);
      expect(events.map(value => value.type)).toEqual(["execution.started"]);
    } finally {
      await host.close();
    }
  });
});

async function waitUntil(predicate: () => boolean | Promise<boolean>, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!(await predicate())) {
    if (Date.now() >= deadline) throw new Error("Condition was not met before timeout");
    await Bun.sleep(20);
  }
}
