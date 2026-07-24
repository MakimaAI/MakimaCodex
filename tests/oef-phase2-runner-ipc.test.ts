import { afterEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AuthenticatedRunnerHttpServer,
  discoverRunnerResource,
  FakeRuntimeAdapter,
  HttpRunnerClient,
  LocalProcessSupervisor,
  LocalRunnerHost,
  type RuntimeExecutionRequest,
} from "../src/oef/phase2";
import { canonicalSha256 } from "../src/oef/phase1/core/contract/task-contract";

const roots: string[] = [];
setDefaultTimeout(30_000);
const verifierWorker = new URL("./fixtures/oef-phase2-verifier-worker.ts", import.meta.url).pathname.replace(/^\/(.:)/, "$1");
afterEach(() => {
  for (const root of roots.splice(0)) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* runner process handles can linger briefly */ }
  }
});

function root(): string {
  const value = mkdtempSync(join(tmpdir(), "oef-phase2-ipc-"));
  roots.push(value);
  return value;
}

describe("authenticated loopback runner IPC", () => {
  test("rejects unauthenticated and impersonated requests", async () => {
    const runnerRoot = root();
    const host = createHost(runnerRoot);
    const token = "a".repeat(64);
    const server = new AuthenticatedRunnerHttpServer({ host, token });
    const endpoint = server.start();
    try {
      expect(endpoint).toMatch(/^http:\/\/127\.0\.0\.1:/);
      expect((await fetch(`${endpoint}/v1/capabilities`)).status).toBe(401);
      expect((await fetch(`${endpoint}/v1/capabilities`, { headers: { authorization: "Bearer wrong" } })).status).toBe(401);
      const response = await fetch(`${endpoint}/v1/capabilities`, { headers: { authorization: `Bearer ${token}` } });
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({ protocol_version: 1, durable_spool: true });
    } finally {
      server.stop();
      await host.close();
    }
  });

  test("runs, observes, and collects through the client protocol without direct process access", async () => {
    const runnerRoot = root();
    const host = createHost(runnerRoot);
    const token = "b".repeat(64);
    const server = new AuthenticatedRunnerHttpServer({ host, token });
    const endpoint = server.start();
    const client = new HttpRunnerClient({ endpoint, token });
    try {
      const request = runtimeRequest(runnerRoot);
      const lease = await client.startExecution({ adapter_id: "fake-runtime", runtime_request: request });
      expect(lease.execution_id).toBe(request.execution_id);
      await waitUntil(async () => (await client.getStatus(request.execution_id)).status === "EXITED", 4_000);
      const events = [];
      for await (const event of client.streamEvents(request.execution_id, 1)) events.push(event);
      expect(events.map(event => event.sequence)).toEqual([1, 2, 3]);
      expect((await client.collectArtifacts(request.execution_id)).event_count).toBe(3);
    } finally {
      server.stop();
      await host.close();
    }
  });

  test("returns event snapshots promptly while a long runtime is still active", async () => {
    const runnerRoot = root();
    const host = createHost(runnerRoot);
    const token = "c".repeat(64);
    const server = new AuthenticatedRunnerHttpServer({ host, token });
    const endpoint = server.start();
    try {
      await host.startExecution({ adapter_id: "fake-runtime", runtime_request: { ...runtimeRequest(runnerRoot), scenario: "idle-timeout" } });
      await waitUntil(async () => (await host.getStatus("execution:ipc")).status === "RUNNING", 2_000);
      const started = Date.now();
      const response = await fetch(`${endpoint}/v1/executions/${encodeURIComponent("execution:ipc")}/events?from=1`, {
        headers: { authorization: `Bearer ${token}` },
      });
      const body = await response.json() as { events: unknown[]; terminal: boolean };
      expect(Date.now() - started).toBeLessThan(250);
      expect(body.events.length).toBeGreaterThan(0);
      expect(body.terminal).toBeFalse();
      await host.cancelExecution("execution:ipc");
    } finally {
      server.stop();
      await host.close();
    }
  });

  test("routes the persistent kill switch through authenticated IPC and waits for process exit", async () => {
    const runnerRoot = root();
    const host = createHost(runnerRoot);
    const token = "d".repeat(64);
    const server = new AuthenticatedRunnerHttpServer({ host, token });
    const client = new HttpRunnerClient({ endpoint: server.start(), token });
    try {
      await client.startExecution({ adapter_id: "fake-runtime", runtime_request: { ...runtimeRequest(runnerRoot), scenario: "child-process-hang" } });
      await waitUntil(async () => (await client.getStatus("execution:ipc")).status === "RUNNING", 2_000);
      const result = await client.applyControl("CANCEL_ALL", "security test");
      expect(result.kill_switch.state).toBe("CANCEL_ALL");
      expect(result.executions).toEqual([expect.objectContaining({ execution_id: "execution:ipc", status: "EXITED", exit: expect.objectContaining({ cancelled: true }) })]);
      expect((await client.getStatus("execution:ipc")).status).toBe("EXITED");
    } finally {
      server.stop();
      await host.close();
    }
  });

  test("runs verifier commands inside the persistent runner with a durable recovery identity", async () => {
    const runnerRoot = root();
    const host = createHost(runnerRoot);
    const token = "v".repeat(64);
    const server = new AuthenticatedRunnerHttpServer({ host, token });
    const client = new HttpRunnerClient({ endpoint: server.start(), token });
    const workspace = join(runnerRoot, "verification-workspace");
    const release = join(runnerRoot, "release.verifier");
    mkdirSync(workspace);
    try {
      const recoveryIdentity = { execution_id: "execution:verification-ipc", attempt_id: "attempt:verification-ipc", workspace_path: workspace };
      let verifierCompleted = false;
      const running = client.runVerificationCommand({
        plan: {
          executable: process.execPath,
          arguments: [verifierWorker, "wait-file", release],
          working_directory: workspace,
          environment: { inherited: ["PATH", "SYSTEMROOT", "WINDIR", "TEMP"], injected_secret_refs: [] },
          stdin: { mode: "closed" },
          output_protocol: { type: "text", version: 1 },
          timeouts: { startup_seconds: 5, idle_seconds: 10, tool_seconds: 10, total_seconds: 10, graceful_shutdown_seconds: 0.05 },
          output_limit_bytes: 1_000_000,
          prompt_hash: `sha256:${"8".repeat(64)}`,
        },
        recovery_identity: recoveryIdentity,
      }).finally(() => { verifierCompleted = true; });
      const processesRoot = join(runnerRoot, "runner", "processes");
      await waitUntil(() => existsSync(processesRoot)
        && readdirSync(processesRoot).some(directory => existsSync(join(processesRoot, directory, "process-identity.json"))), 4_000);
      expect(discoverRunnerResource(join(runnerRoot, "runner"), recoveryIdentity.execution_id, recoveryIdentity.attempt_id))
        .toMatchObject({ state: null, process_identity: { recovery_identity: recoveryIdentity } });
      await client.applyControl("CANCEL_ALL", "verification recovery test");
      expect(verifierCompleted).toBeTrue();
      expect(await running).toMatchObject({ cancelled: true });
    } finally {
      server.stop();
      await host.close();
    }
  }, 15_000);

  test("replays a signed review result after runner reconstruction without launching a second process", async () => {
    const runnerRoot = root();
    const hostRoot = join(runnerRoot, "runner");
    const workspace = join(runnerRoot, "review-workspace");
    mkdirSync(workspace);
    const policy = {
      launch_policy_id: `review-launch-policy:${"a".repeat(32)}`,
      reviewer: { agent_id: "agent:reviewer", provider: "provider-b", model_class: "reviewer", session_id: "session:reviewer", context_id: "context:reviewer" },
    };
    const makeHost = () => new LocalRunnerHost({
      root: hostRoot,
      runner_id: "runner:review-recovery",
      adapters: [new FakeRuntimeAdapter()],
      supervisor: new LocalProcessSupervisor({ root: join(hostRoot, "processes") }),
      review_launch_policies: [policy],
    });
    const pinnedImage = `ghcr.io/opencodex/reviewer@sha256:${"b".repeat(64)}`;
    const reviewContext = { review_unit: { id: "review-unit:recovery" }, snapshot_hash: `sha256:${"d".repeat(64)}` };
    const contextPath = join(workspace, "review-context.json");
    writeFileSync(contextPath, JSON.stringify(reviewContext), "utf8");
    const request = {
      plan: {
        executable: process.execPath,
        arguments: [verifierWorker, "pass", pinnedImage],
        working_directory: workspace,
        environment: { inherited: ["PATH", "SYSTEMROOT", "WINDIR", "TEMP"], injected_secret_refs: [] },
        stdin: { mode: "file" as const, path: contextPath }, output_protocol: { type: "text" as const, version: 1 as const },
        timeouts: { startup_seconds: 5, idle_seconds: 10, tool_seconds: 10, total_seconds: 10, graceful_shutdown_seconds: 0.05 },
        output_limit_bytes: 1_000_000, prompt_hash: canonicalSha256(reviewContext),
      },
      recovery_identity: { execution_id: "execution:review-recovery", attempt_id: "attempt:review-recovery", workspace_path: workspace },
      review_attestation: { review_execution_id: "review-execution:recovery", launch_policy_id: policy.launch_policy_id, isolation_hash: `sha256:${"c".repeat(64)}` },
    };
    const firstHost = makeHost();
    const [first, concurrent] = await Promise.all([
      firstHost.runVerificationCommand(request),
      firstHost.runVerificationCommand(request),
    ]);
    expect(concurrent.process_id).toBe(first.process_id);
    const secondHost = makeHost();
    const second = await secondHost.runVerificationCommand(request);
    expect(second).toMatchObject({ replayed: true, process_id: first.process_id, review_attestation: { output_hash: first.review_attestation?.output_hash } });
    const changedRequest = {
      ...request,
      plan: { ...request.plan, arguments: [verifierWorker, "fail", pinnedImage], timeouts: { ...request.plan.timeouts, total_seconds: 1 } },
    };
    await expect(secondHost.runVerificationCommand(changedRequest)).rejects.toThrow("RUNNER_REVIEW_RECEIPT_BINDING_INVALID");
    expect(readdirSync(join(hostRoot, "processes"))).toHaveLength(1);
    await firstHost.close();
    await secondHost.close();
  }, 30_000);

  test("CANCEL_ALL waits across delayed verifier admission before taking its kill snapshot", async () => {
    const runnerRoot = root();
    let markEntered!: () => void;
    let releaseMaterialization!: () => void;
    const entered = new Promise<void>(resolve => { markEntered = resolve; });
    const release = new Promise<void>(resolve => { releaseMaterialization = resolve; });
    const supervisor = new LocalProcessSupervisor({
      root: join(runnerRoot, "runner", "processes"),
      secretResolver: {
        materialize: async () => {
          markEntered();
          await release;
          return { environment: {}, redaction_values: [], cleanup: async () => {} };
        },
      },
    });
    const host = createHost(runnerRoot, supervisor);
    const token = "w".repeat(64);
    const server = new AuthenticatedRunnerHttpServer({ host, token });
    const client = new HttpRunnerClient({ endpoint: server.start(), token });
    const workspace = join(runnerRoot, "delayed-verification-workspace");
    mkdirSync(workspace);
    try {
      const running = client.runVerificationCommand({
        plan: {
          executable: process.execPath,
          arguments: [verifierWorker, "wait-file", join(runnerRoot, "never-release.verifier")],
          working_directory: workspace,
          environment: { inherited: ["PATH", "SYSTEMROOT", "WINDIR", "TEMP"], injected_secret_refs: [] },
          stdin: { mode: "closed" }, output_protocol: { type: "text", version: 1 },
          timeouts: { startup_seconds: 5, idle_seconds: 10, tool_seconds: 10, total_seconds: 10, graceful_shutdown_seconds: 0.05 },
          output_limit_bytes: 1_000_000, prompt_hash: `sha256:${"9".repeat(64)}`,
        },
        recovery_identity: { execution_id: "execution:delayed-verifier", attempt_id: "attempt:delayed-verifier", workspace_path: workspace },
      });
      const runningOutcome = running.then(
        value => ({ value, error: null as Error | null }),
        error => ({ value: null, error: error as Error }),
      );
      await entered;
      let controlSettled = false;
      const control = client.applyControl("CANCEL_ALL", "delayed verifier admission").finally(() => { controlSettled = true; });
      await Bun.sleep(50);
      expect(controlSettled).toBeFalse();
      releaseMaterialization();
      await control;
      expect((await runningOutcome).error?.message).toContain("RUNNER_ADMISSION_REVOKED");
    } finally {
      releaseMaterialization();
      server.stop();
      await host.close();
    }
  }, 15_000);
});

function createHost(path: string, supervisor = new LocalProcessSupervisor({ root: join(path, "runner", "processes") })): LocalRunnerHost {
  return new LocalRunnerHost({
    root: join(path, "runner"),
    runner_id: "runner:ipc",
    adapters: [new FakeRuntimeAdapter()],
    supervisor,
    heartbeat_interval_ms: 50,
    lease_ttl_ms: 500,
  });
}

function runtimeRequest(workspace: string): RuntimeExecutionRequest {
  return {
    execution_id: "execution:ipc",
    attempt_id: "attempt:ipc",
    workspace_path: workspace,
    prompt_path: join(workspace, "prompt.md"),
    prompt_hash: `sha256:${"3".repeat(64)}`,
    inherited_environment: ["PATH", "SYSTEMROOT", "WINDIR", "TEMP"],
    injected_secret_refs: [],
    timeouts: { startup_seconds: 1, idle_seconds: 1, tool_seconds: 1, total_seconds: 3, graceful_shutdown_seconds: 0.05 },
    output_limit_bytes: 1_000_000,
    scenario: "successful-edit",
  };
}

async function waitUntil(predicate: () => boolean | Promise<boolean>, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!(await predicate())) {
    if (Date.now() >= deadline) throw new Error("Condition was not met before timeout");
    await Bun.sleep(20);
  }
}
