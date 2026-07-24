import { describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  CodexRuntimeAdapter,
  codexResourcePathPrepend,
  LocalRuntimeDiscovery,
  SafeRuntimeProbeExecutor,
  parseRuntimeLaunchPlan,
  type RuntimeExecutionRequest,
} from "../src/oef/phase2";

const HASH = `sha256:${"c".repeat(64)}`;

const request: RuntimeExecutionRequest = {
  execution_id: "execution:codex",
  attempt_id: "attempt:codex-1",
  workspace_path: "C:\\safe\\workspace",
  prompt_path: "C:\\safe\\context\\prompt.md",
  prompt_hash: HASH,
  inherited_environment: ["PATH", "CODEX_HOME"],
  injected_secret_refs: [],
  timeouts: { startup_seconds: 60, idle_seconds: 300, tool_seconds: 600, total_seconds: 3_600, graceful_shutdown_seconds: 10 },
  output_limit_bytes: 50_000_000,
  resolved_model: "gpt-5.6",
};

describe("Codex real runtime adapter", () => {
  test("builds a bounded exec plan without dangerous bypass flags or shell strings", async () => {
    const adapter = new CodexRuntimeAdapter({ binaryCandidates: ["C:\\tools\\codex.exe"] });
    const plan = await adapter.prepareLaunch(request);
    expect(parseRuntimeLaunchPlan(plan)).toEqual(plan);
    expect(plan.executable).toBe("C:\\tools\\codex.exe");
    expect(plan.arguments).toContain("exec");
    expect(plan.arguments).toContain("--json");
    expect(plan.arguments).toContain("workspace-write");
    expect(plan.arguments).toContain(request.workspace_path);
    expect(plan.arguments).toContain("-");
    expect(plan.stdin).toEqual({ mode: "file", path: request.prompt_path });
    expect(plan.arguments).not.toContain("--dangerously-bypass-approvals-and-sandbox");
  });

  test("normalizes Codex JSONL while excluding private reasoning content", async () => {
    const adapter = new CodexRuntimeAdapter({ binaryCandidates: ["codex"] });
    const rows = [
      { type: "thread.started", thread_id: "thread-123" },
      { type: "turn.started" },
      { type: "item.completed", item: { id: "item-reason", type: "reasoning", text: "private chain of thought" } },
      { type: "item.started", item: { id: "cmd-1", type: "command_execution", command: "bun test" } },
      { type: "item.completed", item: { id: "cmd-1", type: "command_execution", command: "bun test", exit_code: 0, status: "completed" } },
      { type: "turn.completed", usage: { input_tokens: 10, output_tokens: 5 } },
    ];
    const events = await adapter.parseEvent({
      stream: "stdout",
      chunk: `${rows.map(row => JSON.stringify(row)).join("\n")}\n`,
      execution_id: request.execution_id,
      attempt_id: request.attempt_id,
      received_at: "2026-07-23T10:00:01.000Z",
    });
    expect(events.map(event => event.type)).toEqual([
      "runtime.session.created",
      "execution.started",
      "command.started",
      "command.completed",
      "usage.reported",
      "execution.completed",
    ]);
    expect(JSON.stringify(events)).not.toContain("private chain of thought");
    expect(events.map(event => event.sequence)).toEqual([1, 2, 3, 4, 5, 6]);
  });

  test("classifies provider and protocol exits without accepting runtime claims as evidence", async () => {
    const adapter = new CodexRuntimeAdapter({ binaryCandidates: ["codex"] });
    expect(await adapter.classifyExit({ exit_code: 1, signal: null, stderr_tail: "HTTP 429 rate limit exceeded", timed_out: null }))
      .toMatchObject({ classification: "RUNTIME_FAILED", failure_type: "RATE_LIMITED", retryability: "retryable" });
    expect(await adapter.classifyExit({ exit_code: 1, signal: null, stderr_tail: "context length exceeded", timed_out: null }))
      .toMatchObject({ failure_type: "CONTEXT_LIMIT_EXCEEDED", retryability: "conditional" });
  });

  test("detects and health-probes the installed Codex runtime using a bounded version command", async () => {
    const localCandidate = process.platform === "win32"
      ? join(process.env.LOCALAPPDATA ?? "", "Programs", "OpenAI", "Codex", "bin", "codex.exe")
      : "codex";
    const adapter = new CodexRuntimeAdapter({ binaryCandidates: [localCandidate] });
    const discovery = new LocalRuntimeDiscovery({ probeExecutor: new SafeRuntimeProbeExecutor({ timeoutMs: 5_000 }) });
    const [snapshot] = await discovery.scan([adapter], { checkedAt: "2026-07-23T10:00:00.000Z" });
    if (existsSync(localCandidate)) {
      expect(snapshot?.detection.found).toBeTrue();
      expect(snapshot?.detection.binary?.version).toMatch(/^\d+\.\d+\.\d+/);
      expect(snapshot?.probe.health.status).toBe("HEALTHY");
      if (process.platform === "win32") {
        const helperPaths = codexResourcePathPrepend(localCandidate);
        expect(helperPaths.length).toBeGreaterThan(0);
        expect(helperPaths.every(path => existsSync(join(path, "codex-windows-sandbox-setup.exe")))).toBeTrue();
        expect((await adapter.prepareLaunch(request)).environment.path_prepend).toEqual(helperPaths);
      }
    } else {
      expect(snapshot?.probe.health.status).toBe("MISSING");
    }
  });

  test("does not report healthy when the CLI authentication probe is not ready", async () => {
    const adapter = new CodexRuntimeAdapter({ binaryCandidates: [process.execPath] });
    const calls: string[][] = [];
    const detection = await adapter.detect({
      environment_path: "",
      probe_executor: {
        async run(_executable, arguments_) {
          calls.push([...arguments_]);
          return arguments_[0] === "--version"
            ? { exit_code: 0, stdout: "codex-cli 0.144.6", stderr: "", timed_out: false }
            : { exit_code: 1, stdout: "Not logged in", stderr: "", timed_out: false };
        },
      },
    });
    const probe = await adapter.probe({ detection, checked_at: "2026-07-23T10:00:00.000Z" });
    expect(calls).toEqual([["--version"], ["login", "status"]]);
    expect(detection.authentication).toBe("MISSING");
    expect(probe.health.status).toBe("UNHEALTHY");
  });

  test("keeps adapter implementations free of process spawning and database access", () => {
    const source = readFileSync(new URL("../src/oef/phase2/runtime/adapters/codex.ts", import.meta.url), "utf8");
    expect(source).not.toMatch(/node:child_process|Bun\.spawn|bun:sqlite|Database\b/);
  });
});
