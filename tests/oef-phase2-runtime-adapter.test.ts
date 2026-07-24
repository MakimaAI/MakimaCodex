import { describe, expect, test } from "bun:test";
import {
  FakeRuntimeAdapter,
  RuntimeEventSequenceTracker,
  negotiateAdapterProtocol,
  parseRuntimeLaunchPlan,
  type RuntimeAdapter,
  type RuntimeExecutionRequest,
} from "../src/oef/phase2";

const HASH = `sha256:${"a".repeat(64)}`;

const request: RuntimeExecutionRequest = {
  execution_id: "execution:adapter",
  attempt_id: "attempt:adapter-1",
  workspace_path: "C:\\safe\\workspace",
  prompt_path: "C:\\safe\\context\\prompt.md",
  prompt_hash: HASH,
  inherited_environment: ["PATH"],
  injected_secret_refs: ["secret-ref:test-account"],
  timeouts: { startup_seconds: 10, idle_seconds: 30, tool_seconds: 60, total_seconds: 120, graceful_shutdown_seconds: 5 },
  output_limit_bytes: 1_000_000,
  scenario: "successful-edit",
};

function adapterContract(name: string, create: () => RuntimeAdapter) {
  describe(`${name} adapter contract`, () => {
    test("detects, probes, and declares a valid capability manifest", async () => {
      const adapter = create();
      const detected = await adapter.detect({ environment_path: process.env.PATH ?? "" });
      expect(detected.found).toBeTrue();
      expect(detected.binary?.version).toBeTruthy();
      const probe = await adapter.probe({ detection: detected, checked_at: "2026-07-23T10:00:00.000Z" });
      expect(probe.health.status).toBe("HEALTHY");
      expect(adapter.manifest.capabilities["structured-output"]?.supported).toBeTrue();
    });

    test("negotiates protocol versions and rejects an incompatible range", () => {
      const manifest = create().manifest;
      expect(negotiateAdapterProtocol(1, manifest.protocol)).toEqual({ ok: true, negotiated_version: 1 });
      expect(negotiateAdapterProtocol(99, manifest.protocol)).toEqual({ ok: false, failure: "ADAPTER_PROTOCOL_INCOMPATIBLE" });
    });

    test("returns a deterministic, shell-free launch plan containing only secret references", async () => {
      const adapter = create();
      const first = await adapter.prepareLaunch(request);
      const second = await adapter.prepareLaunch(request);
      expect(first).toEqual(second);
      expect(parseRuntimeLaunchPlan(first)).toEqual(first);
      expect(JSON.stringify(first)).not.toContain("test-secret-value");
      expect(first.environment.injected_secret_refs).toEqual(["secret-ref:test-account"]);
      expect(() => parseRuntimeLaunchPlan({ ...first, shell: true })).toThrow();
      expect(() => parseRuntimeLaunchPlan({ command: `${first.executable} ${first.arguments.join(" ")}` })).toThrow();
    });

    test("normalizes authoritative JSONL and classifies exits without deciding task success", async () => {
      const adapter = create();
      const events = await adapter.parseEvent({
        stream: "stdout",
        chunk: `${JSON.stringify({ sequence: 1, type: "execution.started", payload: {} })}\n${JSON.stringify({ sequence: 2, type: "execution.completed", payload: { exit_code: 0 } })}\n`,
        execution_id: request.execution_id,
        attempt_id: request.attempt_id,
        received_at: "2026-07-23T10:00:01.000Z",
      });
      expect(events.map(event => event.type)).toEqual(["execution.started", "execution.completed"]);
      expect(events.every(event => event.confidence === "AUTHORITATIVE")).toBeTrue();
      expect(await adapter.classifyExit({ exit_code: 0, signal: null, stderr_tail: "", timed_out: null })).toEqual({
        classification: "RUNTIME_EXITED",
        failure_type: null,
        retryability: "never",
      });
    });

    test("reports resume support honestly", async () => {
      const adapter = create();
      if (adapter.manifest.capabilities["session-resume"]?.supported) {
        expect(typeof adapter.buildResumePlan).toBe("function");
      } else {
        expect(adapter.buildResumePlan).toBeUndefined();
      }
    });
  });
}

adapterContract("fake", () => new FakeRuntimeAdapter());

describe("runtime event integrity", () => {
  test("deduplicates identical events without effects and detects sequence gaps", async () => {
    const adapter = new FakeRuntimeAdapter();
    const duplicate = await adapter.scenarioEvents("duplicate-event", request);
    const tracker = new RuntimeEventSequenceTracker();
    expect(duplicate.map(event => tracker.accept(event).status)).toEqual(["ACCEPTED", "ACCEPTED", "DUPLICATE"]);
    expect(tracker.acceptedEvents()).toHaveLength(2);

    const missing = await adapter.scenarioEvents("missing-sequence", request);
    const missingTracker = new RuntimeEventSequenceTracker();
    expect(missing.map(event => missingTracker.accept(event).status)).toEqual(["ACCEPTED", "GAP"]);
    expect(missingTracker.integrity()).toEqual({ complete: false, next_expected_sequence: 2, missing_sequences: [2] });
  });

  test("exposes every deterministic fault scenario required by the runner suite", () => {
    expect(FakeRuntimeAdapter.SCENARIOS).toEqual([
      "successful-edit",
      "startup-timeout",
      "idle-timeout",
      "malformed-json",
      "duplicate-event",
      "missing-sequence",
      "tool-failure",
      "path-violation",
      "secret-output",
      "child-process-hang",
      "context-limit",
    ]);
  });
});
