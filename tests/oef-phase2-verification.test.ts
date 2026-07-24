import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  EvidencePackageBuilder,
  discoverRunnerResource,
  InProcessVerificationCommandRunner,
  MechanicalVerifier,
  compareWithBaseline,
  derivePhase2Result,
  parseVerificationPlan,
  type SealedWorkspaceInput,
} from "../src/oef/phase2";
import { LocalArtifactStore } from "../src/oef/phase1/artifacts/local/local-artifact-store";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* verifier process logs can linger briefly */ }
  }
});

function root(): string {
  const value = mkdtempSync(join(tmpdir(), "oef-phase2-verifier-"));
  roots.push(value);
  return value;
}

const worker = new URL("./fixtures/oef-phase2-verifier-worker.ts", import.meta.url).pathname.replace(/^\/(.:)/, "$1");
const HASH = `sha256:${"1".repeat(64)}`;

function workspace(path: string, overrides: Partial<SealedWorkspaceInput> = {}): SealedWorkspaceInput {
  return {
    workspace_id: "workspace:verify",
    path,
    base_commit: "abc123",
    environment_hash: HASH,
    sealed: true,
    changed_files: [{ path: "src/app.ts", dependency_file: false }],
    path_policy: { decision: "ALLOW", allowed: ["src/app.ts"], denied: [] },
    patch: "diff --git a/src/app.ts b/src/app.ts\n+safe change\n",
    ...overrides,
  };
}

function recovery(path: string) {
  return { execution_id: "execution:verify", attempt_id: "attempt:verify", workspace_path: path };
}

describe("Phase 2 mechanical verifier", () => {
  test("accepts only structured executable and argument plans", () => {
    expect(parseVerificationPlan({
      schema_version: 1,
      verification_plan_id: "verification:one",
      steps: [{ id: "unit", type: "command", command: { executable: process.execPath, arguments: [worker, "pass"] }, timeout_seconds: 5, required: true }],
    }).steps).toHaveLength(1);
    expect(() => parseVerificationPlan({
      schema_version: 1,
      verification_plan_id: "verification:bad",
      steps: [{ id: "unit", type: "command", command: `${process.execPath} ${worker}`, shell: true, timeout_seconds: 5, required: true }],
    })).toThrow();
  });

  test("runs commands in a separate process and produces structured passing results", async () => {
    const path = root();
    mkdirSync(join(path, "src"));
    writeFileSync(join(path, "src", "app.ts"), "safe\n");
    const verifier = new MechanicalVerifier({ command_runner: new InProcessVerificationCommandRunner({ root: join(path, "verifier") }) });
    const result = await verifier.run(parseVerificationPlan({
      schema_version: 1,
      verification_plan_id: "verification:pass",
      steps: [
        { id: "unit", type: "command", command: { executable: process.execPath, arguments: [worker, "pass"] }, timeout_seconds: 5, required: true },
        { id: "paths", type: "changed-path-policy", required: true },
        { id: "secrets", type: "secret-scan", required: true },
        { id: "dependencies", type: "dependency-change", required: false },
      ],
    }), workspace(path), recovery(path));
    expect(result.status).toBe("PASSED");
    expect(result.summary).toEqual({ required_passed: 3, required_failed: 0, optional_failed: 0 });
    expect(result.steps.map(step => step.status)).toEqual(["PASSED", "PASSED", "PASSED", "PASSED"]);
    expect(derivePhase2Result({ execution_completed: true, verification: result })).toBe("READY_FOR_REVIEW");
  });

  test("retries a failing command exactly once and never promotes a flake", async () => {
    const path = root();
    const flakyState = join(path, "flaky.state");
    const verifier = new MechanicalVerifier({ command_runner: new InProcessVerificationCommandRunner({ root: join(path, "verifier") }) });
    const plan = parseVerificationPlan({
      schema_version: 1,
      verification_plan_id: "verification:flaky",
      steps: [{ id: "unit", type: "command", command: { executable: process.execPath, arguments: [worker, "flaky", flakyState] }, timeout_seconds: 5, required: true }],
    });
    const result = await verifier.run(plan, workspace(path), recovery(path));
    expect(result.steps[0]).toMatchObject({ status: "FLAKY_SUSPECTED", attempts: 2 });
    expect(result.status).toBe("FAILED");
    expect(derivePhase2Result({ execution_completed: true, verification: result })).toBe("REPAIR_REQUIRED");

    const deterministic = await new MechanicalVerifier({ command_runner: new InProcessVerificationCommandRunner({ root: join(path, "verifier-2") }) }).run(parseVerificationPlan({
      schema_version: 1,
      verification_plan_id: "verification:failure",
      steps: [{ id: "unit", type: "command", command: { executable: process.execPath, arguments: [worker, "fail"] }, timeout_seconds: 5, required: true }],
    }), workspace(path), recovery(path));
    expect(deterministic.steps[0]).toMatchObject({ status: "FAILED", attempts: 2, failure_kind: "DETERMINISTIC_FAILURE" });
  });

  test("blocks path violations, secrets, timeouts, and suspicious dependency changes", async () => {
    const path = root();
    mkdirSync(join(path, "src"));
    writeFileSync(join(path, "src", "app.ts"), "const token = 'sk-proj-abcdefghijklmnopqrstuvwxyz123456';\n");
    const verifier = new MechanicalVerifier({ command_runner: new InProcessVerificationCommandRunner({ root: join(path, "verifier") }) });
    const result = await verifier.run(parseVerificationPlan({
      schema_version: 1,
      verification_plan_id: "verification:block",
      steps: [
        { id: "hang", type: "command", command: { executable: process.execPath, arguments: [worker, "hang"] }, timeout_seconds: 0.1, required: true },
        { id: "paths", type: "changed-path-policy", required: true },
        { id: "secrets", type: "secret-scan", required: true },
        { id: "dependencies", type: "dependency-change", required: true },
      ],
    }), workspace(path, {
      changed_files: [{ path: "src/app.ts", dependency_file: false }, { path: "package.json", dependency_file: true }],
      path_policy: { decision: "BLOCK", allowed: ["src/app.ts"], denied: ["package.json"] },
      patch: "sk-proj-abcdefghijklmnopqrstuvwxyz123456",
    }), recovery(path));
    expect(result.steps.find(step => step.id === "hang")?.status).toBe("TIMED_OUT");
    expect(result.steps.find(step => step.id === "paths")?.status).toBe("BLOCKED");
    expect(result.steps.find(step => step.id === "secrets")?.status).toBe("BLOCKED");
    expect(result.steps.find(step => step.id === "dependencies")?.status).toBe("BLOCKED");
    expect(derivePhase2Result({ execution_completed: false, verification: result })).toBe("BLOCKED");
  });

  test("publishes verifier command identity into the shared runner recovery inventory", async () => {
    const path = root();
    const runnerRoot = join(path, "runner");
    const release = join(path, "release.verifier");
    const verifier = new MechanicalVerifier({ command_runner: new InProcessVerificationCommandRunner({ root: join(runnerRoot, "processes") }) });
    const running = verifier.run(parseVerificationPlan({
      schema_version: 1,
      verification_plan_id: "verification:recoverable",
      steps: [{ id: "unit", type: "command", command: { executable: process.execPath, arguments: [worker, "wait-file", release] }, timeout_seconds: 10, required: true }],
    }), workspace(path), recovery(path));
    await waitUntil(() => existsSync(join(runnerRoot, "processes"))
      && readdirSync(join(runnerRoot, "processes")).some(directory => existsSync(join(runnerRoot, "processes", directory, "process-identity.json"))), 4_000);
    const resource = discoverRunnerResource(runnerRoot, "execution:verify", "attempt:verify");
    expect(resource).toMatchObject({
      attempt_id: "attempt:verify",
      workspace_path: path,
      state: null,
      process_identity: { recovery_identity: recovery(path) },
    });
    writeFileSync(release, "continue");
    expect((await running).status).toBe("PASSED");
  }, 15_000);

  test("fails closed when a changed file is too large for the bounded secret scanner", async () => {
    const path = root();
    mkdirSync(join(path, "src"));
    writeFileSync(join(path, "src", "large.bin"), Buffer.alloc(5_000_001, 65));
    const verifier = new MechanicalVerifier({ command_runner: new InProcessVerificationCommandRunner({ root: join(path, "verifier") }) });
    const result = await verifier.run(parseVerificationPlan({
      schema_version: 1,
      verification_plan_id: "verification:oversize-secret-scan",
      steps: [{ id: "secrets", type: "secret-scan", required: true }],
    }), workspace(path, {
      changed_files: [{ path: "src/large.bin", dependency_file: false }],
      patch: "[UNTRACKED BINARY OR LARGE FILE OMITTED]",
    }));
    expect(result.status).toBe("BLOCKED");
    expect(result.steps[0]).toMatchObject({ status: "BLOCKED", failure_kind: "SECRET_LEAK_DETECTED", findings: 1 });
  });

  test("distinguishes approved baseline failures from new regressions", () => {
    const future = "2099-01-01T00:00:00.000Z";
    expect(compareWithBaseline({
      baseline_failure_signatures: [HASH],
      current_failure_signatures: [HASH],
      known_failures: [{ test_id: "unit", signature: HASH, approved_until: future, rationale: "Tracked issue" }],
      now: "2026-07-23T10:00:00.000Z",
    })).toEqual({ status: "KNOWN_BASELINE_FAILURES_ONLY", new_signatures: [], expired_signatures: [] });
    expect(compareWithBaseline({
      baseline_failure_signatures: [HASH],
      current_failure_signatures: [HASH, `sha256:${"2".repeat(64)}`],
      known_failures: [{ test_id: "unit", signature: HASH, approved_until: future, rationale: "Tracked issue" }],
      now: "2026-07-23T10:00:00.000Z",
    }).status).toBe("NEW_REGRESSION");
  });
});

async function waitUntil(predicate: () => boolean, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("Condition was not met before timeout");
    await Bun.sleep(20);
  }
}

describe("content-addressed execution evidence", () => {
  test("builds an integrity-bound package and separates completion, verification, and acceptance", () => {
    const path = root();
    const store = new LocalArtifactStore({ root: join(path, "artifacts") });
    const put = (content: string) => store.put({
      content, media_type: "application/json", classification: "internal", retention_policy: "test",
      created_by: { type: "system", id: "system:test" },
    });
    const manifest = put("manifest");
    const baseline = put("baseline");
    const diff = put("diff");
    const builder = new EvidencePackageBuilder(store);
    const value = builder.build({
      task_id: "task:verify",
      contract_revision_id: "contract-revision:verify",
      assignment_id: "assignment:verify",
      attempt_id: "attempt:verify",
      manifest_ref: { artifact_id: manifest.artifact_id, content_hash: manifest.content_hash },
      evidence: [
        { type: "baseline", artifact_id: baseline.artifact_id, content_hash: baseline.content_hash },
        { type: "code-diff", artifact_id: diff.artifact_id, content_hash: diff.content_hash },
      ],
      result: { execution_completed: true, mechanical_verification: "PASSED" },
    }, [manifest, baseline, diff]);
    expect(value.evidence_package_id).toMatch(/^evidence-package:/);
    expect(value.integrity).toMatchObject({ artifacts_valid: true, package_hash: expect.stringMatching(/^sha256:/) });
    expect(JSON.stringify(value)).not.toContain("ACCEPT");
    expect(() => builder.build({
      task_id: "task:verify", contract_revision_id: "contract-revision:verify", assignment_id: "assignment:verify", attempt_id: "attempt:verify",
      manifest_ref: { artifact_id: manifest.artifact_id, content_hash: manifest.content_hash }, evidence: [],
      result: { execution_completed: true, mechanical_verification: "ACCEPT" as never },
    }, [manifest])).toThrow();
    expect(() => builder.build({
      task_id: "task:verify", contract_revision_id: "contract-revision:verify", assignment_id: "assignment:verify", attempt_id: "attempt:verify",
      manifest_ref: { artifact_id: manifest.artifact_id, content_hash: manifest.content_hash },
      evidence: [{ type: "baseline", artifact_id: baseline.artifact_id, content_hash: HASH }],
      result: { execution_completed: true, mechanical_verification: "PASSED" },
    }, [manifest, baseline])).toThrow("EVIDENCE_ARTIFACT_REFERENCE_INVALID");
  });
});
