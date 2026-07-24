import { afterEach, describe, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ReadOnlyReviewEnvironment,
  RunnerReviewExecutor,
  createReviewLaunchPolicyId,
  type ReviewCommandRunner,
} from "../src/oef/phase3";
import { canonicalSha256 } from "../src/oef/phase1/core/contract/task-contract";
import { TestReviewIdentityAuthority } from "./fixtures/phase3-review-identity-authority";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function root(): string { const value = mkdtempSync(join(tmpdir(), "oef-p3-review-")); roots.push(value); return value; }
const hash = (value: string) => `sha256:${value.repeat(64)}`;
const reviewerIdentity = { agent_id: "agent:reviewer", provider: "provider-b", model_class: "reviewer", session_id: "session:reviewer", context_id: "context:reviewer" };
const pinnedImage = `ghcr.io/opencodex/reviewer@sha256:${"b".repeat(64)}`;
const identityAuthority = new TestReviewIdentityAuthority();

describe("Phase 3 read-only review execution", () => {
  test("provides immutable source/evidence/artifacts and a writable temp area", () => {
    const origin = root();
    const source = join(origin, "input-source");
    const evidence = join(origin, "input-evidence");
    const artifacts = join(origin, "input-artifacts");
    mkdirSync(source); mkdirSync(evidence); mkdirSync(artifacts);
    writeFileSync(join(source, "classifier.ts"), "export const classify = () => 429;\n", "utf8");
    writeFileSync(join(evidence, "tests.json"), "{}", "utf8");
    writeFileSync(join(artifacts, "diff.patch"), "diff", "utf8");

    const environment = new ReadOnlyReviewEnvironment({ root: join(origin, "review") });
    const prepared = environment.prepare({ source, evidence, artifacts });
    expect(() => writeFileSync(join(prepared.source, "classifier.ts"), "tamper", "utf8")).toThrow();
    expect(() => writeFileSync(join(prepared.source, "new.ts"), "tamper", "utf8")).toThrow();
    expect(() => rmSync(join(prepared.source, "classifier.ts"))).toThrow();
    expect(existsSync(join(prepared.source, "classifier.ts"))).toBeTrue();
    writeFileSync(join(prepared.temp, "report.json"), "{}", "utf8");
    expect(environment.assertIntegrity(prepared.environment_id)).toBeTrue();
    expect(prepared.permissions).toEqual({ source_write: "denied", evidence_write: "denied", artifacts_write: "denied", temp_write: "allowed", network: "denied", credentials: "denied" });

    environment.release(prepared.environment_id);
  });

  test("detects source tampering before accepting reviewer output", () => {
    const origin = root();
    const source = join(origin, "source");
    const evidence = join(origin, "evidence");
    const artifacts = join(origin, "artifacts");
    mkdirSync(source); mkdirSync(evidence); mkdirSync(artifacts);
    writeFileSync(join(source, "a.ts"), "before", "utf8");
    const environment = new ReadOnlyReviewEnvironment({ root: join(origin, "review") });
    const prepared = environment.prepare({ source, evidence, artifacts });
    if (process.platform === "win32") {
      expect(Bun.spawnSync(["icacls", prepared.source, "/reset", "/T", "/C"], { stdout: "pipe", stderr: "pipe" }).exitCode).toBe(0);
    }
    else {
      chmodSync(prepared.source, 0o755);
      chmodSync(join(prepared.source, "a.ts"), 0o644);
    }
    writeFileSync(join(prepared.source, "a.ts"), "after", "utf8");
    expect(() => environment.assertIntegrity(prepared.environment_id)).toThrow("REVIEW_SOURCE_INTEGRITY_VIOLATION");
    environment.release(prepared.environment_id);
  });

  test("rejects sensitive paths and secret material before copying reviewer inputs", () => {
    const origin = root();
    const source = join(origin, "source");
    const evidence = join(origin, "evidence");
    const artifacts = join(origin, "artifacts");
    mkdirSync(source); mkdirSync(evidence); mkdirSync(artifacts);
    writeFileSync(join(source, ".env"), "API_KEY=sk-proj-abcdefghijklmnop1234", "utf8");
    const environment = new ReadOnlyReviewEnvironment({ root: join(origin, "review") });
    expect(() => environment.prepare({ source, evidence, artifacts })).toThrow("REVIEW_INPUT_SENSITIVE_PATH_FORBIDDEN");
    rmSync(join(source, ".env"));
    mkdirSync(join(source, ".ssh"));
    writeFileSync(join(source, ".ssh", "config"), "Host internal", "utf8");
    expect(() => environment.prepare({ source, evidence, artifacts })).toThrow("REVIEW_INPUT_SENSITIVE_PATH_FORBIDDEN");
    rmSync(join(source, ".ssh"), { recursive: true });
    writeFileSync(join(source, "safe-name.txt"), "api_key=abcdefghijklmnop1234", "utf8");
    expect(() => environment.prepare({ source, evidence, artifacts })).toThrow("REVIEW_INPUT_SECRET_DETECTED");
  });

  test("reuses the Phase 2 runner through a pinned, networkless, read-only Docker sandbox", async () => {
    const origin = root();
    const source = join(origin, "source");
    const evidence = join(origin, "evidence");
    const artifacts = join(origin, "artifacts");
    mkdirSync(source); mkdirSync(evidence); mkdirSync(artifacts);
    writeFileSync(join(source, "a.ts"), "before", "utf8");
    const environment = new ReadOnlyReviewEnvironment({ root: join(origin, "review") });
    const prepared = environment.prepare({ source, evidence, artifacts });
    let captured: Parameters<ReviewCommandRunner["runVerificationCommand"]>[0] | null = null;
    const runner: ReviewCommandRunner = {
      async runVerificationCommand(request) {
        captured = request;
        expect(request.plan.stdin.mode).toBe("file");
        if (request.plan.stdin.mode === "file") expect(JSON.parse(readFileSync(request.plan.stdin.path, "utf8"))).toEqual({ marker: "a" });
        const stdout = join(origin, "stdout.log");
        const stderr = join(origin, "stderr.log");
        writeFileSync(stdout, JSON.stringify({ schema_version: 1, ok: true }), "utf8");
        writeFileSync(stderr, "", "utf8");
        return identityAuthority.createAtomicReviewResult(request, { process_id: "supervised-process:review-one", exit_code: 0, failure_type: null, timed_out: null, stdout_path: stdout, stderr_path: stderr, output_bytes: 32, redaction_count: 0 } as never, reviewerIdentity);
      },
    };
    const executor = new RunnerReviewExecutor({
      runner,
      environment,
      sandbox: { image: pinnedImage, pids_limit: 64 },
      identity_authority: identityAuthority,
    });
    const result = await executor.execute({
      review_execution_id: "review-execution:one",
      attempt_id: "attempt:review-one",
      environment_id: prepared.environment_id,
      executable: "bun",
      arguments: ["reviewer.ts", prepared.evidence],
      context: { marker: "a" },
      prompt_hash: canonicalSha256({ marker: "a" }),
      inherited_environment: ["PATH"],
      timeout_seconds: 30,
      output_limit_bytes: 100_000,
      launch_policy_id: createReviewLaunchPolicyId({ docker_image: pinnedImage, executable: "bun", arguments: ["reviewer.ts", prepared.evidence] }),
      reviewer_identity: reviewerIdentity,
    });
    expect(result.status).toBe("COMPLETED");
    expect(JSON.parse(result.raw_output)).toEqual({ schema_version: 1, ok: true });
    expect(captured?.plan.working_directory).toBe(prepared.source);
    expect(captured?.plan.executable).toBe("docker");
    expect(captured?.plan.arguments).toEqual([
      "run",
      "--rm",
      "--interactive",
      "--pull=never",
      "--network",
      "none",
      "--read-only",
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges",
      "--pids-limit",
      "64",
      "--mount",
      `type=bind,src=${prepared.source},dst=/review/source,readonly`,
      "--mount",
      `type=bind,src=${prepared.evidence},dst=/review/evidence,readonly`,
      "--mount",
      `type=bind,src=${prepared.artifacts},dst=/review/artifacts,readonly`,
      "--mount",
      `type=bind,src=${prepared.temp},dst=/review/temp`,
      "--workdir",
      "/review/source",
      pinnedImage,
      "bun",
      "reviewer.ts",
      "/review/evidence",
    ]);
    expect(captured?.plan.environment.injected_secret_refs).toEqual([]);
    expect(captured?.recovery_identity.workspace_path).toBe(prepared.source);
    expect(result.isolation).toEqual({
      provider: "docker",
      image: pinnedImage,
      image_digest: `sha256:${"b".repeat(64)}`,
      pull_policy: "never",
      network: "none",
      root_filesystem: "read-only",
      capabilities: "dropped-all",
      no_new_privileges: true,
      pids_limit: 64,
      credentials: "not-mounted",
      working_directory: "/review/source",
      mounts: [
        { purpose: "source", host_path: prepared.source, container_path: "/review/source", access: "read-only" },
        { purpose: "evidence", host_path: prepared.evidence, container_path: "/review/evidence", access: "read-only" },
        { purpose: "artifacts", host_path: prepared.artifacts, container_path: "/review/artifacts", access: "read-only" },
        { purpose: "temp", host_path: prepared.temp, container_path: "/review/temp", access: "read-write" },
      ],
    });
    expect(environment.assertIntegrity(prepared.environment_id)).toBeTrue();
    environment.release(prepared.environment_id);
  });

  test("fails closed before runner execution when no Docker sandbox is configured", async () => {
    const origin = root();
    const source = join(origin, "source");
    const evidence = join(origin, "evidence");
    const artifacts = join(origin, "artifacts");
    mkdirSync(source); mkdirSync(evidence); mkdirSync(artifacts);
    const environment = new ReadOnlyReviewEnvironment({ root: join(origin, "review") });
    const prepared = environment.prepare({ source, evidence, artifacts });
    let calls = 0;
    const runner: ReviewCommandRunner = {
      async runVerificationCommand(request) {
        calls += 1;
        throw new Error("must not run");
      },
    };
    const executor = new RunnerReviewExecutor({ runner, environment, identity_authority: identityAuthority });

    await expect(executor.execute({
      review_execution_id: "review-execution:missing-sandbox",
      attempt_id: "attempt:missing-sandbox",
      environment_id: prepared.environment_id,
      executable: "bun",
      arguments: ["reviewer.ts"],
      context: { marker: "c" },
      prompt_hash: canonicalSha256({ marker: "c" }),
      inherited_environment: ["PATH"],
      timeout_seconds: 30,
      output_limit_bytes: 100_000,
      launch_policy_id: createReviewLaunchPolicyId({ docker_image: pinnedImage, executable: "bun", arguments: ["reviewer.ts"] }),
      reviewer_identity: reviewerIdentity,
    })).rejects.toThrow("REVIEW_SANDBOX_REQUIRED");
    expect(calls).toBe(0);
    environment.release(prepared.environment_id);
  });

  test("rejects unpinned Docker images", () => {
    const environment = new ReadOnlyReviewEnvironment({ root: root() });
    const runner: ReviewCommandRunner = { async runVerificationCommand() { throw new Error("must not run"); } };
    expect(() => new RunnerReviewExecutor({
      runner,
      environment,
      sandbox: { image: "ghcr.io/opencodex/reviewer:latest" },
      identity_authority: identityAuthority,
    })).toThrow("REVIEW_SANDBOX_IMAGE_MUST_BE_PINNED");
  });

  test("rejects a Docker PID limit that disables process containment", () => {
    const environment = new ReadOnlyReviewEnvironment({ root: root() });
    const runner: ReviewCommandRunner = { async runVerificationCommand() { throw new Error("must not run"); } };
    expect(() => new RunnerReviewExecutor({
      runner,
      environment,
      sandbox: { image: pinnedImage, pids_limit: -1 },
      identity_authority: identityAuthority,
    })).toThrow("REVIEW_SANDBOX_PIDS_LIMIT_INVALID");
  });

  test("rejects reviewer host paths outside the prepared environment roots", async () => {
    const origin = root();
    const source = join(origin, "source");
    const evidence = join(origin, "evidence");
    const artifacts = join(origin, "artifacts");
    mkdirSync(source); mkdirSync(evidence); mkdirSync(artifacts);
    const outside = join(origin, "host-credential.txt");
    writeFileSync(outside, "secret", "utf8");
    const environment = new ReadOnlyReviewEnvironment({ root: join(origin, "review") });
    const prepared = environment.prepare({ source, evidence, artifacts });
    let calls = 0;
    const runner: ReviewCommandRunner = {
      async runVerificationCommand(request) {
        calls += 1;
        throw new Error("must not run");
      },
    };
    const executor = new RunnerReviewExecutor({ runner, environment, sandbox: { image: pinnedImage }, identity_authority: identityAuthority });

    await expect(executor.execute({
      review_execution_id: "review-execution:outside-path",
      attempt_id: "attempt:outside-path",
      environment_id: prepared.environment_id,
      executable: "bun",
      arguments: [outside],
      context: { marker: "d" },
      prompt_hash: canonicalSha256({ marker: "d" }),
      inherited_environment: ["PATH"],
      timeout_seconds: 30,
      output_limit_bytes: 100_000,
      launch_policy_id: createReviewLaunchPolicyId({ docker_image: pinnedImage, executable: "bun", arguments: [outside] }),
      reviewer_identity: reviewerIdentity,
    })).rejects.toThrow("REVIEW_SANDBOX_HOST_PATH_OUTSIDE_PREPARED_ROOTS");
    expect(calls).toBe(0);
    environment.release(prepared.environment_id);
  });

  test("converts a bounded Phase 2 total timeout into a failed review result", async () => {
    const origin = root();
    const source = join(origin, "source");
    const evidence = join(origin, "evidence");
    const artifacts = join(origin, "artifacts");
    mkdirSync(source); mkdirSync(evidence); mkdirSync(artifacts);
    const environment = new ReadOnlyReviewEnvironment({ root: join(origin, "review") });
    const prepared = environment.prepare({ source, evidence, artifacts });
    const runner: ReviewCommandRunner = {
      async runVerificationCommand(request) {
        const stdout = join(origin, "timeout-stdout.log");
        const stderr = join(origin, "timeout-stderr.log");
        writeFileSync(stdout, "", "utf8");
        writeFileSync(stderr, "review timed out", "utf8");
        return identityAuthority.createAtomicReviewResult(request, { process_id: "supervised-process:review-timeout", exit_code: null, failure_type: "TOTAL_TIMEOUT", timed_out: "total", stdout_path: stdout, stderr_path: stderr, output_bytes: 16, redaction_count: 0 } as never, reviewerIdentity);
      },
    };
    const executor = new RunnerReviewExecutor({ runner, environment, sandbox: { image: pinnedImage }, identity_authority: identityAuthority });
    const result = await executor.execute({
      review_execution_id: "review-execution:timeout",
      attempt_id: "attempt:review-timeout",
      environment_id: prepared.environment_id,
      executable: "node",
      arguments: ["reviewer.mjs"],
      context: { marker: "f" },
      prompt_hash: canonicalSha256({ marker: "f" }),
      inherited_environment: ["PATH"],
      timeout_seconds: 1,
      output_limit_bytes: 100_000,
      launch_policy_id: createReviewLaunchPolicyId({ docker_image: pinnedImage, executable: "node", arguments: ["reviewer.mjs"] }),
      reviewer_identity: reviewerIdentity,
    });
    expect(result.status).toBe("FAILED");
    expect(result.exit).toMatchObject({ failure_type: "TOTAL_TIMEOUT", timed_out: "total" });
    expect(environment.assertIntegrity(prepared.environment_id)).toBeTrue();
    environment.release(prepared.environment_id);
  });
});
