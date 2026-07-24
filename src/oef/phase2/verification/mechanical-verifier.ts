import { existsSync, lstatSync, readFileSync, realpathSync } from "node:fs";
import { relative, resolve } from "node:path";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { containsLikelyPhase1Secret } from "../../phase1/core/security/secrets";
import { LocalProcessSupervisor } from "../runner/process-supervisor";
import type { ProcessRecoveryIdentity } from "../runner/process-identity";
import type { RuntimeLaunchPlan } from "../runtime/protocol";
import type { SupervisedProcessExit } from "../runner/process-supervisor";
import type {
  SealedWorkspaceInput,
  VerificationPlan,
  VerificationResult,
  VerificationStepResult,
} from "./models";
import { parseVerificationPlan } from "./models";

type PolicyVerificationStep = {
  id: string;
  type: "changed-path-policy" | "secret-scan" | "dependency-change";
  required: boolean;
};

export class MechanicalVerifier {
  private readonly commandRunner: VerificationCommandRunner;
  private readonly clock: () => string;
  constructor(options: { command_runner: VerificationCommandRunner; clock?: () => string }) {
    this.commandRunner = options.command_runner;
    this.clock = options.clock ?? (() => new Date().toISOString());
  }

  async run(
    planInput: VerificationPlan,
    workspace: SealedWorkspaceInput,
    recoveryIdentity?: ProcessRecoveryIdentity,
  ): Promise<VerificationResult> {
    const plan = parseVerificationPlan(planInput);
    if (!workspace.sealed) throw new Error("VERIFIER_REQUIRES_SEALED_WORKSPACE");
    if (plan.steps.some(step => step.type === "command")) {
      if (!recoveryIdentity) throw new Error("VERIFIER_RECOVERY_IDENTITY_REQUIRED");
      if (resolve(recoveryIdentity.workspace_path) !== resolve(workspace.path)) throw new Error("VERIFIER_RECOVERY_WORKSPACE_MISMATCH");
    }
    const startedAt = this.clock();
    const results: VerificationStepResult[] = [];
    for (const step of plan.steps) {
      if (step.type === "command") results.push(await this.runCommand(step, workspace, recoveryIdentity!));
      else if (step.type === "changed-path-policy") results.push(this.pathPolicy(step, workspace));
      else if (step.type === "secret-scan") results.push(this.secretScan(step, workspace));
      else results.push(this.dependencyChange(step, workspace));
    }
    const requiredPassed = results.filter(step => step.required && step.status === "PASSED").length;
    const requiredFailed = results.filter(step => step.required && step.status !== "PASSED").length;
    const optionalFailed = results.filter(step => !step.required && step.status !== "PASSED").length;
    const blocked = results.some(step => step.status === "BLOCKED");
    const status = blocked ? "BLOCKED" : requiredFailed > 0 ? "FAILED" : "PASSED";
    return {
      schema_version: 1,
      verification_plan_id: plan.verification_plan_id,
      workspace_id: workspace.workspace_id,
      status,
      steps: results,
      summary: { required_passed: requiredPassed, required_failed: requiredFailed, optional_failed: optionalFailed },
      failure_classification: status === "PASSED" ? null : { type: "verification-failed", repairable: !blocked },
      started_at: startedAt,
      completed_at: this.clock(),
    };
  }

  private async runCommand(
    step: Extract<VerificationPlan["steps"][number], { type: "command" }>,
    workspace: SealedWorkspaceInput,
    recoveryIdentity: ProcessRecoveryIdentity,
  ): Promise<VerificationStepResult> {
    const attempts = [];
    for (let index = 0; index < 2; index += 1) {
      const started = Date.now();
      const exit = await this.commandRunner.runVerificationCommand({ plan: {
        executable: step.command.executable,
        arguments: step.command.arguments,
        working_directory: workspace.path,
        environment: { inherited: ["PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG"], injected_secret_refs: [] },
        stdin: { mode: "closed" },
        output_protocol: { type: "text", version: 1 },
        timeouts: {
          startup_seconds: step.timeout_seconds,
          idle_seconds: step.timeout_seconds,
          tool_seconds: step.timeout_seconds,
          total_seconds: step.timeout_seconds,
          graceful_shutdown_seconds: Math.min(5, step.timeout_seconds),
        },
        output_limit_bytes: 10_000_000,
        prompt_hash: canonicalSha256({ verification_plan_id: step.id, workspace_id: workspace.workspace_id }),
      }, recovery_identity: recoveryIdentity });
      const stdout = safeRead(exit.stdout_path);
      const stderr = safeRead(exit.stderr_path);
      const passed = exit.exit_code === 0 && !exit.timed_out && !exit.failure_type;
      attempts.push({ exit, stdout, stderr, passed, duration: Date.now() - started });
      if (passed) break;
    }
    const last = attempts.at(-1)!;
    const first = attempts[0]!;
    const flaky = attempts.length === 2 && !first.passed && last.passed;
    const timedOut = !!last.exit.timed_out;
    const status = flaky ? "FLAKY_SUSPECTED" : last.passed ? "PASSED" : timedOut ? "TIMED_OUT" : "FAILED";
    return {
      id: step.id,
      type: step.type,
      required: step.required,
      status,
      attempts: attempts.length,
      exit_code: last.exit.exit_code,
      duration_ms: attempts.reduce((sum, attempt) => sum + attempt.duration, 0),
      artifact_paths: attempts.flatMap(attempt => [attempt.exit.stdout_path, attempt.exit.stderr_path]),
      signature: canonicalSha256(attempts.map(attempt => ({ exit_code: attempt.exit.exit_code, timed_out: attempt.exit.timed_out, stdout: attempt.stdout, stderr: attempt.stderr }))),
      failure_kind: flaky ? "FLAKY_SUSPECTED" : timedOut ? "TIMEOUT" : last.passed ? null : "DETERMINISTIC_FAILURE",
      findings: last.passed ? 0 : 1,
    };
  }

  private pathPolicy(
    step: PolicyVerificationStep,
    workspace: SealedWorkspaceInput,
  ): VerificationStepResult {
    const blocked = workspace.path_policy.decision === "BLOCK" || workspace.path_policy.denied.length > 0;
    return policyResult(step, blocked ? "BLOCKED" : "PASSED", blocked ? "PATH_POLICY_VIOLATION" : null, workspace.path_policy.denied.length, workspace.path_policy);
  }

  private secretScan(
    step: PolicyVerificationStep,
    workspace: SealedWorkspaceInput,
  ): VerificationStepResult {
    const findings: string[] = [];
    if (containsLikelyPhase1Secret(workspace.patch)) findings.push("patch:secret-pattern");
    for (const file of workspace.changed_files) {
      if (/(^|\/)(\.env(?:\.|$)|credentials?\.json$|service-account[^/]*\.json$)/i.test(file.path)) findings.push(`${file.path}:sensitive-path`);
      const path = safeWorkspaceFile(workspace.path, file.path);
      if (!path) { findings.push(`${file.path}:unsafe-path`); continue; }
      if (!existsSync(path)) continue;
      const stat = lstatSync(path);
      if (!stat.isFile()) { findings.push(`${file.path}:unscannable-type`); continue; }
      if (stat.size > 5_000_000) { findings.push(`${file.path}:unscannable-oversize`); continue; }
      const content = readFileSync(path, "utf8");
      if (containsLikelyPhase1Secret(content) || looksLikeJwt(content)) findings.push(`${file.path}:secret-pattern`);
    }
    return policyResult(step, findings.length > 0 ? "BLOCKED" : "PASSED", findings.length > 0 ? "SECRET_LEAK_DETECTED" : null, findings.length, findings);
  }

  private dependencyChange(
    step: PolicyVerificationStep,
    workspace: SealedWorkspaceInput,
  ): VerificationStepResult {
    const changed = workspace.changed_files.filter(file => file.dependency_file).map(file => file.path);
    const status = changed.length > 0 && step.required ? "BLOCKED" : "PASSED";
    return policyResult(step, status, changed.length > 0 ? "DEPENDENCY_CHANGE_DETECTED" : null, changed.length, changed);
  }
}

export interface VerificationCommandRequest {
  plan: RuntimeLaunchPlan;
  recovery_identity: ProcessRecoveryIdentity;
}

export interface VerificationCommandRunner {
  runVerificationCommand(request: VerificationCommandRequest): Promise<SupervisedProcessExit>;
}

export class InProcessVerificationCommandRunner implements VerificationCommandRunner {
  private readonly supervisor: LocalProcessSupervisor;
  constructor(options: { root: string }) {
    this.supervisor = new LocalProcessSupervisor({ root: options.root, maxLineBytes: 100_000, maxLiveBufferBytes: 1_000_000 });
  }
  async runVerificationCommand(request: VerificationCommandRequest): Promise<SupervisedProcessExit> {
    const ref = await this.supervisor.start(request.plan, {}, request.recovery_identity);
    this.supervisor.notifyStarted(ref.process_id);
    return this.supervisor.wait(ref.process_id);
  }
}

function policyResult(
  step: { id: string; type: "changed-path-policy" | "secret-scan" | "dependency-change"; required: boolean },
  status: "PASSED" | "BLOCKED",
  failureKind: VerificationStepResult["failure_kind"],
  findings: number,
  evidence: unknown,
): VerificationStepResult {
  return {
    id: step.id,
    type: step.type,
    required: step.required,
    status,
    attempts: 1,
    exit_code: null,
    duration_ms: 0,
    artifact_paths: [],
    signature: canonicalSha256(evidence),
    failure_kind: failureKind,
    findings,
  };
}

function safeRead(path: string): string { try { return readFileSync(path, "utf8").slice(-1_000_000); } catch { return ""; } }
function safeWorkspaceFile(root: string, repositoryPath: string): string | null {
  const candidate = resolve(root, ...repositoryPath.replaceAll("\\", "/").split("/"));
  const rel = relative(realpathSync(root), candidate);
  return !rel.startsWith("..") && !rel.includes("../") && !rel.includes("..\\") ? candidate : null;
}
function looksLikeJwt(content: string): boolean { return /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/.test(content); }
