import { createPublicKey, verify as verifyBytes } from "node:crypto";
import { readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { isAbsolute, join, relative, resolve, sep, win32 } from "node:path";
import { z } from "zod";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import type {
  RunnerReviewIdentityAttestation, RunnerReviewIdentityAuthority, RunnerReviewIdentityContent,
  RunnerReviewLaunchPolicy, RunnerVerificationCommandRequest, RunnerVerifiedCommandResult,
} from "../../phase2/runner/local-runner-host";
import { hashPortableReviewVerificationPlan } from "../../phase2/runner/local-runner-host";
import { ReadOnlyReviewEnvironment } from "./read-only-environment";

export type ReviewRunnerExit = Pick<
  RunnerVerifiedCommandResult,
  "process_id" | "exit_code" | "failure_type" | "timed_out" | "stdout_path" | "stderr_path" | "output_bytes" | "redaction_count" | "replayed"
> & Pick<RunnerVerifiedCommandResult, "review_attestation">;

export interface ReviewCommandRunner {
  runVerificationCommand(request: RunnerVerificationCommandRequest): Promise<ReviewRunnerExit>;
}

export interface ReviewIdentityAuthorityClient {
  getReviewIdentityAuthority(): Promise<RunnerReviewIdentityAuthority> | RunnerReviewIdentityAuthority;
  getReviewLaunchPolicy(policyId: string): Promise<RunnerReviewLaunchPolicy> | RunnerReviewLaunchPolicy;
}

export interface ReviewDockerSandbox {
  image: string;
  pids_limit?: number;
}

export interface ReviewIsolationAttestation {
  provider: "docker";
  image: string;
  image_digest: string;
  pull_policy: "never";
  network: "none";
  root_filesystem: "read-only";
  capabilities: "dropped-all";
  no_new_privileges: true;
  pids_limit: number;
  credentials: "not-mounted";
  working_directory: "/review/source";
  mounts: Array<{
    purpose: "source" | "evidence" | "artifacts" | "temp";
    host_path: string;
    container_path: "/review/source" | "/review/evidence" | "/review/artifacts" | "/review/temp";
    access: "read-only" | "read-write";
  }>;
}

interface ValidatedReviewDockerSandbox {
  image: string;
  image_digest: string;
  pids_limit: number;
}

const PINNED_IMAGE_PATTERN = /^[a-z0-9][a-z0-9._:/-]*@(?<digest>sha256:[a-f0-9]{64})$/;
const DEFAULT_PIDS_LIMIT = 128;

const executionInputSchema = z.object({
  review_execution_id: z.string().regex(/^review-execution:/),
  attempt_id: z.string().regex(/^attempt:/),
  environment_id: z.string().regex(/^review-environment:/),
  executable: z.string().trim().min(1).max(4_000),
  arguments: z.array(z.string().max(50_000)).max(1_024),
  context: z.record(z.string(), z.unknown()),
  prompt_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  inherited_environment: z.array(z.enum(["PATH", "Path", "SYSTEMROOT", "SystemRoot", "TEMP", "TMP"])).max(6),
  timeout_seconds: z.number().positive().max(3_600),
  output_limit_bytes: z.number().int().positive().max(10_000_000),
  launch_policy_id: z.string().regex(/^review-launch-policy:[a-f0-9]{32}$/),
  reviewer_identity: z.object({
    agent_id: z.string().startsWith("agent:"), provider: z.string().trim().min(1), model_class: z.string().trim().min(1),
    session_id: z.string().startsWith("session:"), context_id: z.string().startsWith("context:"),
  }).strict(),
}).strict();

export interface ReviewExecutionResult {
  status: "COMPLETED" | "FAILED";
  raw_output: string;
  stderr: string;
  exit: ReviewRunnerExit;
  isolation: ReviewIsolationAttestation;
  runtime_identity: {
    review_execution_id: string;
    reviewer: z.infer<typeof executionInputSchema>["reviewer_identity"];
    identity_source: "runner-authenticated-launch-binding";
    container_image_digest: string;
    command_hash: string;
    portable_command_hash: string;
    isolation_hash: string;
    launch_policy_id: string;
    output_hash: string;
    attested_by: "phase2-runner-host";
    runner_process_id: string;
    phase2_execution_id: string;
    attestation_hash: string;
    attestation_key_id: string;
    attestation_signature: string;
    attestation_algorithm: "Ed25519";
    attestation_public_key: string;
  };
}

export class RunnerReviewExecutor {
  private readonly runner: ReviewCommandRunner;
  private readonly environment: ReadOnlyReviewEnvironment;
  private readonly sandbox: ValidatedReviewDockerSandbox | null;
  private readonly identityAuthority: ReviewIdentityAuthorityClient;

  constructor(options: {
    runner: ReviewCommandRunner;
    environment: ReadOnlyReviewEnvironment;
    sandbox?: ReviewDockerSandbox;
    identity_authority: ReviewIdentityAuthorityClient;
  }) {
    this.runner = options.runner;
    this.environment = options.environment;
    this.sandbox = options.sandbox ? validateSandbox(options.sandbox) : null;
    this.identityAuthority = options.identity_authority;
  }

  async execute(input: z.input<typeof executionInputSchema>): Promise<ReviewExecutionResult> {
    const request = executionInputSchema.parse(input);
    const workspace = this.environment.get(request.environment_id);
    this.environment.assertIntegrity(request.environment_id);
    if (!this.sandbox) throw new Error("REVIEW_SANDBOX_REQUIRED");
    const isolation = createIsolationAttestation(workspace, this.sandbox);
    const reviewerCommand = [request.executable, ...request.arguments]
      .map(value => mapReviewerPath(value, workspace));
    if (canonicalSha256(request.context) !== request.prompt_hash) throw new Error("REVIEW_CONTEXT_PROMPT_HASH_MISMATCH");
    const contextPath = join(workspace.root, `context-${canonicalSha256(request.review_execution_id).slice(7, 39)}.json`);
    const renderedContext = JSON.stringify(request.context);
    writeFileSync(contextPath, renderedContext, { encoding: "utf8", flag: "wx" });
    const coordinatorIsolation = {
      mechanism: "docker" as const,
      network: "denied" as const,
      credentials: "unmounted" as const,
      source: "read-only" as const,
      image_digest: isolation.image_digest,
      attested_by: "runner-review-executor",
    };
    const phase2ExecutionId = `execution:review-${request.review_execution_id.slice("review-execution:".length)}`;
    const runnerPlan = {
      executable: "docker",
      arguments: dockerArguments(isolation, reviewerCommand),
      working_directory: workspace.source,
      environment: { inherited: request.inherited_environment, injected_secret_refs: [] },
      stdin: { mode: "file" as const, path: contextPath },
      output_protocol: { type: "text" as const, version: 1 as const },
      timeouts: {
        startup_seconds: Math.min(30, request.timeout_seconds), idle_seconds: request.timeout_seconds,
        tool_seconds: request.timeout_seconds, total_seconds: request.timeout_seconds, graceful_shutdown_seconds: 2,
      },
      output_limit_bytes: request.output_limit_bytes,
      prompt_hash: request.prompt_hash,
    };
    let exit: ReviewRunnerExit;
    try {
      exit = await this.runner.runVerificationCommand({
        plan: runnerPlan,
        recovery_identity: {
          execution_id: phase2ExecutionId,
          attempt_id: request.attempt_id,
          workspace_path: workspace.source,
        },
        review_attestation: {
          review_execution_id: request.review_execution_id,
          launch_policy_id: request.launch_policy_id,
          isolation_hash: canonicalSha256(coordinatorIsolation),
        },
      });
    } finally {
      try { unlinkSync(contextPath); } catch { /* the private control-plane copy is single-use */ }
      this.environment.assertIntegrity(request.environment_id);
    }
    const rawOutput = readFileSync(exit.stdout_path, "utf8");
    const stderr = readFileSync(exit.stderr_path, "utf8");
    const outputHash = canonicalSha256(rawOutput);
    const authority = await this.identityAuthority.getReviewIdentityAuthority();
    const atomic = exit.review_attestation;
    if (!atomic) throw new Error("REVIEW_RUNNER_ATOMIC_ATTESTATION_REQUIRED");
    const runtimeIdentityContent: RunnerReviewIdentityContent = stripSignature(atomic);
    const signed = stripContent(atomic);
    if (!verifyRunnerIdentityAttestation(signed, authority, canonicalSha256(runtimeIdentityContent))) {
      throw new Error("REVIEW_RUNNER_IDENTITY_ATTESTATION_INVALID");
    }
    if (runtimeIdentityContent.review_execution_id !== request.review_execution_id
      || runtimeIdentityContent.phase2_execution_id !== phase2ExecutionId
      || runtimeIdentityContent.runner_process_id !== exit.process_id
      || runtimeIdentityContent.container_image_digest !== isolation.image_digest
      || (!exit.replayed && runtimeIdentityContent.command_hash !== canonicalSha256(runnerPlan))
      || runtimeIdentityContent.portable_command_hash !== hashPortableReviewVerificationPlan(runnerPlan)
      || runtimeIdentityContent.isolation_hash !== canonicalSha256(coordinatorIsolation)
      || runtimeIdentityContent.launch_policy_id !== request.launch_policy_id
      || runtimeIdentityContent.output_hash !== outputHash) throw new Error("REVIEW_RUNNER_ATTESTED_RESULT_MISMATCH");
    return {
      status: exit.exit_code === 0 && exit.failure_type === null && exit.timed_out === null ? "COMPLETED" : "FAILED",
      raw_output: rawOutput,
      stderr,
      exit,
      isolation,
      runtime_identity: {
        ...runtimeIdentityContent,
        attestation_hash: signed.content_hash,
        attestation_key_id: signed.key_id,
        attestation_signature: signed.signature,
        attestation_algorithm: signed.algorithm,
        attestation_public_key: signed.public_key_spki,
      },
    };
  }
}

function stripSignature(input: RunnerReviewIdentityContent & RunnerReviewIdentityAttestation): RunnerReviewIdentityContent {
  const { algorithm: ignoredAlgorithm, key_id: ignoredKey, public_key_spki: ignoredPublicKey, content_hash: ignoredHash, signature: ignoredSignature, ...content } = input;
  return content;
}

function stripContent(input: RunnerReviewIdentityContent & RunnerReviewIdentityAttestation): RunnerReviewIdentityAttestation {
  return {
    algorithm: input.algorithm, key_id: input.key_id, public_key_spki: input.public_key_spki,
    content_hash: input.content_hash, signature: input.signature,
  };
}

export function createReviewLaunchPolicyId(input: { docker_image: string; executable: string; arguments: readonly string[] }): string {
  const image = validateSandbox({ image: input.docker_image });
  const executable = z.string().trim().min(1).max(4_000).parse(input.executable);
  const arguments_ = z.array(z.string().max(50_000)).max(1_024).parse(input.arguments);
  return `review-launch-policy:${canonicalSha256({ image: image.image, executable, arguments: arguments_ }).slice(7, 39)}`;
}

export function verifyRunnerIdentityAttestation(
  input: RunnerReviewIdentityAttestation | {
    attestation_hash: string; attestation_key_id: string; attestation_signature: string;
    attestation_algorithm: "Ed25519"; attestation_public_key: string;
  },
  trustedAuthority: RunnerReviewIdentityAuthority,
  expectedContentHash?: string,
): boolean {
  const normalized = "content_hash" in input ? {
    contentHash: input.content_hash, keyId: input.key_id, signature: input.signature,
    algorithm: input.algorithm, publicKey: input.public_key_spki,
  } : {
    contentHash: input.attestation_hash, keyId: input.attestation_key_id, signature: input.attestation_signature,
    algorithm: input.attestation_algorithm, publicKey: input.attestation_public_key,
  };
  if (normalized.algorithm !== "Ed25519" || normalized.keyId !== trustedAuthority.key_id
    || normalized.publicKey !== trustedAuthority.public_key_spki || (expectedContentHash && normalized.contentHash !== expectedContentHash)) return false;
  try {
    const publicKey = createPublicKey({ key: Buffer.from(normalized.publicKey, "base64url"), type: "spki", format: "der" });
    return verifyBytes(null, Buffer.from(normalized.contentHash, "utf8"), publicKey, Buffer.from(normalized.signature, "base64url"));
  } catch { return false; }
}

function validateSandbox(input: ReviewDockerSandbox): ValidatedReviewDockerSandbox {
  const match = PINNED_IMAGE_PATTERN.exec(input.image);
  if (!match?.groups?.digest) throw new Error("REVIEW_SANDBOX_IMAGE_MUST_BE_PINNED");
  const pidsLimit = input.pids_limit ?? DEFAULT_PIDS_LIMIT;
  if (!Number.isInteger(pidsLimit) || pidsLimit < 1 || pidsLimit > 4_096) {
    throw new Error("REVIEW_SANDBOX_PIDS_LIMIT_INVALID");
  }
  return { image: input.image, image_digest: match.groups.digest, pids_limit: pidsLimit };
}

function createIsolationAttestation(
  workspace: ReturnType<ReadOnlyReviewEnvironment["get"]>,
  sandbox: ValidatedReviewDockerSandbox,
): ReviewIsolationAttestation {
  const mounts = [
    mount(workspace, "source", "/review/source", "read-only"),
    mount(workspace, "evidence", "/review/evidence", "read-only"),
    mount(workspace, "artifacts", "/review/artifacts", "read-only"),
    mount(workspace, "temp", "/review/temp", "read-write"),
  ];
  return {
    provider: "docker",
    image: sandbox.image,
    image_digest: sandbox.image_digest,
    pull_policy: "never",
    network: "none",
    root_filesystem: "read-only",
    capabilities: "dropped-all",
    no_new_privileges: true,
    pids_limit: sandbox.pids_limit,
    credentials: "not-mounted",
    working_directory: "/review/source",
    mounts,
  };
}

function mount(
  workspace: ReturnType<ReadOnlyReviewEnvironment["get"]>,
  purpose: "source" | "evidence" | "artifacts" | "temp",
  containerPath: ReviewIsolationAttestation["mounts"][number]["container_path"],
  access: "read-only" | "read-write",
): ReviewIsolationAttestation["mounts"][number] {
  const hostPath = resolve(workspace[purpose]);
  if (!isWithin(resolve(workspace.root), hostPath) || /[\r\n,]/.test(hostPath)) {
    throw new Error("REVIEW_SANDBOX_HOST_PATH_OUTSIDE_PREPARED_ROOTS");
  }
  return { purpose, host_path: hostPath, container_path: containerPath, access };
}

function dockerArguments(attestation: ReviewIsolationAttestation, reviewerCommand: string[]): string[] {
  const arguments_: string[] = [
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
    String(attestation.pids_limit),
  ];
  for (const item of attestation.mounts) {
    arguments_.push(
      "--mount",
      `type=bind,src=${item.host_path},dst=${item.container_path}${item.access === "read-only" ? ",readonly" : ""}`,
    );
  }
  arguments_.push("--workdir", attestation.working_directory, attestation.image, ...reviewerCommand);
  return arguments_;
}

function mapReviewerPath(
  value: string,
  workspace: ReturnType<ReadOnlyReviewEnvironment["get"]>,
): string {
  if (value.includes("\0")) throw new Error("REVIEW_SANDBOX_COMMAND_PATH_INVALID");
  const optionValue = value.match(/^(--?[A-Za-z0-9][A-Za-z0-9._-]*)=(.+)$/);
  if (optionValue && isHostAbsolute(optionValue[2]!)) {
    return `${optionValue[1]}=${mapAbsoluteHostPath(optionValue[2]!, workspace)}`;
  }
  if (isHostAbsolute(value)) return mapAbsoluteHostPath(value, workspace);
  if (/^[A-Za-z]:/.test(value) || value.split(/[\\/]/).includes("..")) {
    throw new Error("REVIEW_SANDBOX_COMMAND_PATH_INVALID");
  }
  return value;
}

function mapAbsoluteHostPath(
  value: string,
  workspace: ReturnType<ReadOnlyReviewEnvironment["get"]>,
): string {
  const candidate = resolve(value);
  const mappings: Array<[string, ReviewIsolationAttestation["mounts"][number]["container_path"]]> = [
    [workspace.source, "/review/source"],
    [workspace.evidence, "/review/evidence"],
    [workspace.artifacts, "/review/artifacts"],
    [workspace.temp, "/review/temp"],
  ];
  for (const [root, containerRoot] of mappings) {
    const resolvedRoot = resolve(root);
    if (!isWithin(resolvedRoot, candidate)) continue;
    const suffix = relative(resolvedRoot, candidate).split(sep).join("/");
    return suffix ? `${containerRoot}/${suffix}` : containerRoot;
  }
  throw new Error("REVIEW_SANDBOX_HOST_PATH_OUTSIDE_PREPARED_ROOTS");
}

function isHostAbsolute(value: string): boolean {
  return isAbsolute(value) || win32.isAbsolute(value);
}

function isWithin(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path === "" || (!path.startsWith(`..${sep}`) && path !== ".." && !isAbsolute(path));
}
