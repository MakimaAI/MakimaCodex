import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign as signBytes, verify as verifyBytes, type KeyObject } from "node:crypto";
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync, writeSync } from "node:fs";
import { join, resolve } from "node:path";
import { z } from "zod";
import { runtimeLaunchPlanSchema, type RuntimeAdapter, type RuntimeExecutionRequest, type NormalizedRuntimeEvent, type ClassifiedRuntimeExit } from "../runtime/protocol";
import { LocalProcessSupervisor, type SupervisedProcessExit, type SupervisedProcessRef } from "./process-supervisor";
import type { ProcessRecoveryIdentity } from "./process-identity";
import { RunnerEventSpool } from "./event-spool";
import { RunnerLeaseStore, type RunnerLease } from "./lease-store";
import { RunnerKillSwitchStore, type KillSwitchState } from "./kill-switch";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { hardenSecretPath, inspectSecretPathAcl } from "../../../lib/windows-secret-acl";

export interface RunnerExecutionRequest {
  adapter_id: string;
  runtime_request: RuntimeExecutionRequest;
}

export interface RunnerCapabilities {
  protocol_version: 1;
  local: true;
  durable_spool: true;
  cancellation: true;
  verification_commands: true;
}

const runnerVerificationCommandRequestSchema = z.object({
  plan: runtimeLaunchPlanSchema,
  recovery_identity: z.object({
    execution_id: z.string().regex(/^execution:/),
    attempt_id: z.string().regex(/^attempt:/),
    workspace_path: z.string().trim().min(1).max(4_000),
  }).strict(),
  review_attestation: z.object({
    review_execution_id: z.string().regex(/^review-execution:/),
    launch_policy_id: z.string().regex(/^review-launch-policy:[a-f0-9]{32}$/),
    isolation_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  }).strict().optional(),
}).strict();

export interface RunnerVerificationCommandRequest {
  plan: z.infer<typeof runnerVerificationCommandRequestSchema>["plan"];
  recovery_identity: ProcessRecoveryIdentity;
  review_attestation?: z.infer<typeof runnerVerificationCommandRequestSchema>["review_attestation"];
}

export interface RunnerReviewLaunchPolicy {
  launch_policy_id: string;
  reviewer: {
    agent_id: string; provider: string; model_class: string; session_id: string; context_id: string;
  };
}

const runnerReviewLaunchPolicySchema = z.object({
  launch_policy_id: z.string().regex(/^review-launch-policy:[a-f0-9]{32}$/),
  reviewer: z.object({
    agent_id: z.string().startsWith("agent:"), provider: z.string().trim().min(1), model_class: z.string().trim().min(1),
    session_id: z.string().startsWith("session:"), context_id: z.string().startsWith("context:"),
  }).strict(),
}).strict();

export interface RunnerReviewIdentityAuthority {
  algorithm: "Ed25519";
  key_id: string;
  public_key_spki: string;
}

export interface RunnerReviewIdentityAttestation extends RunnerReviewIdentityAuthority {
  content_hash: string;
  signature: string;
}

export const runnerReviewIdentityContentSchema = z.object({
  review_execution_id: z.string().regex(/^review-execution:/),
  phase2_execution_id: z.string().regex(/^execution:review-/),
  runner_process_id: z.string().regex(/^supervised-process:/),
  reviewer: z.object({
    agent_id: z.string().startsWith("agent:"), provider: z.string().trim().min(1), model_class: z.string().trim().min(1),
    session_id: z.string().startsWith("session:"), context_id: z.string().startsWith("context:"),
  }).strict(),
  identity_source: z.literal("runner-authenticated-launch-binding"),
  container_image_digest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  command_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  portable_command_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  isolation_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  launch_policy_id: z.string().regex(/^review-launch-policy:[a-f0-9]{32}$/),
  output_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  attested_by: z.literal("phase2-runner-host"),
}).strict();
export type RunnerReviewIdentityContent = z.infer<typeof runnerReviewIdentityContentSchema>;

export interface RunnerVerifiedCommandResult extends SupervisedProcessExit {
  review_attestation?: RunnerReviewIdentityContent & RunnerReviewIdentityAttestation;
  replayed?: boolean;
}

export interface RunnerExecutionStatus {
  execution_id: string;
  attempt_id: string;
  workspace_path: string;
  status: "STARTING" | "RUNNING" | "CANCELLING" | "EXITED" | "INTERRUPTED";
  process_id: string;
  process_identity: SupervisedProcessRef["identity"];
  lease: RunnerLease;
  event_integrity: { complete: boolean; next_expected_sequence: number; missing_sequences: number[] };
  exit: (SupervisedProcessExit & { classification: ClassifiedRuntimeExit }) | null;
}

interface ActiveExecution {
  adapter: RuntimeAdapter;
  status: RunnerExecutionStatus;
  heartbeat: ReturnType<typeof setInterval>;
  completion: Promise<void>;
}

interface Admission {
  generation: number;
  end(): void;
}

export class LocalRunnerHost {
  readonly killSwitch: RunnerKillSwitchStore;
  private readonly root: string;
  private readonly runnerId: string;
  private readonly nonce: string;
  private readonly adapters: ReadonlyMap<string, RuntimeAdapter>;
  private readonly supervisor: LocalProcessSupervisor;
  private readonly spool: RunnerEventSpool;
  private readonly leases: RunnerLeaseStore;
  private readonly heartbeatIntervalMs: number;
  private readonly leaseTtlMs: number;
  private readonly admissionTimeoutMs: number;
  private readonly active = new Map<string, ActiveExecution>();
  private admissions = 0;
  private admissionWaiters: Array<() => void> = [];
  private controlGeneration = 0;
  private degraded = false;
  private closing = false;
  private readonly reviewIdentityPrivateKey: KeyObject;
  private readonly reviewIdentityAuthority: RunnerReviewIdentityAuthority;
  private readonly reviewLaunchPolicies = new Map<string, RunnerReviewLaunchPolicy>();
  private readonly reviewVerificationsInFlight = new Map<string, { recovery_key: string; promise: Promise<RunnerVerifiedCommandResult> }>();

  constructor(options: {
    root: string;
    runner_id: string;
    adapters: readonly RuntimeAdapter[];
    supervisor: LocalProcessSupervisor;
    heartbeat_interval_ms?: number;
    lease_ttl_ms?: number;
    admission_timeout_ms?: number;
    review_launch_policies?: readonly RunnerReviewLaunchPolicy[];
  }) {
    this.root = options.root;
    this.runnerId = options.runner_id;
    this.nonce = randomBytes(16).toString("hex");
    const stateRoot = join(this.root, "state");
    mkdirSync(stateRoot, { recursive: true });
    const identityKeys = loadOrCreateReviewIdentityKey(join(stateRoot, "review-identity-key.pem"));
    this.reviewIdentityPrivateKey = identityKeys.privateKey;
    const publicKey = identityKeys.publicKeySpki;
    this.reviewIdentityAuthority = { algorithm: "Ed25519", key_id: canonicalSha256(publicKey), public_key_spki: publicKey };
    for (const policy of options.review_launch_policies ?? []) this.registerReviewLaunchPolicy(policy);
    this.adapters = new Map(options.adapters.map(adapter => [adapter.manifest.adapter.id, adapter]));
    this.supervisor = options.supervisor;
    this.heartbeatIntervalMs = options.heartbeat_interval_ms ?? 10_000;
    this.leaseTtlMs = options.lease_ttl_ms ?? 30_000;
    this.admissionTimeoutMs = options.admission_timeout_ms ?? 5_000;
    if (this.heartbeatIntervalMs <= 0 || this.leaseTtlMs <= this.heartbeatIntervalMs) throw new Error("Runner lease TTL must exceed heartbeat interval");
    if (this.admissionTimeoutMs <= 0) throw new Error("Runner admission timeout must be positive");
    mkdirSync(this.root, { recursive: true });
    this.spool = new RunnerEventSpool({ root: join(this.root, "events") });
    this.leases = new RunnerLeaseStore({ root: join(this.root, "leases") });
    this.killSwitch = new RunnerKillSwitchStore({ root: join(this.root, "kill-switch"), actor: this.runnerId });
  }

  private registerReviewLaunchPolicy(policyInput: RunnerReviewLaunchPolicy): RunnerReviewLaunchPolicy {
    const policy = runnerReviewLaunchPolicySchema.parse(policyInput);
    const existing = this.reviewLaunchPolicies.get(policy.launch_policy_id);
    if (existing && canonicalSha256(existing) !== canonicalSha256(policy)) throw new Error("RUNNER_REVIEW_LAUNCH_POLICY_CONFLICT");
    if (!existing) this.reviewLaunchPolicies.set(policy.launch_policy_id, Object.freeze(policy));
    return { ...policy, reviewer: { ...policy.reviewer } };
  }

  getReviewLaunchPolicy(policyId: string): RunnerReviewLaunchPolicy {
    const policy = this.reviewLaunchPolicies.get(policyId);
    if (!policy) throw new Error("RUNNER_REVIEW_LAUNCH_POLICY_NOT_FOUND");
    return { ...policy, reviewer: { ...policy.reviewer } };
  }

  async startExecution(request: RunnerExecutionRequest): Promise<RunnerLease> {
    const admission = this.beginAdmission();
    try { return await this.startExecutionAdmitted(request, admission.generation); }
    finally { admission.end(); }
  }

  private async startExecutionAdmitted(request: RunnerExecutionRequest, generation: number): Promise<RunnerLease> {
    this.assertAdmission(generation);
    const adapter = this.adapters.get(request.adapter_id);
    if (!adapter) throw new Error(`RUNTIME_ADAPTER_NOT_FOUND: ${request.adapter_id}`);
    const executionId = request.runtime_request.execution_id;
    const existing = this.active.get(executionId);
    if (existing) {
      if (existing.status.status !== "EXITED" && existing.status.status !== "INTERRUPTED") throw new Error("EXECUTION_ALREADY_RUNNING");
      clearInterval(existing.heartbeat);
      this.active.delete(executionId);
    }
    const acquired = this.leases.acquire({
      execution_id: executionId,
      runner_id: this.runnerId,
      runner_instance_nonce: this.nonce,
      ttl_ms: this.leaseTtlMs,
    });
    if (!acquired.ok) throw new Error("RUNNER_LEASE_HELD");
    const pendingEvents: Array<{ process_id: string; event: NormalizedRuntimeEvent }> = [];
    let processRef: SupervisedProcessRef;
    try {
      const plan = await adapter.prepareLaunch(request.runtime_request);
      this.assertAdmission(generation);
      processRef = await this.supervisor.start(plan, {
        onOutput: async chunk => {
          const events = await adapter.parseEvent({
            stream: chunk.stream,
            chunk: chunk.text,
            execution_id: executionId,
            attempt_id: request.runtime_request.attempt_id,
            received_at: chunk.received_at,
          });
          for (const event of events) {
            if (this.active.has(executionId)) this.acceptEvent(chunk.process_id, event);
            else pendingEvents.push({ process_id: chunk.process_id, event });
          }
        },
      }, {
        execution_id: executionId,
        attempt_id: request.runtime_request.attempt_id,
        workspace_path: request.runtime_request.workspace_path,
      });
      try { this.assertAdmission(generation); }
      catch (error) {
        await this.supervisor.cancel(processRef.process_id, "revoked execution admission");
        await this.supervisor.waitForTermination(processRef.process_id);
        throw error;
      }
    } catch (error) {
      this.leases.release(executionId, this.nonce);
      if (error instanceof Error && error.message.includes("PROCESS_START_CLEANUP_UNCONFIRMED")) {
        this.enterDegraded("unconfirmed process start cleanup");
        try { await this.supervisor.killAll("unconfirmed process start cleanup"); } catch { /* degraded and fail closed */ }
      }
      if (error instanceof Error && error.message.includes("PROCESS_START_REVOKED")
        && generation !== this.controlGeneration) {
        throw new Error("RUNNER_ADMISSION_REVOKED", { cause: error });
      }
      throw error;
    }
    const status: RunnerExecutionStatus = {
      execution_id: executionId,
      attempt_id: request.runtime_request.attempt_id,
      workspace_path: request.runtime_request.workspace_path,
      status: "STARTING",
      process_id: processRef.process_id,
      process_identity: processRef.identity,
      lease: acquired.lease,
      event_integrity: { complete: true, next_expected_sequence: 1, missing_sequences: [] },
      exit: null,
    };
    const heartbeat = setInterval(() => {
      const active = this.active.get(executionId);
      if (!active || active.status.status === "EXITED") return;
      try {
        active.status.lease = this.leases.heartbeat(executionId, this.nonce, this.leaseTtlMs);
        this.persist(active.status);
      } catch {
        this.enterDegraded("runner heartbeat failure");
        active.status.status = "INTERRUPTED";
        clearInterval(active.heartbeat);
        void this.containAfterFailure(active.status.process_id, "runner heartbeat failure");
        try { active.status.lease = this.leases.release(executionId, this.nonce); } catch { /* containment is independent of lease storage */ }
        try { this.persist(active.status); } catch { /* in-memory degradation still blocks admissions */ }
      }
    }, this.heartbeatIntervalMs);
    heartbeat.unref?.();
    const active: ActiveExecution = { adapter, status, heartbeat, completion: Promise.resolve() };
    this.active.set(executionId, active);
    active.completion = this.monitor(executionId);
    try {
      for (const pending of pendingEvents) this.acceptEvent(pending.process_id, pending.event);
      this.persist(status);
      return acquired.lease;
    } catch (error) {
      try { await this.cancelExecution(executionId); }
      catch { await this.supervisor.killAll("execution start rollback"); }
      if (!await settlesWithin(active.completion, 5_000)) throw new Error("RUNNER_COMPLETION_BARRIER_TIMEOUT", { cause: error });
      throw error;
    }
  }

  async runVerificationCommand(requestInput: RunnerVerificationCommandRequest): Promise<RunnerVerifiedCommandResult> {
    const request = runnerVerificationCommandRequestSchema.parse(requestInput);
    if (resolve(request.plan.working_directory) !== resolve(request.recovery_identity.workspace_path)) {
      throw new Error("VERIFIER_RECOVERY_WORKSPACE_MISMATCH");
    }
    const reviewContextStdin = request.review_attestation ? readAndValidateReviewContextStdin(request.plan) : undefined;
    const recoveryKey = request.review_attestation ? reviewVerificationRecoveryKey(request) : null;
    if (recoveryKey) {
      const recovered = this.readReviewVerificationReceipt(request, recoveryKey);
      if (recovered) return recovered;
    }
    if (!recoveryKey) return this.executeVerificationCommand(request, null, reviewContextStdin);
    const executionId = request.recovery_identity.execution_id;
    const existing = this.reviewVerificationsInFlight.get(executionId);
    if (existing) {
      if (existing.recovery_key !== recoveryKey) throw new Error("RUNNER_REVIEW_RECOVERY_BINDING_CONFLICT");
      return existing.promise;
    }
    const promise = this.executeVerificationCommand(request, recoveryKey, reviewContextStdin);
    this.reviewVerificationsInFlight.set(executionId, { recovery_key: recoveryKey, promise });
    try { return await promise; }
    finally {
      if (this.reviewVerificationsInFlight.get(executionId)?.promise === promise) this.reviewVerificationsInFlight.delete(executionId);
    }
  }

  private async executeVerificationCommand(
    request: z.infer<typeof runnerVerificationCommandRequestSchema>,
    recoveryKey: string | null,
    reviewContextStdin?: Uint8Array,
  ): Promise<RunnerVerifiedCommandResult> {
    const admission = this.beginAdmission();
    let ref: SupervisedProcessRef;
    try {
      this.assertAdmission(admission.generation);
      ref = await this.supervisor.start(request.plan, {}, request.recovery_identity, { stdin_bytes: reviewContextStdin });
      try {
        this.assertAdmission(admission.generation);
        this.supervisor.notifyStarted(ref.process_id);
      }
      catch (error) {
        await this.supervisor.cancel(ref.process_id, "verification admission rollback");
        await this.supervisor.waitForTermination(ref.process_id);
        throw error;
      }
    } catch (error) {
      if (error instanceof Error && error.message.includes("PROCESS_START_CLEANUP_UNCONFIRMED")) {
        this.enterDegraded("unconfirmed verifier start cleanup");
        try { await this.supervisor.killAll("unconfirmed verifier start cleanup"); } catch { /* degraded and fail closed */ }
      }
      if (error instanceof Error && error.message.includes("PROCESS_START_REVOKED")
        && admission.generation !== this.controlGeneration) {
        throw new Error("RUNNER_ADMISSION_REVOKED", { cause: error });
      }
      throw error;
    } finally {
      admission.end();
    }
    const exit = await this.supervisor.wait(ref.process_id);
    const outputHash = canonicalSha256(readFileSync(exit.stdout_path, "utf8"));
    if (!request.review_attestation) return exit;
    const policyId = request.review_attestation.launch_policy_id;
    const policy = this.getReviewLaunchPolicy(policyId);
    const imageDigest = deriveContainerImageDigest(request.plan);
    const content = runnerReviewIdentityContentSchema.parse({
      review_execution_id: request.review_attestation.review_execution_id,
      phase2_execution_id: request.recovery_identity.execution_id,
      runner_process_id: exit.process_id,
      reviewer: policy.reviewer,
      identity_source: "runner-authenticated-launch-binding",
      container_image_digest: imageDigest,
      command_hash: canonicalSha256(request.plan),
      portable_command_hash: hashPortableReviewVerificationPlan(request.plan),
      isolation_hash: request.review_attestation.isolation_hash,
      launch_policy_id: policy.launch_policy_id,
      output_hash: outputHash,
      attested_by: "phase2-runner-host",
    });
    const signed = this.signReviewIdentity(content);
    const result: RunnerVerifiedCommandResult = { ...exit, review_attestation: { ...content, ...signed } };
    const receiptContent = { schema_version: 1, recovery_key: recoveryKey!, result };
    atomicWriteJson(this.reviewVerificationReceiptPath(request.recovery_identity.execution_id), {
      ...receiptContent,
      receipt_attestation: this.signContentHash(canonicalSha256(receiptContent)),
    });
    return result;
  }

  getReviewIdentityAuthority(): RunnerReviewIdentityAuthority { return { ...this.reviewIdentityAuthority }; }

  private signReviewIdentity(content: RunnerReviewIdentityContent): RunnerReviewIdentityAttestation {
    return this.signContentHash(canonicalSha256(content));
  }

  private signContentHash(contentHash: string): RunnerReviewIdentityAttestation {
    return {
      ...this.reviewIdentityAuthority,
      content_hash: contentHash,
      signature: signBytes(null, Buffer.from(contentHash, "utf8"), this.reviewIdentityPrivateKey).toString("base64url"),
    };
  }

  private reviewVerificationReceiptPath(executionId: string): string {
    return join(this.root, "state", `review-result-${createHash("sha256").update(executionId).digest("hex")}.json`);
  }

  private readReviewVerificationReceipt(request: z.infer<typeof runnerVerificationCommandRequestSchema>, recoveryKey: string): RunnerVerifiedCommandResult | null {
    const path = this.reviewVerificationReceiptPath(request.recovery_identity.execution_id);
    if (!existsSync(path)) return null;
    const receipt = JSON.parse(readFileSync(path, "utf8")) as {
      schema_version?: unknown; recovery_key?: unknown; result?: RunnerVerifiedCommandResult; receipt_attestation?: RunnerReviewIdentityAttestation;
    };
    if (receipt.schema_version !== 1 || receipt.recovery_key !== recoveryKey || !receipt.result?.review_attestation || !receipt.receipt_attestation) {
      throw new Error("RUNNER_REVIEW_RECEIPT_BINDING_INVALID");
    }
    const receiptContent = { schema_version: 1, recovery_key: receipt.recovery_key, result: receipt.result };
    if (!this.verifyContentHash(canonicalSha256(receiptContent), receipt.receipt_attestation)) throw new Error("RUNNER_REVIEW_RECEIPT_SIGNATURE_INVALID");
    const attestation = receipt.result.review_attestation;
    const {
      algorithm: ignoredAlgorithm,
      key_id: ignoredKey,
      public_key_spki: ignoredPublicKey,
      content_hash: ignoredContentHash,
      signature: ignoredSignature,
      ...unsignedContent
    } = attestation;
    const attestedContent = runnerReviewIdentityContentSchema.parse(unsignedContent);
    if (!this.verifyContentHash(canonicalSha256(attestedContent), attestation)
      || attestedContent.phase2_execution_id !== request.recovery_identity.execution_id
      || attestedContent.review_execution_id !== request.review_attestation!.review_execution_id
      || attestedContent.launch_policy_id !== request.review_attestation!.launch_policy_id
      || attestedContent.isolation_hash !== request.review_attestation!.isolation_hash
      || attestedContent.container_image_digest !== deriveContainerImageDigest(request.plan)
      || !existsSync(receipt.result.stdout_path)
      || canonicalSha256(readFileSync(receipt.result.stdout_path, "utf8")) !== attestedContent.output_hash) {
      throw new Error("RUNNER_REVIEW_RECEIPT_INTEGRITY_INVALID");
    }
    return { ...receipt.result, replayed: true };
  }

  private verifyContentHash(contentHash: string, attestation: RunnerReviewIdentityAttestation): boolean {
    if (attestation.algorithm !== this.reviewIdentityAuthority.algorithm
      || attestation.key_id !== this.reviewIdentityAuthority.key_id
      || attestation.public_key_spki !== this.reviewIdentityAuthority.public_key_spki
      || attestation.content_hash !== contentHash) return false;
    try {
      const publicKey = createPublicKey({ key: Buffer.from(attestation.public_key_spki, "base64url"), type: "spki", format: "der" });
      return verifyBytes(null, Buffer.from(contentHash, "utf8"), publicKey, Buffer.from(attestation.signature, "base64url"));
    } catch { return false; }
  }

  async *streamEvents(executionId: string, fromSequence = 1): AsyncIterable<NormalizedRuntimeEvent> {
    let next = fromSequence;
    while (true) {
      const events = this.spool.read(executionId, next);
      for (const event of events) { yield event; next = Math.max(next, event.sequence + 1); }
      const status = await this.getStatus(executionId);
      if (status.status === "EXITED" || status.status === "INTERRUPTED") return;
      await new Promise(resolve => setTimeout(resolve, 20));
    }
  }

  async readEventSnapshot(executionId: string, fromSequence = 1): Promise<{
    events: NormalizedRuntimeEvent[];
    terminal: boolean;
    status: RunnerExecutionStatus["status"];
  }> {
    const status = await this.getStatus(executionId);
    return {
      events: this.spool.read(executionId, fromSequence),
      terminal: status.status === "EXITED" || status.status === "INTERRUPTED",
      status: status.status,
    };
  }

  async getStatus(executionId: string): Promise<RunnerExecutionStatus> {
    return this.active.get(executionId)?.status ?? this.readState(executionId);
  }

  async cancelExecution(executionId: string): Promise<void> {
    const active = this.active.get(executionId);
    if (!active) {
      const state = this.readState(executionId);
      if (state.status === "EXITED") return;
      throw new Error("RUNNER_EXECUTION_NOT_ATTACHED");
    }
    if (active.status.status === "EXITED") return;
    const preserveInterrupted = active.status.status === "INTERRUPTED";
    if (!preserveInterrupted && active.status.status !== "CANCELLING") {
      active.status.status = "CANCELLING";
      this.persist(active.status);
    }
    try {
      await this.supervisor.cancel(active.status.process_id, "runner cancellation");
      await this.supervisor.waitForTermination(active.status.process_id);
      if (!preserveInterrupted && !await settlesWithin(active.completion, 5_000)) {
        throw new Error("RUNNER_COMPLETION_BARRIER_TIMEOUT");
      }
      if (preserveInterrupted) {
        try { active.status.lease = this.leases.release(executionId, this.nonce); } catch { /* may already be released or unavailable */ }
        this.persist(active.status);
      }
    } catch (error) {
      this.enterDegraded("runner cancellation unconfirmed");
      try { await this.supervisor.killAll("runner cancellation unconfirmed"); } catch { /* preserve the original barrier failure */ }
      throw new Error("RUNNER_CANCELLATION_UNCONFIRMED", { cause: error });
    }
  }

  async collectArtifacts(executionId: string): Promise<{ stdout_path: string; stderr_path: string; event_count: number }> {
    const status = await this.getStatus(executionId);
    if (!status.exit) throw new Error("RUNNER_ARTIFACTS_NOT_READY");
    return { stdout_path: status.exit.stdout_path, stderr_path: status.exit.stderr_path, event_count: this.spool.read(executionId, 1).length };
  }

  async applyControlState(state: KillSwitchState, reason: string): Promise<ReturnType<RunnerKillSwitchStore["current"]>> {
    if (this.closing) throw new Error("RUNNER_HOST_CLOSING");
    if (this.degraded && state === "RUNNING") throw new Error("RUNNER_HOST_DEGRADED");
    if (state !== "RUNNING") this.controlGeneration += 1;
    let controlWriteError: unknown = null;
    try { this.killSwitch.set(state, reason); }
    catch (error) {
      controlWriteError = error;
      if (state === "CANCEL_ALL" || state === "CANCEL_RUNNING_LOW_RISK") this.enterDegraded("kill switch persistence failure");
      else throw error;
    }
    if (state === "CANCEL_ALL" || state === "CANCEL_RUNNING_LOW_RISK") {
      let terminationError: unknown = controlWriteError;
      try { await this.terminateKnownWork(reason); } catch (error) { terminationError = error; }
      const admissionsSettled = await settlesWithin(this.waitForAdmissions(), this.admissionTimeoutMs);
      try { await this.terminateKnownWork(`${reason} (post-admission barrier)`); }
      catch (error) { terminationError ??= error; }
      if (!admissionsSettled) {
        this.enterDegraded("runner admission barrier timeout");
        throw new Error("RUNNER_ADMISSION_BARRIER_TIMEOUT", { cause: terminationError ?? undefined });
      }
      if (terminationError) {
        this.enterDegraded("runner cancellation barrier failure");
        throw new Error("RUNNER_CANCELLATION_UNCONFIRMED", { cause: terminationError });
      }
    }
    return this.killSwitch.current();
  }

  listExecutionStatuses(): RunnerExecutionStatus[] {
    return [...this.active.values()].map(execution => execution.status);
  }

  async close(): Promise<void> {
    this.closing = true;
    this.controlGeneration += 1;
    let terminationError: unknown = null;
    try { this.killSwitch.set("CANCEL_ALL", "runner host shutdown"); }
    catch (error) {
      terminationError = error;
      this.enterDegraded("runner shutdown kill switch persistence failure");
    }
    try { await this.terminateKnownWork("runner host shutdown"); } catch (error) { terminationError = error; }
    const admissionsSettled = await settlesWithin(this.waitForAdmissions(), this.admissionTimeoutMs);
    try { await this.terminateKnownWork("runner host shutdown (post-admission barrier)"); }
    catch (error) { terminationError ??= error; }
    if (!admissionsSettled) {
      this.enterDegraded("runner shutdown admission barrier timeout");
      throw new Error("RUNNER_ADMISSION_BARRIER_TIMEOUT", { cause: terminationError ?? undefined });
    }
    if (terminationError) {
      this.enterDegraded("runner shutdown containment failure");
      throw new Error("RUNNER_CANCELLATION_UNCONFIRMED", { cause: terminationError });
    }
    const executions = [...this.active.values()];
    for (const execution of executions) clearInterval(execution.heartbeat);
    this.active.clear();
  }

  getCapabilities(): RunnerCapabilities {
    return { protocol_version: 1, local: true, durable_spool: true, cancellation: true, verification_commands: true };
  }

  private acceptEvent(processId: string, event: NormalizedRuntimeEvent): void {
    const active = this.active.get(event.execution_id);
    if (!active) return;
    this.spool.append(event);
    active.status.event_integrity = this.spool.integrity(event.execution_id, event.attempt_id);
    if (event.type === "execution.started") {
      this.supervisor.notifyStarted(processId);
      active.status.status = "RUNNING";
    }
    this.supervisor.notifyActivity(processId);
    if (event.type === "tool.started" || event.type === "command.started") this.supervisor.notifyToolStarted(processId);
    if (event.type === "tool.completed" || event.type === "command.completed") this.supervisor.notifyToolCompleted(processId);
    this.persist(active.status);
  }

  private beginAdmission(): Admission {
    if (this.closing) throw new Error("RUNNER_HOST_CLOSING");
    if (this.degraded) throw new Error("RUNNER_HOST_DEGRADED");
    this.admissions += 1;
    const generation = this.controlGeneration;
    let ended = false;
    return {
      generation,
      end: () => {
        if (ended) return;
        ended = true;
        this.admissions -= 1;
        if (this.admissions === 0) {
          const waiters = this.admissionWaiters;
          this.admissionWaiters = [];
          for (const resolveWaiter of waiters) resolveWaiter();
        }
      },
    };
  }

  private assertAdmission(generation: number): void {
    if (generation !== this.controlGeneration) throw new Error("RUNNER_ADMISSION_REVOKED");
    if (this.closing) throw new Error("RUNNER_HOST_CLOSING");
    if (this.degraded) throw new Error("RUNNER_HOST_DEGRADED");
    const gate = this.killSwitch.canStart();
    if (!gate.allowed) throw new Error(gate.reason);
  }

  private waitForAdmissions(): Promise<void> {
    return this.admissions === 0 ? Promise.resolve() : new Promise(resolveWaiter => this.admissionWaiters.push(resolveWaiter));
  }

  private async monitor(executionId: string): Promise<void> {
    const active = this.active.get(executionId);
    if (!active) return;
    let exit: SupervisedProcessExit;
    try { exit = await this.supervisor.wait(active.status.process_id); }
    catch {
      this.enterDegraded("supervised process termination unconfirmed");
      await this.containAfterFailure(active.status.process_id, "supervised process termination unconfirmed");
      active.status.status = "INTERRUPTED";
      clearInterval(active.heartbeat);
      try { active.status.lease = this.leases.release(executionId, this.nonce); } catch { /* containment already ran; host remains degraded */ }
      try { this.persist(active.status); } catch { /* in-memory degradation still blocks admissions */ }
      return;
    }
    let classification: ClassifiedRuntimeExit;
    try {
      classification = exit.failure_type === "PROTOCOL_ERROR"
        ? { classification: "RUNTIME_FAILED", failure_type: "PROTOCOL_ERROR", retryability: "never" }
        : await active.adapter.classifyExit({
          exit_code: exit.exit_code,
          signal: exit.signal,
          stderr_tail: safeTail(exit.stderr_path),
          timed_out: exit.timed_out,
        });
    } catch {
      classification = { classification: "RUNTIME_FAILED", failure_type: "PROTOCOL_ERROR", retryability: "never" };
    }
    active.status.status = "EXITED";
    active.status.exit = { ...exit, classification };
    active.status.event_integrity = this.spool.integrity(executionId, active.status.attempt_id);
    clearInterval(active.heartbeat);
    try { active.status.lease = this.leases.release(executionId, this.nonce); }
    catch { this.enterDegraded("runner lease release failure"); }
    try { this.persist(active.status); }
    catch { this.enterDegraded("runner terminal state persistence failure"); }
  }

  private async terminateKnownWork(reason: string): Promise<void> {
    const failures: unknown[] = [];
    try { await this.supervisor.killAll(reason); } catch (error) { failures.push(error); }
    const executions = [...this.active.values()];
    const cancellations = await Promise.allSettled(executions.map(execution => this.cancelExecution(execution.status.execution_id)));
    for (const result of cancellations) if (result.status === "rejected") failures.push(result.reason);
    const completed = await Promise.all(executions.map(execution => settlesWithin(execution.completion, 5_000)));
    if (completed.some(value => !value)) failures.push(new Error("RUNNER_COMPLETION_BARRIER_TIMEOUT"));
    if (failures.length > 0) throw new AggregateError(failures, "RUNNER_TERMINATION_BARRIER_FAILED");
  }

  private enterDegraded(reason: string): void {
    if (!this.degraded) {
      this.degraded = true;
      this.controlGeneration += 1;
    }
    try { this.killSwitch.set("CANCEL_ALL", reason); } catch { /* in-memory degradation remains authoritative */ }
  }

  private async containAfterFailure(processId: string, reason: string): Promise<void> {
    try {
      await this.supervisor.cancel(processId, reason);
      await this.supervisor.waitForTermination(processId);
      return;
    } catch { /* retry through the supervisor-wide inventory */ }
    try { await this.supervisor.killAll(reason); } catch { /* host remains degraded and admissions stay disabled */ }
  }

  private statePath(executionId: string): string {
    return join(this.root, "state", `${createHash("sha256").update(executionId).digest("hex")}.json`);
  }
  private persist(status: RunnerExecutionStatus): void { atomicWriteJson(this.statePath(status.execution_id), status); }
  private readState(executionId: string): RunnerExecutionStatus {
    const path = this.statePath(executionId);
    if (!existsSync(path)) throw new Error(`RUNNER_EXECUTION_NOT_FOUND: ${executionId}`);
    const status = JSON.parse(readFileSync(path, "utf8")) as RunnerExecutionStatus;
    if (status.execution_id !== executionId) throw new Error("RUNNER_STATE_CORRUPT");
    return status;
  }
}

async function settlesWithin(promise: Promise<void>, timeoutMs: number): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise.then(() => true, () => false),
      new Promise<boolean>(resolve => { timer = setTimeout(() => resolve(false), timeoutMs); }),
    ]);
  } finally { if (timer) clearTimeout(timer); }
}

function safeTail(path: string): string {
  try { const value = readFileSync(path, "utf8"); return value.slice(-64_000); }
  catch { return ""; }
}

function loadOrCreateReviewIdentityKey(path: string): { privateKey: KeyObject; publicKeySpki: string } {
  let privateKey: KeyObject;
  if (existsSync(path)) {
    if (process.platform === "win32") {
      if (inspectSecretPathAcl(path, 15_000).secure !== true) throw new Error("RUNNER_REVIEW_IDENTITY_ACL_ISOLATION_INVALID");
    }
    privateKey = createPrivateKey(readFileSync(path, "utf8"));
  }
  else {
    const generated = generateKeyPairSync("ed25519");
    privateKey = generated.privateKey;
    atomicWriteText(path, generated.privateKey.export({ type: "pkcs8", format: "pem" }).toString());
  }
  const publicKeySpki = createPublicKey(privateKey.export({ type: "pkcs8", format: "pem" }).toString())
    .export({ type: "spki", format: "der" }).toString("base64url");
  return { privateKey, publicKeySpki };
}

function reviewVerificationRecoveryKey(request: z.infer<typeof runnerVerificationCommandRequestSchema>): string {
  if (!request.review_attestation) throw new Error("RUNNER_REVIEW_RECOVERY_BINDING_MISSING");
  return canonicalSha256({
    execution_id: request.recovery_identity.execution_id,
    attempt_id: request.recovery_identity.attempt_id,
    review_attestation: request.review_attestation,
    portable_command_hash: hashPortableReviewVerificationPlan(request.plan),
  });
}

export function hashPortableReviewVerificationPlan(planInput: z.input<typeof runtimeLaunchPlanSchema>): string {
  const plan = runtimeLaunchPlanSchema.parse(planInput);
  const arguments_ = plan.arguments.map(argument => {
    const mount = argument.match(/^type=bind,src=[^,]+,dst=(\/review\/(source|evidence|artifacts|temp))(,readonly)?$/);
    return mount ? `type=bind,src=<host:${mount[2]}>,dst=${mount[1]}${mount[3] ?? ""}` : argument;
  });
  return canonicalSha256({
    ...plan,
    arguments: arguments_,
    working_directory: "<review-source>",
    stdin: plan.stdin.mode === "file" ? { mode: "file", content_hash: plan.prompt_hash } : plan.stdin,
  });
}

function readAndValidateReviewContextStdin(plan: z.infer<typeof runtimeLaunchPlanSchema>): Uint8Array {
  if (plan.stdin.mode !== "file") throw new Error("RUNNER_REVIEW_CONTEXT_STDIN_REQUIRED");
  let bytes: Uint8Array;
  let parsed: unknown;
  try {
    bytes = readFileSync(plan.stdin.path);
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  }
  catch { throw new Error("RUNNER_REVIEW_CONTEXT_STDIN_INVALID"); }
  if (canonicalSha256(parsed) !== plan.prompt_hash) throw new Error("RUNNER_REVIEW_CONTEXT_STDIN_HASH_MISMATCH");
  return bytes!;
}

function deriveContainerImageDigest(plan: z.infer<typeof runtimeLaunchPlanSchema>): string {
  const image = plan.arguments.find(argument => /^[a-z0-9][a-z0-9._:/-]*@sha256:[a-f0-9]{64}$/.test(argument));
  const digest = image?.match(/@(sha256:[a-f0-9]{64})$/)?.[1];
  if (!digest) throw new Error("RUNNER_REVIEW_IMAGE_DIGEST_UNRESOLVABLE");
  return digest;
}

function atomicWriteText(path: string, value: string): void {
  const temporary = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  let descriptor: number | null = null;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    closeSync(descriptor);
    descriptor = null;
    if (process.platform === "win32") {
      hardenSecretPath(temporary, { required: true, force: true });
      if (inspectSecretPathAcl(temporary, 15_000).secure !== true) throw new Error("RUNNER_REVIEW_IDENTITY_ACL_ISOLATION_INVALID");
    }
    descriptor = openSync(temporary, "r+");
    writeSync(descriptor, value, undefined, "utf8");
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

function atomicWriteJson(path: string, value: unknown): void {
  const temporary = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  let descriptor: number | null = null;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    writeSync(descriptor, JSON.stringify(value), undefined, "utf8");
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
