import { generateKeyPairSync, sign as signBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { canonicalSha256 } from "../../src/oef/phase1/core/contract/task-contract";
import type {
  RunnerReviewIdentityAttestation,
  RunnerReviewIdentityAuthority,
  RunnerReviewLaunchPolicy,
  RunnerVerificationCommandRequest,
  RunnerVerifiedCommandResult,
} from "../../src/oef/phase2/runner/local-runner-host";
import { hashPortableReviewVerificationPlan } from "../../src/oef/phase2/runner/local-runner-host";
import type { ReviewIdentityAuthorityClient } from "../../src/oef/phase3";

export class TestReviewIdentityAuthority implements ReviewIdentityAuthorityClient {
  private readonly privateKey;
  private readonly authority: RunnerReviewIdentityAuthority;
  private readonly policies = new Map<string, RunnerReviewLaunchPolicy>();

  constructor() {
    const keys = generateKeyPairSync("ed25519");
    this.privateKey = keys.privateKey;
    const publicKey = keys.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
    this.authority = { algorithm: "Ed25519", key_id: canonicalSha256(publicKey), public_key_spki: publicKey };
  }

  getReviewIdentityAuthority(): RunnerReviewIdentityAuthority { return { ...this.authority }; }
  registerReviewLaunchPolicy(policy: RunnerReviewLaunchPolicy): void { this.policies.set(policy.launch_policy_id, policy); }
  getReviewLaunchPolicy(policyId: string): RunnerReviewLaunchPolicy {
    const policy = this.policies.get(policyId);
    if (!policy) throw new Error("RUNNER_REVIEW_LAUNCH_POLICY_NOT_FOUND");
    return policy;
  }

  async attestReviewIdentity(content: unknown): Promise<RunnerReviewIdentityAttestation> {
    const contentHash = canonicalSha256(content);
    return {
      ...this.authority,
      content_hash: contentHash,
      signature: signBytes(null, Buffer.from(contentHash, "utf8"), this.privateKey).toString("base64url"),
    };
  }

  async createAtomicReviewResult(
    request: RunnerVerificationCommandRequest,
    exit: Omit<RunnerVerifiedCommandResult, "review_attestation">,
    reviewer?: RunnerReviewLaunchPolicy["reviewer"],
  ): Promise<RunnerVerifiedCommandResult> {
    const requested = request.review_attestation;
    if (!requested) throw new Error("TEST_REVIEW_ATTESTATION_REQUEST_MISSING");
    const policyReviewer = reviewer ?? this.getReviewLaunchPolicy(requested.launch_policy_id).reviewer;
    const image = request.plan.arguments.find(argument => /@sha256:[a-f0-9]{64}$/.test(argument));
    const imageDigest = image?.match(/@(sha256:[a-f0-9]{64})$/)?.[1];
    if (!imageDigest) throw new Error("TEST_REVIEW_IMAGE_MISSING");
    const content = {
      review_execution_id: requested.review_execution_id,
      phase2_execution_id: request.recovery_identity.execution_id,
      runner_process_id: exit.process_id,
      reviewer: policyReviewer,
      identity_source: "runner-authenticated-launch-binding" as const,
      container_image_digest: imageDigest,
      command_hash: canonicalSha256(request.plan),
      portable_command_hash: hashPortableReviewVerificationPlan(request.plan),
      isolation_hash: requested.isolation_hash,
      launch_policy_id: requested.launch_policy_id,
      output_hash: canonicalSha256(readFileSync(exit.stdout_path, "utf8")),
      attested_by: "phase2-runner-host" as const,
    };
    return { ...exit, review_attestation: { ...content, ...(await this.attestReviewIdentity(content)) } };
  }
}
