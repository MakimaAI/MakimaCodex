import type {
  ReviewFinding,
  ReviewPlan,
  ReviewPlanState,
  ReviewSnapshot,
  Waiver,
} from "../core/domain";
import type { FindingValidationContext, ReviewValidityInputs } from "../decision";
import type { ReviewDecisionRecord } from "../governance";
import type { ReviewerBinding, ReviewResultValidationContext } from "../review";

export interface MechanicalReviewEvidence {
  readonly passed: boolean;
  readonly evidence_hash: string;
  readonly artifact_refs: readonly string[];
}

export interface ReviewCoordinatorDataPort {
  loadPlan(reviewPlanId: string): Promise<ReviewPlan>;
  loadPlanState(reviewPlanId: string): Promise<ReviewPlanState>;
  loadCurrentSnapshot(taskId: string): Promise<unknown>;
  loadMechanicalEvidence(reviewPlanId: string): Promise<MechanicalReviewEvidence>;
  loadSatisfiedPrerequisites(reviewUnitId: string): Promise<readonly string[]>;
  loadReviewerBinding(reviewUnitId: string): Promise<ReviewerBinding>;
  buildContextInput(
    unit: ReviewPlan["review_units"][number],
    priorFindings: readonly Pick<ReviewFinding, "finding_id" | "status" | "claim">[],
  ): Promise<unknown>;
  loadResultValidationContext(reviewUnitId: string): Promise<ReviewResultValidationContext>;
  loadFindingValidationContext(reviewPlanId: string): Promise<FindingValidationContext>;
  loadWaivers(reviewPlanId: string): Promise<readonly Waiver[]>;
  loadReviewValidityBaseline(reviewPlanId: string): Promise<ReviewValidityInputs>;
  loadCurrentReviewValidity(reviewPlanId: string): Promise<ReviewValidityInputs>;
  loadHumanApproval(reviewPlanId: string): Promise<unknown | null>;
  loadLatestReviewDecision(reviewPlanId: string): Promise<ReviewDecisionRecord | null>;
  verifyRuntimeIdentityAttestation(attestation: unknown): Promise<boolean>;
}

export interface ReviewCoordinatorExecutionInput {
  readonly review_execution_id: string;
  readonly plan: ReviewPlan;
  readonly unit: ReviewPlan["review_units"][number];
  readonly binding: ReviewerBinding;
  readonly context: unknown;
}

export interface ReviewCoordinatorExecutionResult {
  readonly status: "COMPLETED" | "FAILED" | "CANCELLED";
  readonly raw_output: unknown;
  readonly output_hash: string;
  readonly cost_units: number;
  readonly runtime_attestation: {
    readonly reviewer: {
      readonly agent_id: string;
      readonly provider: string;
      readonly model_class: string;
      readonly session_id: string;
      readonly context_id: string;
    };
    readonly review_execution_id: string;
    readonly phase2_execution_id: string;
    readonly runner_process_id: string;
    readonly identity_source: "runner-authenticated-launch-binding";
    readonly container_image_digest: string;
    readonly command_hash: string;
    readonly portable_command_hash: string;
    readonly isolation_hash: string;
    readonly launch_policy_id: string;
    readonly output_hash: string;
    readonly attested_by: "phase2-runner-host";
    readonly attestation_hash: string;
    readonly attestation_key_id: string;
    readonly attestation_signature: string;
    readonly attestation_algorithm: "Ed25519";
    readonly attestation_public_key: string;
    readonly isolation: {
      readonly mechanism: "docker";
      readonly network: "denied";
      readonly credentials: "unmounted";
      readonly source: "read-only";
      readonly image_digest: string;
      readonly attested_by: string;
    };
  };
}

export interface ReviewCoordinatorExecutorPort {
  execute(input: ReviewCoordinatorExecutionInput): Promise<ReviewCoordinatorExecutionResult>;
  cancelPlan(reviewPlanId: string): Promise<void>;
}

export interface ReviewArtifactPort {
  putJson(input: {
    readonly idempotency_key: string;
    readonly artifact_ref: string;
    readonly value: unknown;
  }): Promise<{ readonly artifact_ref: string; readonly replayed: boolean }>;
}

export interface ReviewAuditPort {
  append(input: {
    readonly idempotency_key: string;
    readonly event_id: string;
    readonly event_type: string;
    readonly aggregate_id: string;
    readonly occurred_at: string;
    readonly payload: unknown;
  }): Promise<{ readonly replayed: boolean }>;
  assertIntegrity(aggregateId: string): Promise<void>;
}

export interface ReviewCancellationPort {
  isCancellationRequested(reviewPlanId: string): Promise<boolean>;
}

export interface IdempotentReviewEffectPort {
  runOnce<T>(
    key: string,
    inputHash: string,
    operation: () => Promise<T>,
  ): Promise<{ readonly value: T; readonly replayed: boolean }>;
}

interface StoredEffect {
  readonly inputHash: string;
  readonly value: Promise<unknown>;
}

/** Useful for local composition and tests; durable runtimes should inject a transactional implementation. */
export class InMemoryReviewEffectPort implements IdempotentReviewEffectPort {
  private readonly effects = new Map<string, StoredEffect>();

  async runOnce<T>(key: string, inputHash: string, operation: () => Promise<T>): Promise<{ value: T; replayed: boolean }> {
    const existing = this.effects.get(key);
    if (existing) {
      if (existing.inputHash !== inputHash) throw new Error("REVIEW_EFFECT_IDEMPOTENCY_CONFLICT");
      return { value: await existing.value as T, replayed: true };
    }
    const value = operation();
    this.effects.set(key, { inputHash, value });
    try {
      return { value: await value, replayed: false };
    } catch (error) {
      this.effects.delete(key);
      throw error;
    }
  }
}

export type CurrentSnapshot = ReviewSnapshot;
