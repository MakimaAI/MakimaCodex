import type {
  ReviewPlan,
  ReviewProfile,
  ReviewerCapability,
  ReviewSnapshot,
} from "../core/domain";

export interface ReviewProfileRef {
  readonly id: string;
  readonly version: string;
  readonly hash: string;
}

export interface ReviewTypeDefinition {
  readonly review_type: string;
  readonly profile_ref: ReviewProfileRef;
  readonly required_capabilities: readonly ReviewerCapability[];
  readonly preferred_capabilities: readonly ReviewerCapability[];
  readonly prerequisites: readonly string[];
  readonly source:
    | { readonly type: "built-in" }
    | { readonly type: "plugin"; readonly plugin_id: string };
}

export interface ReviewPluginManifest {
  readonly plugin_id: string;
  readonly protocol_version: 1;
  readonly review_types: readonly Omit<ReviewTypeDefinition, "source">[];
}

export interface ReviewTypeRegistryPort {
  resolve(reviewType: string): ReviewTypeDefinition | undefined;
  list(): readonly ReviewTypeDefinition[];
}

export interface ReviewChangedFile {
  readonly path: string;
  readonly change: "added" | "modified" | "deleted";
  /** Trusted facts emitted by the diff classifier, not free-form reviewer output. */
  readonly classifications: readonly string[];
}

export interface ReviewDependencyChange {
  readonly name: string;
  readonly change: "added" | "updated" | "removed";
}

export interface ReviewChangeSet {
  readonly changed_files: readonly ReviewChangedFile[];
  readonly dependency_changes: readonly ReviewDependencyChange[];
  readonly api_contract_changed: boolean;
  readonly performance_critical_changed: boolean;
}

export interface AdditiveReviewRecommendations {
  readonly add_review_types: readonly string[];
  /** Removals are advisory and can never remove a policy-required unit. */
  readonly remove_review_types: readonly string[];
}

export interface ReviewRiskQuorumPolicy {
  readonly minimum_independent_providers: number;
  readonly minimum_independence_score: number;
  readonly human_approval: "not-required" | "required";
}

export interface ReviewPlanningPolicy {
  readonly quorum_by_risk: Readonly<Record<"low" | "medium" | "high" | "critical", ReviewRiskQuorumPolicy>>;
  readonly budget: ReviewPlan["budget"];
  readonly limits: ReviewPlan["limits"];
}

export interface CompileReviewPlanInput {
  readonly review_plan_id: string;
  readonly revision: number;
  readonly previous_revision_hash: string | null;
  readonly review_request_id: string;
  readonly task_id: string;
  readonly snapshot: ReviewSnapshot;
  readonly risk: {
    readonly level: "low" | "medium" | "high" | "critical";
    readonly reasons: readonly string[];
  };
  readonly changes: ReviewChangeSet;
  readonly evidence_types: readonly string[];
  readonly workflow_id: string;
  readonly repository_class: string;
  readonly assignment_role: string;
  readonly requested_review_types: readonly string[];
  readonly registry: ReviewTypeRegistryPort;
  readonly profiles: Readonly<Record<string, ReviewProfile>>;
  readonly recommendations: AdditiveReviewRecommendations;
  readonly adjudication_policy_ref: ReviewPlan["adjudication_policy_ref"];
  readonly planning_policy?: ReviewPlanningPolicy;
  readonly created_at: string;
}
