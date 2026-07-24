export const CIRCUIT_BREAKER_DECISIONS = [
  "CONTINUE",
  "RETRY_TRANSIENT",
  "CREATE_REPAIR",
  "REDISPATCH_FRESH_CONTEXT",
  "ESCALATE_MODEL",
  "ESCALATE_ARCHITECTURE",
  "NEEDS_HUMAN",
  "STOP_BUDGET",
] as const;
export type CircuitBreakerDecision = typeof CIRCUIT_BREAKER_DECISIONS[number];

interface AttemptLedgerEntry { failure_signature: string; action_signature: string; progress: boolean }

export class RetryCircuitBreaker {
  private readonly policy: { max_attempts: number; same_error_threshold: number; similar_action_threshold: number; no_progress_threshold: number };
  constructor(policy: { max_attempts: number; same_error_threshold: number; similar_action_threshold: number; no_progress_threshold: number }) {
    if (Object.values(policy).some(value => !Number.isInteger(value) || value <= 0)) throw new Error("Circuit breaker thresholds must be positive integers");
    this.policy = policy;
  }

  decide(input: {
    attempts: AttemptLedgerEntry[];
    failure_type: string;
    failure_signature: string;
    action_signature: string;
    progress: boolean;
  }): CircuitBreakerDecision {
    if (input.attempts.length + 1 >= this.policy.max_attempts) return "STOP_BUDGET";
    const withCurrent = [...input.attempts, {
      failure_signature: input.failure_signature,
      action_signature: input.action_signature,
      progress: input.progress,
    }];
    if (trailingCount(withCurrent, entry => entry.failure_signature === input.failure_signature) >= this.policy.same_error_threshold) return "NEEDS_HUMAN";
    if (trailingCount(withCurrent, entry => entry.action_signature === input.action_signature) >= this.policy.similar_action_threshold) return "ESCALATE_ARCHITECTURE";
    if (trailingCount(withCurrent, entry => !entry.progress) >= this.policy.no_progress_threshold) return "NEEDS_HUMAN";
    if (["AUTHENTICATION_FAILED", "AUTHORIZATION_FAILED", "PATH_POLICY_VIOLATION", "SECRET_LEAK_DETECTED"].includes(input.failure_type)) return "NEEDS_HUMAN";
    if (input.failure_type === "VERIFICATION_FAILED") return "CREATE_REPAIR";
    if (input.failure_type === "CONTEXT_LIMIT_EXCEEDED") return "REDISPATCH_FRESH_CONTEXT";
    if (["NETWORK_FAILED", "PROVIDER_UNAVAILABLE", "RATE_LIMITED", "STARTUP_TIMEOUT", "RUNTIME_STARTUP_FAILED"].includes(input.failure_type)) return "RETRY_TRANSIENT";
    if (input.failure_type === "MODEL_BEHAVIOR_ERROR" || input.failure_type === "MODEL_REFUSAL") return "ESCALATE_MODEL";
    return input.progress ? "CONTINUE" : "NEEDS_HUMAN";
  }
}

function trailingCount<T>(items: readonly T[], predicate: (item: T) => boolean): number {
  let count = 0;
  for (let index = items.length - 1; index >= 0 && predicate(items[index]!); index -= 1) count += 1;
  return count;
}

export interface ProgressSnapshot {
  changed_files_hash: string;
  failing_tests: number;
  evidence_count: number;
  failure_signature: string;
  build_stage: number;
  assistant_message_bytes: number;
  tokens_used: number;
}

export class ProgressDetector {
  evaluate(previous: ProgressSnapshot, current: ProgressSnapshot): { progressed: boolean; signals: string[] } {
    const signals: string[] = [];
    if (current.changed_files_hash !== previous.changed_files_hash) signals.push("CHANGED_FILES_DIFFER");
    if (current.failing_tests < previous.failing_tests) signals.push("FAILING_TESTS_REDUCED");
    if (current.evidence_count > previous.evidence_count) signals.push("NEW_EVIDENCE");
    if (current.failure_signature !== previous.failure_signature) signals.push("FAILURE_SIGNATURE_CHANGED");
    if (current.build_stage > previous.build_stage) signals.push("BUILD_STAGE_ADVANCED");
    return { progressed: signals.length > 0, signals };
  }
}
