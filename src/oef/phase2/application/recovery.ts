export interface ReconciliationInput {
  control_status: "RUNNING" | "CANCELLING" | "INTERRUPTED" | "TERMINAL";
  runner_status: "RUNNING" | "EXITED" | "MISSING";
  lease_status: "ACTIVE" | "EXPIRED" | "MISSING";
  process: { alive: boolean; identity_verified: boolean };
  event_sequences_match: boolean;
  resumable: boolean;
}

export type ReconciliationAssessment =
  | { state: "HEALTHY"; action: "REATTACH" }
  | { state: "EVENT_STREAM_DIVERGED"; action: "REQUEST_MISSING_EVENTS" }
  | { state: "CONTROL_PLANE_LOST"; action: "REATTACH" }
  | { state: "RUNNER_LOST_PROCESS_VERIFIED"; action: "QUARANTINE_AND_TERMINATE_TREE" }
  | { state: "RUNNER_LOST_PROCESS_UNVERIFIED"; action: "DO_NOT_KILL_MARK_ORPHANED" }
  | { state: "PROCESS_LOST"; action: "MARK_INTERRUPTED_AND_PLAN_RECOVERY" }
  | { state: "STATE_ONLY_ORPHAN"; action: "MARK_INTERRUPTED_PRESERVE_WORKSPACE" }
  | { state: "TERMINAL"; action: "NONE" };

export class ExecutionReconciler {
  assess(input: ReconciliationInput): ReconciliationAssessment {
    if (input.control_status === "TERMINAL") return { state: "TERMINAL", action: "NONE" };
    if (input.runner_status === "RUNNING" && input.process.alive && input.process.identity_verified) {
      if (!input.event_sequences_match) return { state: "EVENT_STREAM_DIVERGED", action: "REQUEST_MISSING_EVENTS" };
      if (!input.resumable) return { state: "RUNNER_LOST_PROCESS_VERIFIED", action: "QUARANTINE_AND_TERMINATE_TREE" };
      return input.lease_status === "ACTIVE"
        ? { state: "HEALTHY", action: "REATTACH" }
        : { state: "CONTROL_PLANE_LOST", action: "REATTACH" };
    }
    if (input.process.alive) {
      return input.process.identity_verified
        ? { state: "RUNNER_LOST_PROCESS_VERIFIED", action: "QUARANTINE_AND_TERMINATE_TREE" }
        : { state: "RUNNER_LOST_PROCESS_UNVERIFIED", action: "DO_NOT_KILL_MARK_ORPHANED" };
    }
    if (input.runner_status === "RUNNING" || input.runner_status === "EXITED") {
      return { state: "PROCESS_LOST", action: "MARK_INTERRUPTED_AND_PLAN_RECOVERY" };
    }
    return { state: "STATE_ONLY_ORPHAN", action: "MARK_INTERRUPTED_PRESERVE_WORKSPACE" };
  }
}
