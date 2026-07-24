import { executionBindingSchema, type ExecutionBinding } from "../../phase2/core/domain";
import { assertExecutionBindingSetIntegrity, type ExecutionBindingSet } from "../core/domain";

export function toPhase2ExecutionBinding(input: {
  binding_set: ExecutionBindingSet; role_node_id: string; assignment_id: string; assignment_revision: number;
  environment_type: string; environment_version: number; created_at: string;
}): ExecutionBinding {
  assertExecutionBindingSetIntegrity(input.binding_set);
  const binding = input.binding_set.bindings.find(value => value.role_node_id === input.role_node_id);
  if (!binding) throw new Error("PHASE5_BINDING_NOT_FOUND");
  return executionBindingSchema.parse({
    schema_version: 1, binding_id: binding.binding_id, assignment_id: input.assignment_id, assignment_revision: input.assignment_revision,
    agent_profile_ref: { id: binding.agent_profile_id, version: binding.agent_profile_version },
    runtime_ref: { id: binding.runtime_id, adapter_version: binding.runtime_adapter_version },
    model_ref: { provider: binding.provider_id, model_class: binding.role_id, resolved_model: binding.model_version_id },
    environment_ref: { type: input.environment_type, version: input.environment_version }, account_ref: { id: binding.account_id },
    created_by: { type: "integration", id: "phase5-routing-kernel" }, created_at: input.created_at,
  });
}
