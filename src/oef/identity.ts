declare const identityBrand: unique symbol;

type BrandedId<Kind extends string> = string & {
  readonly [identityBrand]: Kind;
};

export type RoleId = BrandedId<"RoleId">;
export type AgentId = BrandedId<"AgentId">;
export type RuntimeId = BrandedId<"RuntimeId">;
export type ProviderId = BrandedId<"ProviderId">;
export type ModelId = BrandedId<"ModelId">;
export type AccountId = BrandedId<"AccountId">;
export type TaskId = BrandedId<"TaskId">;
export type PermissionEnvelopeId = BrandedId<"PermissionEnvelopeId">;

type IdentityPrefix =
  | "role"
  | "agent"
  | "runtime"
  | "provider"
  | "model"
  | "account"
  | "task"
  | "permission";

const ID_PREFIXES: readonly IdentityPrefix[] = [
  "role",
  "agent",
  "runtime",
  "provider",
  "model",
  "account",
  "task",
  "permission",
];

const ID_VALUE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/@:-]*$/;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;

function parseId<Id extends string>(prefix: IdentityPrefix, value: unknown): Id {
  if (
    typeof value !== "string"
    || value !== value.trim()
    || CONTROL_CHARACTER_PATTERN.test(value)
    || !value.startsWith(`${prefix}:`)
  ) {
    throw new Error(`Expected an identifier with the ${prefix}: prefix`);
  }
  const localValue = value.slice(prefix.length + 1);
  if (!ID_VALUE_PATTERN.test(localValue)) {
    throw new Error(`Invalid ${prefix}: identifier`);
  }
  return value as Id;
}

function createId<Id extends string>(prefix: IdentityPrefix, localValue: string): Id {
  const value = localValue.trim();
  const suppliedPrefix = ID_PREFIXES.find(candidate => value.startsWith(`${candidate}:`));
  if (suppliedPrefix && suppliedPrefix !== prefix) {
    throw new Error(`Expected ${prefix}: but received ${suppliedPrefix}:`);
  }
  return parseId<Id>(prefix, suppliedPrefix ? value : `${prefix}:${value}`);
}

export const roleId = (value: string): RoleId => createId<RoleId>("role", value);
export const agentId = (value: string): AgentId => createId<AgentId>("agent", value);
export const runtimeId = (value: string): RuntimeId => createId<RuntimeId>("runtime", value);
export const providerId = (value: string): ProviderId => createId<ProviderId>("provider", value);
export const modelId = (value: string): ModelId => createId<ModelId>("model", value);
export const accountId = (value: string): AccountId => createId<AccountId>("account", value);
export const taskId = (value: string): TaskId => createId<TaskId>("task", value);
export const permissionEnvelopeId = (value: string): PermissionEnvelopeId =>
  createId<PermissionEnvelopeId>("permission", value);

export const parseRoleId = (value: unknown): RoleId => parseId<RoleId>("role", value);
export const parseAgentId = (value: unknown): AgentId => parseId<AgentId>("agent", value);
export const parseRuntimeId = (value: unknown): RuntimeId => parseId<RuntimeId>("runtime", value);
export const parseProviderId = (value: unknown): ProviderId => parseId<ProviderId>("provider", value);
export const parseModelId = (value: unknown): ModelId => parseId<ModelId>("model", value);
export const parseAccountId = (value: unknown): AccountId => parseId<AccountId>("account", value);
export const parseTaskId = (value: unknown): TaskId => parseId<TaskId>("task", value);
export const parsePermissionEnvelopeId = (value: unknown): PermissionEnvelopeId =>
  parseId<PermissionEnvelopeId>("permission", value);

export interface RoleDefinition {
  id: RoleId;
  objective: string;
  requiredCapabilities: string[];
}

export interface RuntimeDefinition {
  id: RuntimeId;
  kind: "codex" | "claude" | "gemini" | "kimi" | "qwen" | "mistral" | "custom";
  version: string;
  capabilities: string[];
}

export interface ProviderDefinition {
  id: ProviderId;
  displayName: string;
}

export interface ModelDefinition {
  id: ModelId;
  providerId: ProviderId;
  apiModelId: string;
}

export interface AccountDefinition {
  id: AccountId;
  providerId: ProviderId;
  credentialReference?: string;
}

export interface AgentProfile {
  id: AgentId;
  roleId: RoleId;
  runtimeId: RuntimeId;
  allowedModelIds: ModelId[];
  toolBundle: string[];
  memoryScopes: {
    read: string[];
    write: string[];
  };
  permissionEnvelopeId: PermissionEnvelopeId;
  workspace: "read-only" | "isolated-worktree" | "sandbox";
  verifiers: string[];
  stopConditions: string[];
}

export type AgentBindingDecision =
  | { ok: true }
  | {
      ok: false;
      reason: "model-not-allowed" | "model-account-provider-mismatch";
    };

export function validateAgentBinding(input: {
  profile: AgentProfile;
  model: ModelDefinition;
  account: AccountDefinition;
}): AgentBindingDecision {
  if (!input.profile.allowedModelIds.includes(input.model.id)) {
    return { ok: false, reason: "model-not-allowed" };
  }
  if (input.model.providerId !== input.account.providerId) {
    return { ok: false, reason: "model-account-provider-mismatch" };
  }
  return { ok: true };
}
