import {
  accountId,
  agentId,
  modelId,
  providerId,
  roleId,
  runtimeId,
  type AccountId,
  type AgentId,
  type ModelId,
  type ProviderId,
  type RoleId,
  type RuntimeId,
} from "../../src/oef";

const acceptsRole = (_value: RoleId): void => {};
const acceptsAgent = (_value: AgentId): void => {};
const acceptsRuntime = (_value: RuntimeId): void => {};
const acceptsProvider = (_value: ProviderId): void => {};
const acceptsModel = (_value: ModelId): void => {};
const acceptsAccount = (_value: AccountId): void => {};

const role = roleId("architect");
const agent = agentId("architect-01");
const runtime = runtimeId("codex-cli");
const provider = providerId("openai");
const model = modelId("openai/gpt-5.6-sol");
const account = accountId("openai/main");

acceptsRole(role);
acceptsAgent(agent);
acceptsRuntime(runtime);
acceptsProvider(provider);
acceptsModel(model);
acceptsAccount(account);

// @ts-expect-error A model is not an agent.
acceptsAgent(model);
// @ts-expect-error An account is not a provider.
acceptsProvider(account);
// @ts-expect-error A runtime is not a role.
acceptsRole(runtime);
// @ts-expect-error An agent is not an account.
acceptsAccount(agent);
