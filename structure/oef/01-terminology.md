# OEF terminology and identity boundaries

The words below name different control-plane entities. They must not be used as synonyms in code,
configuration, traces, audit records, or user-facing explanations.

| Entity | Meaning | Owns | Must not mean |
| --- | --- | --- | --- |
| Role | A task objective and required capability set | Intent and evaluation expectations | A model name, process, or credential |
| Agent | A configured execution profile | Role reference, runtime, allowed models, tools, memory scope, permissions, workspace, verifiers, stop conditions | The underlying model or provider |
| Runtime | The harness that executes an agent turn | Process/protocol behavior and supported capabilities | A provider account or model |
| Provider | The service or deployment boundary that exposes models | Endpoint, service policy, and model namespace | A credential-bearing account |
| Model | A provider-owned inference artifact/version | API model identifier and provider reference | A running agent or account |
| Account | A provider-scoped quota, billing, and credential identity | A reference to credentials, never raw credentials in OEF records | The provider itself |

## Canonical relationship

```text
Role
  -> selected by AgentProfile
AgentProfile
  -> executed by Runtime
  -> permits a set of Models
Model
  -> belongs to Provider
Account
  -> belongs to the same Provider as the selected Model
```

The model produces tokens. The runtime executes the turn. The provider serves the model. The
account authorizes and meters access. The agent is the policy-bound profile that combines those
parts for a task. The role states why that profile exists.

## Identifier contract

OEF identifiers are nominal TypeScript types and carry serialized prefixes:

```text
role:chief-architect
agent:architect-01
runtime:codex-cli
provider:openai
model:openai/gpt-5.6-sol
account:openai/main
```

The prefix is an audit and deserialization guard. The nominal type is the compile-time guard. Both
are required because TypeScript brands disappear at runtime.

## Agent profile

An `AgentProfile` is:

```text
role reference
+ runtime reference
+ allowed model policy
+ tool bundle
+ memory read/write scopes
+ permission envelope reference
+ workspace isolation mode
+ verifiers
+ stop conditions
```

It contains no access token, refresh token, API key, or provider secret. Credential resolution is a
separate trusted runtime action using an account reference after authorization succeeds.

## Binding invariants

- The selected model must be in the agent profile's allowed-model set.
- The selected model and account must reference the same provider.
- A role never selects credentials.
- A model never carries runtime or workspace authority.
- An account never grants tool, memory, filesystem, or deployment permissions.
- A runtime capability does not imply that an agent is authorized to use it.
