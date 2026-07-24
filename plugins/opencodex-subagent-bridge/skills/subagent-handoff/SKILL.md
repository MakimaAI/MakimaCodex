---
name: subagent-handoff
description: Prepare secure one-time handoffs whenever a standard collaboration tool targets an opencodex-routed subagent model.
---

# Routed subagent handoffs

For an opencodex-routed model, call `prepare_subagent_handoff` immediately before the corresponding standard collaboration tool:

- Before `spawn_agent`, prepare with `kind: "spawn"`, the intended `task_name`, routed `model`, and exact `message`. Then call `spawn_agent` with the returned unique task name and the same model and message.
- Before `send_message`, prepare with `kind: "message"`, the exact `target` and `message`. Then call `send_message` with the returned verified target and the same message.
- Before `followup_task`, prepare with `kind: "followup"`, the exact `target` and `message`. Then call `followup_task` with the returned verified target and the same message.

The preparation and standard tool call must remain adjacent. If the preparation expires or the standard call changes, prepare again.

Never prepare a handoff for a native model. Call the standard collaboration tool directly for native children.

## Preconditions and recovery

- The routed model must be configured in opencodex and selected in `subagentModels`. `ocx health` must report a live proxy before preparation.
- After installing the bridge, running `ocx restart`, or changing routed models, start a new Codex task. An already-running task keeps its original provider binding.
- If preparation fails, do not call the collaboration tool. Check `ocx health`; run `ocx restart` if the proxy is unavailable, then prepare again.
- If a routed child returns `subagent_handoff_missing` (HTTP 409), the one-time record was absent, expired, mismatched, or lost during a proxy restart. Check `ocx health`, prepare a fresh handoff, use the new returned target unchanged, and retry once. Never reuse an expired prepared result.
