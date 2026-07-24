import { readFileSync } from "node:fs";
import { extname, resolve } from "node:path";
import {
  createPhase1Runtime,
  runPhase1Demo,
  readTaskSummary,
  verifyTaskIntegrity,
  type Phase1Runtime,
} from "../oef/phase1";

interface ParsedArgs {
  positionals: string[];
  options: Map<string, string | true>;
  json: boolean;
}

function parseArgs(args: string[]): ParsedArgs {
  const positionals: string[] = [];
  const options = new Map<string, string | true>();
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index];
    if (!value.startsWith("--")) {
      positionals.push(value);
      continue;
    }
    const equal = value.indexOf("=");
    if (equal > 2) {
      options.set(value.slice(2, equal), value.slice(equal + 1));
      continue;
    }
    const key = value.slice(2);
    if (key === "json") {
      options.set(key, true);
      continue;
    }
    const next = args[index + 1];
    if (!next || next.startsWith("--")) throw new Error(`Missing value for --${key}`);
    options.set(key, next);
    index += 1;
  }
  return { positionals, options, json: options.has("json") };
}

function requireOption(parsed: ParsedArgs, name: string): string {
  const value = parsed.options.get(name);
  if (typeof value !== "string" || !value.trim()) throw new Error(`Missing required option --${name}`);
  return value;
}

function parseDefinitionRef(value: string): { id: string; version: string } {
  const separator = value.lastIndexOf("@");
  if (separator <= 0 || separator === value.length - 1) throw new Error(`Expected id@version, received: ${value}`);
  return { id: value.slice(0, separator), version: value.slice(separator + 1) };
}

function printValue(value: unknown, json: boolean): void {
  console.log(JSON.stringify(value, null, json ? 0 : 2));
}

function parseDataFile(pathInput: string): unknown {
  const path = resolve(pathInput);
  const source = readFileSync(path, "utf8");
  return extname(path).toLowerCase() === ".json" ? JSON.parse(source) : Bun.YAML.parse(source);
}

function execute(
  runtime: Phase1Runtime,
  input: { taskId: string; commandType: string; payload: unknown; actor?: { type: "human" | "system"; id: string } },
) {
  const commandId = runtime.ids.next("command");
  const result = runtime.bus.execute({
    schema_version: 1,
    command_id: commandId,
    command_type: input.commandType,
    task_id: input.taskId,
    expected_aggregate_version: runtime.store.getTask(input.taskId)?.aggregate_version ?? 0,
    actor: input.actor ?? { type: "human", id: "human:local-owner" },
    idempotency_key: commandId,
    payload: input.payload,
  });
  if (!result.ok) throw new Error(JSON.stringify(result.error));
  return result.value;
}

function taskCommand(runtime: Phase1Runtime, parsed: ParsedArgs): unknown {
  const subcommand = parsed.positionals[0];
  if (subcommand === "create") {
    const taskId = runtime.ids.next("task");
    const workflow = parseDefinitionRef(requireOption(parsed, "workflow"));
    const policy = parseDefinitionRef(requireOption(parsed, "policy"));
    return execute(runtime, {
      taskId,
      commandType: "CreateTask",
      payload: {
        title: requireOption(parsed, "title"),
        workflow,
        policy,
        risk: {
          level: typeof parsed.options.get("risk") === "string" ? parsed.options.get("risk") : "low",
          reasons: typeof parsed.options.get("risk-reason") === "string" ? [parsed.options.get("risk-reason")] : [],
        },
      },
    }).task;
  }
  const taskId = parsed.positionals[1];
  if (!taskId) throw new Error(`Usage: ocx task ${subcommand ?? "<subcommand>"} <task-id>`);
  const task = runtime.store.getTask(taskId);
  if (!task) throw new Error(`Task not found: ${taskId}`);
  if (subcommand === "show") {
    return {
      ...task,
      summary: readTaskSummary({ taskId, store: runtime.store, artifactStore: runtime.artifacts }),
      audit_integrity: verifyTaskIntegrity({ taskId, store: runtime.store, artifactStore: runtime.artifacts }),
    };
  }
  if (subcommand === "timeline") return runtime.store.getTimeline(taskId);
  if (subcommand === "transition") {
    const value = execute(runtime, {
      taskId,
      commandType: "TransitionTaskStage",
      payload: { from_stage: task.stage, to_stage: requireOption(parsed, "to") },
    });
    return {
      ...value.task,
      transition_applied: value.transition_applied ?? true,
      transition_denial: value.transition_denial,
    };
  }
  if (subcommand === "migrate-workflow") {
    return execute(runtime, {
      taskId,
      commandType: "MigrateWorkflow",
      payload: {
        from: parseDefinitionRef(requireOption(parsed, "from")),
        to: parseDefinitionRef(requireOption(parsed, "to")),
        stage_map: parseDataFile(requireOption(parsed, "stage-map")),
        rationale: requireOption(parsed, "rationale"),
      },
    }).task;
  }
  if (subcommand === "block") {
    return execute(runtime, { taskId, commandType: "BlockTask", payload: { reason: requireOption(parsed, "reason") } }).task;
  }
  if (subcommand === "unblock") {
    return execute(runtime, { taskId, commandType: "UnblockTask", payload: { reason: requireOption(parsed, "reason") } }).task;
  }
  if (subcommand === "cancel") {
    return execute(runtime, { taskId, commandType: "CancelTask", payload: { reason: requireOption(parsed, "reason") } }).task;
  }
  if (subcommand === "reopen") {
    return execute(runtime, {
      taskId,
      commandType: "ReopenTask",
      payload: { to_stage: requireOption(parsed, "to"), rationale: requireOption(parsed, "rationale") },
    }).task;
  }
  throw new Error(`Unknown task command: ${subcommand ?? ""}`);
}

function contractCommand(runtime: Phase1Runtime, parsed: ParsedArgs): unknown {
  const subcommand = parsed.positionals[0];
  const taskId = requireOption(parsed, "task");
  const task = runtime.store.getTask(taskId);
  if (!task) throw new Error(`Task not found: ${taskId}`);
  if (subcommand === "create") {
    const revisions = runtime.store.listContractRevisions(taskId);
    execute(runtime, {
      taskId,
      commandType: "CreateContractRevision",
      payload: {
        document: parseDataFile(requireOption(parsed, "file")),
        parent_revision_id: revisions.at(-1)?.revision_id ?? null,
      },
    });
    return runtime.store.listContractRevisions(taskId).at(-1);
  }
  const revisionNumber = Number(requireOption(parsed, "revision"));
  const revision = runtime.store.listContractRevisions(taskId).find(item => item.revision_number === revisionNumber);
  if (!revision) throw new Error(`Contract revision not found: ${revisionNumber}`);
  if (subcommand === "propose") {
    execute(runtime, { taskId, commandType: "ProposeContractRevision", payload: { revision_id: revision.revision_id } });
  } else if (subcommand === "approve") {
    execute(runtime, {
      taskId,
      commandType: "ApproveContractRevision",
      payload: { revision_id: revision.revision_id, rationale: requireOption(parsed, "rationale") },
    });
  } else if (subcommand === "reject") {
    execute(runtime, {
      taskId,
      commandType: "RejectContractRevision",
      payload: { revision_id: revision.revision_id, rationale: requireOption(parsed, "rationale") },
    });
  } else {
    throw new Error(`Unknown contract command: ${subcommand ?? ""}`);
  }
  return runtime.store.getContractRevision(revision.revision_id);
}

function evidenceCommand(runtime: Phase1Runtime, parsed: ParsedArgs): unknown {
  const subcommand = parsed.positionals[0];
  const taskId = requireOption(parsed, "task");
  const task = runtime.store.getTask(taskId);
  if (!task?.active_contract_revision_id) throw new Error(`Task has no active contract: ${taskId}`);
  if (subcommand === "add") {
    const file = resolve(requireOption(parsed, "file"));
    const artifact = runtime.artifacts.put({
      content: readFileSync(file),
      media_type: extname(file).toLowerCase() === ".json" ? "application/json" : "application/octet-stream",
      classification: "internal",
      retention_policy: "task-lifetime",
      created_by: { type: "human", id: "human:local-owner" },
    });
    execute(runtime, {
      taskId,
      commandType: "RecordEvidence",
      payload: {
        contract_revision_id: task.active_contract_revision_id,
        criterion_key: requireOption(parsed, "criterion"),
        type: requireOption(parsed, "type"),
        summary: typeof parsed.options.get("summary") === "string" ? parsed.options.get("summary") : `${requireOption(parsed, "type")} recorded.`,
        artifacts: [artifact],
        environment: {
          repository_commit: typeof parsed.options.get("commit") === "string"
            ? parsed.options.get("commit")
            : undefined,
        },
      },
      actor: { type: "system", id: "system:local-cli" },
    });
    return runtime.store.listEvidence(taskId).at(-1);
  }
  if (subcommand === "verify") {
    const evidenceId = requireOption(parsed, "evidence");
    execute(runtime, {
      taskId,
      commandType: "VerifyEvidence",
      payload: { evidence_id: evidenceId },
      actor: { type: "system", id: "system:local-cli" },
    });
    return runtime.store.getEvidence(evidenceId);
  }
  throw new Error(`Unknown evidence command: ${subcommand ?? ""}`);
}

function verdictCommand(runtime: Phase1Runtime, parsed: ParsedArgs): unknown {
  if (parsed.positionals[0] !== "issue") throw new Error(`Unknown verdict command: ${parsed.positionals[0] ?? ""}`);
  const taskId = requireOption(parsed, "task");
  const task = runtime.store.getTask(taskId);
  if (!task?.active_contract_revision_id) throw new Error(`Task has no active contract: ${taskId}`);
  const evidenceRefs = runtime.store.listEvidence(taskId)
    .filter(item => item.contract_revision_id === task.active_contract_revision_id && item.status === "VERIFIED")
    .map(item => item.evidence_id);
  execute(runtime, {
    taskId,
    commandType: "IssueVerdict",
    payload: {
      contract_revision_id: task.active_contract_revision_id,
      decision: requireOption(parsed, "decision").toUpperCase(),
      rationale: requireOption(parsed, "rationale"),
      evidence_refs: evidenceRefs,
      repository_commit: typeof parsed.options.get("commit") === "string" ? parsed.options.get("commit") : null,
    },
    actor: { type: "system", id: "system:local-cli" },
  });
  return runtime.store.listVerdicts(taskId).at(-1);
}

export async function cmdOefDomain(group: string, args: string[]): Promise<number> {
  const parsed = parseArgs(args);
  if (group === "oef-demo") {
    printValue(runPhase1Demo({ home: process.env.OPENCODEX_OEF_HOME ?? resolve(".opencodex-demo") }), parsed.json);
    return 0;
  }
  let runtime: Phase1Runtime | undefined;
  try {
    runtime = createPhase1Runtime();
    let value: unknown;
    if (group === "task") value = taskCommand(runtime, parsed);
    else if (group === "contract") value = contractCommand(runtime, parsed);
    else if (group === "evidence") value = evidenceCommand(runtime, parsed);
    else if (group === "verdict") value = verdictCommand(runtime, parsed);
    else if (group === "integrity" && parsed.positionals[0] === "verify") {
      const taskId = parsed.positionals[1];
      if (!taskId) throw new Error("Usage: ocx integrity verify <task-id>");
      value = verifyTaskIntegrity({ taskId, store: runtime.store, artifactStore: runtime.artifacts });
    } else throw new Error(`Unknown OEF command: ${group}`);
    printValue(value, parsed.json);
    return 0;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    return 1;
  } finally {
    runtime?.close();
  }
}
