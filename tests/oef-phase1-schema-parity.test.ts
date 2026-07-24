import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020";
import addFormats from "ajv-formats";
import {
  createDomainEvent,
  parseActor,
  parseArtifactRef,
  parseCommandEnvelope,
  parseDomainEvent,
  parseEvidenceRecord,
  parsePolicyPack,
  parseTask,
  parseTaskContractDocument,
  parseVerdict,
  parseWorkflowDefinition,
  traceSpanSchema,
} from "../src/oef/phase1";

const schemaRoot = join(import.meta.dir, "..", "schemas", "oef");
const load = (name: string) => JSON.parse(readFileSync(join(schemaRoot, name), "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
for (const name of [
  "actor-v1.schema.json",
  "artifact-ref-v1.schema.json",
  "command-envelope-v1.schema.json",
  "event-envelope-v1.schema.json",
  "evidence-record-v1.schema.json",
  "policy-pack-v1.schema.json",
  "task-contract-v1.schema.json",
  "task-v1.schema.json",
  "trace-span-v1.schema.json",
  "verdict-v1.schema.json",
  "workflow-definition-v1.schema.json",
]) ajv.addSchema(load(name));

const actor = { type: "system", id: "system:schema-test" } as const;
const hash = `sha256:${"a".repeat(64)}`;
const artifact = {
  artifact_id: "artifact:schema-test",
  content_hash: hash,
  media_type: "application/json",
  size_bytes: 12,
  classification: "internal" as const,
  retention_policy: "task-lifetime",
  created_by: actor,
  storage_key: `aa/aa/${"a".repeat(64)}`,
  deduplicated: false,
};
const evidence = {
  schema_version: 1 as const,
  evidence_id: "evidence:schema-test",
  task_id: "task:schema-test",
  contract_revision_id: "contract-revision:schema-test",
  criterion_key: "tests",
  type: "opencodex.test-result",
  status: "VERIFIED" as const,
  producer: actor,
  summary: "Tests pass.",
  artifacts: [artifact],
  environment: { repository_commit: "abc123" },
  created_at: "2026-07-23T12:00:00.000Z",
  verified_at: "2026-07-23T12:01:00.000Z",
};
const task = {
  schema_version: 1 as const,
  task_id: "task:schema-test",
  title: "Schema parity",
  status: "OPEN" as const,
  stage: "verification",
  active_contract_revision_id: "contract-revision:schema-test",
  workflow_ref: { id: "software-development", version: "1.0.0", hash },
  policy_pack_ref: { id: "safe-default", version: "1.0.0", hash },
  risk: { level: "low" as const, reasons: [] },
  created_by: { type: "human", id: "human:owner" } as const,
  created_at: "2026-07-23T12:00:00.000Z",
  updated_at: "2026-07-23T12:01:00.000Z",
  aggregate_version: 7,
};
const command = {
  schema_version: 1 as const,
  command_id: "command:schema-test",
  command_type: "BlockTask" as const,
  task_id: task.task_id,
  expected_aggregate_version: task.aggregate_version,
  actor: task.created_by,
  idempotency_key: "schema-test",
  payload: { reason: "Schema parity." },
};
const event = createDomainEvent({
  eventId: "event:schema-test",
  eventType: "task.blocked",
  aggregateId: task.task_id,
  aggregateVersion: 8,
  actor: task.created_by,
  traceId: "trace:schema-test",
  causationId: command.command_id,
  occurredAt: "2026-07-23T12:02:00.000Z",
  recordedAt: "2026-07-23T12:02:00.000Z",
  payload: command.payload,
  previousEventHash: hash,
});
const policy = {
  schema_version: 1 as const,
  policy_pack_id: "schema-policy",
  version: "1.0.0",
  rules: [{
    id: "require-contract",
    when: { operation: "transition" as const, transition_to: "planning" },
    require: { contract_status: "APPROVED" as const },
  }],
};
const contract = {
  schema_version: 1 as const,
  task_id: task.task_id,
  revision: 1,
  title: "Schema contract",
  goal: { summary: "Validate every public schema." },
  scope: { included: ["Schemas"], excluded: [] },
  constraints: [],
  acceptance_criteria: [{ key: "tests", statement: "Tests pass.", required_evidence: ["opencodex.test-result"] }],
  risk: { level: "low" as const, reasons: [] },
  budgets: { max_attempts: 1, max_parallel_writers: 1, max_cost_units: 1 },
  extensions: {},
};
const trace = {
  schema_version: 1 as const,
  trace_id: "trace:schema-test",
  span_id: "span:schema-test",
  parent_span_id: null,
  name: "schema-test",
  status: "ok" as const,
  started_at: "2026-07-23T12:00:00.000Z",
  ended_at: "2026-07-23T12:01:00.000Z",
  attributes: { component: "oef" },
};
const verdict = {
  schema_version: 1 as const,
  verdict_id: "verdict:schema-test",
  task_id: task.task_id,
  scope: { type: "task" as const, id: task.task_id },
  contract_revision_id: "contract-revision:schema-test",
  decision: "ACCEPT" as const,
  status: "CURRENT" as const,
  rationale: "All requirements pass.",
  evidence_refs: [evidence.evidence_id],
  missing_requirements: [],
  issued_by: actor,
  policy_pack_ref: task.policy_pack_ref,
  repository_commit: "abc123",
  dependency_hashes: {
    contract: hash,
    workflow: hash,
    policy: hash,
    evidence: [{ evidence_id: evidence.evidence_id, evidence_hash: hash }],
  },
  created_at: "2026-07-23T12:02:00.000Z",
};
const workflow = {
  schema_version: 1 as const,
  workflow_id: "schema-workflow",
  version: "1.0.0",
  stages: [{ id: "intake" }, { id: "done", terminal: true }],
  transitions: [{ from: "intake", to: "done", guards: ["verdict.accepted"] }],
};

const cases = [
  ["actor-v1.schema.json", actor, parseActor],
  ["artifact-ref-v1.schema.json", artifact, parseArtifactRef],
  ["command-envelope-v1.schema.json", command, parseCommandEnvelope],
  ["event-envelope-v1.schema.json", event, parseDomainEvent],
  ["evidence-record-v1.schema.json", evidence, parseEvidenceRecord],
  ["policy-pack-v1.schema.json", policy, parsePolicyPack],
  ["task-contract-v1.schema.json", contract, parseTaskContractDocument],
  ["task-v1.schema.json", task, parseTask],
  ["trace-span-v1.schema.json", trace, (value: unknown) => traceSpanSchema.parse(value)],
  ["verdict-v1.schema.json", verdict, parseVerdict],
  ["workflow-definition-v1.schema.json", workflow, parseWorkflowDefinition],
] as const;

const nestedInvalidCases = [
  ["actor-v1.schema.json", { ...actor, id: "" }, parseActor],
  ["artifact-ref-v1.schema.json", { ...artifact, created_by: { ...actor, unexpected: true } }, parseArtifactRef],
  ["command-envelope-v1.schema.json", { ...command, command_type: "UnknownCommand" }, parseCommandEnvelope],
  ["event-envelope-v1.schema.json", { ...event, aggregate: { ...event.aggregate, version: 0 } }, parseDomainEvent],
  ["evidence-record-v1.schema.json", { ...evidence, type: "not-namespaced" }, parseEvidenceRecord],
  ["policy-pack-v1.schema.json", {
    ...policy,
    rules: [{ ...policy.rules[0], when: { ...policy.rules[0].when, unexpected: true } }],
  }, parsePolicyPack],
  ["task-contract-v1.schema.json", {
    ...contract,
    acceptance_criteria: [{ ...contract.acceptance_criteria[0], required_evidence: ["not-namespaced"] }],
  }, parseTaskContractDocument],
  ["task-v1.schema.json", { ...task, workflow_ref: { ...task.workflow_ref, hash: "not-a-hash" } }, parseTask],
  ["trace-span-v1.schema.json", { ...trace, name: "" }, (value: unknown) => traceSpanSchema.parse(value)],
  ["verdict-v1.schema.json", {
    ...verdict,
    dependency_hashes: {
      ...verdict.dependency_hashes,
      evidence: [{ ...verdict.dependency_hashes.evidence[0], unexpected: true }],
    },
  }, parseVerdict],
  ["workflow-definition-v1.schema.json", {
    ...workflow,
    stages: [{ id: "Invalid" }, workflow.stages[1]],
  }, parseWorkflowDefinition],
] as const;

describe("Phase 1 public JSON schema parity", () => {
  test("accepts a representative runtime-valid document for every published schema", () => {
    for (const [name, value, parse] of cases) {
      expect(parse(value)).toEqual(value);
      expect(ajv.validate(`https://opencodex.local/schemas/oef/${name}`, value), `${name}: ${ajv.errorsText()}`).toBe(true);
    }
  });

  test("rejects the same missing, weak nested, and extra fields at both boundaries", () => {
    const invalidArtifact = { ...artifact, unexpected: true };
    const invalidEvidence = { ...evidence, verified_at: undefined };
    const invalidTask = { ...task, workflow_ref: { id: "software-development", version: "1.0.0" } };

    expect(() => parseArtifactRef(invalidArtifact)).toThrow();
    expect(() => parseEvidenceRecord(invalidEvidence)).toThrow();
    expect(() => parseTask(invalidTask)).toThrow();
    expect(ajv.validate("https://opencodex.local/schemas/oef/artifact-ref-v1.schema.json", invalidArtifact)).toBe(false);
    expect(ajv.validate("https://opencodex.local/schemas/oef/evidence-record-v1.schema.json", invalidEvidence)).toBe(false);
    expect(ajv.validate("https://opencodex.local/schemas/oef/task-v1.schema.json", invalidTask)).toBe(false);
  });

  test("rejects root extensions at both boundaries for every published schema", () => {
    for (const [name, value, parse] of cases) {
      const invalid = { ...value, unexpected_root_field: true };
      expect(() => parse(invalid)).toThrow();
      expect(ajv.validate(`https://opencodex.local/schemas/oef/${name}`, invalid), name).toBe(false);
    }
  });

  test("rejects generated nested constraint violations at both boundaries for every schema", () => {
    for (const [name, value, parse] of nestedInvalidCases) {
      expect(() => parse(value)).toThrow();
      expect(ajv.validate(`https://opencodex.local/schemas/oef/${name}`, value), `${name}: ${ajv.errorsText()}`).toBe(false);
    }
  });
});
