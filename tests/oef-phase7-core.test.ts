import { describe, expect, test } from "bun:test";
import {
  BUILTIN_FAILURE_TYPES,
  ROOT_CAUSE_CONFIRMATION_CONDITIONS,
  SIGNATURE_PROFILE,
  addIncidentHypothesis,
  appendIncidentRevision,
  attachFailureObservation,
  confirmIncidentRootCause,
  createFailureObservation,
  createIncident,
  createPlaybookCandidate,
  markIncidentRootCauseProbable,
  normalizeFailureText,
  parseFailureObservation,
  parseIncident,
  parsePlaybookCandidate,
  resolveIncidentHypothesis,
  signFailure,
  validateFailureTypeExtension,
  type FailureObservationInput,
  type Incident,
} from "../src/oef/phase7";

const hashA = `sha256:${"a".repeat(64)}`;
const human = { type: "human" as const, id: "human:incident-commander" };
const verifier = { type: "integration" as const, id: "verifier:independent" };
const scope = { type: "REPOSITORY" as const, id: "repo:makima" };

function observationInput(overrides: Partial<FailureObservationInput> = {}): FailureObservationInput {
  return {
    observation_id: "failure-observation:one",
    provenance_ids: ["runtime-event:one", "verifier-result:one"],
    source_phase: 2,
    task_id: "task:one",
    execution_id: "execution:one",
    attempt_id: "attempt:one",
    artifact_refs: [{ artifact_id: "artifact:repo:makima:one", artifact_hash: hashA }],
    scope,
    failure: {
      category: "RUNTIME",
      code: "opencodex.runtime-startup-failed",
      summary: "RuntimeError in codex spawn returned HTTP 503",
    },
    environment: {
      provider: "openai",
      runtime: "codex",
      runtime_version: "1.2.3",
      tool: "shell",
      operation: "spawn",
      os: "windows",
      arch: "x64",
    },
    sensitivity: "INTERNAL",
    redaction: { state: "REDACTED", profile_version: "1.0.0" },
    observed_at: "2026-07-24T10:00:00.000Z",
    ...overrides,
  };
}

function incident(): Incident {
  return createIncident({
    incident_id: "incident:one",
    title: "Codex runtime startup failure",
    status: "OPEN",
    stage: "INVESTIGATING",
    reproduction: { state: "REPRODUCIBLE", evidence_refs: ["artifact:reproduction"] },
    root_cause: { state: "UNCONFIRMED", statement: null, evidence_refs: [], hypothesis_id: null, acceptance: null },
    containment: { state: "NOT_STARTED", summary: null, evidence_refs: [] },
    severity: "SEV2",
    priority: "HIGH",
    confidence: 0.45,
    owner: human,
    scope,
    observation_ids: ["failure-observation:one"],
    hypotheses: [],
    created_at: "2026-07-24T10:05:00.000Z",
    created_by: human,
  });
}

describe("Phase 7 failure observations and taxonomy", () => {
  test("creates a strict immutable observation with a verified canonical hash", () => {
    const input = observationInput();
    const value = createFailureObservation(input);
    expect(value.canonical_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(Object.isFrozen(value)).toBe(true);
    expect(Object.isFrozen(value.failure)).toBe(true);
    input.failure.summary = "changed after creation";
    expect(value.failure.summary).not.toBe(input.failure.summary);
    expect(parseFailureObservation(value)).toEqual(value);
    expect(() => parseFailureObservation({ ...value, canonical_hash: hashA })).toThrow("FAILURE_OBSERVATION_HASH_MISMATCH");
    expect(() => createFailureObservation({ ...observationInput(), raw_log: "forbidden" } as FailureObservationInput)).toThrow();
    expect(() => createFailureObservation({ ...observationInput(), failure: { ...observationInput().failure, summary: "api_key=abcdefghijklmnop" } })).toThrow("FAILURE_OBSERVATION_SECRET_REJECTED");
    expect(() => createFailureObservation({ ...observationInput(), artifact_refs: [{ artifact_id: "artifact:repo:foreign:one", artifact_hash: hashA }] })).toThrow("FAILURE_OBSERVATION_ARTIFACT_SCOPE_MISMATCH");
  });

  test("provides versioned built-ins and prevents extensions from shadowing opencodex", () => {
    expect(BUILTIN_FAILURE_TYPES).toContain("opencodex.runtime-startup-failed");
    expect(BUILTIN_FAILURE_TYPES).toContain("opencodex.secret-leak-detected");
    expect(validateFailureTypeExtension({ taxonomy_version: "1.0.0", type: "acme.gpu-driver-failed" }).type).toBe("acme.gpu-driver-failed");
    expect(() => validateFailureTypeExtension({ taxonomy_version: "1.0.0", type: "opencodex.custom-failure" })).toThrow("FAILURE_TAXONOMY_SHADOW_FORBIDDEN");
    expect(() => validateFailureTypeExtension({ taxonomy_version: "2.0.0", type: "acme.gpu-driver-failed" })).toThrow("FAILURE_TAXONOMY_VERSION_UNSUPPORTED");
  });
});

describe("Phase 7 signatures", () => {
  test("normalizes volatile noise without merging preserved failure context", () => {
    const first = "2026-07-24T10:00:00.123Z pid=1234 port 43123 temp C:\\Users\\Ada\\AppData\\Local\\Temp\\run-a\\out.log request_id=req_AbCd123456 UUID 123e4567-e89b-12d3-a456-426614174000 at 0x7ffdeadbeef file.ts:91:17 retry 2/5 HTTP 503 E_CONNRESET TypeError";
    const second = "2026-07-24T11:22:33.999Z pid=9988 port 51999 temp C:\\Users\\Ada\\AppData\\Local\\Temp\\run-b\\out.log request_id=req_ZyXw987654 UUID 987e6543-e21b-12d3-a456-426614174999 at 0x123abc file.ts:4:9 retry 4/5 HTTP 503 E_CONNRESET TypeError";
    expect(normalizeFailureText(first)).toBe(normalizeFailureText(second));

    const context = { category: "RUNTIME" as const, code: "opencodex.runtime-startup-failed", provider: "openai", runtime: "codex", tool: "shell", operation: "spawn", http_status: 503, error_code: "E_CONNRESET", exception: "TypeError", symbol: "startRuntime", environment: { os: "windows", arch: "x64", runtime_version: "1.2.3" } };
    const signedA = signFailure({ profile: SIGNATURE_PROFILE, message: first, ...context });
    const signedB = signFailure({ profile: SIGNATURE_PROFILE, message: second, ...context });
    expect(signedA.exact_hash).not.toBe(signedB.exact_hash);
    expect(signedA.normalized_signature).toBe(signedB.normalized_signature);
    expect(signedA.structural_signature).toBe(signedB.structural_signature);
    expect(signedA.normalized_text).toContain("HTTP 503");
    expect(signedA.normalized_text).toContain("E_CONNRESET");
    expect(signedA.normalized_text).toContain("TypeError");
    expect(signFailure({ profile: SIGNATURE_PROFILE, message: first, ...context, http_status: 429 }).normalized_signature).not.toBe(signedA.normalized_signature);
    expect(signFailure({ profile: SIGNATURE_PROFILE, message: first, ...context, operation: "resume" }).normalized_signature).not.toBe(signedA.normalized_signature);
    expect(signFailure({ profile: SIGNATURE_PROFILE, message: first, ...context, provider: "anthropic" }).normalized_signature).not.toBe(signedA.normalized_signature);
  });

  test("versions profiles and distinguishes environments", () => {
    const base = { profile: SIGNATURE_PROFILE, message: "RuntimeError HTTP 503", category: "RUNTIME" as const, code: "opencodex.runtime-startup-failed", provider: "openai", runtime: "codex", tool: "shell", operation: "spawn", http_status: 503, error_code: "E_CONNRESET", exception: "RuntimeError", symbol: "startRuntime" };
    const windows = signFailure({ ...base, environment: { os: "windows", arch: "x64", runtime_version: "1.2.3" } });
    const linux = signFailure({ ...base, environment: { os: "linux", arch: "x64", runtime_version: "1.2.3" } });
    expect(windows.profile).toEqual(SIGNATURE_PROFILE);
    expect(windows.environment_fingerprint).not.toBe(linux.environment_fingerprint);
    expect(() => signFailure({ ...base, profile: { ...SIGNATURE_PROFILE, version: "2.0.0" }, environment: { os: "linux", arch: "x64", runtime_version: "1.2.3" } })).toThrow("SIGNATURE_PROFILE_UNSUPPORTED");
  });
});

describe("Phase 7 incident revisions and authority", () => {
  test("keeps lifecycle dimensions separate and appends monotonic hash-linked revisions", () => {
    const initial = incident();
    expect(initial).toMatchObject({ status: "OPEN", stage: "INVESTIGATING", severity: "SEV2", priority: "HIGH", confidence: 0.45 });
    expect(initial.revision_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(Object.isFrozen(initial)).toBe(true);
    expect(Object.isFrozen(initial.root_cause)).toBe(true);
    expect(() => parseIncident({ ...initial, revision_hash: hashA })).toThrow("INCIDENT_REVISION_HASH_MISMATCH");
    const next = appendIncidentRevision(initial, { severity: "SEV1", priority: "URGENT", confidence: 0.8, containment: { state: "IN_PROGRESS", summary: "Traffic diverted", evidence_refs: ["artifact:containment"] } }, { expected_revision: 1, reason: "impact increased", actor: human, at: "2026-07-24T10:10:00.000Z" });
    expect(next.revision).toBe(2);
    expect(next.previous_revision_hash).toBe(initial.revision_hash);
    expect(next.revision_hash).not.toBe(initial.revision_hash);
    expect(initial.severity).toBe("SEV2");
    expect(() => appendIncidentRevision(initial, {}, { expected_revision: 2, reason: "stale", actor: human, at: "2026-07-24T10:11:00.000Z" })).toThrow("INCIDENT_REVISION_CONFLICT");
  });

  test("rejects cross-scope observations and reopens a closed incident by revision", () => {
    const closed = appendIncidentRevision(incident(), { status: "CLOSED", stage: "RESOLVED" }, { expected_revision: 1, reason: "resolved", actor: human, at: "2026-07-24T10:10:00.000Z" });
    const foreign = createFailureObservation(observationInput({ observation_id: "failure-observation:foreign", scope: { type: "REPOSITORY", id: "repo:foreign" }, artifact_refs: [{ artifact_id: "artifact:repo:foreign:one", artifact_hash: hashA }] }));
    expect(() => attachFailureObservation(closed, foreign, { expected_revision: 2, actor: human, at: "2026-07-24T10:20:00.000Z" })).toThrow("INCIDENT_SCOPE_MISMATCH");
    const fresh = createFailureObservation(observationInput({ observation_id: "failure-observation:fresh", observed_at: "2026-07-24T10:19:00.000Z" }));
    const reopened = attachFailureObservation(closed, fresh, { expected_revision: 2, actor: human, at: "2026-07-24T10:20:00.000Z" });
    expect(reopened).toMatchObject({ revision: 3, status: "OPEN", stage: "INVESTIGATING" });
    expect(reopened.observation_ids).toContain(fresh.observation_id);
    expect(closed.status).toBe("CLOSED");
  });

  test("limits active falsifiable hypotheses to five and prevents self-confirmation", () => {
    let current = incident();
    for (let index = 1; index <= 5; index += 1) {
      current = addIncidentHypothesis(current, {
        hypothesis_id: `hypothesis:${index}`,
        statement: `Candidate causal mechanism ${index}`,
        falsifiable_prediction: `Removing candidate ${index} prevents the failure`,
        disproof_conditions: [`Failure persists without candidate ${index}`],
        proposed_by: { type: "agent", id: `agent:${index}` },
      }, { expected_revision: current.revision, actor: human, at: `2026-07-24T10:${10 + index}:00.000Z` });
    }
    expect(current.hypotheses.filter(item => item.status === "ACTIVE")).toHaveLength(5);
    expect(() => addIncidentHypothesis(current, { hypothesis_id: "hypothesis:6", statement: "Sixth cause", falsifiable_prediction: "Sixth prediction", disproof_conditions: ["Sixth disproof"], proposed_by: human }, { expected_revision: current.revision, actor: human, at: "2026-07-24T10:20:00.000Z" })).toThrow("INCIDENT_ACTIVE_HYPOTHESIS_LIMIT");
    expect(() => resolveIncidentHypothesis(current, "hypothesis:1", "SUPPORTED", { expected_revision: current.revision, actor: { type: "agent", id: "agent:1" }, at: "2026-07-24T10:21:00.000Z", evidence_refs: ["artifact:self"] })).toThrow("HYPOTHESIS_SELF_CONFIRMATION_FORBIDDEN");
    const resolved = resolveIncidentHypothesis(current, "hypothesis:1", "SUPPORTED", { expected_revision: current.revision, actor: verifier, at: "2026-07-24T10:21:00.000Z", evidence_refs: ["artifact:independent"] });
    expect(resolved.hypotheses.find(item => item.hypothesis_id === "hypothesis:1")?.status).toBe("SUPPORTED");
  });

  test("denies incomplete confirmation and approves only complete independent evidence", () => {
    const withHypothesis = addIncidentHypothesis(incident(), { hypothesis_id: "hypothesis:root", statement: "Runtime binary mismatch", falsifiable_prediction: "Pinning the compatible binary removes startup failure", disproof_conditions: ["Pinned binary still fails"], proposed_by: { type: "agent", id: "agent:diagnoser" } }, { expected_revision: 1, actor: human, at: "2026-07-24T10:10:00.000Z" });
    const incomplete = ROOT_CAUSE_CONFIRMATION_CONDITIONS.slice(0, -1).map(condition => ({ condition, evidence_refs: [`artifact:repo:makima:${condition}`] }));
    expect(() => confirmIncidentRootCause(withHypothesis, { hypothesis_id: "hypothesis:root", statement: "Runtime binary mismatch", conditions: incomplete, authority: { kind: "INDEPENDENT_REVIEW", actor: verifier } }, { expected_revision: 2, at: "2026-07-24T10:20:00.000Z" })).toThrow("ROOT_CAUSE_CONFIRMATION_EVIDENCE_INCOMPLETE");
    const complete = ROOT_CAUSE_CONFIRMATION_CONDITIONS.map(condition => ({ condition, evidence_refs: [`artifact:repo:makima:${condition}`] }));
    expect(() => confirmIncidentRootCause(withHypothesis, { hypothesis_id: "hypothesis:root", statement: "Runtime binary mismatch", conditions: complete, authority: { kind: "INDEPENDENT_REVIEW", actor: { type: "agent", id: "agent:diagnoser" } } }, { expected_revision: 2, at: "2026-07-24T10:20:00.000Z" })).toThrow("ROOT_CAUSE_SELF_CONFIRMATION_FORBIDDEN");
    expect(() => confirmIncidentRootCause(withHypothesis, { hypothesis_id: "hypothesis:root", statement: "Runtime binary mismatch", conditions: complete, authority: { kind: "INDEPENDENT_REVIEW", actor: { type: "agent", id: "agent:other" } } }, { expected_revision: 2, at: "2026-07-24T10:20:00.000Z" })).toThrow("ROOT_CAUSE_CONFIRMATION_AUTHORITY_REQUIRED");
    const crossScope = complete.map((condition, index) => index === 0 ? { ...condition, evidence_refs: ["artifact:repo:foreign:evidence"] } : condition);
    expect(() => confirmIncidentRootCause(withHypothesis, { hypothesis_id: "hypothesis:root", statement: "Runtime binary mismatch", conditions: crossScope, authority: { kind: "INDEPENDENT_REVIEW", actor: verifier } }, { expected_revision: 2, at: "2026-07-24T10:20:00.000Z" })).toThrow("ROOT_CAUSE_EVIDENCE_SCOPE_MISMATCH");
    const nonReproducible = appendIncidentRevision(withHypothesis, { reproduction: { state: "NON_REPRODUCIBLE", evidence_refs: ["artifact:attempts"] } }, { expected_revision: 2, reason: "could not reproduce", actor: human, at: "2026-07-24T10:15:00.000Z" });
    expect(() => confirmIncidentRootCause(nonReproducible, { hypothesis_id: "hypothesis:root", statement: "Runtime binary mismatch", conditions: complete, authority: { kind: "INDEPENDENT_REVIEW", actor: verifier } }, { expected_revision: 3, at: "2026-07-24T10:20:00.000Z" })).toThrow("ROOT_CAUSE_CONFIRMATION_REPRODUCTION_REQUIRED");
    const confirmed = confirmIncidentRootCause(withHypothesis, { hypothesis_id: "hypothesis:root", statement: "Runtime binary mismatch", conditions: complete, authority: { kind: "INDEPENDENT_REVIEW", actor: verifier } }, { expected_revision: 2, at: "2026-07-24T10:20:00.000Z" });
    expect(confirmed.root_cause).toMatchObject({ state: "CONFIRMED", hypothesis_id: "hypothesis:root", statement: "Runtime binary mismatch" });
    expect(() => appendIncidentRevision(withHypothesis, { root_cause: confirmed.root_cause }, { expected_revision: 2, reason: "bypass gate", actor: human, at: "2026-07-24T10:20:00.000Z" })).toThrow("ROOT_CAUSE_CONFIRMATION_GATE_REQUIRED");
  });

  test("allows explicitly accepted probable external causes without claiming confirmation", () => {
    const external = appendIncidentRevision(incident(), { reproduction: { state: "NON_REPRODUCIBLE", evidence_refs: ["artifact:attempts"] } }, { expected_revision: 1, reason: "external incident cannot be replayed", actor: human, at: "2026-07-24T10:10:00.000Z" });
    expect(() => markIncidentRootCauseProbable(external, { statement: "External provider outage", external_dependency: true, evidence_refs: ["artifact:repo:foreign:provider-status"], acceptance: { accepted_by: human, rationale: "Provider telemetry and timing align" } }, { expected_revision: 2, at: "2026-07-24T10:20:00.000Z" })).toThrow("ROOT_CAUSE_EVIDENCE_SCOPE_MISMATCH");
    const probable = markIncidentRootCauseProbable(external, { statement: "External provider outage", external_dependency: true, evidence_refs: ["artifact:repo:makima:provider-status"], acceptance: { accepted_by: human, rationale: "Provider telemetry and timing align" } }, { expected_revision: 2, at: "2026-07-24T10:20:00.000Z" });
    expect(probable.root_cause).toMatchObject({ state: "PROBABLE", statement: "External provider outage" });
    expect(probable.root_cause.state).not.toBe("CONFIRMED");
  });

  test("requires authority gates even for the first incident revision", () => {
    const base = incident();
    expect(() => createIncident({
      incident_id: "incident:bypass-confirmed",
      title: base.title,
      status: "OPEN",
      stage: "INVESTIGATING",
      reproduction: base.reproduction,
      root_cause: {
        state: "CONFIRMED",
        statement: "Bypassed conclusion",
        evidence_refs: ["artifact:repo:makima:evidence"],
        hypothesis_id: null,
        acceptance: { kind: "INDEPENDENT_REVIEW", accepted_by: verifier, rationale: "claimed complete", accepted_at: "2026-07-24T10:05:00.000Z" },
        confirmation_conditions: [...ROOT_CAUSE_CONFIRMATION_CONDITIONS],
      },
      containment: base.containment,
      severity: base.severity,
      priority: base.priority,
      confidence: base.confidence,
      owner: base.owner,
      scope,
      observation_ids: base.observation_ids,
      hypotheses: [],
      created_at: "2026-07-24T10:05:00.000Z",
      created_by: human,
    })).toThrow("ROOT_CAUSE_INITIAL_STATE_FORBIDDEN");
  });
});

describe("Phase 7 playbook candidate authority", () => {
  test("can represent only a candidate and never an active skill", () => {
    const candidate = createPlaybookCandidate({ candidate_id: "playbook-candidate:one", source_incident_id: "incident:one", scope, title: "Pin compatible runtime", trigger_signature: hashA, steps: ["Verify the runtime version", "Pin a compatible runtime"], created_at: "2026-07-24T11:00:00.000Z", created_by: human });
    expect(candidate.status).toBe("CANDIDATE");
    expect(Object.isFrozen(candidate)).toBe(true);
    expect(() => parsePlaybookCandidate({ ...candidate, status: "ACTIVE" })).toThrow();
    expect(() => parsePlaybookCandidate({ ...candidate, skill_id: "skill:active" })).toThrow();
  });
});
