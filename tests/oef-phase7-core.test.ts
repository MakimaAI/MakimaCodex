import { describe, expect, test } from "bun:test";
import { canonicalSha256 } from "../src/oef";
import {
  BUILTIN_FAILURE_TYPES,
  ROOT_CAUSE_CONFIRMATION_CONDITIONS,
  SIGNATURE_PROFILE,
  addIncidentHypothesis,
  appendIncidentRevision,
  attachFailureObservation,
  confirmIncidentRootCause,
  correctFailureObservation,
  createFailureObservation,
  createIncident,
  createPlaybookCandidate,
  markIncidentRootCauseProbable,
  normalizeFailureText,
  parseFailureObservation,
  parseIncident,
  parsePlaybookCandidate,
  recordIncidentHypothesisContradiction,
  resolveIncidentHypothesis,
  resolveIncidentHypothesisContradiction,
  signFailure,
  supersedeIncidentRootCause,
  validateFailureTypeExtension,
  type FailureObservationInput,
  type FailureObservationCorrectionPatch,
  type Incident,
  type IncidentInput,
  type IncidentRevisionPatch,
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

function incidentInput(): IncidentInput {
  return {
    incident_id: "incident:one",
    title: "Codex runtime startup failure",
    status: "OPEN",
    stage: "INVESTIGATING",
    reproduction: { state: "REPRODUCIBLE", evidence_refs: ["artifact:reproduction"] },
    root_cause: { state: "UNCONFIRMED", statement: null, mechanism: null, evidence_refs: [], hypothesis_id: null, acceptance: null, adjudication_id: null, supersedes_adjudication_id: null },
    containment: { state: "NOT_STARTED", summary: null, evidence_refs: [] },
    severity: "SEV2",
    priority: "HIGH",
    confidence: 0.45,
    owner: human,
    scope,
    hypotheses: [],
    created_at: "2026-07-24T10:05:00.000Z",
    created_by: human,
  };
}

function incident(): Incident {
  return createIncident(incidentInput(), [createFailureObservation(observationInput())]);
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

  test("appends immutable hash-linked observation corrections", () => {
    const original = createFailureObservation(observationInput());
    const corrected = correctFailureObservation(original, {
      failure: { ...original.failure, summary: "RuntimeError in codex spawn returned HTTP 502" },
      provenance_ids: [...original.provenance_ids, "human-correction:one"],
    }, { expected_revision: 1, reason: "upstream status was transcribed incorrectly", actor: human, at: "2026-07-24T10:30:00.000Z" });
    expect(original.revision).toBe(1);
    expect(original.previous_observation_hash).toBeNull();
    expect(corrected.revision).toBe(2);
    expect(corrected.previous_observation_hash).toBe(original.canonical_hash);
    expect(corrected.previous_revision_id).toBe(original.revision_id);
    expect(corrected.observation_id).toBe(original.observation_id);
    expect(corrected.scope).toEqual(original.scope);
    expect(corrected.source_phase).toBe(original.source_phase);
    expect(corrected.task_id).toBe(original.task_id);
    expect(corrected.execution_id).toBe(original.execution_id);
    expect(corrected.attempt_id).toBe(original.attempt_id);
    expect(corrected.canonical_hash).not.toBe(original.canonical_hash);
    expect(original.failure.summary).toContain("503");
    expect(Object.isFrozen(corrected)).toBe(true);
    expect(() => correctFailureObservation(corrected, {}, { expected_revision: 1, reason: "stale correction", actor: human, at: "2026-07-24T10:31:00.000Z", resolve_predecessor: () => original })).toThrow("FAILURE_OBSERVATION_REVISION_CONFLICT");
    expect(() => correctFailureObservation(original, { scope: { type: "REPOSITORY", id: "repo:foreign" } } as FailureObservationCorrectionPatch, { expected_revision: 1, reason: "scope rewrite", actor: human, at: "2026-07-24T10:31:00.000Z" })).toThrow("FAILURE_OBSERVATION_CORRECTION_FORBIDDEN_FIELD");
    const inheritedCorrection = Object.create({ failure: { ...original.failure, summary: "inherited mutation" } }) as FailureObservationCorrectionPatch;
    expect(() => correctFailureObservation(original, inheritedCorrection, { expected_revision: 1, reason: "prototype rewrite", actor: human, at: "2026-07-24T10:31:00.000Z" })).toThrow("FAILURE_OBSERVATION_CORRECTION_FORBIDDEN_FIELD");
    expect(() => parseFailureObservation({ ...original, failure: { ...original.failure, summary: "mutated" } })).toThrow("FAILURE_OBSERVATION_HASH_MISMATCH");
  });

  test("rejects forged partial or incorrect observation lineage even with a recomputed hash", () => {
    const original = createFailureObservation(observationInput());
    const corrected = correctFailureObservation(original, {}, { expected_revision: 1, reason: "metadata correction", actor: human, at: "2026-07-24T10:30:00.000Z" });
    const { canonical_hash: _hash, ...payload } = corrected;
    const missingPrevious = { ...payload, previous_revision_id: null };
    expect(() => parseFailureObservation({ ...missingPrevious, canonical_hash: canonicalSha256(missingPrevious) }, () => original)).toThrow("Observation correction lineage is invalid");
    const wrongPrevious = { ...payload, previous_revision_id: "observation-revision:wrong" };
    expect(() => parseFailureObservation({ ...wrongPrevious, canonical_hash: canonicalSha256(wrongPrevious) }, () => original)).toThrow("Observation correction lineage is invalid");
  });

  test("requires and authenticates the actual predecessor for revised observation parsing", () => {
    const original = createFailureObservation(observationInput());
    const corrected = correctFailureObservation(original, { failure: { ...original.failure, summary: "Corrected HTTP 502" } }, { expected_revision: 1, reason: "corrected status", actor: human, at: "2026-07-24T10:30:00.000Z" });
    expect(() => parseFailureObservation(corrected)).toThrow("FAILURE_OBSERVATION_PREDECESSOR_REQUIRED");
    const forgedPredecessor = createFailureObservation(observationInput({ failure: { ...observationInput().failure, summary: "Forged predecessor" } }));
    expect(() => parseFailureObservation(corrected, () => forgedPredecessor)).toThrow("FAILURE_OBSERVATION_PREDECESSOR_MISMATCH");
    expect(parseFailureObservation(corrected, revisionId => revisionId === original.revision_id ? original : undefined)).toEqual(corrected);
  });
});

describe("Phase 7 signatures", () => {
  test("normalizes volatile noise without merging preserved failure context", () => {
    const first = "2026-07-24T10:00:00.123Z pid=1234 port 43123 temp C:\\Users\\Ada\\AppData\\Local\\Temp\\run-a\\out.log request_id=req_AbCd123456 UUID 123e4567-e89b-12d3-a456-426614174000 at 0x7ffdeadbeef file.ts:91:17 retry 2/5 HTTP 503 E_CONNRESET TypeError";
    const second = "2026-07-24T11:22:33.999Z pid=9988 port 51999 temp C:\\Users\\Ada\\AppData\\Local\\Temp\\run-b\\out.log request_id=req_ZyXw987654 UUID 987e6543-e21b-12d3-a456-426614174999 at 0x123abc file.ts:4:9 retry 4/5 HTTP 503 E_CONNRESET TypeError";
    expect(normalizeFailureText(first)).toBe(normalizeFailureText(second));

    const context = { scope, category: "RUNTIME" as const, code: "opencodex.runtime-startup-failed", provider: "openai", runtime: "codex", tool: "shell", operation: "spawn", http_status: 503, error_code: "E_CONNRESET", exception: "TypeError", symbol: "startRuntime", environment: { os: "windows", arch: "x64", runtime_version: "1.2.3" } };
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
    const base = { profile: SIGNATURE_PROFILE, scope, message: "RuntimeError HTTP 503", category: "RUNTIME" as const, code: "opencodex.runtime-startup-failed", provider: "openai", runtime: "codex", tool: "shell", operation: "spawn", http_status: 503, error_code: "E_CONNRESET", exception: "RuntimeError", symbol: "startRuntime" };
    const windows = signFailure({ ...base, environment: { os: "windows", arch: "x64", runtime_version: "1.2.3" } });
    const linux = signFailure({ ...base, environment: { os: "linux", arch: "x64", runtime_version: "1.2.3" } });
    expect(windows.profile).toEqual(SIGNATURE_PROFILE);
    expect(windows.environment_fingerprint).not.toBe(linux.environment_fingerprint);
    expect(() => signFailure({ ...base, profile: { ...SIGNATURE_PROFILE, version: "2.0.0" }, environment: { os: "linux", arch: "x64", runtime_version: "1.2.3" } })).toThrow("SIGNATURE_PROFILE_UNSUPPORTED");
  });

  test("normalizes parenthesized and line-only source locations without erasing codes", () => {
    expect(normalizeFailureText("at file.ts(91,17) HTTP 503 E_CONNRESET")).toBe("at file.ts:<line>:<column> HTTP 503 E_CONNRESET");
    expect(normalizeFailureText("at file.ts:91 HTTP 503 E_CONNRESET")).toBe("at file.ts:<line> HTTP 503 E_CONNRESET");
  });

  test("binds normalized and structural correlation identities to scope and environment", () => {
    const base = { profile: SIGNATURE_PROFILE, scope, message: "pid=1234 RuntimeError HTTP 503", category: "RUNTIME" as const, code: "opencodex.runtime-startup-failed", provider: "openai", runtime: "codex", tool: "shell", operation: "spawn", http_status: 503, error_code: "E_CONNRESET", exception: "RuntimeError", symbol: "startRuntime", environment: { os: "windows", arch: "x64", runtime_version: "1.2.3" } };
    const first = signFailure(base);
    const volatileOnly = signFailure({ ...base, message: "pid=9999 RuntimeError HTTP 503" });
    const foreignScope = signFailure({ ...base, scope: { type: "REPOSITORY", id: "repo:foreign" } });
    const otherRuntime = signFailure({ ...base, environment: { ...base.environment, runtime_version: "2.0.0" } });
    expect(volatileOnly.normalized_signature).toBe(first.normalized_signature);
    expect(volatileOnly.structural_signature).toBe(first.structural_signature);
    expect(foreignScope.exact_hash).not.toBe(first.exact_hash);
    expect(foreignScope.normalized_signature).not.toBe(first.normalized_signature);
    expect(foreignScope.structural_signature).not.toBe(first.structural_signature);
    expect(otherRuntime.normalized_signature).not.toBe(first.normalized_signature);
    expect(otherRuntime.structural_signature).not.toBe(first.structural_signature);
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
    expect(reopened.observation_ids).toContain(fresh.revision_id);
    expect(closed.status).toBe("CLOSED");
  });

  test("verifies actual observations when creating the initial incident", () => {
    const foreign = createFailureObservation(observationInput({ observation_id: "failure-observation:foreign-initial", scope: { type: "REPOSITORY", id: "repo:foreign" }, artifact_refs: [{ artifact_id: "artifact:repo:foreign:initial", artifact_hash: hashA }] }));
    expect(() => createIncident(incidentInput(), [])).toThrow("INCIDENT_OBSERVATION_REQUIRED");
    expect(() => createIncident(incidentInput(), [foreign])).toThrow("INCIDENT_SCOPE_MISMATCH");
  });

  test("limits active falsifiable hypotheses to five and prevents self-confirmation", () => {
    let current = incident();
    for (let index = 1; index <= 5; index += 1) {
      current = addIncidentHypothesis(current, {
        hypothesis_id: `hypothesis:${index}`,
        statement: `Candidate causal mechanism ${index}`,
        causal_mechanism: `Candidate ${index} corrupts runtime startup state`,
        falsifiable_prediction: `Removing candidate ${index} prevents the failure`,
        disproof_conditions: [`Failure persists without candidate ${index}`],
        proposed_by: { type: "agent", id: `agent:${index}` },
      }, { expected_revision: current.revision, actor: human, at: `2026-07-24T10:${10 + index}:00.000Z` });
    }
    expect(current.hypotheses.filter(item => item.status === "ACTIVE")).toHaveLength(5);
    expect(() => addIncidentHypothesis(current, { hypothesis_id: "hypothesis:6", statement: "Sixth cause", causal_mechanism: "Sixth causal mechanism", falsifiable_prediction: "Sixth prediction", disproof_conditions: ["Sixth disproof"], proposed_by: human }, { expected_revision: current.revision, actor: human, at: "2026-07-24T10:20:00.000Z" })).toThrow("INCIDENT_ACTIVE_HYPOTHESIS_LIMIT");
    expect(() => resolveIncidentHypothesis(current, "hypothesis:1", "SUPPORTED", { expected_revision: current.revision, actor: { type: "agent", id: "agent:1" }, at: "2026-07-24T10:21:00.000Z", evidence_refs: ["artifact:self"] })).toThrow("HYPOTHESIS_SELF_CONFIRMATION_FORBIDDEN");
    const resolved = resolveIncidentHypothesis(current, "hypothesis:1", "SUPPORTED", { expected_revision: current.revision, actor: verifier, at: "2026-07-24T10:21:00.000Z", evidence_refs: ["artifact:repo:makima:independent"] });
    expect(resolved.hypotheses.find(item => item.hypothesis_id === "hypothesis:1")?.status).toBe("SUPPORTED");
  });

  test("denies incomplete confirmation and approves only complete independent evidence", () => {
    const withHypothesis = addIncidentHypothesis(incident(), { hypothesis_id: "hypothesis:root", statement: "Runtime binary mismatch", causal_mechanism: "The incompatible runtime rejects the startup protocol", falsifiable_prediction: "Pinning the compatible binary removes startup failure", disproof_conditions: ["Pinned binary still fails"], proposed_by: { type: "agent", id: "agent:diagnoser" } }, { expected_revision: 1, actor: human, at: "2026-07-24T10:10:00.000Z" });
    const supported = resolveIncidentHypothesis(withHypothesis, "hypothesis:root", "SUPPORTED", { expected_revision: 2, actor: verifier, at: "2026-07-24T10:11:00.000Z", evidence_refs: ["artifact:repo:makima:support"] });
    const incomplete = ROOT_CAUSE_CONFIRMATION_CONDITIONS.slice(0, -1).map(condition => ({ condition, evidence_refs: [`artifact:repo:makima:${condition}`] }));
    expect(() => confirmIncidentRootCause(supported, { hypothesis_id: "hypothesis:root", statement: "Runtime binary mismatch", mechanism: "The incompatible runtime rejects the startup protocol", conditions: incomplete, authority: { kind: "INDEPENDENT_REVIEW", actor: verifier } }, { expected_revision: 3, at: "2026-07-24T10:20:00.000Z" })).toThrow("ROOT_CAUSE_CONFIRMATION_EVIDENCE_INCOMPLETE");
    const complete = ROOT_CAUSE_CONFIRMATION_CONDITIONS.map(condition => ({ condition, evidence_refs: [`artifact:repo:makima:${condition}`] }));
    expect(() => confirmIncidentRootCause(supported, { hypothesis_id: "hypothesis:root", statement: "Runtime binary mismatch", mechanism: "The incompatible runtime rejects the startup protocol", conditions: complete, authority: { kind: "INDEPENDENT_REVIEW", actor: { type: "agent", id: "agent:diagnoser" } } }, { expected_revision: 3, at: "2026-07-24T10:20:00.000Z" })).toThrow("ROOT_CAUSE_SELF_CONFIRMATION_FORBIDDEN");
    expect(() => confirmIncidentRootCause(supported, { hypothesis_id: "hypothesis:root", statement: "Runtime binary mismatch", mechanism: "The incompatible runtime rejects the startup protocol", conditions: complete, authority: { kind: "INDEPENDENT_REVIEW", actor: { type: "agent", id: "agent:other" } } }, { expected_revision: 3, at: "2026-07-24T10:20:00.000Z" })).toThrow("ROOT_CAUSE_CONFIRMATION_AUTHORITY_REQUIRED");
    const crossScope = complete.map((condition, index) => index === 0 ? { ...condition, evidence_refs: ["artifact:repo:foreign:evidence"] } : condition);
    expect(() => confirmIncidentRootCause(supported, { hypothesis_id: "hypothesis:root", statement: "Runtime binary mismatch", mechanism: "The incompatible runtime rejects the startup protocol", conditions: crossScope, authority: { kind: "INDEPENDENT_REVIEW", actor: verifier } }, { expected_revision: 3, at: "2026-07-24T10:20:00.000Z" })).toThrow("ROOT_CAUSE_EVIDENCE_SCOPE_MISMATCH");
    const nonReproducible = appendIncidentRevision(supported, { reproduction: { state: "NON_REPRODUCIBLE", evidence_refs: ["artifact:attempts"] } }, { expected_revision: 3, reason: "could not reproduce", actor: human, at: "2026-07-24T10:15:00.000Z" });
    expect(() => confirmIncidentRootCause(nonReproducible, { hypothesis_id: "hypothesis:root", statement: "Runtime binary mismatch", mechanism: "The incompatible runtime rejects the startup protocol", conditions: complete, authority: { kind: "INDEPENDENT_REVIEW", actor: verifier } }, { expected_revision: 4, at: "2026-07-24T10:20:00.000Z" })).toThrow("ROOT_CAUSE_CONFIRMATION_REPRODUCTION_REQUIRED");
    const confirmed = confirmIncidentRootCause(supported, { hypothesis_id: "hypothesis:root", statement: "Runtime binary mismatch", mechanism: "The incompatible runtime rejects the startup protocol", conditions: complete, authority: { kind: "INDEPENDENT_REVIEW", actor: verifier } }, { expected_revision: 3, at: "2026-07-24T10:20:00.000Z" });
    expect(confirmed.root_cause).toMatchObject({ state: "CONFIRMED", hypothesis_id: "hypothesis:root", statement: "Runtime binary mismatch" });
    expect(() => appendIncidentRevision(supported, { root_cause: confirmed.root_cause } as IncidentRevisionPatch, { expected_revision: 3, reason: "bypass gate", actor: human, at: "2026-07-24T10:20:00.000Z" })).toThrow("INCIDENT_REVISION_PATCH_FORBIDDEN_FIELD");
  });

  test("requires a supported hypothesis and exact statement binding for confirmation", () => {
    const active = addIncidentHypothesis(incident(), { hypothesis_id: "hypothesis:binding", statement: "Pinned runtime is incompatible", causal_mechanism: "The pinned runtime rejects protocol negotiation", falsifiable_prediction: "A compatible runtime starts", disproof_conditions: ["Compatible runtime still fails"], proposed_by: { type: "agent", id: "agent:binding" } }, { expected_revision: 1, actor: human, at: "2026-07-24T10:10:00.000Z" });
    const complete = ROOT_CAUSE_CONFIRMATION_CONDITIONS.map(condition => ({ condition, evidence_refs: [`artifact:repo:makima:${condition}`] }));
    expect(() => confirmIncidentRootCause(active, { hypothesis_id: "hypothesis:binding", statement: "Pinned runtime is incompatible", mechanism: "The pinned runtime rejects protocol negotiation", conditions: complete, authority: { kind: "INDEPENDENT_REVIEW", actor: verifier } }, { expected_revision: 2, at: "2026-07-24T10:20:00.000Z" })).toThrow("ROOT_CAUSE_HYPOTHESIS_NOT_SUPPORTED");
    const supported = resolveIncidentHypothesis(active, "hypothesis:binding", "SUPPORTED", { expected_revision: 2, actor: verifier, at: "2026-07-24T10:11:00.000Z", evidence_refs: ["artifact:repo:makima:support"] });
    expect(() => confirmIncidentRootCause(supported, { hypothesis_id: "hypothesis:binding", statement: "Different root cause", mechanism: "The pinned runtime rejects protocol negotiation", conditions: complete, authority: { kind: "INDEPENDENT_REVIEW", actor: verifier } }, { expected_revision: 3, at: "2026-07-24T10:20:00.000Z" })).toThrow("ROOT_CAUSE_HYPOTHESIS_BINDING_MISMATCH");
    expect(() => confirmIncidentRootCause(supported, { hypothesis_id: "hypothesis:binding", statement: "Pinned runtime is incompatible", mechanism: "A different mechanism", conditions: complete, authority: { kind: "INDEPENDENT_REVIEW", actor: verifier } }, { expected_revision: 3, at: "2026-07-24T10:20:00.000Z" })).toThrow("ROOT_CAUSE_HYPOTHESIS_BINDING_MISMATCH");
  });

  test("cannot confirm a rejected hypothesis", () => {
    const active = addIncidentHypothesis(incident(), { hypothesis_id: "hypothesis:rejected", statement: "Rejected cause", causal_mechanism: "Rejected mechanism changes startup", falsifiable_prediction: "Removing it starts runtime", disproof_conditions: ["Runtime still fails"], proposed_by: { type: "agent", id: "agent:rejected" } }, { expected_revision: 1, actor: human, at: "2026-07-24T10:10:00.000Z" });
    const rejected = resolveIncidentHypothesis(active, "hypothesis:rejected", "REJECTED", { expected_revision: 2, actor: verifier, at: "2026-07-24T10:11:00.000Z", evidence_refs: ["artifact:repo:makima:rejection"] });
    const complete = ROOT_CAUSE_CONFIRMATION_CONDITIONS.map(condition => ({ condition, evidence_refs: [`artifact:repo:makima:${condition}`] }));
    expect(() => confirmIncidentRootCause(rejected, { hypothesis_id: "hypothesis:rejected", statement: "Rejected cause", mechanism: "Rejected mechanism changes startup", conditions: complete, authority: { kind: "INDEPENDENT_REVIEW", actor: verifier } }, { expected_revision: 3, at: "2026-07-24T10:20:00.000Z" })).toThrow("ROOT_CAUSE_HYPOTHESIS_NOT_SUPPORTED");
  });

  test("requires incident-scoped evidence to support or reject hypotheses", () => {
    const supportCandidate = addIncidentHypothesis(incident(), { hypothesis_id: "hypothesis:foreign-support", statement: "Foreign support cause", causal_mechanism: "Foreign support changes startup", falsifiable_prediction: "Removing it starts runtime", disproof_conditions: ["Runtime still fails"], proposed_by: { type: "agent", id: "agent:foreign-support" } }, { expected_revision: 1, actor: human, at: "2026-07-24T10:10:00.000Z" });
    expect(() => resolveIncidentHypothesis(supportCandidate, "hypothesis:foreign-support", "SUPPORTED", { expected_revision: 2, actor: verifier, at: "2026-07-24T10:11:00.000Z", evidence_refs: ["artifact:repo:foreign:support"] })).toThrow("HYPOTHESIS_EVIDENCE_SCOPE_MISMATCH");
    const rejectCandidate = addIncidentHypothesis(incident(), { hypothesis_id: "hypothesis:unscoped-reject", statement: "Unscoped reject cause", causal_mechanism: "Unscoped reject changes startup", falsifiable_prediction: "Removing it starts runtime", disproof_conditions: ["Runtime still fails"], proposed_by: { type: "agent", id: "agent:unscoped-reject" } }, { expected_revision: 1, actor: human, at: "2026-07-24T10:10:00.000Z" });
    expect(() => resolveIncidentHypothesis(rejectCandidate, "hypothesis:unscoped-reject", "REJECTED", { expected_revision: 2, actor: verifier, at: "2026-07-24T10:11:00.000Z", evidence_refs: ["artifact:unscoped"] })).toThrow("HYPOTHESIS_EVIDENCE_SCOPE_MISMATCH");
  });

  test("rejects unresolved contradictory evidence before confirmation", () => {
    const active = addIncidentHypothesis(incident(), { hypothesis_id: "hypothesis:contradicted", statement: "Runtime protocol mismatch", causal_mechanism: "The runtime rejects an unsupported protocol version", falsifiable_prediction: "A compatible protocol starts", disproof_conditions: ["The same mismatch succeeds"], proposed_by: { type: "agent", id: "agent:contradicted" } }, { expected_revision: 1, actor: human, at: "2026-07-24T10:10:00.000Z" });
    const supported = resolveIncidentHypothesis(active, "hypothesis:contradicted", "SUPPORTED", { expected_revision: 2, actor: verifier, at: "2026-07-24T10:11:00.000Z", evidence_refs: ["artifact:repo:makima:support"] });
    const contradicted = recordIncidentHypothesisContradiction(supported, "hypothesis:contradicted", { contradiction_id: "contradiction:one", statement: "One matching runtime did start", evidence_refs: ["artifact:repo:makima:against"] }, { expected_revision: 3, actor: human, at: "2026-07-24T10:12:00.000Z" });
    const complete = ROOT_CAUSE_CONFIRMATION_CONDITIONS.map(condition => ({ condition, evidence_refs: [`artifact:repo:makima:${condition}`] }));
    const claim = { hypothesis_id: "hypothesis:contradicted", statement: "Runtime protocol mismatch", mechanism: "The runtime rejects an unsupported protocol version", conditions: complete, authority: { kind: "INDEPENDENT_REVIEW" as const, actor: verifier } };
    expect(() => confirmIncidentRootCause(contradicted, claim, { expected_revision: 4, at: "2026-07-24T10:20:00.000Z" })).toThrow("ROOT_CAUSE_UNRESOLVED_CONTRADICTION");
    const resolved = resolveIncidentHypothesisContradiction(contradicted, "hypothesis:contradicted", "contradiction:one", { expected_revision: 4, actor: verifier, at: "2026-07-24T10:13:00.000Z", rationale: "The successful run used a different protocol", evidence_refs: ["artifact:repo:makima:resolution"] });
    expect(confirmIncidentRootCause(resolved, claim, { expected_revision: 5, at: "2026-07-24T10:20:00.000Z" }).root_cause.state).toBe("CONFIRMED");
  });

  test("requires scoped evidence to resolve a contradiction", () => {
    const active = addIncidentHypothesis(incident(), { hypothesis_id: "hypothesis:resolution-evidence", statement: "Evidence cause", causal_mechanism: "Evidence mechanism changes startup", falsifiable_prediction: "Removing it starts runtime", disproof_conditions: ["Runtime still fails"], proposed_by: { type: "agent", id: "agent:resolution-evidence" } }, { expected_revision: 1, actor: human, at: "2026-07-24T10:10:00.000Z" });
    const supported = resolveIncidentHypothesis(active, "hypothesis:resolution-evidence", "SUPPORTED", { expected_revision: 2, actor: verifier, at: "2026-07-24T10:11:00.000Z", evidence_refs: ["artifact:repo:makima:support"] });
    const contradicted = recordIncidentHypothesisContradiction(supported, "hypothesis:resolution-evidence", { contradiction_id: "contradiction:resolution-evidence", statement: "Counterexample exists", evidence_refs: ["artifact:repo:makima:against"] }, { expected_revision: 3, actor: human, at: "2026-07-24T10:12:00.000Z" });
    expect(() => resolveIncidentHypothesisContradiction(contradicted, "hypothesis:resolution-evidence", "contradiction:resolution-evidence", { expected_revision: 4, actor: verifier, at: "2026-07-24T10:13:00.000Z", rationale: "Claimed resolution", evidence_refs: [] })).toThrow("HYPOTHESIS_CONTRADICTION_RESOLUTION_EVIDENCE_REQUIRED");
  });

  test("supersedes an accepted root cause only through a fresh gated adjudication", () => {
    const first = addIncidentHypothesis(incident(), { hypothesis_id: "hypothesis:first", statement: "First cause", causal_mechanism: "First mechanism changes startup", falsifiable_prediction: "Removing first cause starts runtime", disproof_conditions: ["Runtime fails without first cause"], proposed_by: { type: "agent", id: "agent:first" } }, { expected_revision: 1, actor: human, at: "2026-07-24T10:10:00.000Z" });
    const firstSupported = resolveIncidentHypothesis(first, "hypothesis:first", "SUPPORTED", { expected_revision: 2, actor: verifier, at: "2026-07-24T10:11:00.000Z", evidence_refs: ["artifact:repo:makima:first-support"] });
    const complete = ROOT_CAUSE_CONFIRMATION_CONDITIONS.map(condition => ({ condition, evidence_refs: [`artifact:repo:makima:first-${condition}`] }));
    const confirmed = confirmIncidentRootCause(firstSupported, { hypothesis_id: "hypothesis:first", statement: "First cause", mechanism: "First mechanism changes startup", conditions: complete, authority: { kind: "INDEPENDENT_REVIEW", actor: verifier } }, { expected_revision: 3, at: "2026-07-24T10:20:00.000Z" });
    const second = addIncidentHypothesis(confirmed, { hypothesis_id: "hypothesis:second", statement: "Second cause", causal_mechanism: "Second mechanism changes startup", falsifiable_prediction: "Removing second cause starts runtime", disproof_conditions: ["Runtime fails without second cause"], proposed_by: { type: "agent", id: "agent:second" } }, { expected_revision: 4, actor: human, at: "2026-07-24T10:21:00.000Z" });
    const secondSupported = resolveIncidentHypothesis(second, "hypothesis:second", "SUPPORTED", { expected_revision: 5, actor: verifier, at: "2026-07-24T10:22:00.000Z", evidence_refs: ["artifact:repo:makima:second-support"] });
    expect(() => confirmIncidentRootCause(secondSupported, { hypothesis_id: "hypothesis:second", statement: "Second cause", mechanism: "Second mechanism changes startup", conditions: complete, authority: { kind: "INDEPENDENT_REVIEW", actor: verifier } }, { expected_revision: 6, at: "2026-07-24T10:30:00.000Z" })).toThrow("ROOT_CAUSE_SUPERSESSION_REQUIRED");
    const superseded = supersedeIncidentRootCause(secondSupported, { hypothesis_id: "hypothesis:second", statement: "Second cause", mechanism: "Second mechanism changes startup", conditions: complete, authority: { kind: "INDEPENDENT_REVIEW", actor: verifier } }, { expected_revision: 6, at: "2026-07-24T10:30:00.000Z" });
    expect(superseded.root_cause.supersedes_adjudication_id).toBe(confirmed.root_cause.adjudication_id);
    expect(superseded.root_cause.adjudication_id).not.toBe(confirmed.root_cause.adjudication_id);
    expect(confirmed.root_cause.statement).toBe("First cause");
  });

  test("new contradictory evidence disputes and reopens the latest confirmed incident revision", () => {
    const active = addIncidentHypothesis(incident(), { hypothesis_id: "hypothesis:post-confirmation", statement: "Confirmed cause", causal_mechanism: "Confirmed mechanism changes startup", falsifiable_prediction: "Removing it starts runtime", disproof_conditions: ["Runtime still fails"], proposed_by: { type: "agent", id: "agent:post-confirmation" } }, { expected_revision: 1, actor: human, at: "2026-07-24T10:10:00.000Z" });
    const supported = resolveIncidentHypothesis(active, "hypothesis:post-confirmation", "SUPPORTED", { expected_revision: 2, actor: verifier, at: "2026-07-24T10:11:00.000Z", evidence_refs: ["artifact:repo:makima:support"] });
    const complete = ROOT_CAUSE_CONFIRMATION_CONDITIONS.map(condition => ({ condition, evidence_refs: [`artifact:repo:makima:${condition}`] }));
    const confirmed = confirmIncidentRootCause(supported, { hypothesis_id: "hypothesis:post-confirmation", statement: "Confirmed cause", mechanism: "Confirmed mechanism changes startup", conditions: complete, authority: { kind: "INDEPENDENT_REVIEW", actor: verifier } }, { expected_revision: 3, at: "2026-07-24T10:20:00.000Z" });
    const closed = appendIncidentRevision(confirmed, { status: "CLOSED", stage: "RESOLVED" }, { expected_revision: 4, reason: "accepted cause remediated", actor: human, at: "2026-07-24T10:21:00.000Z" });
    const disputed = recordIncidentHypothesisContradiction(closed, "hypothesis:post-confirmation", { contradiction_id: "contradiction:post-confirmation", statement: "The failure persisted after removing the cause", evidence_refs: ["artifact:repo:makima:post-confirmation"] }, { expected_revision: 5, actor: human, at: "2026-07-24T10:22:00.000Z" });
    expect(disputed).toMatchObject({ revision: 6, status: "OPEN", stage: "INVESTIGATING", root_cause: { state: "DISPUTED", adjudication_id: confirmed.root_cause.adjudication_id } });
    expect(disputed.root_cause.disputed_by_contradiction_ids).toContain("contradiction:post-confirmation");
    expect(disputed.previous_revision_hash).toBe(closed.revision_hash);
    expect(closed).toMatchObject({ status: "CLOSED", root_cause: { state: "CONFIRMED" } });
  });

  test("generic incident patches cannot replace adjudicated collections", () => {
    const current = incident();
    const options = { expected_revision: 1, reason: "bypass", actor: human, at: "2026-07-24T10:10:00.000Z" };
    expect(() => appendIncidentRevision(current, { root_cause: current.root_cause } as IncidentRevisionPatch, options)).toThrow("INCIDENT_REVISION_PATCH_FORBIDDEN_FIELD");
    expect(() => appendIncidentRevision(current, { hypotheses: [] } as IncidentRevisionPatch, options)).toThrow("INCIDENT_REVISION_PATCH_FORBIDDEN_FIELD");
    expect(() => appendIncidentRevision(current, { observation_ids: current.observation_ids } as IncidentRevisionPatch, options)).toThrow("INCIDENT_REVISION_PATCH_FORBIDDEN_FIELD");
    const withHypothesis = addIncidentHypothesis(current, { hypothesis_id: "hypothesis:prototype", statement: "Prototype cause", causal_mechanism: "Prototype mechanism changes startup", falsifiable_prediction: "Removing prototype cause starts runtime", disproof_conditions: ["Runtime still fails"], proposed_by: { type: "agent", id: "agent:prototype" } }, { expected_revision: 1, actor: human, at: "2026-07-24T10:09:00.000Z" });
    const inheritedPatch = Object.create({ hypotheses: [] }) as IncidentRevisionPatch;
    expect(() => appendIncidentRevision(withHypothesis, inheritedPatch, { ...options, expected_revision: 2 })).toThrow("INCIDENT_REVISION_PATCH_FORBIDDEN_FIELD");
    const hiddenPatch: IncidentRevisionPatch = {};
    Object.defineProperty(hiddenPatch, "root_cause", { value: current.root_cause, enumerable: false });
    expect(() => appendIncidentRevision(current, hiddenPatch, options)).toThrow("INCIDENT_REVISION_PATCH_FORBIDDEN_FIELD");
  });

  test("allows explicitly accepted probable external causes without claiming confirmation", () => {
    const external = appendIncidentRevision(incident(), { reproduction: { state: "NON_REPRODUCIBLE", evidence_refs: ["artifact:attempts"] } }, { expected_revision: 1, reason: "external incident cannot be replayed", actor: human, at: "2026-07-24T10:10:00.000Z" });
    expect(() => markIncidentRootCauseProbable(external, { statement: "External provider outage", mechanism: "The provider dropped startup requests", external_dependency: true, evidence_refs: ["artifact:repo:foreign:provider-status"], acceptance: { accepted_by: human, rationale: "Provider telemetry and timing align" } }, { expected_revision: 2, at: "2026-07-24T10:20:00.000Z" })).toThrow("ROOT_CAUSE_EVIDENCE_SCOPE_MISMATCH");
    const probable = markIncidentRootCauseProbable(external, { statement: "External provider outage", mechanism: "The provider dropped startup requests", external_dependency: true, evidence_refs: ["artifact:repo:makima:provider-status"], acceptance: { accepted_by: human, rationale: "Provider telemetry and timing align" } }, { expected_revision: 2, at: "2026-07-24T10:20:00.000Z" });
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
        mechanism: "Bypassed mechanism",
        evidence_refs: ["artifact:repo:makima:evidence"],
        hypothesis_id: null,
        acceptance: { kind: "INDEPENDENT_REVIEW", accepted_by: verifier, rationale: "claimed complete", accepted_at: "2026-07-24T10:05:00.000Z" },
        confirmation_conditions: [...ROOT_CAUSE_CONFIRMATION_CONDITIONS],
        adjudication_id: "root-cause-adjudication:bypass",
        supersedes_adjudication_id: null,
      },
      containment: base.containment,
      severity: base.severity,
      priority: base.priority,
      confidence: base.confidence,
      owner: base.owner,
      scope,
      hypotheses: [],
      created_at: "2026-07-24T10:05:00.000Z",
      created_by: human,
    }, [createFailureObservation(observationInput())])).toThrow("ROOT_CAUSE_INITIAL_STATE_FORBIDDEN");
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
