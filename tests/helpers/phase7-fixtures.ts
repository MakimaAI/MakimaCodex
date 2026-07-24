export const PHASE7_HASH = `sha256:${"a".repeat(64)}`;
export const PHASE7_COMMIT = "1".repeat(40);
export const PHASE7_TIME = "2026-07-24T10:00:00.000Z";

export function phase2FailureEnvelope(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const scopeId = String(overrides.scope_id ?? "repo:makima");
  const eventId = String(overrides.event_id ?? "event:phase7-403-one");
  const artifactId = `artifact:${scopeId}:phase2-403`;
  const manifest = {
    execution_manifest_version: 1,
    task: { id: "task:phase7-demo", contract_hash: PHASE7_HASH },
    assignment: { id: "assignment:phase7-demo", revision: 1, hash: PHASE7_HASH },
    workflow: { id: "workflow:phase7", version: "1.0.0", hash: PHASE7_HASH },
    policy: { id: "policy:phase7", version: "1.0.0", hash: PHASE7_HASH },
    source: { repository: scopeId, base_commit: PHASE7_COMMIT, tree_hash: PHASE7_HASH },
    runtime: { id: "codex", binary_version: "2.4.1", adapter_version: "1.0.0", protocol_version: 1 },
    model: { provider: "openai", resolved_id: "gpt-phase7" },
    environment: { provider: "openai", fingerprint: PHASE7_HASH },
    context: { bundle_hash: PHASE7_HASH, prompt_hash: PHASE7_HASH },
    started_at: PHASE7_TIME,
  };
  const failureType = String(overrides.failure_type ?? "AUTHORIZATION_FAILED");
  const envelopeOverrides = Object.fromEntries(Object.entries(overrides).filter(([key]) => !["scope_id", "failure_type"].includes(key)));
  const failure = {
    schema_version: 1,
    failure_id: `failure:${eventId.replace(/[^A-Za-z0-9._:@/-]/g, "-")}`,
    type: failureType,
    category: failureType === "SECRET_LEAK_DETECTED" ? "policy" : "provider",
    retryability: "never",
    scope: { runtime: true, model: false, account: true, task: true },
    safe_actions: ["inspect-permissions"],
    unsafe_actions: ["change-production-permissions"],
    signature: PHASE7_HASH,
    evidence_refs: [artifactId],
  };
  return {
    schema_version: 1,
    event_id: eventId,
    task_id: "task:phase7-demo",
    execution_id: "execution:phase7-demo",
    attempt_id: "attempt:phase7-demo-1",
    scope: { type: "REPOSITORY", id: scopeId },
    failure,
    execution_manifest: manifest,
    artifact_hashes: { [artifactId]: PHASE7_HASH },
    message: overrides.message ?? "HTTP 403 forbidden while checking repository permissions request_id=req_123456",
    environment: { os: "windows", arch: "x64", tool: "codex", operation: "provider-request" },
    http_status: 403,
    error_code: "permission_denied",
    exception: null,
    symbol: "provider.request",
    sensitivity: "INTERNAL",
    observed_at: overrides.observed_at ?? PHASE7_TIME,
    ...envelopeOverrides,
  };
}

export function reproductionManifest(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    manifest_id: "reproduction-manifest:phase7-403",
    incident_id: "incident:phase7-403",
    scope: { type: "REPOSITORY", id: "repo:makima" },
    source_commit: PHASE7_COMMIT,
    image_digest: PHASE7_HASH,
    seed: 403,
    attempts: 5,
    budgets: { timeout_ms: 30_000, max_output_bytes: 64_000, max_memory_mb: 512 },
    production_access: false,
    secret_refs: [],
    network_access: false,
    phase2_adapter: { id: "phase2-local-replay", version: "1.0.0" },
    created_at: PHASE7_TIME,
    ...overrides,
  };
}
