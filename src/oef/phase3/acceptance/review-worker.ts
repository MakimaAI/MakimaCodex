import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const SOURCE_PATH = "src/providers/clinepass/error-classifier.ts";
const TEST_PATH = "tests/providers/clinepass/error-classifier.test.ts";

export function buildDeterministicReviewResult(input: {
  source_root: string;
  review_unit_id: string;
  snapshot_hash: string;
  review_type: string;
}) {
  const content = readFileSync(join(input.source_root, SOURCE_PATH), "utf8");
  const lines = content.split(/\r?\n/);
  const regressionLine = lines.findIndex(line =>
    line.includes("status === 429 || status === 403") && line.includes("rate-limit"),
  );
  const hasFinding = regressionLine >= 0 && input.review_type !== "opencodex.security";
  const fileHash = `sha256:${createHash("sha256").update(content).digest("hex")}`;
  return {
    schema_version: 1,
    review_unit_id: input.review_unit_id,
    snapshot_hash: input.snapshot_hash,
    decision: { recommendation: hasFinding ? "changes-requested" : "pass" },
    summary: hasFinding
      ? "HTTP 403 violates the approved authentication contract."
      : "No blocking finding in this review scope.",
    findings: hasFinding ? [{
      finding_key: input.review_type === "opencodex.spec-compliance" ? "FIND-SPEC-403" : "FIND-QUALITY-403",
      category: "correctness",
      proposed_severity: "HIGH",
      confidence: 0.97,
      claim: "HTTP 403 is classified as a rate limit instead of an authentication failure.",
      impact: "Authentication failures can rotate accounts and hide invalid credentials.",
      contract_refs: ["AC-429"],
      code_locations: [{ path: SOURCE_PATH, start_line: regressionLine + 1, end_line: regressionLine + 1, file_hash: fileHash }],
      evidence_refs: ["evidence:test-403"],
      verification: { reproducible: true, reproduction_steps: [`Inspect ${SOURCE_PATH} and run ${TEST_PATH}`] },
      recommendation: "Separate 429 rate limits from 401/403 authentication failures and add regression tests.",
    }] : [],
    unanswered_questions: [],
    requested_evidence: [],
  };
}

function requiredArgument(arguments_: string[], name: string): string {
  const index = arguments_.indexOf(name);
  const value = index >= 0 ? arguments_[index + 1] : undefined;
  if (!value) throw new Error(`Phase 3 review worker requires ${name}`);
  return value;
}

async function measureSandboxIsolation() {
  let networkDenied = false;
  let networkError = null;
  try {
    await fetch("http://1.1.1.1/", { signal: AbortSignal.timeout(1_500) });
  } catch (error) {
    networkDenied = true;
    networkError = error instanceof Error ? error.name : "unknown";
  }
  let hostCredentialsUnmounted = false;
  let credentialError = null;
  try {
    readFileSync("/root/.docker/config.json", "utf8");
  } catch (error) {
    hostCredentialsUnmounted = true;
    credentialError = error && typeof error === "object" && "code" in error ? String(error.code) : "unknown";
  }
  return {
    network_denied: networkDenied,
    host_credentials_unmounted: hostCredentialsUnmounted,
    network_error: networkError,
    credential_error: credentialError,
  };
}

async function main() {
  const arguments_ = process.argv.slice(2);
  const context = JSON.parse(readFileSync(0, "utf8")) as {
    snapshot_hash?: unknown;
    review_unit?: { id?: unknown };
  };
  const expectedUnit = requiredArgument(arguments_, "--review-unit-id");
  const expectedSnapshot = requiredArgument(arguments_, "--snapshot-hash");
  if (context.review_unit?.id !== expectedUnit || context.snapshot_hash !== expectedSnapshot) {
    throw new Error("REVIEW_CONTEXT_BINDING_MISMATCH");
  }
  const probe = await measureSandboxIsolation();
  process.stderr.write(`REVIEW_SANDBOX_PROBE:${JSON.stringify(probe)}\n`);
  if (!probe.network_denied || !probe.host_credentials_unmounted) {
    throw new Error("REVIEW_SANDBOX_PROBE_FAILED");
  }
  const result = buildDeterministicReviewResult({
    source_root: requiredArgument(arguments_, "--source"),
    review_unit_id: expectedUnit,
    snapshot_hash: expectedSnapshot,
    review_type: requiredArgument(arguments_, "--review-type"),
  });
  process.stdout.write(JSON.stringify(result));
}

if (import.meta.main) {
  void main().catch(error => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
