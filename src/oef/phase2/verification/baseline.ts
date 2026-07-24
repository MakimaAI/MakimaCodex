export interface KnownBaselineFailure {
  test_id: string;
  signature: string;
  approved_until: string;
  rationale: string;
}

export function compareWithBaseline(input: {
  baseline_failure_signatures: string[];
  current_failure_signatures: string[];
  known_failures: KnownBaselineFailure[];
  now: string;
}): { status: "CLEAN" | "KNOWN_BASELINE_FAILURES_ONLY" | "NEW_REGRESSION" | "KNOWN_FAILURE_EXPIRED"; new_signatures: string[]; expired_signatures: string[] } {
  const baseline = new Set(input.baseline_failure_signatures);
  const known = new Map(input.known_failures.map(failure => [failure.signature, failure]));
  const newSignatures = [...new Set(input.current_failure_signatures.filter(signature => !baseline.has(signature)))].sort();
  const expired = [...new Set(input.current_failure_signatures.filter(signature => {
    const record = known.get(signature);
    return record && Date.parse(record.approved_until) <= Date.parse(input.now);
  }))].sort();
  if (newSignatures.length > 0) return { status: "NEW_REGRESSION", new_signatures: newSignatures, expired_signatures: expired };
  if (expired.length > 0) return { status: "KNOWN_FAILURE_EXPIRED", new_signatures: [], expired_signatures: expired };
  if (input.current_failure_signatures.length > 0) {
    const allApproved = input.current_failure_signatures.every(signature => known.has(signature));
    return { status: allApproved ? "KNOWN_BASELINE_FAILURES_ONLY" : "NEW_REGRESSION", new_signatures: allApproved ? [] : [...new Set(input.current_failure_signatures.filter(signature => !known.has(signature)))].sort(), expired_signatures: [] };
  }
  return { status: "CLEAN", new_signatures: [], expired_signatures: [] };
}
