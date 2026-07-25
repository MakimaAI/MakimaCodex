import { redactSecrets } from "../../../lib/redact";
import type { MemoryContextItem, MemoryContextPack, MemoryQuery } from "../core/domain";
import type { MemoryRetrievalEngine } from "../retrieval/engine";

export interface MemoryRetrievalBenchmarkCase {
  case_id: string;
  query: MemoryQuery;
  relevant_memory_ids: string[];
  forbidden_memory_ids?: string[];
}

export interface MemoryRetrievalBenchmarkReport {
  cases: number;
  retrieved_records: number;
  relevant_records: number;
  retrieval_precision: number;
  verified_memory_precision: number;
  citation_completeness: number;
  cross_scope_leakage: number;
  secret_leakage: number;
  passed: boolean;
  thresholds: { retrieval_precision: number; verified_memory_precision: number; citation_completeness: number };
  case_results: Array<{ case_id: string; retrieved: string[]; relevant: string[]; forbidden: string[] }>;
}

export async function runMemoryRetrievalBenchmark(input: {
  engine: Pick<MemoryRetrievalEngine, "recall">;
  cases: MemoryRetrievalBenchmarkCase[];
  thresholds?: Partial<MemoryRetrievalBenchmarkReport["thresholds"]>;
}): Promise<MemoryRetrievalBenchmarkReport> {
  if (input.cases.length === 0) throw new Error("MEMORY_BENCHMARK_CASES_REQUIRED");
  const thresholds = {
    retrieval_precision: input.thresholds?.retrieval_precision ?? 0.8,
    verified_memory_precision: input.thresholds?.verified_memory_precision ?? 0.9,
    citation_completeness: input.thresholds?.citation_completeness ?? 1,
  };
  let retrievedRecords = 0;
  let relevantRecords = 0;
  let verifiedRetrieved = 0;
  let verifiedRelevant = 0;
  let citedRecords = 0;
  let scopeLeakage = 0;
  let secretLeakage = 0;
  const caseResults: MemoryRetrievalBenchmarkReport["case_results"] = [];
  for (const benchmarkCase of input.cases) {
    if (benchmarkCase.query.usage_mode === "AGENT_INJECTION") throw new Error("MEMORY_BENCHMARK_REQUIRES_RECALL_MODE");
    const pack = await input.engine.recall(benchmarkCase.query);
    const items = contextItems(pack);
    const relevant = new Set(benchmarkCase.relevant_memory_ids);
    const forbidden = new Set(benchmarkCase.forbidden_memory_ids ?? []);
    const retrieved = items.map(item => item.memory_id);
    retrievedRecords += items.length;
    relevantRecords += items.filter(item => relevant.has(item.memory_id)).length;
    const verified = items.filter(item => item.lifecycle_status === "VERIFIED" || item.lifecycle_status === "PROMOTED");
    verifiedRetrieved += verified.length;
    verifiedRelevant += verified.filter(item => relevant.has(item.memory_id)).length;
    citedRecords += items.filter(item => item.evidence_refs.length > 0).length;
    scopeLeakage += items.filter(item => forbidden.has(item.memory_id)).length;
    if (JSON.stringify(redactSecrets(pack)) !== JSON.stringify(pack)) secretLeakage += 1;
    caseResults.push({ case_id: benchmarkCase.case_id, retrieved, relevant: [...relevant].sort(), forbidden: [...forbidden].sort() });
  }
  const retrievalPrecision = ratio(relevantRecords, retrievedRecords);
  const verifiedPrecision = ratio(verifiedRelevant, verifiedRetrieved);
  const citationCompleteness = ratio(citedRecords, retrievedRecords);
  return {
    cases: input.cases.length,
    retrieved_records: retrievedRecords,
    relevant_records: relevantRecords,
    retrieval_precision: retrievalPrecision,
    verified_memory_precision: verifiedPrecision,
    citation_completeness: citationCompleteness,
    cross_scope_leakage: scopeLeakage,
    secret_leakage: secretLeakage,
    passed: retrievalPrecision >= thresholds.retrieval_precision
      && verifiedPrecision >= thresholds.verified_memory_precision
      && citationCompleteness >= thresholds.citation_completeness
      && scopeLeakage === 0 && secretLeakage === 0,
    thresholds,
    case_results: caseResults,
  };
}

function contextItems(pack: MemoryContextPack): MemoryContextItem[] {
  return [...pack.sections.must_know, ...pack.sections.relevant_lessons, ...pack.sections.similar_episodes];
}

function ratio(numerator: number, denominator: number): number {
  return denominator === 0 ? 0 : Math.round((numerator / denominator) * 1_000_000) / 1_000_000;
}
