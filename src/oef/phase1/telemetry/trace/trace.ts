import { appendFileSync, existsSync, lstatSync, mkdirSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { z } from "zod";
import { containsLikelyPhase1Secret } from "../../core/security/secrets";

export const traceSpanSchema = z.object({
  schema_version: z.literal(1),
  trace_id: z.string().trim().min(1),
  span_id: z.string().trim().min(1),
  parent_span_id: z.string().trim().min(1).nullable(),
  name: z.string().trim().min(1).max(300),
  status: z.enum(["ok", "error"]),
  started_at: z.iso.datetime(),
  ended_at: z.iso.datetime(),
  attributes: z.record(z.string(), z.unknown()),
}).strict().refine(span => Date.parse(span.ended_at) >= Date.parse(span.started_at), {
  message: "Trace span cannot end before it starts",
  path: ["ended_at"],
});

export type TraceSpan = z.infer<typeof traceSpanSchema>;

export interface TraceExporter {
  export(span: TraceSpan): void;
}

const sensitiveKey = /(?:authorization|api[_-]?key|token|secret|password|cookie|private[_-]?key)/i;

function redactTraceValue(value: unknown, key = ""): unknown {
  if (sensitiveKey.test(key)) return "[REDACTED]";
  if (typeof value === "string") return containsLikelyPhase1Secret(value) ? "[REDACTED]" : value;
  if (Array.isArray(value)) return value.map(item => redactTraceValue(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([childKey, child]) => [childKey, redactTraceValue(child, childKey)]),
    );
  }
  return value;
}

export class JsonlTraceExporter implements TraceExporter {
  readonly root: string;

  constructor(options: { root: string }) {
    const requested = resolve(options.root);
    if (existsSync(requested) && lstatSync(requested).isSymbolicLink()) {
      throw new Error("Trace root cannot be a symlink");
    }
    mkdirSync(requested, { recursive: true });
    const actual = realpathSync(requested);
    if ((process.platform === "win32" ? actual.toLowerCase() : actual)
      !== (process.platform === "win32" ? requested.toLowerCase() : requested)) {
      throw new Error("Trace root resolves through a symlink");
    }
    this.root = actual;
  }

  export(input: TraceSpan): void {
    const span = traceSpanSchema.parse(input);
    const date = span.started_at.slice(0, 10);
    const path = join(this.root, `${date}.jsonl`);
    if (existsSync(path) && lstatSync(path).isSymbolicLink()) throw new Error("Trace file cannot be a symlink");
    appendFileSync(path, `${JSON.stringify(redactTraceValue(span))}\n`, { encoding: "utf8", flag: "a" });
  }
}
