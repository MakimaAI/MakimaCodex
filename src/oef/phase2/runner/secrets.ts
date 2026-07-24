export interface SecretMaterializationScope {
  execution_id?: string;
  attempt_id?: string;
  process_id: string;
}

export interface MaterializedSecrets {
  environment: Record<string, string>;
  redaction_values: string[];
  cleanup(): Promise<void>;
}

export interface SecretResolver {
  materialize(refs: readonly string[], scope: SecretMaterializationScope): Promise<MaterializedSecrets>;
}

export interface StaticSecretEntry { environment: Record<string, string> }

export class StaticSecretResolver implements SecretResolver {
  private readonly entries: Readonly<Record<string, StaticSecretEntry>>;
  constructor(entries: Readonly<Record<string, StaticSecretEntry>>) { this.entries = entries; }

  async materialize(refs: readonly string[], _scope: SecretMaterializationScope): Promise<MaterializedSecrets> {
    const environment: Record<string, string> = {};
    const redactionValues = new Set<string>();
    for (const ref of refs) {
      const entry = this.entries[ref];
      if (!entry) throw new Error(`Secret reference could not be materialized: ${ref}`);
      for (const [name, value] of Object.entries(entry.environment)) {
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new Error(`Invalid secret environment name: ${name}`);
        if (!value) throw new Error(`Secret materialization returned an empty value: ${ref}`);
        if (environment[name] !== undefined && environment[name] !== value) throw new Error(`Secret environment collision: ${name}`);
        environment[name] = value;
        redactionValues.add(value);
      }
    }
    return { environment, redaction_values: [...redactionValues], cleanup: async () => {} };
  }
}

export class EmptySecretResolver implements SecretResolver {
  async materialize(refs: readonly string[]): Promise<MaterializedSecrets> {
    if (refs.length > 0) throw new Error("No SecretResolver is configured for the requested secret references");
    return { environment: {}, redaction_values: [], cleanup: async () => {} };
  }
}

const structuredPatterns = [
  /((?:authorization|proxy-authorization)\s*:\s*(?:bearer|basic)\s+)[^\s"']+/gi,
  /((?:api[_-]?key|access[_-]?token|session|cookie)\s*[=:]\s*)[^\s,;"']+/gi,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
] as const;

export class StreamingSecretRedactor {
  private readonly exactPatterns: RegExp[];
  private readonly retain: number;
  private carry = "";
  private discardCarry = "";
  private discardingPrivateKey = false;
  private readonly maxPrivateKeyBytes: number;
  count = 0;

  constructor(values: readonly string[], options: { max_private_key_bytes?: number } = {}) {
    this.exactPatterns = [...new Set(values.filter(value => value.length > 0))]
      .sort((left, right) => right.length - left.length)
      .map(value => new RegExp(escapeRegExp(value), "g"));
    this.retain = Math.max(4_096, ...values.map(value => value.length));
    this.maxPrivateKeyBytes = options.max_private_key_bytes ?? 64 * 1024;
    if (!Number.isInteger(this.maxPrivateKeyBytes) || this.maxPrivateKeyBytes < 64) {
      throw new Error("Private-key redaction buffer must be at least 64 bytes");
    }
  }

  push(input: string, final = false): string {
    if (this.discardingPrivateKey) return this.discardPrivateKey(input, final);
    const combined = this.carry + input;
    const lastNewline = combined.lastIndexOf("\n");
    let splitAt = final
      ? combined.length
      : lastNewline >= 0
        ? lastNewline + 1
        : Math.max(0, combined.length - this.retain);
    const privateKeyStart = unmatchedPrivateKeyStart(combined);
    if (!final && privateKeyStart >= 0) {
      splitAt = Math.min(splitAt, privateKeyStart);
      const quarantined = combined.slice(privateKeyStart);
      if (Buffer.byteLength(quarantined, "utf8") > this.maxPrivateKeyBytes) {
        const ready = combined.slice(0, privateKeyStart);
        this.carry = "";
        this.discardingPrivateKey = true;
        this.discardCarry = quarantined.slice(-128);
        this.count += 1;
        return `${this.redact(ready)}[REDACTED PRIVATE KEY BLOCK]\n`;
      }
    }
    const ready = combined.slice(0, splitAt);
    this.carry = combined.slice(splitAt);
    return this.redact(ready);
  }

  flush(): string { return this.push("", true); }

  bufferedBytes(): number { return Buffer.byteLength(this.carry + this.discardCarry, "utf8"); }

  private discardPrivateKey(input: string, final: boolean): string {
    const combined = this.discardCarry + input;
    const end = /-----END [A-Z ]*PRIVATE KEY-----/.exec(combined);
    if (!end) {
      this.discardCarry = final ? "" : combined.slice(-128);
      if (final) this.discardingPrivateKey = false;
      return "";
    }
    const suffix = combined.slice(end.index + end[0].length);
    this.discardCarry = "";
    this.discardingPrivateKey = false;
    return this.push(suffix, final);
  }

  private redact(input: string): string {
    let output = input;
    for (const pattern of this.exactPatterns) {
      output = output.replace(pattern, () => { this.count += 1; return "[REDACTED]"; });
    }
    for (const pattern of structuredPatterns) {
      pattern.lastIndex = 0;
      output = output.replace(pattern, (...args: unknown[]) => {
        this.count += 1;
        const prefix = typeof args[1] === "string" ? args[1] : "";
        return `${prefix}[REDACTED]`;
      });
    }
    output = output.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*$/g, () => {
      this.count += 1;
      return "[REDACTED]";
    });
    return output;
  }
}

function escapeRegExp(value: string): string { return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
function unmatchedPrivateKeyStart(value: string): number {
  const begin = [...value.matchAll(/-----BEGIN [A-Z ]*PRIVATE KEY-----/g)].at(-1)?.index ?? -1;
  const end = [...value.matchAll(/-----END [A-Z ]*PRIVATE KEY-----/g)].at(-1)?.index ?? -1;
  return begin > end ? begin : -1;
}
