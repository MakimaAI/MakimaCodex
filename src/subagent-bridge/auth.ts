import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes as cryptoRandomBytes,
  timingSafeEqual,
} from "node:crypto";

export const SUBAGENT_BRIDGE_HEALTH_DOMAIN = "opencodex-subagent-bridge/health/v1";
export const SUBAGENT_BRIDGE_REQUEST_DOMAIN = "opencodex-subagent-bridge/request/v1";
export const SUBAGENT_BRIDGE_RESPONSE_DOMAIN = "opencodex-subagent-bridge/response/v1";
export const SUBAGENT_BRIDGE_REQUEST_ENCRYPTION_KEY_DOMAIN = "opencodex-subagent-bridge/request-encryption-key/v2";
export const SUBAGENT_BRIDGE_REQUEST_ENCRYPTION_AAD_DOMAIN = "opencodex-subagent-bridge/request-encryption-aad/v2";
export const SUBAGENT_BRIDGE_REQUEST_ENVELOPE_VERSION = 2;
export const SUBAGENT_BRIDGE_INSTANCE_HEADER = "x-opencodex-bridge-instance";
export const SUBAGENT_BRIDGE_REQUEST_ID_HEADER = "x-opencodex-bridge-request-id";
export const SUBAGENT_BRIDGE_ISSUED_AT_HEADER = "x-opencodex-bridge-issued-at";
export const SUBAGENT_BRIDGE_SIGNATURE_HEADER = "x-opencodex-bridge-signature";
export const SUBAGENT_BRIDGE_RESPONSE_SIGNATURE_HEADER = "x-opencodex-bridge-response-signature";
export const SUBAGENT_BRIDGE_STAGING_PATH = "/internal/subagent-handoffs";
export const SUBAGENT_BRIDGE_REQUEST_MAX_AGE_MS = 30_000;
export const SUBAGENT_BRIDGE_REQUEST_FUTURE_SKEW_MS = 5_000;
export const SUBAGENT_BRIDGE_REPLAY_RETENTION_MS = 60_000;
export const SUBAGENT_BRIDGE_FRESHNESS_HORIZON_MS = SUBAGENT_BRIDGE_REQUEST_MAX_AGE_MS
  + SUBAGENT_BRIDGE_REQUEST_FUTURE_SKEW_MS;

type RandomBytesFn = (length: number) => Uint8Array;

function canonicalMacInput(fields: readonly string[]): Buffer {
  const chunks: Buffer[] = [];
  for (const field of fields) {
    const value = Buffer.from(field, "utf8");
    const length = Buffer.allocUnsafe(4);
    length.writeUInt32BE(value.byteLength);
    chunks.push(length, value);
  }
  return Buffer.concat(chunks);
}

function tokenKey(token: string): Buffer | null {
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  try {
    const key = Buffer.from(token, "base64url");
    return key.byteLength === 32 ? key : null;
  } catch {
    return null;
  }
}

interface SubagentBridgeRequestEncryptionContext {
  token: string;
  protocol: string;
  method: string;
  path: string;
  instanceId: string;
  requestId: string;
  issuedAtMs: number;
}

function requestEncryptionKey(token: string, protocol: string): Buffer | null {
  const masterKey = tokenKey(token);
  if (!masterKey) return null;
  try {
    return createHmac("sha256", masterKey)
      .update(canonicalMacInput([SUBAGENT_BRIDGE_REQUEST_ENCRYPTION_KEY_DOMAIN, protocol]))
      .digest();
  } finally {
    masterKey.fill(0);
  }
}

function requestEncryptionAad(options: Omit<SubagentBridgeRequestEncryptionContext, "token">): Buffer | null {
  if (!Number.isSafeInteger(options.issuedAtMs) || options.issuedAtMs < 0) return null;
  return canonicalMacInput([
    SUBAGENT_BRIDGE_REQUEST_ENCRYPTION_AAD_DOMAIN,
    options.protocol,
    options.method,
    options.path,
    options.instanceId,
    options.requestId,
    String(options.issuedAtMs),
  ]);
}

/** Seal sensitive staging payloads before opening the post-discovery connection. */
export function sealSubagentBridgeRequestBody(options: SubagentBridgeRequestEncryptionContext & {
  body: string | Uint8Array;
  randomBytesFn?: RandomBytesFn;
}): string | null {
  const key = requestEncryptionKey(options.token, options.protocol);
  const aad = requestEncryptionAad(options);
  if (!key || !aad) return null;
  try {
    const nonce = Buffer.from((options.randomBytesFn ?? cryptoRandomBytes)(12));
    if (nonce.byteLength !== 12) return null;
    const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(options.body), cipher.final()]);
    return JSON.stringify({
      v: SUBAGENT_BRIDGE_REQUEST_ENVELOPE_VERSION,
      n: nonce.toString("base64url"),
      c: ciphertext.toString("base64url"),
      t: cipher.getAuthTag().toString("base64url"),
    });
  } catch {
    return null;
  } finally {
    key.fill(0);
  }
}

/** Open only the exact versioned AEAD envelope bound to this request's identity metadata. */
export function openSubagentBridgeRequestBody(
  envelopeBody: string | Uint8Array,
  options: SubagentBridgeRequestEncryptionContext,
): Uint8Array | null {
  const key = requestEncryptionKey(options.token, options.protocol);
  const aad = requestEncryptionAad(options);
  if (!key || !aad) return null;
  try {
    const rawText = typeof envelopeBody === "string"
      ? envelopeBody
      : new TextDecoder("utf-8", { fatal: true }).decode(envelopeBody);
    const envelope = JSON.parse(rawText) as Record<string, unknown>;
    if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) return null;
    const keys = Object.keys(envelope).sort();
    if (keys.join("\0") !== ["c", "n", "t", "v"].join("\0")
      || envelope.v !== SUBAGENT_BRIDGE_REQUEST_ENVELOPE_VERSION
      || typeof envelope.n !== "string"
      || typeof envelope.c !== "string"
      || typeof envelope.t !== "string"
      || !/^[A-Za-z0-9_-]{16}$/.test(envelope.n)
      || !/^[A-Za-z0-9_-]+$/.test(envelope.c)
      || !/^[A-Za-z0-9_-]{22}$/.test(envelope.t)) return null;
    const nonce = Buffer.from(envelope.n, "base64url");
    const ciphertext = Buffer.from(envelope.c, "base64url");
    const tag = Buffer.from(envelope.t, "base64url");
    if (nonce.byteLength !== 12 || ciphertext.byteLength === 0 || tag.byteLength !== 16) return null;
    const decipher = createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return new Uint8Array(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
  } catch {
    return null;
  } finally {
    key.fill(0);
  }
}

function mac(token: string, fields: readonly string[]): string | null {
  const key = tokenKey(token);
  return key ? createHmac("sha256", key).update(canonicalMacInput(fields)).digest("base64url") : null;
}

export function isSubagentBridgeRandomValue(value: unknown): value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
  try { return Buffer.from(value, "base64url").byteLength === 32; } catch { return false; }
}

export function createSubagentBridgeRandomValue(
  randomBytesFn: RandomBytesFn = cryptoRandomBytes,
): string {
  const bytes = Buffer.from(randomBytesFn(32));
  if (bytes.byteLength !== 32) throw new Error("bridge authentication entropy unavailable");
  return bytes.toString("base64url");
}

export function subagentBridgeBodyDigest(body: string | Uint8Array): string {
  return createHash("sha256").update(body).digest("hex");
}

export function createSubagentBridgeHealthProof(options: {
  token: string;
  protocol: string;
  instanceId: string;
  nonce: string;
  pid: number;
  port: number;
}): string | null {
  return mac(options.token, [
    SUBAGENT_BRIDGE_HEALTH_DOMAIN,
    options.protocol,
    options.instanceId,
    options.nonce,
    String(options.pid),
    String(options.port),
  ]);
}

export function createSubagentBridgeRequestSignature(options: {
  token: string;
  protocol: string;
  method: string;
  path: string;
  instanceId: string;
  requestId: string;
  issuedAtMs: number;
  body: string | Uint8Array;
}): string | null {
  if (!Number.isSafeInteger(options.issuedAtMs) || options.issuedAtMs < 0) return null;
  return mac(options.token, [
    SUBAGENT_BRIDGE_REQUEST_DOMAIN,
    options.protocol,
    options.method,
    options.path,
    options.instanceId,
    options.requestId,
    String(options.issuedAtMs),
    subagentBridgeBodyDigest(options.body),
  ]);
}

export function createSubagentBridgeResponseSignature(options: {
  token: string;
  protocol: string;
  instanceId: string;
  requestId: string;
  status: number;
  body: string | Uint8Array;
}): string | null {
  return mac(options.token, [
    SUBAGENT_BRIDGE_RESPONSE_DOMAIN,
    options.protocol,
    options.instanceId,
    options.requestId,
    String(options.status),
    subagentBridgeBodyDigest(options.body),
  ]);
}

export function subagentBridgeMacMatches(actual: unknown, expected: string | null): boolean {
  if (typeof actual !== "string" || expected === null
    || !/^[A-Za-z0-9_-]{43}$/.test(actual)
    || !/^[A-Za-z0-9_-]{43}$/.test(expected)) {
    return false;
  }
  const actualBytes = Buffer.from(actual, "base64url");
  const expectedBytes = Buffer.from(expected, "base64url");
  return actualBytes.byteLength === expectedBytes.byteLength && timingSafeEqual(actualBytes, expectedBytes);
}

export class SubagentBridgeReplayGuard {
  private readonly seen = new Map<string, number>();
  private readonly now: () => number;
  private readonly ttlMs: number;
  private readonly maxEntries: number;

  constructor(options: { now?: () => number; ttlMs?: number; maxEntries?: number } = {}) {
    this.now = options.now ?? Date.now;
    this.ttlMs = options.ttlMs ?? SUBAGENT_BRIDGE_REPLAY_RETENTION_MS;
    this.maxEntries = options.maxEntries ?? 4096;
    if (!Number.isSafeInteger(this.ttlMs) || this.ttlMs <= SUBAGENT_BRIDGE_FRESHNESS_HORIZON_MS
      || !Number.isSafeInteger(this.maxEntries) || this.maxEntries <= 0) {
      throw new Error("invalid bridge replay bounds");
    }
  }

  claim(requestId: string): boolean {
    const now = this.now();
    if (!Number.isFinite(now)) return false;
    for (const [id, expiresAt] of this.seen) {
      if (expiresAt <= now) this.seen.delete(id);
    }
    if (this.seen.has(requestId) || this.seen.size >= this.maxEntries) return false;
    this.seen.set(requestId, now + this.ttlMs);
    return true;
  }
}
