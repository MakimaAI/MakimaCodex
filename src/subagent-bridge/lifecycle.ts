import { createHmac, randomBytes as cryptoRandomBytes, timingSafeEqual } from "node:crypto";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import {
  closeSync,
  constants as fsConstants,
  chmodSync,
  cpSync,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
  type BigIntStats,
  type Stats,
} from "node:fs";
import { homedir } from "node:os";
import { delimiter, dirname, extname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { getConfigDir } from "../config";
import { durableBunPath } from "../lib/bun-runtime";
import { hardenSecretDir, hardenSecretPath, inspectSecretPathAcl } from "../lib/windows-secret-acl";

export const SUBAGENT_BRIDGE_PLUGIN_NAME = "opencodex-subagent-bridge";
const OWNER_MARKER = ".opencodex-subagent-bridge-owner.json";
const INSTALL_RECORD = "subagent-bridge-install.json";
const LIFECYCLE_LOCK = "subagent-bridge-lifecycle.lock";
const TOKEN_ATTESTATION_SUFFIX = ".attestation.json";
const TOKEN_ATTESTATION_DOMAIN = "opencodex-subagent-bridge/attestation/v1";
const TOKEN_ATTESTATION_MAX_BYTES = 2 * 1024;
const HANDOFF_SKILL = join("skills", "subagent-handoff", "SKILL.md");
const OWNER_RECORD = { owner: "opencodex", plugin: SUBAGENT_BRIDGE_PLUGIN_NAME, version: 1 } as const;
const MARKETPLACE_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const REGISTRATION_INSPECT_TIMEOUT_MS = 5_000;
const REGISTRATION_INSPECT_MAX_BYTES = 1024 * 1024;
const PLUGIN_TEXT_MAX_BYTES = 1024 * 1024;
const TOKEN_MAX_BYTES = 128;
const TOKEN_SECURITY_CACHE_MS = 1_000;
const LIFECYCLE_LOCK_MAX_BYTES = 4 * 1024;
const LIFECYCLE_LOCK_STALE_MS = 60_000;
let lifecycleSequence = 0;
const tokenSecurityCache = new Map<string, { checkedAt: number; secure: boolean | null }>();

export interface SubagentBridgeStatus {
  installed: boolean;
  registered: boolean;
  enabled: boolean;
  tokenPresent: boolean;
  tokenSecure: boolean | null;
  marketplaceReady: boolean;
  mcpReady: boolean;
  ready: boolean;
  warnings: string[];
}

type ProcessResult = { status: number | null; error?: Error };
export interface CodexPluginRegistrationState {
  installed: boolean;
  enabled: boolean;
}
type SpawnRunner = (
  command: string,
  args: readonly string[],
  options: { stdio: "inherit"; windowsHide: true; shell: false },
) => SpawnSyncReturns<Buffer>;
type RegistrationSpawnRunner = (
  command: string,
  args: readonly string[],
  options: {
    encoding: "utf8";
    stdio: ["ignore", "pipe", "ignore"];
    windowsHide: true;
    shell: false;
    timeout: number;
    maxBuffer: number;
  },
) => SpawnSyncReturns<string>;

export interface SubagentBridgeLifecycleOptions {
  homeDir?: string;
  configDir?: string;
  bundleDir?: string;
  runtimeCommand?: string;
  runtimeArgs?: string[];
  codexCommand?: string;
  now?: () => Date;
  randomBytes?: (length: number) => Uint8Array;
  runCodex?: (command: string, args: string[]) => ProcessResult;
  hardenSecret?: (path: string) => boolean | void;
  hardenConfigDir?: (path: string) => boolean | void;
  hardenLifecycleLock?: (path: string) => boolean | void;
  inspectRegistration?: (command: string, selector: string) => CodexPluginRegistrationState | null;
  inspectTokenSecurity?: (path: string) => boolean | null;
  expectedUid?: number;
  isProcessAlive?: (pid: number) => boolean;
  platform?: NodeJS.Platform;
  copyDir?: (source: string, destination: string) => void;
  writeBytes?: (path: string, bytes: Uint8Array, secret: boolean) => void;
}

interface ResolvedOptions {
  homeDir: string;
  configDir: string;
  bundleDir: string;
  pluginDir: string;
  marketplacePath: string;
  tokenPath: string;
  tokenAttestationPath: string;
  configPath: string;
  installRecordPath: string;
  lifecycleLockPath: string;
  runtimeCommand: string;
  runtimeArgs: string[];
  codexCommand?: string;
  now: () => Date;
  randomBytes: (length: number) => Uint8Array;
  runCodex: (command: string, args: string[]) => ProcessResult;
  hardenSecret: (path: string) => boolean | void;
  hardenConfigDir: (path: string) => boolean | void;
  hardenLifecycleLock: (path: string) => boolean | void;
  inspectRegistration: (command: string, selector: string) => CodexPluginRegistrationState | null;
  inspectTokenSecurity?: (path: string) => boolean | null;
  expectedUid?: number;
  isProcessAlive: (pid: number) => boolean;
  platform: NodeJS.Platform;
  copyDir: (source: string, destination: string) => void;
  writeBytes: (path: string, bytes: Uint8Array, secret: boolean) => void;
}

interface JsonState {
  exists: boolean;
  bytes: Buffer | null;
  value: Record<string, any>;
}

interface FileSnapshot {
  path: string;
  exists: boolean;
  bytes: Buffer | null;
  mode?: number;
}

export interface SecureSubagentBridgeTokenReadOptions {
  configDir?: string;
  tokenPath?: string;
  platform?: NodeJS.Platform;
  expectedUid?: number;
  inspectTokenSecurity?: (path: string) => boolean | null;
  allowWindowsAclMigration?: boolean;
}

export interface SubagentBridgeTokenAttestationRepairOptions extends SecureSubagentBridgeTokenReadOptions {
  writeBytes?: (path: string, bytes: Uint8Array, secret: boolean) => void;
  hardenConfigDir?: (path: string) => boolean | void;
}

interface SecureTokenState {
  token: string | null;
  present: boolean;
  secure: boolean | null;
}

interface TokenAttestationFingerprint {
  type: "file";
  noSymlink: true;
  dev: string;
  ino: string;
  ctimeNs: string;
  size: string;
}

interface TokenAttestationRecord {
  owner: typeof OWNER_RECORD.owner;
  plugin: typeof OWNER_RECORD.plugin;
  version: 1;
  fingerprint: TokenAttestationFingerprint;
  mac: string;
}

interface LifecycleLockMetadata {
  owner: typeof OWNER_RECORD.owner;
  plugin: typeof OWNER_RECORD.plugin;
  version: typeof OWNER_RECORD.version;
  pid: number;
  createdAtMs: number;
  nonce: string;
}

interface LifecycleLockHandle {
  bytes: Buffer;
  dev: number;
  ino: number;
}

function defaultHardenSecret(path: string): void {
  chmodSync(path, 0o600);
  if (process.platform === "win32") {
    const result = hardenSecretPath(path, { required: true, verifyIsolation: true });
    if (!result.ok) throw new Error("bridge token ACL hardening failed");
  }
}

export function hardenSubagentBridgeConfigDir(
  path: string,
  platform: NodeJS.Platform = process.platform,
): void {
  if (!subagentBridgeConfigDirStabilizationRequired(platform)) return;
  mkdirSync(path, { recursive: true });
  chmodSync(path, 0o700);
  const result = hardenSecretDir(path, { required: true, verifyIsolation: true });
  if (!result.ok) throw new Error("bridge config directory ACL hardening failed");
}

export function subagentBridgeConfigDirStabilizationRequired(platform: NodeJS.Platform): boolean {
  return platform === "win32";
}

function defaultHardenLifecycleLock(path: string): void {
  chmodSync(path, 0o600);
  if (process.platform === "win32") {
    const result = hardenSecretPath(path, { required: true, verifyIsolation: true, force: true });
    if (!result.ok) throw new Error("bridge lifecycle lock ACL hardening failed");
  }
}

function defaultWriteBytes(path: string, bytes: Uint8Array, secret: boolean): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, bytes, { mode: secret ? 0o600 : undefined });
  if (secret) chmodSync(path, 0o600);
}

function defaultIsProcessAlive(pid: number): boolean {
  if (pid === process.pid) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return !(error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === "ESRCH");
  }
}

export function runCodexCommand(
  command: string,
  args: string[],
  runner: SpawnRunner = spawnSync as unknown as SpawnRunner,
): ProcessResult {
  const result = runner(command, args, {
    stdio: "inherit",
    windowsHide: true,
    shell: false,
  });
  return { status: result.status, ...(result.error ? { error: result.error } : {}) };
}

export function inspectCodexPluginRegistration(
  command: string,
  selector: string,
  runner: RegistrationSpawnRunner = spawnSync as unknown as RegistrationSpawnRunner,
): CodexPluginRegistrationState | null {
  const separator = selector.lastIndexOf("@");
  if (separator <= 0 || separator === selector.length - 1) return null;
  const pluginName = selector.slice(0, separator);
  const marketplaceName = selector.slice(separator + 1);
  try {
    const result = runner(command, ["plugin", "list", "--json"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      windowsHide: true,
      shell: false,
      timeout: REGISTRATION_INSPECT_TIMEOUT_MS,
      maxBuffer: REGISTRATION_INSPECT_MAX_BYTES,
    });
    if (result.status !== 0 || typeof result.stdout !== "string") return null;
    if (Buffer.byteLength(result.stdout, "utf8") > REGISTRATION_INSPECT_MAX_BYTES) return null;
    const parsed = JSON.parse(result.stdout);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || !Array.isArray(parsed.installed)) return null;
    for (const candidate of parsed.installed) {
      if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)
        || typeof candidate.pluginId !== "string"
        || typeof candidate.name !== "string"
        || typeof candidate.marketplaceName !== "string"
        || typeof candidate.installed !== "boolean"
        || typeof candidate.enabled !== "boolean") {
        return null;
      }
    }
    const rows = parsed.installed.filter((candidate: any) => (
      candidate.pluginId === selector
      && candidate.name === pluginName
      && candidate.marketplaceName === marketplaceName
    ));
    if (rows.length > 1) return null;
    const row = rows[0];
    return row ? { installed: row.installed, enabled: row.enabled } : { installed: false, enabled: false };
  } catch {
    return null;
  }
}

function resolveOptions(options: SubagentBridgeLifecycleOptions = {}): ResolvedOptions {
  const homeDir = resolve(options.homeDir ?? homedir());
  const configDir = resolve(options.configDir ?? getConfigDir());
  const platform = options.platform ?? process.platform;
  return {
    homeDir,
    configDir,
    bundleDir: resolve(options.bundleDir ?? fileURLToPath(new URL(`../../plugins/${SUBAGENT_BRIDGE_PLUGIN_NAME}`, import.meta.url))),
    pluginDir: resolve(homeDir, "plugins", SUBAGENT_BRIDGE_PLUGIN_NAME),
    marketplacePath: resolve(homeDir, ".agents", "plugins", "marketplace.json"),
    tokenPath: resolve(configDir, "subagent-bridge-token"),
    tokenAttestationPath: subagentBridgeTokenAttestationPath(resolve(configDir, "subagent-bridge-token")),
    configPath: resolve(configDir, "config.json"),
    installRecordPath: resolve(configDir, INSTALL_RECORD),
    lifecycleLockPath: resolve(configDir, LIFECYCLE_LOCK),
    runtimeCommand: resolve(options.runtimeCommand ?? durableBunPath()),
    runtimeArgs: options.runtimeArgs ?? [fileURLToPath(new URL("../cli/index.ts", import.meta.url)), "__subagent-bridge-mcp"],
    codexCommand: options.codexCommand ? resolve(options.codexCommand) : undefined,
    now: options.now ?? (() => new Date()),
    randomBytes: options.randomBytes ?? cryptoRandomBytes,
    runCodex: options.runCodex ?? runCodexCommand,
    hardenSecret: options.hardenSecret ?? defaultHardenSecret,
    hardenConfigDir: options.hardenConfigDir ?? (path => hardenSubagentBridgeConfigDir(path, platform)),
    hardenLifecycleLock: options.hardenLifecycleLock ?? options.hardenSecret ?? defaultHardenLifecycleLock,
    inspectRegistration: options.inspectRegistration ?? inspectCodexPluginRegistration,
    inspectTokenSecurity: options.inspectTokenSecurity,
    expectedUid: options.expectedUid,
    isProcessAlive: options.isProcessAlive ?? defaultIsProcessAlive,
    platform,
    copyDir: options.copyDir ?? ((source, destination) => cpSync(source, destination, { recursive: true })),
    writeBytes: options.writeBytes ?? defaultWriteBytes,
  };
}

function readJsonState(path: string, label: string, allowMissing: boolean): JsonState {
  if (!existsSync(path)) {
    if (!allowMissing) throw new Error(`${label} is missing`);
    return { exists: false, bytes: null, value: {} };
  }
  const bytes = readFileSync(path);
  try {
    const parsed = JSON.parse(bytes.toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
    return { exists: true, bytes, value: parsed };
  } catch {
    throw new Error(`${label} is invalid JSON`);
  }
}

function tryJsonState(path: string): JsonState | null {
  try { return readJsonState(path, "state", false); } catch { return null; }
}

function jsonBytes(value: unknown): Buffer {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function sameFileIdentity(
  left: { dev: number | bigint; ino: number | bigint },
  right: { dev: number | bigint; ino: number | bigint },
): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function pathEntryExists(path: string): boolean {
  try { lstatSync(path); return true; } catch { return false; }
}

function validLifecycleLock(value: unknown): LifecycleLockMetadata | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const candidate = value as Partial<LifecycleLockMetadata>;
  const keys = Object.keys(candidate).sort();
  if (keys.join("\0") !== ["createdAtMs", "nonce", "owner", "pid", "plugin", "version"].sort().join("\0")) return null;
  if (candidate.owner !== OWNER_RECORD.owner || candidate.plugin !== OWNER_RECORD.plugin || candidate.version !== OWNER_RECORD.version) return null;
  if (!Number.isSafeInteger(candidate.pid) || Number(candidate.pid) <= 0) return null;
  if (!Number.isSafeInteger(candidate.createdAtMs) || Number(candidate.createdAtMs) < 0) return null;
  if (typeof candidate.nonce !== "string" || !/^[0-9a-f]{24}$/.test(candidate.nonce)) return null;
  return candidate as LifecycleLockMetadata;
}

function lockFileIsOwned(paths: ResolvedOptions, stat: Stats): boolean {
  if (stat.isSymbolicLink() || !stat.isFile()) return false;
  if (paths.platform === "win32") {
    try {
      return (paths.inspectTokenSecurity
        ? paths.inspectTokenSecurity(paths.lifecycleLockPath)
        : inspectWindowsTokenSecurity(paths.lifecycleLockPath, stat)) === true;
    } catch {
      return false;
    }
  }
  const expectedUid = paths.expectedUid ?? process.getuid?.();
  return expectedUid !== undefined && stat.uid === expectedUid && (stat.mode & 0o077) === 0;
}

function recoverStaleLifecycleLock(paths: ResolvedOptions): boolean {
  try {
    const before = lstatSync(paths.lifecycleLockPath);
    if (!lockFileIsOwned(paths, before) || before.size <= 0 || before.size > LIFECYCLE_LOCK_MAX_BYTES) return false;
    const bytes = readFileSync(paths.lifecycleLockPath);
    if (bytes.byteLength !== before.size) return false;
    const metadata = validLifecycleLock(JSON.parse(bytes.toString("utf8")));
    if (!metadata) return false;
    const age = paths.now().getTime() - metadata.createdAtMs;
    if (!Number.isSafeInteger(age) || age < LIFECYCLE_LOCK_STALE_MS) return false;
    let alive = true;
    try { alive = paths.isProcessAlive(metadata.pid); } catch { return false; }
    if (alive) return false;
    const after = lstatSync(paths.lifecycleLockPath);
    if (!sameFileIdentity(before, after) || !lockFileIsOwned(paths, after)) return false;
    if (!readFileSync(paths.lifecycleLockPath).equals(bytes)) return false;
    unlinkSync(paths.lifecycleLockPath);
    return true;
  } catch {
    return false;
  }
}

function createLifecycleLock(paths: ResolvedOptions): LifecycleLockHandle {
  mkdirSync(paths.configDir, { recursive: true });
  const nonceBytes = Buffer.from(paths.randomBytes(12));
  if (nonceBytes.byteLength !== 12) throw new Error("failed to create lifecycle lock nonce");
  const metadata: LifecycleLockMetadata = {
    ...OWNER_RECORD,
    pid: process.pid,
    createdAtMs: paths.now().getTime(),
    nonce: nonceBytes.toString("hex"),
  };
  const bytes = jsonBytes(metadata);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    let fd: number | null = null;
    let created: LifecycleLockHandle | null = null;
    try {
      fd = openSync(paths.lifecycleLockPath, "wx", 0o600);
      writeFileSync(fd, bytes);
      const stat = fstatSync(fd);
      created = { bytes, dev: stat.dev, ino: stat.ino };
      closeSync(fd);
      fd = null;
      if (paths.platform === "win32" && paths.hardenLifecycleLock(paths.lifecycleLockPath) === false) {
        throw new Error("bridge lifecycle lock ACL hardening failed");
      }
      const secured = lstatSync(paths.lifecycleLockPath);
      if (!sameFileIdentity(created, secured) || !lockFileIsOwned(paths, secured)) {
        throw new Error("bridge lifecycle lock ownership could not be verified");
      }
      return { bytes, dev: secured.dev, ino: secured.ino };
    } catch (error) {
      const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
      if (created) {
        try {
          const stat = lstatSync(paths.lifecycleLockPath);
          if (sameFileIdentity(created, stat) && readFileSync(paths.lifecycleLockPath).equals(bytes)) {
            unlinkSync(paths.lifecycleLockPath);
          }
        } catch { /* leave an unverifiable path untouched */ }
        throw new Error("subagent bridge lifecycle lock could not be established securely");
      }
      if (code !== "EEXIST" || attempt > 0 || !recoverStaleLifecycleLock(paths)) {
        throw new Error("subagent bridge lifecycle operation is already in progress");
      }
    } finally {
      if (fd !== null) closeSync(fd);
    }
  }
  throw new Error("subagent bridge lifecycle operation is already in progress");
}

function releaseLifecycleLock(paths: ResolvedOptions, lock: LifecycleLockHandle): void {
  try {
    const stat = lstatSync(paths.lifecycleLockPath);
    if (!lockFileIsOwned(paths, stat) || !sameFileIdentity(lock, stat) || !readFileSync(paths.lifecycleLockPath).equals(lock.bytes)) {
      throw new Error("ownership changed");
    }
    unlinkSync(paths.lifecycleLockPath);
  } catch {
    throw new Error("subagent bridge lifecycle lock could not be released safely");
  }
}

function withLifecycleLock<T>(paths: ResolvedOptions, operation: () => T): T {
  const lock = createLifecycleLock(paths);
  try {
    return operation();
  } finally {
    releaseLifecycleLock(paths, lock);
  }
}

function snapshotFile(path: string): FileSnapshot {
  if (!existsSync(path)) return { path, exists: false, bytes: null };
  const stat = statSync(path);
  return { path, exists: true, bytes: readFileSync(path), mode: stat.mode & 0o777 };
}

function restoreSnapshot(snapshot: FileSnapshot): void {
  if (!snapshot.exists) {
    try { unlinkSync(snapshot.path); } catch { /* already absent */ }
    return;
  }
  mkdirSync(dirname(snapshot.path), { recursive: true });
  writeFileSync(snapshot.path, snapshot.bytes!);
  if (snapshot.mode !== undefined) chmodSync(snapshot.path, snapshot.mode);
}

function removeOwnedDirectory(path: string): void {
  if (existsSync(path)) rmSync(path, { recursive: true, force: true });
}

function isOwnedPluginDir(pluginDir: string): boolean {
  const marker = tryJsonState(join(pluginDir, OWNER_MARKER))?.value;
  return marker?.owner === OWNER_RECORD.owner
    && marker?.plugin === OWNER_RECORD.plugin
    && marker?.version === OWNER_RECORD.version;
}

function assertSafePluginTarget(paths: ResolvedOptions): void {
  const expected = resolve(paths.homeDir, "plugins", SUBAGENT_BRIDGE_PLUGIN_NAME);
  if (paths.pluginDir !== expected || dirname(paths.pluginDir) !== resolve(paths.homeDir, "plugins")) {
    throw new Error("refusing unsafe subagent bridge plugin target");
  }
}

function timestamp(date: Date): string {
  const p = (value: number) => String(value).padStart(2, "0");
  const milliseconds = String(date.getUTCMilliseconds()).padStart(3, "0");
  return `${date.getUTCFullYear()}${p(date.getUTCMonth() + 1)}${p(date.getUTCDate())}-${p(date.getUTCHours())}${p(date.getUTCMinutes())}${p(date.getUTCSeconds())}${milliseconds}`;
}

function bridgeMarketplaceEntry(): Record<string, unknown> {
  return {
    name: SUBAGENT_BRIDGE_PLUGIN_NAME,
    source: { source: "local", path: `./plugins/${SUBAGENT_BRIDGE_PLUGIN_NAME}` },
    policy: { installation: "AVAILABLE", authentication: "ON_INSTALL" },
    category: "Productivity",
  };
}

function isOwnedMarketplaceEntry(entry: any): boolean {
  return entry?.name === SUBAGENT_BRIDGE_PLUGIN_NAME
    && entry?.source?.source === "local"
    && entry?.source?.path === `./plugins/${SUBAGENT_BRIDGE_PLUGIN_NAME}`;
}

function validateMarketplace(state: JsonState, options: { allowForeignBridgeEntry?: boolean } = {}): Record<string, any> {
  const marketplace = state.exists
    ? state.value
    : { name: "personal", interface: { displayName: "Personal" }, plugins: [] };
  if (typeof marketplace.name !== "string" || !MARKETPLACE_NAME_RE.test(marketplace.name)) {
    throw new Error("personal marketplace name is invalid");
  }
  if (!Array.isArray(marketplace.plugins)) throw new Error("personal marketplace plugins are invalid");
  const collisions = marketplace.plugins.filter((entry: any) => entry?.name === SUBAGENT_BRIDGE_PLUGIN_NAME);
  if (!options.allowForeignBridgeEntry && collisions.some((entry: any) => !isOwnedMarketplaceEntry(entry))) {
    throw new Error("foreign same-named bridge marketplace entry exists");
  }
  return marketplace;
}

function nextMarketplace(marketplace: Record<string, any>, install: boolean): Record<string, any> {
  const next = JSON.parse(JSON.stringify(marketplace)) as Record<string, any>;
  if (!install) {
    next.plugins = next.plugins.filter((entry: any) => !isOwnedMarketplaceEntry(entry));
    return next;
  }
  const first = next.plugins.findIndex((entry: any) => isOwnedMarketplaceEntry(entry));
  next.plugins = next.plugins.filter((entry: any) => !isOwnedMarketplaceEntry(entry));
  const at = first < 0 ? next.plugins.length : Math.min(first, next.plugins.length);
  next.plugins.splice(at, 0, bridgeMarketplaceEntry());
  return next;
}

function nextConfig(config: Record<string, any>, enabled: boolean): Record<string, any> {
  const next = JSON.parse(JSON.stringify(config)) as Record<string, any>;
  const existing = next.subagentBridge && typeof next.subagentBridge === "object" && !Array.isArray(next.subagentBridge)
    ? next.subagentBridge
    : {};
  next.subagentBridge = { ...existing, enabled };
  return next;
}

export function isValidSubagentBridgeToken(value: string): boolean {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
  try { return Buffer.from(value, "base64url").byteLength === 32; } catch { return false; }
}

export function subagentBridgeTokenAttestationPath(tokenPath: string): string {
  return `${resolve(tokenPath)}${TOKEN_ATTESTATION_SUFFIX}`;
}

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

function tokenAttestationFingerprint(stat: BigIntStats): TokenAttestationFingerprint {
  return {
    type: "file",
    noSymlink: true,
    dev: stat.dev.toString(),
    ino: stat.ino.toString(),
    ctimeNs: stat.ctimeNs.toString(),
    size: stat.size.toString(),
  };
}

function sameTokenAttestationFingerprint(
  left: TokenAttestationFingerprint,
  right: TokenAttestationFingerprint,
): boolean {
  return left.type === right.type
    && left.noSymlink === right.noSymlink
    && left.dev === right.dev
    && left.ino === right.ino
    && left.ctimeNs === right.ctimeNs
    && left.size === right.size;
}

function tokenAttestationMac(token: string, fingerprint: TokenAttestationFingerprint): string {
  const key = Buffer.from(token, "base64url");
  return createHmac("sha256", key).update(canonicalMacInput([
    TOKEN_ATTESTATION_DOMAIN,
    fingerprint.type,
    fingerprint.noSymlink ? "1" : "0",
    fingerprint.dev,
    fingerprint.ino,
    fingerprint.ctimeNs,
    fingerprint.size,
  ])).digest("base64url");
}

function safeMacMatches(actual: string, expected: string): boolean {
  if (!/^[A-Za-z0-9_-]{43}$/.test(actual) || !/^[A-Za-z0-9_-]{43}$/.test(expected)) return false;
  const actualBytes = Buffer.from(actual, "base64url");
  const expectedBytes = Buffer.from(expected, "base64url");
  return actualBytes.byteLength === expectedBytes.byteLength && timingSafeEqual(actualBytes, expectedBytes);
}

function exactTokenAttestationRecord(value: unknown): TokenAttestationRecord | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Partial<TokenAttestationRecord>;
  if (!exactKeys(record, ["owner", "plugin", "version", "fingerprint", "mac"])
    || record.owner !== OWNER_RECORD.owner
    || record.plugin !== OWNER_RECORD.plugin
    || record.version !== 1
    || typeof record.mac !== "string"
    || !record.fingerprint
    || !exactKeys(record.fingerprint, ["type", "noSymlink", "dev", "ino", "ctimeNs", "size"])) {
    return null;
  }
  const fingerprint = record.fingerprint as Partial<TokenAttestationFingerprint>;
  if (fingerprint.type !== "file"
    || fingerprint.noSymlink !== true
    || typeof fingerprint.dev !== "string"
    || typeof fingerprint.ino !== "string"
    || typeof fingerprint.ctimeNs !== "string"
    || typeof fingerprint.size !== "string"
    || !/^\d+$/.test(fingerprint.dev)
    || !/^\d+$/.test(fingerprint.ino)
    || !/^\d+$/.test(fingerprint.ctimeNs)
    || !/^\d+$/.test(fingerprint.size)) {
    return null;
  }
  return record as TokenAttestationRecord;
}

function readTokenAttestation(path: string): { kind: "missing" | "invalid" | "valid"; record?: TokenAttestationRecord } {
  try {
    const before = lstatSync(path, { bigint: true });
    if (before.isSymbolicLink() || !before.isFile() || before.size <= 0n || before.size > BigInt(TOKEN_ATTESTATION_MAX_BYTES)) {
      return { kind: "invalid" };
    }
    const bytes = readFileSync(path);
    const after = lstatSync(path, { bigint: true });
    if (!sameFileIdentity(before, after)
      || before.ctimeNs !== after.ctimeNs
      || before.size !== after.size
      || BigInt(bytes.byteLength) !== before.size) {
      return { kind: "invalid" };
    }
    const record = exactTokenAttestationRecord(JSON.parse(bytes.toString("utf8")));
    return record ? { kind: "valid", record } : { kind: "invalid" };
  } catch (error) {
    const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
    return { kind: code === "ENOENT" ? "missing" : "invalid" };
  }
}

function writeTokenAttestation(
  tokenPath: string,
  token: string,
  writeBytes: (path: string, bytes: Uint8Array, secret: boolean) => void,
): boolean {
  let fd: number | null = null;
  try {
    const before = lstatSync(tokenPath, { bigint: true });
    if (before.isSymbolicLink() || !before.isFile()) return false;
    const noFollow = process.platform === "win32" ? 0 : (fsConstants.O_NOFOLLOW ?? 0);
    fd = openSync(tokenPath, fsConstants.O_RDONLY | noFollow);
    const opened = fstatSync(fd, { bigint: true });
    if (!opened.isFile() || !sameFileIdentity(before, opened) || before.ctimeNs !== opened.ctimeNs) return false;
    if (opened.size <= 0n || opened.size > BigInt(TOKEN_MAX_BYTES)) return false;
    const value = readFileSync(fd).toString("utf8");
    if (value !== `${token}\n` && value !== `${token}\r\n` && value !== token) return false;
    const after = lstatSync(tokenPath, { bigint: true });
    const fingerprint = tokenAttestationFingerprint(opened);
    if (!sameTokenAttestationFingerprint(fingerprint, tokenAttestationFingerprint(after))) return false;
    const record: TokenAttestationRecord = {
      ...OWNER_RECORD,
      fingerprint,
      mac: tokenAttestationMac(token, fingerprint),
    };
    const bytes = jsonBytes(record);
    if (bytes.byteLength > TOKEN_ATTESTATION_MAX_BYTES) return false;
    writeBytes(subagentBridgeTokenAttestationPath(tokenPath), bytes, true);
    return true;
  } catch {
    return false;
  } finally {
    if (fd !== null) closeSync(fd);
  }
}

function tokenFileFingerprint(path: string, stat: Stats): string {
  return `${path}\0${stat.dev}\0${stat.ino}\0${stat.ctimeMs}\0${stat.mode}\0${stat.size}`;
}

function inspectWindowsTokenSecurity(path: string, stat: Stats): boolean | null {
  const key = tokenFileFingerprint(path, stat);
  const now = Date.now();
  const cached = tokenSecurityCache.get(key);
  if (cached && now - cached.checkedAt <= TOKEN_SECURITY_CACHE_MS) return cached.secure;
  const secure = inspectSecretPathAcl(path).secure;
  tokenSecurityCache.clear();
  tokenSecurityCache.set(key, { checkedAt: now, secure });
  return secure;
}

export function isSecurePosixBridgeTokenFile(
  stat: Pick<Stats, "uid" | "mode" | "isFile" | "isSymbolicLink">,
  expectedUid: number,
): boolean {
  return stat.isFile() && !stat.isSymbolicLink()
    && stat.uid === expectedUid
    && (stat.mode & 0o077) === 0;
}

function assertExecutable(path: string, platform: NodeJS.Platform, label: string): void {
  if (!isAbsolute(path) || !existsSync(path) || !statSync(path).isFile()) throw new Error(`${label} does not exist`);
  if (platform !== "win32" && (statSync(path).mode & 0o111) === 0) throw new Error(`${label} is not executable`);
}

function validateRuntime(runtimeCommand: string, runtimeArgs: string[], platform: NodeJS.Platform): void {
  assertExecutable(runtimeCommand, platform, "bridge runtime command");
  if (runtimeArgs.length < 2 || runtimeArgs.at(-1) !== "__subagent-bridge-mcp") {
    throw new Error("bridge launcher arguments are invalid");
  }
  const launcher = runtimeArgs[0]!;
  if (!isAbsolute(launcher) || !existsSync(launcher) || !statSync(launcher).isFile()) {
    throw new Error("bridge CLI launcher does not exist");
  }
}

function resolveCodexFromPath(platform: NodeJS.Platform): string | null {
  const pathEntries = (process.env.PATH ?? "").split(delimiter).filter(Boolean);
  const names = platform === "win32" ? ["codex.exe", "codex.com"] : ["codex"];
  for (const dir of pathEntries) {
    for (const name of names) {
      const candidate = resolve(dir, name);
      try {
        assertExecutable(candidate, platform, "Codex executable");
        return candidate;
      } catch { /* keep searching */ }
    }
  }
  return null;
}

function codexCommand(paths: ResolvedOptions): string {
  const command = paths.codexCommand ?? resolveCodexFromPath(paths.platform);
  if (!command) throw new Error("Codex executable was not found");
  assertExecutable(command, paths.platform, "Codex executable");
  if (paths.platform === "win32" && ![".exe", ".com"].includes(extname(command).toLowerCase())) {
    throw new Error("Codex command must be a native executable");
  }
  return command;
}

function exactKeys(value: unknown, expected: string[]): boolean {
  return !!value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).sort().join("\0") === [...expected].sort().join("\0");
}

function validateBridgeManifest(manifest: Record<string, any>, label: string): void {
  if (manifest.name !== SUBAGENT_BRIDGE_PLUGIN_NAME
    || typeof manifest.version !== "string"
    || !manifest.version.trim()
    || manifest.mcpServers !== "./.mcp.json"
    || manifest.skills !== "./skills/") {
    throw new Error(`${label} is invalid`);
  }
}

function validateExactMcpDeclaration(
  pluginDir: string,
  expectedCommand: string,
  expectedArgs: string[],
  platform?: NodeJS.Platform,
): void {
  const mcp = readJsonState(join(pluginDir, ".mcp.json"), "bridge MCP config", false).value;
  if (!exactKeys(mcp, ["mcpServers"]) || !exactKeys(mcp.mcpServers, [SUBAGENT_BRIDGE_PLUGIN_NAME])) {
    throw new Error("bridge MCP declaration is not exact");
  }
  const server = mcp.mcpServers[SUBAGENT_BRIDGE_PLUGIN_NAME];
  if (!exactKeys(server, ["command", "args"])
    || server.command !== expectedCommand
    || !Array.isArray(server.args)
    || server.args.length !== expectedArgs.length
    || server.args.some((arg: unknown, index: number) => arg !== expectedArgs[index])) {
    throw new Error("bridge MCP declaration is invalid");
  }
  if (platform) validateRuntime(server.command, server.args, platform);
}

function validateHandoffSkill(pluginDir: string): void {
  const skillPath = join(pluginDir, HANDOFF_SKILL);
  const stat = lstatSync(skillPath);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.size <= 0 || stat.size > PLUGIN_TEXT_MAX_BYTES) {
    throw new Error("bridge handoff skill is missing or invalid");
  }
  if (!readFileSync(skillPath, "utf8").trim()) throw new Error("bridge handoff skill is empty");
}

function validateInstalledPlugin(
  pluginDir: string,
  expectedCommand: string,
  expectedArgs: string[],
  platform: NodeJS.Platform,
): void {
  const manifest = readJsonState(join(pluginDir, ".codex-plugin", "plugin.json"), "installed bridge manifest", false).value;
  validateBridgeManifest(manifest, "installed bridge manifest");
  validateExactMcpDeclaration(pluginDir, expectedCommand, expectedArgs, platform);
  validateHandoffSkill(pluginDir);
}

function validateBundle(paths: ResolvedOptions): Record<string, any> {
  if (!existsSync(paths.bundleDir) || !statSync(paths.bundleDir).isDirectory()) throw new Error("bundled subagent bridge plugin is missing");
  const manifest = readJsonState(join(paths.bundleDir, ".codex-plugin", "plugin.json"), "bundled bridge manifest", false).value;
  validateBridgeManifest(manifest, "bundled bridge manifest");
  validateExactMcpDeclaration(paths.bundleDir, "ocx", ["__subagent-bridge-mcp"]);
  validateHandoffSkill(paths.bundleDir);
  return manifest;
}

function registrationValue(marketplace: string): Record<string, unknown> {
  return { ...OWNER_RECORD, marketplace };
}

function validRegistration(path: string, marketplace?: string): { marketplace: string } | null {
  const record = tryJsonState(path)?.value;
  if (record?.owner !== OWNER_RECORD.owner || record?.plugin !== OWNER_RECORD.plugin || record?.version !== OWNER_RECORD.version) return null;
  if (typeof record.marketplace !== "string" || !MARKETPLACE_NAME_RE.test(record.marketplace)) return null;
  if (marketplace !== undefined && record.marketplace !== marketplace) return null;
  return { marketplace: record.marketplace };
}

function secureTokenState(
  options: SecureSubagentBridgeTokenReadOptions,
  forceDeepWindowsAcl = false,
): SecureTokenState {
  const tokenPath = resolve(options.tokenPath ?? join(resolve(options.configDir ?? getConfigDir()), "subagent-bridge-token"));
  const platform = options.platform ?? process.platform;
  let fd: number | null = null;
  try {
    const before = lstatSync(tokenPath);
    const beforeBig = lstatSync(tokenPath, { bigint: true });
    if (before.isSymbolicLink() || !before.isFile()) return { token: null, present: false, secure: false };
    const noFollow = process.platform === "win32" ? 0 : (fsConstants.O_NOFOLLOW ?? 0);
    fd = openSync(tokenPath, fsConstants.O_RDONLY | noFollow);
    const opened = fstatSync(fd);
    const openedBig = fstatSync(fd, { bigint: true });
    if (!opened.isFile()
      || !sameFileIdentity(before, opened)
      || !sameFileIdentity(beforeBig, openedBig)
      || beforeBig.ctimeNs !== openedBig.ctimeNs) {
      return { token: null, present: false, secure: false };
    }

    let secure: boolean | null;
    let attestation: TokenAttestationRecord | null = null;
    if (platform === "win32") {
      const attestationState = forceDeepWindowsAcl
        ? { kind: "missing" as const }
        : readTokenAttestation(subagentBridgeTokenAttestationPath(tokenPath));
      if (!forceDeepWindowsAcl && attestationState.kind === "valid") {
        attestation = attestationState.record!;
        secure = true;
      } else if (!forceDeepWindowsAcl
        && attestationState.kind === "missing"
        && options.allowWindowsAclMigration !== true) {
        return { token: null, present: true, secure: null };
      } else if (!forceDeepWindowsAcl && attestationState.kind === "invalid") {
        return { token: null, present: true, secure: false };
      } else {
        try {
          secure = options.inspectTokenSecurity
            ? options.inspectTokenSecurity(tokenPath)
            : inspectWindowsTokenSecurity(tokenPath, opened);
        } catch {
          secure = null;
        }
      }
    } else {
      const expectedUid = options.expectedUid ?? process.getuid?.();
      secure = expectedUid === undefined
        ? null
        : isSecurePosixBridgeTokenFile(opened, expectedUid);
    }
    if (secure !== true) return { token: null, present: true, secure };

    const after = lstatSync(tokenPath);
    const afterBig = lstatSync(tokenPath, { bigint: true });
    if (after.isSymbolicLink() || !after.isFile()
      || tokenFileFingerprint(tokenPath, opened) !== tokenFileFingerprint(tokenPath, after)
      || !sameTokenAttestationFingerprint(
        tokenAttestationFingerprint(openedBig),
        tokenAttestationFingerprint(afterBig),
      )) {
      return { token: null, present: false, secure: false };
    }
    if (opened.size <= 0 || opened.size > TOKEN_MAX_BYTES) return { token: null, present: false, secure: false };
    const value = readFileSync(fd).toString("utf8");
    const match = /^([A-Za-z0-9_-]{43})(?:\r?\n)?$/.exec(value);
    const token = match?.[1] ?? "";
    if (!isValidSubagentBridgeToken(token)) return { token: null, present: false, secure: false };
    if (attestation) {
      const fingerprint = tokenAttestationFingerprint(openedBig);
      if (!sameTokenAttestationFingerprint(attestation.fingerprint, fingerprint)
        || !safeMacMatches(attestation.mac, tokenAttestationMac(token, fingerprint))) {
        return { token: null, present: true, secure: false };
      }
    }
    return { token, present: true, secure: true };
  } catch {
    return { token: null, present: false, secure: false };
  } finally {
    if (fd !== null) closeSync(fd);
  }
}

/** Read the bridge credential only after its file identity and platform security state are proven. */
export function readSecureSubagentBridgeToken(options: SecureSubagentBridgeTokenReadOptions = {}): string | null {
  return secureTokenState(options).token;
}

/** Explicit install/migration repair path. Existing invalid attestations are never overwritten. */
export function repairSubagentBridgeTokenAttestation(
  options: SubagentBridgeTokenAttestationRepairOptions = {},
): boolean {
  if ((options.platform ?? process.platform) !== "win32") return false;
  const tokenPath = resolve(options.tokenPath ?? join(resolve(options.configDir ?? getConfigDir()), "subagent-bridge-token"));
  if (readTokenAttestation(subagentBridgeTokenAttestationPath(tokenPath)).kind !== "missing") return false;
  const hardenConfigDir = options.hardenConfigDir
    ?? (path => hardenSubagentBridgeConfigDir(path, options.platform ?? process.platform));
  if (hardenConfigDir(dirname(tokenPath)) === false) return false;
  const state = secureTokenState({ ...options, allowWindowsAclMigration: true });
  if (!state.token || state.secure !== true) return false;
  const writeBytes = options.writeBytes ?? defaultWriteBytes;
  if (!writeTokenAttestation(tokenPath, state.token, writeBytes)) return false;
  return secureTokenState({ tokenPath, platform: "win32" }).token === state.token;
}

function pluginMcpReady(
  pluginDir: string,
  expectedCommand: string,
  expectedArgs: string[],
  platform: NodeJS.Platform,
): boolean {
  try {
    validateInstalledPlugin(pluginDir, expectedCommand, expectedArgs, platform);
    return true;
  } catch {
    return false;
  }
}

function marketplaceStatus(path: string): { ready: boolean; name?: string; warning?: string } {
  if (!existsSync(path)) return { ready: false, warning: "Bridge marketplace entry is missing." };
  try {
    const marketplace = validateMarketplace(readJsonState(path, "personal marketplace", false));
    return {
      ready: marketplace.plugins.some(isOwnedMarketplaceEntry),
      name: marketplace.name,
      ...(!marketplace.plugins.some(isOwnedMarketplaceEntry) ? { warning: "Bridge marketplace entry is missing." } : {}),
    };
  } catch {
    return { ready: false, warning: "Bridge marketplace is invalid or foreign-owned." };
  }
}

export function statusSubagentBridge(options: SubagentBridgeLifecycleOptions = {}): SubagentBridgeStatus {
  const paths = resolveOptions(options);
  assertSafePluginTarget(paths);
  const targetExists = existsSync(paths.pluginDir);
  const installed = targetExists && isOwnedPluginDir(paths.pluginDir);
  const mcpReady = installed && pluginMcpReady(paths.pluginDir, paths.runtimeCommand, paths.runtimeArgs, paths.platform);
  const marketplace = marketplaceStatus(paths.marketplacePath);
  const config = tryJsonState(paths.configPath)?.value;
  const enabled = config?.subagentBridge?.enabled === true;
  const tokenState = secureTokenState({
    tokenPath: paths.tokenPath,
    platform: paths.platform,
    expectedUid: paths.expectedUid,
    inspectTokenSecurity: paths.inspectTokenSecurity,
  });
  const tokenPresent = tokenState.present;
  const tokenSecure = tokenState.secure;
  const registrationMarker = validRegistration(paths.installRecordPath, marketplace.name);
  let actualRegistration: CodexPluginRegistrationState | null = null;
  if (registrationMarker) {
    try {
      const command = codexCommand(paths);
      actualRegistration = paths.inspectRegistration(command, `${SUBAGENT_BRIDGE_PLUGIN_NAME}@${registrationMarker.marketplace}`);
    } catch { /* unavailable is not registered */ }
  }
  const registered = !!registrationMarker && actualRegistration?.installed === true && actualRegistration.enabled === true;
  const warnings: string[] = [];
  if (targetExists && !installed) warnings.push("Bridge plugin target exists but is not owned by opencodex.");
  else if (!installed) warnings.push("Bridge plugin is not installed.");
  if (installed && !mcpReady) warnings.push("Bridge MCP launcher is missing or invalid.");
  if (marketplace.warning) warnings.push(marketplace.warning);
  if (!registered) warnings.push("Bridge Codex registration is missing or invalid.");
  if (!tokenPresent) warnings.push("Bridge authentication token is missing or invalid.");
  if (tokenPresent && tokenSecure === false) warnings.push("Bridge authentication token permissions are insecure.");
  if (tokenPresent && tokenSecure === null) warnings.push("Bridge authentication token security is unknown.");
  if (!enabled) warnings.push("Bridge is disabled in opencodex config.");
  return {
    installed,
    registered,
    enabled,
    tokenPresent,
    tokenSecure,
    marketplaceReady: marketplace.ready,
    mcpReady,
    ready: installed && registered && enabled && tokenPresent && tokenSecure === true && marketplace.ready && mcpReady,
    warnings,
  };
}

function transactionPaths(paths: ResolvedOptions): FileSnapshot[] {
  return [
    paths.marketplacePath,
    paths.configPath,
    paths.tokenPath,
    paths.tokenAttestationPath,
    paths.installRecordPath,
  ].map(snapshotFile);
}

function rollbackFiles(snapshots: FileSnapshot[]): void {
  for (const snapshot of snapshots) restoreSnapshot(snapshot);
}

function refreshWindowsTokenAttestation(paths: ResolvedOptions): void {
  if (paths.platform !== "win32" || !existsSync(paths.tokenPath)) return;
  if (paths.hardenSecret(paths.tokenPath) === false) throw new Error("bridge token rollback hardening failed");
  const state = secureTokenState({
    tokenPath: paths.tokenPath,
    platform: paths.platform,
    expectedUid: paths.expectedUid,
    inspectTokenSecurity: paths.inspectTokenSecurity,
  }, true);
  if (!state.token || state.secure !== true
    || !writeTokenAttestation(paths.tokenPath, state.token, paths.writeBytes)
    || secureTokenState({ tokenPath: paths.tokenPath, platform: "win32" }).token !== state.token) {
    throw new Error("bridge token rollback attestation failed");
  }
}

function ownedTokenAttestation(path: string): boolean {
  return readTokenAttestation(path).kind === "valid";
}

function registrationIsActive(state: CodexPluginRegistrationState): boolean {
  return state.installed && state.enabled;
}

function registrationStatesEqual(left: CodexPluginRegistrationState, right: CodexPluginRegistrationState): boolean {
  return left.installed === right.installed && left.enabled === right.enabled;
}

function assertSupportedRegistrationPrestate(state: CodexPluginRegistrationState): void {
  if (state.installed && !state.enabled) {
    throw new Error("exact Codex plugin registration is disabled; refusing to mutate it");
  }
  if (!state.installed && state.enabled) throw new Error("exact Codex plugin registration state is invalid");
}

function compensateRegistration(
  paths: ResolvedOptions,
  command: string,
  selector: string,
  before: CodexPluginRegistrationState,
  after: CodexPluginRegistrationState,
): void {
  if (registrationStatesEqual(before, after)) return;
  const action = before.installed ? "add" : "remove";
  paths.runCodex(command, ["plugin", action, selector]);
  const restored = paths.inspectRegistration(command, selector);
  if (!restored || !registrationStatesEqual(before, restored)) {
    throw new Error("Codex plugin registration compensation failed");
  }
}

export function installSubagentBridge(options: SubagentBridgeLifecycleOptions = {}): SubagentBridgeStatus {
  const paths = resolveOptions(options);
  return withLifecycleLock(paths, () => installSubagentBridgeLocked(paths, options));
}

function installSubagentBridgeLocked(paths: ResolvedOptions, options: SubagentBridgeLifecycleOptions): SubagentBridgeStatus {
  assertSafePluginTarget(paths);
  const bundleManifest = validateBundle(paths);
  validateRuntime(paths.runtimeCommand, paths.runtimeArgs, paths.platform);
  const command = codexCommand(paths);
  const marketplaceState = readJsonState(paths.marketplacePath, "personal marketplace", true);
  const marketplace = validateMarketplace(marketplaceState);
  const configState = readJsonState(paths.configPath, "opencodex config", true);
  if (existsSync(paths.pluginDir) && !isOwnedPluginDir(paths.pluginDir)) throw new Error("bridge plugin target is not owned by opencodex");
  const previousRecordState = existsSync(paths.installRecordPath)
    ? readJsonState(paths.installRecordPath, "bridge install record", false)
    : null;
  const previousRegistration = previousRecordState ? validRegistration(paths.installRecordPath) : null;
  if (previousRecordState && !previousRegistration) throw new Error("bridge install record is invalid");
  if (previousRegistration && previousRegistration.marketplace !== marketplace.name) {
    throw new Error("bridge install record marketplace mismatch");
  }
  const selector = `${SUBAGENT_BRIDGE_PLUGIN_NAME}@${marketplace.name}`;
  const registrationBefore = paths.inspectRegistration(command, selector);
  if (!registrationBefore) throw new Error("Codex plugin registration could not be inspected");
  assertSupportedRegistrationPrestate(registrationBefore);
  if (!previousRegistration && registrationIsActive(registrationBefore)) {
    throw new Error("exact Codex plugin registration is already active without a matching owned install record");
  }
  const existingToken = secureTokenState({
    tokenPath: paths.tokenPath,
    platform: paths.platform,
    expectedUid: paths.expectedUid,
    inspectTokenSecurity: paths.inspectTokenSecurity,
    allowWindowsAclMigration: true,
  });
  if (pathEntryExists(paths.tokenPath) && !existingToken.token) {
    throw new Error("existing bridge token is invalid, insecure, or has unknown ownership");
  }
  if (!pathEntryExists(paths.tokenPath) && pathEntryExists(paths.tokenAttestationPath)) {
    throw new Error("existing bridge token attestation is invalid or foreign-owned");
  }
  const snapshots = transactionPaths(paths);

  const pluginParent = dirname(paths.pluginDir);
  mkdirSync(pluginParent, { recursive: true });
  const sequence = ++lifecycleSequence;
  const stageDir = join(pluginParent, `.${SUBAGENT_BRIDGE_PLUGIN_NAME}.stage-${process.pid}-${sequence}`);
  const backupDir = join(pluginParent, `.${SUBAGENT_BRIDGE_PLUGIN_NAME}.backup-${process.pid}-${sequence}`);
  if (existsSync(stageDir) || existsSync(backupDir)) throw new Error("bridge staging path collision");
  try {
    paths.copyDir(paths.bundleDir, stageDir);
    const stagedManifestPath = join(stageDir, ".codex-plugin", "plugin.json");
    const stagedManifest = readJsonState(stagedManifestPath, "staged bridge manifest", false).value;
    validateBridgeManifest(stagedManifest, "staged bridge manifest");
    if (stagedManifest.version !== bundleManifest.version) {
      throw new Error("staged bridge manifest is invalid");
    }
    const cacheEntropy = Buffer.from(paths.randomBytes(6));
    if (cacheEntropy.byteLength !== 6) throw new Error("failed to create bridge cachebuster entropy");
    stagedManifest.version = `${stagedManifest.version.split("+", 1)[0]}+codex.local-${timestamp(paths.now())}-${process.pid}-${sequence}-${cacheEntropy.toString("hex")}`;
    paths.writeBytes(stagedManifestPath, jsonBytes(stagedManifest), false);
    paths.writeBytes(join(stageDir, ".mcp.json"), jsonBytes({
      mcpServers: {
        [SUBAGENT_BRIDGE_PLUGIN_NAME]: { command: paths.runtimeCommand, args: paths.runtimeArgs },
      },
    }), false);
    paths.writeBytes(join(stageDir, OWNER_MARKER), jsonBytes(OWNER_RECORD), false);
    if (!isOwnedPluginDir(stageDir) || !pluginMcpReady(stageDir, paths.runtimeCommand, paths.runtimeArgs, paths.platform)) {
      throw new Error("staged bridge plugin failed validation");
    }
  } catch (error) {
    removeOwnedDirectory(stageDir);
    throw error;
  }

  const marketplaceNext = nextMarketplace(marketplace, true);
  const configNext = nextConfig(configState.value, true);
  let registrationAttempted = false;
  let registrationAfter: CodexPluginRegistrationState | null = null;
  try {
    if (existsSync(paths.pluginDir)) renameSync(paths.pluginDir, backupDir);
    renameSync(stageDir, paths.pluginDir);
    if (paths.hardenConfigDir(paths.configDir) === false) throw new Error("bridge config directory ACL hardening failed");
    paths.writeBytes(paths.marketplacePath, jsonBytes(marketplaceNext), false);
    let token = existingToken.token ?? "";
    if (!isValidSubagentBridgeToken(token)) token = Buffer.from(paths.randomBytes(32)).toString("base64url");
    if (!isValidSubagentBridgeToken(token)) throw new Error("failed to create bridge token");
    paths.writeBytes(paths.tokenPath, Buffer.from(`${token}\n`), true);
    if (paths.hardenSecret(paths.tokenPath) === false) throw new Error("bridge token ACL hardening failed");
    const hardenedToken = secureTokenState({
      tokenPath: paths.tokenPath,
      platform: paths.platform,
      expectedUid: paths.expectedUid,
      inspectTokenSecurity: paths.inspectTokenSecurity,
    }, paths.platform === "win32");
    if (hardenedToken.token !== token || hardenedToken.secure !== true) {
      throw new Error("bridge token security verification failed");
    }
    if (paths.platform === "win32"
      && (!writeTokenAttestation(paths.tokenPath, token, paths.writeBytes)
        || secureTokenState({ tokenPath: paths.tokenPath, platform: "win32" }).token !== token)) {
      throw new Error("bridge token attestation failed");
    }
    paths.writeBytes(paths.configPath, jsonBytes(configNext), true);
    registrationAttempted = true;
    const registered = paths.runCodex(command, ["plugin", "add", selector]);
    registrationAfter = paths.inspectRegistration(command, selector);
    if (registered.status !== 0) throw new Error(`codex plugin add failed${registered.error ? `: ${registered.error.message}` : ""}`);
    if (!registrationAfter || !registrationIsActive(registrationAfter)) throw new Error("codex plugin add was not confirmed");
    paths.writeBytes(paths.installRecordPath, jsonBytes(registrationValue(marketplace.name)), false);
    removeOwnedDirectory(backupDir);
    return statusSubagentBridge(options);
  } catch (error) {
    removeOwnedDirectory(paths.pluginDir);
    if (existsSync(backupDir)) renameSync(backupDir, paths.pluginDir);
    rollbackFiles(snapshots);
    refreshWindowsTokenAttestation(paths);
    removeOwnedDirectory(stageDir);
    if (registrationAttempted) {
      const post = registrationAfter ?? paths.inspectRegistration(command, selector);
      if (post) compensateRegistration(paths, command, selector, registrationBefore, post);
    }
    throw error;
  }
}

export function removeSubagentBridge(options: SubagentBridgeLifecycleOptions = {}): SubagentBridgeStatus & { removed: boolean } {
  const paths = resolveOptions(options);
  return withLifecycleLock(paths, () => removeSubagentBridgeLocked(paths, options));
}

function removeSubagentBridgeLocked(
  paths: ResolvedOptions,
  options: SubagentBridgeLifecycleOptions,
): SubagentBridgeStatus & { removed: boolean } {
  assertSafePluginTarget(paths);
  const marketplaceState = readJsonState(paths.marketplacePath, "personal marketplace", true);
  const marketplace = validateMarketplace(marketplaceState, { allowForeignBridgeEntry: true });
  const configState = readJsonState(paths.configPath, "opencodex config", true);
  if (existsSync(paths.pluginDir) && !isOwnedPluginDir(paths.pluginDir)) throw new Error("bridge plugin target is not owned by opencodex");
  const registrationState = existsSync(paths.installRecordPath)
    ? readJsonState(paths.installRecordPath, "bridge install record", false)
    : null;
  const registration = registrationState ? validRegistration(paths.installRecordPath) : null;
  if (registrationState && !registration) throw new Error("bridge install record is invalid");
  if (registration && registration.marketplace !== marketplace.name) {
    throw new Error("bridge install record marketplace mismatch");
  }
  const command = registration ? codexCommand(paths) : null;
  const selector = registration ? `${SUBAGENT_BRIDGE_PLUGIN_NAME}@${registration.marketplace}` : null;
  const registrationBefore = command && selector ? paths.inspectRegistration(command, selector) : null;
  if (registration && !registrationBefore) throw new Error("Codex plugin registration could not be inspected");
  if (registrationBefore) assertSupportedRegistrationPrestate(registrationBefore);

  const snapshots = transactionPaths(paths);
  const sequence = ++lifecycleSequence;
  const backupDir = join(dirname(paths.pluginDir), `.${SUBAGENT_BRIDGE_PLUGIN_NAME}.remove-${process.pid}-${sequence}`);
  if (existsSync(backupDir)) throw new Error("bridge removal staging path collision");
  const marketplaceNext = nextMarketplace(marketplace, false);
  const configNext = nextConfig(configState.value, false);
  const hadPlugin = existsSync(paths.pluginDir);
  const hadMarketplace = marketplace.plugins.some(isOwnedMarketplaceEntry);
  const hadToken = existsSync(paths.tokenPath);
  const hadAttestation = ownedTokenAttestation(paths.tokenAttestationPath);
  const hadRecord = !!registrationState;
  const rollbackLocalState = (): void => {
    if (existsSync(paths.pluginDir)) removeOwnedDirectory(paths.pluginDir);
    if (existsSync(backupDir)) renameSync(backupDir, paths.pluginDir);
    rollbackFiles(snapshots);
    refreshWindowsTokenAttestation(paths);
  };
  try {
    if (hadPlugin) renameSync(paths.pluginDir, backupDir);
    if (hadMarketplace) paths.writeBytes(paths.marketplacePath, jsonBytes(marketplaceNext), false);
    paths.writeBytes(paths.configPath, jsonBytes(configNext), true);
    if (hadAttestation) unlinkSync(paths.tokenAttestationPath);
    if (hadToken) unlinkSync(paths.tokenPath);
    if (hadRecord) unlinkSync(paths.installRecordPath);
  } catch (error) {
    rollbackLocalState();
    throw error;
  }

  if (registration && command && selector && registrationBefore?.installed) {
    let registrationAfter: CodexPluginRegistrationState | null = null;
    try {
      const removed = paths.runCodex(command, ["plugin", "remove", selector]);
      registrationAfter = paths.inspectRegistration(command, selector);
      if (removed.status !== 0) throw new Error(`codex plugin remove failed${removed.error ? `: ${removed.error.message}` : ""}`);
      if (!registrationAfter || !registrationStatesEqual(registrationAfter, { installed: false, enabled: false })) {
        throw new Error("codex plugin remove was not confirmed");
      }
    } catch (error) {
      let rollbackError: unknown;
      try { rollbackLocalState(); } catch (failure) { rollbackError = failure; }
      if (registrationAfter) compensateRegistration(paths, command, selector, registrationBefore, registrationAfter);
      if (rollbackError) throw rollbackError;
      throw error;
    }
  }

  try { removeOwnedDirectory(backupDir); } catch { /* committed removal cleanup is best-effort */ }
  return { ...statusSubagentBridge(options), removed: hadPlugin || hadMarketplace || hadToken || hadAttestation || hadRecord };
}
