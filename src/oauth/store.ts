/**
 * OAuth token store at ~/.opencodex/auth.json, keyed by provider name.
 *
 * Multiauth shape (260706): each provider value is a ProviderAccountSet
 * `{ activeAccountId, accounts: [{ id, credential, needsReauth?, addedAt? }] }`.
 * Legacy single-credential values (`{ access, refresh, expires, ... }`) normalize on load,
 * and the first new-shape persist writes a one-time `auth.json.pre-multiauth` backup so a
 * downgraded loader (which silently drops unknown shapes) cannot destroy refresh tokens.
 *
 * Exceptions:
 * - `chatgpt` stays single-slot (always replaced): codex-auth-api uses it as a scratch slot
 *   for Codex pool logins, which have their own ledger (codex-accounts.json).
 * - Credentials without identity (no accountId/email — e.g. kiro) replace the active slot
 *   instead of appending: their refresh tokens rotate, so a derived id would duplicate the
 *   same human on every re-login. Kimi extracts JWT `user_id`/`sub` as accountId; Cursor
 *   extracts JWT `sub` — both append distinct accounts under multiauth.
 */
import { createHash, randomUUID } from "node:crypto";
import { chmodSync, closeSync, existsSync, fstatSync, mkdirSync, openSync, readFileSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { AtomicWriteSecretResidualError, getConfigDir, atomicWriteFile, backupInvalidConfig, hardenConfigDir, hardenExistingSecret } from "../config";
import { validateCopilotApiBaseUrl } from "./github-copilot";
import type { OAuthCredentialSource, OAuthCredentials, ProviderAccount, ProviderAccountSet } from "./types";

type AuthStore = Record<string, ProviderAccountSet>;
interface LoginFenceStore {
  version: 1;
  epoch: string;
  generations: Record<string, number>;
}
export interface OAuthLoginFenceSnapshot {
  epoch: string;
  generation: number;
}

/** Providers whose account set is pinned to a single slot (see module doc). */
const SINGLE_SLOT_PROVIDERS = new Set(["chatgpt"]);

export function getAuthStorePath(): string {
  return join(getConfigDir(), "auth.json");
}
export function getAuthStoreLockPath(): string { return join(getConfigDir(), "auth.store.lock"); }
export function getAuthLoginFencePath(): string { return join(getConfigDir(), "auth.login-fences.json"); }
export function getAuthRefreshIntentLockPath(provider: string, accountId: string): string {
  const safeProvider = provider.replace(/[^a-zA-Z0-9_-]/g, "_");
  const accountHash = createHash("sha256").update(accountId).digest("hex").slice(0, 24);
  return join(getConfigDir(), `auth.refresh.${safeProvider}.${accountHash}.lock`);
}
export function credentialGeneration(cred: OAuthCredentials): string {
  return createHash("sha256").update(JSON.stringify([cred.refresh, cred.access, cred.expires])).digest("hex");
}

export class OAuthLoginFenceError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "OAuthLoginFenceError";
  }
}

export class OAuthLoginSupersededError extends Error {
  constructor(provider: string) {
    super(`OAuth login for ${provider} was superseded by logout`);
    this.name = "OAuthLoginSupersededError";
  }
}

function emptyLoginFenceStore(): LoginFenceStore {
  return { version: 1, epoch: randomUUID(), generations: Object.create(null) as Record<string, number> };
}

function loadLoginFenceStore(): LoginFenceStore | null {
  const path = getAuthLoginFencePath();
  hardenConfigDir();
  hardenExistingSecret(path);
  if (!existsSync(path)) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch (cause) {
    throw new OAuthLoginFenceError("OAuth login fence is corrupt; refusing credential mutation", { cause });
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new OAuthLoginFenceError("OAuth login fence has an invalid shape; refusing credential mutation");
  }
  const candidate = parsed as { version?: unknown; epoch?: unknown; generations?: unknown };
  if (
    candidate.version !== 1
    || typeof candidate.epoch !== "string"
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(candidate.epoch)
    || !candidate.generations
    || typeof candidate.generations !== "object"
    || Array.isArray(candidate.generations)
  ) {
    throw new OAuthLoginFenceError("OAuth login fence has an invalid shape; refusing credential mutation");
  }
  const generations = Object.create(null) as Record<string, number>;
  for (const [provider, generation] of Object.entries(candidate.generations)) {
    if (!Number.isSafeInteger(generation) || Number(generation) < 0) {
      throw new OAuthLoginFenceError("OAuth login fence has an invalid generation; refusing credential mutation");
    }
    generations[provider] = Number(generation);
  }
  return { version: 1, epoch: candidate.epoch, generations };
}

function loadAuthStoreInternal(): { store: AuthStore; hadLegacy: boolean } {
  const path = getAuthStorePath();
  hardenConfigDir();
  hardenExistingSecret(path);
  if (!existsSync(path)) return { store: {}, hadLegacy: false };
  try {
    return normalizeAuthStore(JSON.parse(readFileSync(path, "utf-8")));
  } catch {
    backupInvalidConfig(path);
    return { store: {}, hadLegacy: false };
  }
}

export function loadAuthStore(): AuthStore {
  return loadAuthStoreInternal().store;
}

function ensureAuthDirectory(): void {
  const dir = getConfigDir();
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  } else {
    try { chmodSync(dir, 0o700); } catch { /* best-effort on existing dir */ }
  }
  hardenConfigDir();
}

function persist(store: AuthStore): void {
  ensureAuthDirectory();
  atomicWriteFile(getAuthStorePath(), JSON.stringify(store, null, 2) + "\n");
}

function persistLoginFenceStore(store: LoginFenceStore): void {
  ensureAuthDirectory();
  atomicWriteFile(getAuthLoginFencePath(), JSON.stringify(store, null, 2) + "\n");
}

export class OAuthFileLockError extends Error { readonly code = "OAUTH_FILE_LOCK_UNAVAILABLE"; constructor(message: string, options?: { cause?: unknown }) { super(message, options); this.name = "OAuthFileLockError"; } }
interface LockSnapshot { bytes: string; dev: number; ino: number; mtimeMs: number; size: number }
export interface OAuthFileLockOptions { path: string; waitTimeoutMs?: number; staleAfterMs?: number; pollMinMs?: number; pollMaxMs?: number; sleep?: (ms: number) => Promise<void>; now?: () => number; random?: () => number; beforeStaleUnlink?: () => void; beforeReleaseUnlink?: () => void; beforeFailedCreateUnlink?: () => void; writeMetadata?: (fd: number, bytes: string) => void }
export interface OAuthFileLockGuard { readonly ownerId: string; release(): void }
function errorCode(error: unknown): string | undefined { return error && typeof error === "object" && "code" in error ? String((error as { code?: unknown }).code) : undefined; }
function snapshot(path: string): LockSnapshot { const bytes = readFileSync(path, "utf8"); const s = statSync(path); return { bytes, dev:s.dev, ino:s.ino, mtimeMs:s.mtimeMs, size:s.size }; }
function sameSnapshot(a: LockSnapshot,b: LockSnapshot): boolean { return a.bytes===b.bytes&&a.dev===b.dev&&a.ino===b.ino&&a.mtimeMs===b.mtimeMs&&a.size===b.size; }
function sameFd(a: LockSnapshot,b: ReturnType<typeof fstatSync>): boolean { return a.dev===b.dev&&a.ino===b.ino&&a.mtimeMs===b.mtimeMs&&a.size===b.size; }
export function createOAuthFileLock(options: OAuthFileLockOptions): { acquire(): Promise<OAuthFileLockGuard> } {
 const wait=options.waitTimeoutMs??5000, stale=options.staleAfterMs??120000, min=options.pollMinMs??25,max=options.pollMaxMs??100,sleep=options.sleep??(ms=>Bun.sleep(ms)),now=options.now??Date.now,random=options.random??Math.random,write=options.writeMetadata??((fd,b)=>writeFileSync(fd,b,"utf8"));
 if(wait<0||stale<=0||min<0||max<min) throw new OAuthFileLockError("Invalid OAuth file-lock timing options");
 return { async acquire() { hardenConfigDir(); if(!existsSync(getConfigDir())) mkdirSync(getConfigDir(),{recursive:true,mode:0o700}); const ownerId=randomUUID(),started=now(); for(;;){ let fd:number|undefined; try { fd=openSync(options.path,"wx",0o600); const bytes=`${JSON.stringify({version:1,ownerId,pid:process.pid,createdAt:now()})}\n`; write(fd,bytes); const fs=fstatSync(fd); closeSync(fd); fd=undefined; const owned=snapshot(options.path); if(owned.bytes!==bytes||!sameFd(owned,fs)) throw new OAuthFileLockError("OAuth lock changed during creation"); let released=false; return {ownerId,release(){if(released)return;released=true;try{const a=snapshot(options.path);if(!sameSnapshot(owned,a))return;options.beforeReleaseUnlink?.();const b=snapshot(options.path);if(sameSnapshot(owned,b))unlinkSync(options.path);}catch(e){if(errorCode(e)!=="ENOENT")console.warn(`[oauth] lock release failed: ${e instanceof Error?e.message:String(e)}`);}}}; } catch(e) { if(fd!==undefined){let fs;try{fs=fstatSync(fd);}catch{}try{closeSync(fd);}catch{}if(fs)try{const a=snapshot(options.path);if(sameFd(a,fs)){options.beforeFailedCreateUnlink?.();const b=snapshot(options.path);if(sameSnapshot(a,b)&&sameFd(b,fs))unlinkSync(options.path);}}catch{}} if(errorCode(e)!=="EEXIST")throw e instanceof OAuthFileLockError?e:new OAuthFileLockError("Could not create OAuth file lock",{cause:e}); }
 try{const a=snapshot(options.path);let created=a.mtimeMs;try{const p=JSON.parse(a.bytes);if(typeof p.createdAt==="number")created=Math.max(created,p.createdAt);}catch{}if(now()-created>stale){options.beforeStaleUnlink?.();const b=snapshot(options.path);if(sameSnapshot(a,b))unlinkSync(options.path);continue;}}catch(e){if(errorCode(e)==="ENOENT")continue;throw new OAuthFileLockError("Could not inspect OAuth file lock",{cause:e});} const elapsed=now()-started;if(elapsed>=wait)throw new OAuthFileLockError(`Timed out after ${wait}ms waiting for OAuth file lock`);await sleep(Math.min(wait-elapsed,min+Math.floor(random()*(max-min+1)))); } } };
}
export function createOAuthRefreshIntentLock(provider:string,accountId:string,overrides:Partial<OAuthFileLockOptions>={}) { return createOAuthFileLock({path:getAuthRefreshIntentLockPath(provider,accountId),staleAfterMs:120000,...overrides}); }

/**
 * One-time downgrade safety net: the first time we persist the NEW shape over a file that
 * still contains legacy single-credential entries, keep a pristine copy. An older opencodex
 * would silently drop the new shape (normalizeCredential -> null) and then persist an empty
 * store, destroying refresh tokens; the backup makes that recoverable.
 */
function backupLegacyOnce(): void {
  const path = getAuthStorePath();
  const backup = `${path}.pre-multiauth`;
  if (!existsSync(path) || existsSync(backup)) return;
  try {
    // This file contains the same refresh tokens as auth.json. Reuse the secret-aware atomic
    // writer so bytes are added only after the temp file's Windows ACL is hardened, even when
    // the process-local directory hardening cache outlives a delete/recreate of that path.
    atomicWriteFile(backup, readFileSync(path, "utf8"));
  } catch (error) {
    // Losing the optional downgrade backup may be tolerated, but a temp file that still contains
    // refresh tokens is a confidentiality incident and must never be hidden from the caller.
    if (error instanceof AtomicWriteSecretResidualError) throw error;
  }
}

function isCredentialSource(value: unknown): value is OAuthCredentialSource {
  return value === "oauth" || value === "local-cli" || value === "credential-file" || value === "environment" || value === "manual";
}

function normalizeCredential(cred: unknown): OAuthCredentials | null {
  if (!cred || typeof cred !== "object") return null;
  const candidate = cred as Partial<OAuthCredentials>;
  if (typeof candidate.access !== "string" || typeof candidate.refresh !== "string" || typeof candidate.expires !== "number") {
    return null;
  }
  const normalized: OAuthCredentials = {
    access: candidate.access,
    refresh: candidate.refresh,
    expires: candidate.expires,
  };
  if (typeof candidate.email === "string" && candidate.email.length > 0) normalized.email = candidate.email;
  if (typeof candidate.accountId === "string" && candidate.accountId.length > 0) normalized.accountId = candidate.accountId;
  if (isCredentialSource(candidate.source)) normalized.source = candidate.source;
  if (typeof candidate.projectId === "string" && candidate.projectId.length > 0) normalized.projectId = candidate.projectId;
  if (typeof candidate.apiBaseUrl === "string" && candidate.apiBaseUrl.length > 0) {
    // Persist only allowlisted Copilot origins; drop anything else so auth.json cannot
    // become an SSRF springboard across reloads.
    const validated = validateCopilotApiBaseUrl(candidate.apiBaseUrl);
    if (validated) normalized.apiBaseUrl = validated;
  }
  return normalized;
}

/**
 * Stable short account id. MUST be deterministic for a given credential: legacy
 * single-credential stores are re-normalized on EVERY load without being persisted,
 * so a time-salted id would differ between two loads (getAccountSet vs
 * getAccountCredential), surfacing as a spurious OAuthLoginRequiredError and making
 * refresh persists silently miss the account (rotated refresh token lost).
 */
function newAccountId(cred: OAuthCredentials): string {
  const identity = cred.accountId ?? cred.email ?? cred.refresh;
  return createHash("sha256").update(identity).digest("hex").slice(0, 8);
}

function normalizeAccount(value: unknown): ProviderAccount | null {
  if (!value || typeof value !== "object") return null;
  const candidate = value as Partial<ProviderAccount>;
  if (typeof candidate.id !== "string" || candidate.id.length === 0) return null;
  const credential = normalizeCredential(candidate.credential);
  if (!credential) return null;
  const account: ProviderAccount = { id: candidate.id, credential };
  if (candidate.needsReauth === true) account.needsReauth = true;
  if (typeof candidate.addedAt === "number") account.addedAt = candidate.addedAt;
  return account;
}

function normalizeAccountSet(raw: unknown): { set: ProviderAccountSet | null; wasLegacy: boolean } {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { set: null, wasLegacy: false };
  const candidate = raw as Partial<ProviderAccountSet>;
  if (Array.isArray(candidate.accounts)) {
    const accounts = candidate.accounts.map(normalizeAccount).filter((a): a is ProviderAccount => a !== null);
    if (accounts.length === 0) return { set: null, wasLegacy: false };
    const active = typeof candidate.activeAccountId === "string" && accounts.some(a => a.id === candidate.activeAccountId)
      ? candidate.activeAccountId
      : accounts[0]!.id;
    return { set: { activeAccountId: active, accounts }, wasLegacy: false };
  }
  // Legacy single-credential value.
  const cred = normalizeCredential(raw);
  if (!cred) return { set: null, wasLegacy: false };
  const id = newAccountId(cred);
  return { set: { activeAccountId: id, accounts: [{ id, credential: cred }] }, wasLegacy: true };
}

function normalizeAuthStore(raw: unknown): { store: AuthStore; hadLegacy: boolean } {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { store: {}, hadLegacy: false };
  const normalized: AuthStore = {};
  let hadLegacy = false;
  for (const [provider, value] of Object.entries(raw)) {
    const { set, wasLegacy } = normalizeAccountSet(value);
    if (set) normalized[provider] = set;
    if (wasLegacy) hadLegacy = true;
  }
  return { store: normalized, hadLegacy };
}

/**
 * In-process write serialization plus a cross-process file lock: every mutation runs
 * load-modify-persist under the same lock so auth.json and the persisted login fence share
 * one ordering boundary.
 */
let mutationTail: Promise<void> = Promise.resolve();
function serializeMutation<T>(work:()=>Promise<T>):Promise<T>{const result=mutationTail.then(work,work);mutationTail=result.then(()=>undefined,()=>undefined);return result;}
function withAuthStoreLock<T>(work: () => T | Promise<T>): Promise<T> {
  return serializeMutation(async () => {
    const guard = await createOAuthFileLock({ path: getAuthStoreLockPath(), staleAfterMs: 30000 }).acquire();
    try {
      return await work();
    } finally {
      guard.release();
    }
  });
}

export function mutateStore<T>(fn:(store:AuthStore)=>T|Promise<T>, shouldPersist:()=>boolean=()=>true):Promise<T>{return withAuthStoreLock(async()=>{
    const { store, hadLegacy } = loadAuthStoreInternal();
    if (hadLegacy) backupLegacyOnce();
    const result = await fn(store);
    // A cancellation can land at the `await fn` microtask boundary after the in-memory mutation.
    // Recheck immediately before publishing so a stale login never reaches auth.json.
    if (shouldPersist()) persist(store);
    return result;
  });
}

/** Snapshot the store incarnation and provider logout generation before external OAuth I/O. */
export function snapshotLoginFenceGeneration(provider: string): Promise<OAuthLoginFenceSnapshot> {
  return withAuthStoreLock(() => {
    const loaded = loadLoginFenceStore();
    const fences = loaded ?? emptyLoginFenceStore();
    const providerMissing = !Object.hasOwn(fences.generations, provider);
    if (providerMissing) fences.generations[provider] = 0;
    if (!loaded || providerMissing) persistLoginFenceStore(fences);
    return { epoch: fences.epoch, generation: fences.generations[provider]! };
  });
}

function assertLoginFenceGeneration(provider: string, expectedFence: OAuthLoginFenceSnapshot | undefined): void {
  if (expectedFence === undefined) return;
  const fences = loadLoginFenceStore();
  if (!fences) {
    throw new OAuthLoginFenceError("OAuth login fence disappeared; refusing credential mutation");
  }
  if (
    fences.epoch !== expectedFence.epoch
    || !Object.hasOwn(fences.generations, provider)
    || fences.generations[provider] !== expectedFence.generation
  ) {
    throw new OAuthLoginSupersededError(provider);
  }
}

/** Advance the provider generation before a destructive credential mutation. Lock required. */
function advanceLoginFence(provider: string): void {
  const fences = loadLoginFenceStore() ?? emptyLoginFenceStore();
  const generation = fences.generations[provider] ?? 0;
  if (generation >= Number.MAX_SAFE_INTEGER) {
    throw new OAuthLoginFenceError("OAuth login fence generation is exhausted; refusing logout");
  }
  fences.generations[provider] = generation + 1;
  persistLoginFenceStore(fences);
}

function loginPersistGuard(
  provider: string,
  shouldPersist: () => boolean,
  expectedLoginFence: OAuthLoginFenceSnapshot | undefined,
): () => boolean {
  return () => {
    if (!shouldPersist()) return false;
    assertLoginFenceGeneration(provider, expectedLoginFence);
    return true;
  };
}

/** The ACTIVE account's credential for a provider (what requests should use). */
export function getCredential(provider: string): OAuthCredentials | null {
  const set = loadAuthStore()[provider];
  if (!set) return null;
  return set.accounts.find(a => a.id === set.activeAccountId)?.credential ?? null;
}

/**
 * Persist a credential as the ACTIVE account. Identity-matching (accountId ?? email) upserts
 * the same human's slot; a new identity appends a new account. Credentials without identity
 * (rotating refresh tokens would fabricate duplicates) and single-slot providers replace the
 * active slot / whole set instead.
 */
export async function saveCredential(
  provider: string,
  cred: OAuthCredentials,
  shouldPersist: () => boolean = () => true,
  expectedLoginFence?: OAuthLoginFenceSnapshot,
): Promise<void> {
  const safe = normalizeCredential(cred);
  if (!safe) return;
  const canPersist = loginPersistGuard(provider, shouldPersist, expectedLoginFence);
  await mutateStore(store => {
    // Recheck after the store lock is acquired: a logout/cancel may have happened while this
    // mutation waited behind another writer.
    if (!canPersist()) return;
    const set = store[provider];
    const identity = safe.accountId ?? safe.email;
    if (!set || SINGLE_SLOT_PROVIDERS.has(provider)) {
      const id = newAccountId(safe);
      store[provider] = { activeAccountId: id, accounts: [{ id, credential: safe, addedAt: Date.now() }] };
      return;
    }
    if (identity) {
      const existing = set.accounts.find(a => (a.credential.accountId ?? a.credential.email) === identity);
      if (existing) {
        existing.credential = safe;
        delete existing.needsReauth;
        set.activeAccountId = existing.id;
        return;
      }
      // Legacy migration: a pre-identity row (no accountId/email) for this provider is the
      // SAME human re-logging in after the identity extraction shipped — upgrading the
      // active identity-less row in place prevents a stale duplicate that stays selectable
      // and would re-refresh into a second row with the same identity.
      const active = set.accounts.find(a => a.id === set.activeAccountId);
      if (active && active.credential.accountId === undefined && active.credential.email === undefined) {
        active.credential = safe;
        delete active.needsReauth;
        return;
      }
      const id = newAccountId(safe);
      set.accounts.push({ id, credential: safe, addedAt: Date.now() });
      set.activeAccountId = id;
      return;
    }
    // No identity: replace the active slot in place (single-account semantics).
    const active = set.accounts.find(a => a.id === set.activeAccountId);
    if (active) {
      active.credential = safe;
      delete active.needsReauth;
    } else {
      const id = newAccountId(safe);
      set.accounts.push({ id, credential: safe, addedAt: Date.now() });
      set.activeAccountId = id;
    }
  }, canPersist);
}

/**
 * Remove the ACTIVE account; remaining accounts promote the first one. The persisted generation
 * is advanced first under the shared lock, so a crash can leave an old credential present but can
 * never allow a login that started before this logout to publish afterward.
 */
export async function removeCredential(provider: string): Promise<void> {
  await withAuthStoreLock(() => {
    advanceLoginFence(provider);

    const { store, hadLegacy } = loadAuthStoreInternal();
    if (hadLegacy) backupLegacyOnce();
    const set = store[provider];
    if (set) {
      set.accounts = set.accounts.filter(a => a.id !== set.activeAccountId);
      if (set.accounts.length === 0) delete store[provider];
      else set.activeAccountId = set.accounts[0]!.id;
    }
    persist(store);
  });
}

// ---------------------------------------------------------------------------
// Multi-account API
// ---------------------------------------------------------------------------

export function getAccountSet(provider: string): ProviderAccountSet | null {
  return loadAuthStore()[provider] ?? null;
}

export function listAccounts(provider: string): ProviderAccount[] {
  return loadAuthStore()[provider]?.accounts ?? [];
}

export function getAccountCredential(provider: string, accountId: string): OAuthCredentials | null {
  return loadAuthStore()[provider]?.accounts.find(a => a.id === accountId)?.credential ?? null;
}

/** Persist a refreshed credential for a SPECIFIC account without touching activeAccountId. */
export async function saveAccountCredential(
  provider: string,
  accountId: string,
  cred: OAuthCredentials,
  shouldPersist: () => boolean = () => true,
  expectedLoginFence?: OAuthLoginFenceSnapshot,
): Promise<void> {
  const safe = normalizeCredential(cred);
  if (!safe) return;
  const canPersist = loginPersistGuard(provider, shouldPersist, expectedLoginFence);
  await mutateStore(store => {
    if (!canPersist()) return;
    const account = store[provider]?.accounts.find(a => a.id === accountId);
    if (!account) return;
    account.credential = safe;
    delete account.needsReauth;
  }, canPersist);
}

export async function setActiveAccount(provider: string, accountId: string): Promise<boolean> {
  return await mutateStore(store => {
    const set = store[provider];
    if (!set || !set.accounts.some(a => a.id === accountId)) return false;
    set.activeAccountId = accountId;
    return true;
  });
}

/** Preview the next usable account without changing the user's active selection. */
export function nextAccountAfterFailure(
  provider: string,
  failedAccountId: string,
  excludedAccountIds: ReadonlySet<string>,
): ProviderAccount | null {
  const set = getAccountSet(provider);
  if (!set || set.accounts.length < 2) return null;
  const failedIndex = set.accounts.findIndex(account => account.id === failedAccountId);
  if (failedIndex < 0) return null;
  for (let offset = 1; offset < set.accounts.length; offset++) {
    const candidate = set.accounts[(failedIndex + offset) % set.accounts.length]!;
    if (candidate.needsReauth || excludedAccountIds.has(candidate.id)) continue;
    return { ...candidate, credential: { ...candidate.credential } };
  }
  return null;
}

/** Commit a successful fallback only if the user's active account did not change meanwhile. */
export async function setActiveAccountIfCurrent(
  provider: string,
  expectedAccountId: string,
  nextAccountId: string,
): Promise<boolean> {
  return await mutateStore(store => {
    const set = store[provider];
    if (!set || !set.accounts.some(account => account.id === nextAccountId)) return false;
    if (set.activeAccountId === nextAccountId) return true;
    if (set.activeAccountId !== expectedAccountId) return false;
    set.activeAccountId = nextAccountId;
    return true;
  });
}

/** Remove one account by id; active removal promotes the first remaining account. */
export async function removeAccount(provider: string, accountId: string): Promise<boolean> {
  return await withAuthStoreLock(() => {
    const { store, hadLegacy } = loadAuthStoreInternal();
    if (hadLegacy) backupLegacyOnce();
    const set = store[provider];
    if (!set) return false;
    if (!set.accounts.some(account => account.id === accountId)) return false;

    // Account deletion is logout-equivalent for this provider. Publish the fence before
    // auth.json so a crash can retain an old account but cannot admit an older pending login.
    advanceLoginFence(provider);
    set.accounts = set.accounts.filter(account => account.id !== accountId);
    if (set.accounts.length === 0) {
      delete store[provider];
    } else if (set.activeAccountId === accountId) {
      set.activeAccountId = set.accounts[0]!.id;
    }
    persist(store);
    return true;
  });
}

export async function markAccountNeedsReauth(provider: string, accountId: string, needsReauth: boolean): Promise<void> {
  await mutateStore(store => {
    const account = store[provider]?.accounts.find(a => a.id === accountId);
    if (!account) return;
    if (needsReauth) account.needsReauth = true;
    else delete account.needsReauth;
  });
}

export async function mergeAccountCredential(provider:string,accountId:string,credential:OAuthCredentials,opts:{expectedGeneration?:string;afterPrePersistRead?:()=>void|Promise<void>}={}):Promise<{superseded:false}|{superseded:true;stored:OAuthCredentials}>{const safe=normalizeCredential(credential);if(!safe)throw new Error("Refusing to persist invalid OAuth credential");return await mutateStore(async store=>{await opts.afterPrePersistRead?.();const account=store[provider]?.accounts.find(x=>x.id===accountId);if(!account)throw new Error(`OAuth account disappeared before persist: ${provider}`);if(opts.expectedGeneration!==undefined&&credentialGeneration(account.credential)!==opts.expectedGeneration)return{superseded:true,stored:account.credential};account.credential=safe;delete account.needsReauth;return{superseded:false};});}
export async function markAccountNeedsReauthIfGeneration(provider:string,accountId:string,generation:string):Promise<boolean>{return await mutateStore(store=>{const account=store[provider]?.accounts.find(x=>x.id===accountId);if(!account?.credential||credentialGeneration(account.credential)!==generation)return false;account.needsReauth=true;return true;});}
