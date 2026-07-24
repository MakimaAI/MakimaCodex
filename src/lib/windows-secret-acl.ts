/**
 * Windows per-user NTFS ACL hardening for secret files and directories.
 *
 * On Windows, `chmod` only controls POSIX-style bits in the ACE list and does NOT remove
 * inherited permissions from other users. Real per-user isolation requires icacls to:
 *   1. Grant the current user full control (icacls path /grant:r "CURRENTUSER:(F)")
 *   2. Disable inheritance   (icacls path /inheritance:r)
 *   3. Strip broad explicit grants by SID (Everyone, Users, Authenticated Users)
 *
 * On non-Windows platforms the helpers fall through to the caller's existing chmod-based
 * behaviour: they return ok:true without invoking any external process.
 *
 * Design:
 *   hardenSecretPath(path, { required: false }) — non-fatal read-path mode.
 *     Never throws. Returns { ok, diagnostics? }.
 *   hardenSecretPath(path, { required: true })  — write-path mode.
 *     Throws a sanitized error (no raw path) on Windows ACL failure — EXCEPT a
 *     genuine icacls timeout, which soft-fails (warn + ok:false) so a hung/slow
 *     icacls cannot block OAuth logins or token refresh (field report: Kimi auth
 *     stuck behind ETIMEDOUT). Real EPERM/EACCES/exit-code failures still throw:
 *     availability never silently overrides confidentiality for those.
 *   hardenSecretDir  — same contract for directories.
 */

import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { env, platform } from "node:process";
import { fileURLToPath } from "node:url";

const hardenedDirectories = new Set<string>();
const hardenedPaths = new Set<string>();
/** Paths whose harden TIMED OUT this process: do not re-stall every loadConfig on them. */
const timedOutPaths = new Set<string>();

export interface HardenResult {
  ok: boolean;
  diagnostics?: string;
}

export interface AclInspectionResult {
  secure: boolean | null;
  diagnostics?: string;
}

export interface HardenOptions {
  required: boolean;
  verifyIsolation?: boolean;
  force?: boolean;
}

/**
 * Total icacls budget per harden call — ALL steps share it, including the single
 * timeout retry and the diagnostic verification pass (no per-attempt fresh budget:
 * loadConfig hardens dir+config+auth sequentially, so per-attempt budgets stack
 * into multi-minute startup stalls). Override with OPENCODEX_ACL_TIMEOUT_MS
 * (integer ms, clamped to [1000, 60000]; invalid values fall back to 5000).
 */
const HARDEN_DEADLINE_DEFAULT_MS = 5_000;
const HARDEN_DEADLINE_MIN_MS = 1_000;
const HARDEN_DEADLINE_MAX_MS = 60_000;

/** Resolve the total harden budget once per call (env mutation cannot change it midway). */
function resolveHardenDeadlineMs(): number {
  const raw = env["OPENCODEX_ACL_TIMEOUT_MS"]?.trim();
  if (!raw) return HARDEN_DEADLINE_DEFAULT_MS;
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed)) return HARDEN_DEADLINE_DEFAULT_MS;
  return Math.min(HARDEN_DEADLINE_MAX_MS, Math.max(HARDEN_DEADLINE_MIN_MS, parsed));
}

export interface IcaclsResult {
  success: boolean;
  exitCode: number | null;
  timedOut: boolean;
  stdout: string;
}

type IcaclsRunner = (args: string[], timeoutMs: number) => IcaclsResult;
type AclInspectorRunner = (args: string[], timeoutMs: number) => IcaclsResult;
const ACL_INSPECT_MAX_BYTES = 1024 * 1024;
const ACL_INSPECT_SCRIPT_PATH = fileURLToPath(new URL("./windows-acl-inspect.ps1", import.meta.url));

function defaultIcaclsRunner(args: string[], timeoutMs: number): IcaclsResult {
  // Bun.spawnSync with windowsHide: Node execFileSync has hung under the GUI/proxy even
  // with windowsHide, and console-subsystem tools flash a visible window otherwise.
  const result = Bun.spawnSync(["icacls.exe", ...args], {
    stdin: "ignore",
    stdout: "pipe",
    stderr: "ignore",
    timeout: timeoutMs,
    windowsHide: true,
  });
  return {
    success: result.success,
    exitCode: result.exitCode,
    timedOut: result.exitedDueToTimeout ?? false,
    stdout: result.stdout ? result.stdout.toString() : "",
  };
}

let icaclsRunner: IcaclsRunner = defaultIcaclsRunner;
function defaultAclInspectorRunner(args: string[], timeoutMs: number): IcaclsResult {
  const result = spawnSync("powershell.exe", args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
    windowsHide: true,
    shell: false,
    timeout: timeoutMs,
    maxBuffer: ACL_INSPECT_MAX_BYTES,
  });
  return {
    success: result.status === 0 && !result.error,
    exitCode: result.status,
    timedOut: (result.error as NodeJS.ErrnoException | undefined)?.code === "ETIMEDOUT",
    stdout: typeof result.stdout === "string" ? result.stdout : "",
  };
}

let aclInspectorRunner: AclInspectorRunner = defaultAclInspectorRunner;
let platformOverride: string | null = null;
let nowFn: () => number = Date.now;

/** Test seam: replace the icacls process runner. Pass null to restore the default. */
export function setIcaclsRunnerForTests(runner: IcaclsRunner | null): void {
  icaclsRunner = runner ?? defaultIcaclsRunner;
}

/** Test seam: replace the read-only PowerShell/Get-Acl runner. */
export function setAclInspectorRunnerForTests(runner: AclInspectorRunner | null): void {
  aclInspectorRunner = runner ?? defaultAclInspectorRunner;
}

/** Test seam: force the platform gate (e.g. "win32") so CI on POSIX reaches the runner. */
export function setPlatformForTests(value: string | null): void {
  platformOverride = value;
}

/** Test seam: injectable clock for deadline tests (no real sleeps). */
export function setNowForTests(fn: (() => number) | null): void {
  nowFn = fn ?? Date.now;
}

/** Test seam: clear memo/failure caches between cases. */
export function resetHardenedStateForTests(): void {
  hardenedDirectories.clear();
  hardenedPaths.clear();
  timedOutPaths.clear();
}

function effectivePlatform(): string {
  return platformOverride ?? platform;
}

/** Error carrying an honest code: ETIMEDOUT only for real timeouts, EICACLS otherwise. */
function icaclsError(step: string, result: IcaclsResult): NodeJS.ErrnoException {
  const err = new Error(
    result.timedOut ? `icacls ${step} timed out` : `icacls ${step} exited ${result.exitCode ?? "null"}`,
  ) as NodeJS.ErrnoException;
  err.code = result.timedOut ? "ETIMEDOUT" : "EICACLS";
  return err;
}

/**
 * Return the current Windows username from the environment.
 * Falls back to USERDOMAIN\USERNAME if USERNAME alone is ambiguous.
 * The value is used directly in icacls arguments, so it must be present.
 */
function currentWindowsUser(): string | undefined {
  const username = env["USERNAME"];
  const domain = env["USERDOMAIN"];
  if (!username) return undefined;
  // USERDOMAIN is the machine/domain name; USERNAME is the account name.
  // icacls accepts "DOMAIN\User" or just "User" for local accounts.
  return domain ? `${domain}\\${username}` : username;
}

/**
 * Run icacls to harden a single file system entry.
 * - Disables inheritance (keeps nothing: /inheritance:r)
 * - Grants the current user Full Control
 *
 * We do NOT use a shell string; all arguments are passed as an array so no
 * shell injection is possible even for paths with unusual characters.
 *
 * Throws the raw child_process error on failure (caller sanitizes).
 */
const BROAD_SIDS = ["*S-1-1-0", "*S-1-5-11", "*S-1-5-18", "*S-1-5-32-544", "*S-1-5-32-545"] as const;

interface SerializedAclRule {
  identitySid: string;
  accessControlType: "Allow" | "Deny";
  fileSystemRights: number;
  isInherited: boolean;
}

const WINDOWS_FULL_CONTROL = 2_032_127;
const WINDOWS_SID_RE = /^S-\d+(?:-\d+)+$/i;

function aclInspectorArgs(targetPath: string): string[] {
  return [
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    ACL_INSPECT_SCRIPT_PATH,
    "-TargetPath",
    targetPath,
  ];
}

function aclVerificationError(): NodeJS.ErrnoException {
  const error = new Error("ACL hardening verification failed") as NodeJS.ErrnoException;
  error.code = "EACLVERIFY";
  return error;
}

/** Inspect the complete Windows DACL through fixed-script, SID-stable Get-Acl output. */
export function inspectSecretPathAcl(targetPath: string, timeoutMs = resolveHardenDeadlineMs()): AclInspectionResult {
  if (!existsSync(targetPath)) return { secure: false, diagnostics: "secret path is missing" };
  if (effectivePlatform() !== "win32") return { secure: null, diagnostics: "Windows ACL inspection is unavailable" };
  const boundedTimeoutMs = Number.isSafeInteger(timeoutMs)
    ? Math.min(HARDEN_DEADLINE_MAX_MS, Math.max(HARDEN_DEADLINE_MIN_MS, timeoutMs))
    : HARDEN_DEADLINE_DEFAULT_MS;
  let result: IcaclsResult;
  try {
    result = aclInspectorRunner(aclInspectorArgs(targetPath), boundedTimeoutMs);
  } catch {
    return { secure: null, diagnostics: "ACL inspection failed" };
  }
  if (!result.success) return { secure: null, diagnostics: result.timedOut ? "ACL inspection timed out" : "ACL inspection failed" };
  if (Buffer.byteLength(result.stdout, "utf8") > ACL_INSPECT_MAX_BYTES) {
    return { secure: null, diagnostics: "ACL inspection output exceeded its limit" };
  }
  try {
    const parsed = JSON.parse(result.stdout) as {
      protected?: unknown;
      currentUserSid?: unknown;
      ownerSid?: unknown;
      rules?: unknown;
    };
    if (parsed.protected !== true) return { secure: false, diagnostics: "DACL inheritance is not protected" };
    if (typeof parsed.currentUserSid !== "string" || !WINDOWS_SID_RE.test(parsed.currentUserSid)) {
      return { secure: null, diagnostics: "current-user SID is unavailable" };
    }
    if (typeof parsed.ownerSid !== "string" || !WINDOWS_SID_RE.test(parsed.ownerSid)) {
      return { secure: null, diagnostics: "secret owner SID is unavailable" };
    }
    if (parsed.ownerSid.toUpperCase() !== parsed.currentUserSid.toUpperCase()) {
      return { secure: false, diagnostics: "secret owner is not the current user" };
    }
    if (!Array.isArray(parsed.rules) || parsed.rules.length === 0) {
      return { secure: false, diagnostics: "DACL has no explicit current-user grant" };
    }
    let currentUserRights = 0;
    for (const value of parsed.rules) {
      const rule = value as Partial<SerializedAclRule>;
      if (typeof rule.identitySid !== "string" || !WINDOWS_SID_RE.test(rule.identitySid)
        || !["Allow", "Deny"].includes(String(rule.accessControlType))
        || typeof rule.fileSystemRights !== "number"
        || !Number.isSafeInteger(rule.fileSystemRights)
        || typeof rule.isInherited !== "boolean") {
        return { secure: null, diagnostics: "DACL rule output is invalid" };
      }
      if (rule.isInherited) return { secure: false, diagnostics: "inherited DACL rule detected" };
      if (rule.identitySid.toUpperCase() !== parsed.currentUserSid.toUpperCase()) {
        return { secure: false, diagnostics: "foreign DACL rule detected" };
      }
      if (rule.accessControlType === "Allow") {
        currentUserRights |= rule.fileSystemRights;
      } else {
        return { secure: false, diagnostics: "current-user DACL deny rule detected" };
      }
    }
    if ((currentUserRights & WINDOWS_FULL_CONTROL) !== WINDOWS_FULL_CONTROL) {
      return { secure: false, diagnostics: "current-user full-control DACL is missing" };
    }
    return { secure: true };
  } catch {
    return { secure: null, diagnostics: "ACL inspection output is invalid" };
  }
}

function runIcacls(targetPath: string, directory: boolean, deadline: number): void {
  const user = currentWindowsUser();
  if (!user) {
    throw new Error("Cannot determine current Windows user for ACL hardening");
  }

  // The deadline is owned by hardenEntry (total budget incl. retry + verification).
  const run = (step: string, args: string[]): IcaclsResult => {
    const remaining = deadline - nowFn();
    if (remaining <= 0) {
      throw icaclsError(step, { success: false, exitCode: null, timedOut: true, stdout: "" });
    }
    return icaclsRunner(args, remaining);
  };
  const runOrThrow = (step: string, args: string[]): void => {
    const result = run(step, args);
    if (!result.success) throw icaclsError(step, result);
  };

  // Grant first so an interruption can never strand an entry with no usable owner ACE.
  // Atomic secret writes harden an empty temp before adding sensitive bytes.
  const grant = directory ? `${user}:(OI)(CI)(F)` : `${user}:(F)`;
  runOrThrow("/grant:r", [targetPath, "/grant:r", grant]);

  // Step 2: disable inheritance and remove inherited ACEs.
  runOrThrow("/inheritance:r", [targetPath, "/inheritance:r"]);

  // Step 3: remove broad explicit grants using stable SIDs (not localized names).
  // Missing ACEs can yield a non-zero exit; verify with locale-independent /findsid
  // before accepting the failure as harmless — a swallowed real failure would leave
  // Everyone/Users/Authenticated Users grants while reporting hardened.
  const removal = run("/remove:g", [targetPath, "/remove:g", ...BROAD_SIDS]);
  if (!removal.success) {
    if (removal.timedOut) throw icaclsError("/remove:g", removal);
    for (const sid of BROAD_SIDS) {
      const found = run("/findsid", [targetPath, "/findsid", sid]);
      if (!found.success) throw icaclsError("/findsid", found);
      // icacls /findsid echoes the target path in its "SID Found" line only when the SID
      // still holds an ACE; the summary lines carry only counts. Matching the path echo —
      // not the (localized) prose — keeps the check locale-independent.
      if (found.stdout.includes(targetPath)) {
        throw icaclsError("/remove:g", removal);
      }
    }
  }
}

/**
 * Sanitize an error from a failed ACL operation into a safe diagnostic string.
 * The raw path must not appear in the returned string (it may contain
 * sensitive username components or PII from the home directory path).
 */
function sanitizeDiagnostics(error: unknown): string {
  // We do not expose the raw error message or any path-like fragments —
  // just an honest, code-specific cause (issue #160: a transient icacls stall
  // must not read like filesystem non-support).
  const code = error instanceof Error && "code" in error ? String((error as NodeJS.ErrnoException).code) : "";
  switch (code) {
    case "ETIMEDOUT":
      return "ACL hardening timed out (ETIMEDOUT) — transient icacls stall; the volume may still support per-user NTFS ACLs";
    case "EPERM":
    case "EACCES":
      return `ACL hardening failed (${code}) — permission denied running icacls`;
    case "EICACLS":
      return "ACL hardening failed (EICACLS) — icacls command error; filesystem may not support per-user NTFS ACLs";
    case "EACLVERIFY":
      return "ACL hardening verification failed (EACLVERIFY) — the resulting DACL is not isolated to the current user";
    default:
      return `ACL hardening failed${code ? ` (${code})` : ""} — filesystem may not support per-user NTFS ACLs`;
  }
}

function isTimeoutError(error: unknown): boolean {
  return error instanceof Error && "code" in error
    && String((error as NodeJS.ErrnoException).code) === "ETIMEDOUT";
}

/**
 * Diagnostic-only post-timeout probe (never promotes to ok:true — a clean /findsid
 * does not prove inheritance was disabled or the user grant ran; only a fully
 * completed harden sequence may enter the hardened cache). Bounded by the remaining
 * total budget; returns a short state note for the soft-fail diagnostic.
 */
function describeAclStateAfterTimeout(targetPath: string, deadline: number): string {
  try {
    for (const sid of BROAD_SIDS) {
      const remaining = deadline - nowFn();
      if (remaining <= 0) return "ACL state unverified (budget exhausted)";
      const found = icaclsRunner([targetPath, "/findsid", sid], remaining);
      if (!found.success) return "ACL state unverified (probe failed)";
      if (found.stdout.includes(targetPath)) return "broad ACL grants still present";
    }
    return "no broad ACL grants detected (hardening still incomplete)";
  } catch {
    return "ACL state unverified (probe failed)";
  }
}

/**
 * Shared harden flow for files and directories: one total budget (env-configurable)
 * covering the initial attempt, ONE timeout retry, and the diagnostic verification.
 * Real EPERM/EACCES/EICACLS failures stay fail-closed on required paths; only
 * genuine timeouts soft-fail, with an honest state-annotated diagnostic.
 */
function hardenEntry(
  targetPath: string,
  directory: boolean,
  opts: HardenOptions,
  cache: Set<string>,
): HardenResult {
  if (!existsSync(targetPath)) return { ok: true };
  if (effectivePlatform() !== "win32") return { ok: true };
  if (!opts.force && cache.has(targetPath)) return { ok: true };
  if (timedOutPaths.has(targetPath)) {
    return { ok: false, diagnostics: "ACL hardening skipped — previous attempt timed out" };
  }

  // Re-applying inheritable directory ACEs updates child ctime on NTFS even when the DACL is
  // already correct. A read-only preflight prevents fresh processes from invalidating child
  // identity attestations while retaining the mutation path for unknown or insecure state.
  if (directory && !opts.force) {
    const inspected = inspectSecretPathAcl(targetPath);
    if (inspected.secure === true) {
      cache.add(targetPath);
      return { ok: true };
    }
  }

  const deadline = nowFn() + resolveHardenDeadlineMs();
  let lastErr: unknown;
  for (let attempt = 0; attempt < 2; attempt++) {
    if (attempt > 0 && deadline - nowFn() <= 0) break; // retry only while budget remains
    try {
      runIcacls(targetPath, directory, deadline);
      if (opts.required && opts.verifyIsolation) {
        const inspection = inspectSecretPathAcl(targetPath);
        if (inspection.secure !== true) {
          const verificationError = new Error("ACL hardening verification failed") as NodeJS.ErrnoException;
          verificationError.code = "EACLVERIFY";
          throw verificationError;
        }
      }
      cache.add(targetPath);
      return { ok: true };
    } catch (err) {
      lastErr = err;
      if (!isTimeoutError(err)) break; // real failures do not retry
    }
  }

  const diagnostics = sanitizeDiagnostics(lastErr);
  if (isTimeoutError(lastErr)) {
    timedOutPaths.add(targetPath);
    const state = describeAclStateAfterTimeout(targetPath, deadline);
    const annotated = `${diagnostics}; ${state}`;
    // Timeout-only soft-fail: a hung icacls must not block OAuth/token writes.
    // chmod is still applied by the caller.
    console.warn(`[opencodex] ${annotated} — continuing without NTFS ACL harden`);
    return { ok: false, diagnostics: annotated };
  }
  if (opts.required) throw new Error(diagnostics);
  return { ok: false, diagnostics };
}

/**
 * Harden a single file path with per-user NTFS ACLs on Windows.
 * On non-Windows platforms, returns ok:true immediately (caller owns chmod).
 *
 * @param targetPath  Absolute path to the file to harden.
 * @param opts        { required: boolean } — required:true throws on failure.
 */
export function hardenSecretPath(targetPath: string, opts: HardenOptions): HardenResult {
  return hardenEntry(targetPath, false, opts, hardenedPaths);
}

/**
 * Harden a directory path with per-user NTFS ACLs on Windows.
 * On non-Windows platforms, returns ok:true immediately (caller owns chmod).
 *
 * @param targetPath  Absolute path to the directory to harden.
 * @param opts        { required: boolean } — required:true throws on failure.
 */
export function hardenSecretDir(targetPath: string, opts: HardenOptions): HardenResult {
  return hardenEntry(targetPath, true, opts, hardenedDirectories);
}
