import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { canonicalRepositoryPath, evaluatePathPolicy } from "./path-policy";

const CONTROL_DENIED_PATHS = [
  ".git/**",
  ".github/**",
  ".opencodex/control/**",
  ".codex/**",
  "policies/**",
  "workflows/**",
] as const;

export interface WorkspacePrepareRequest {
  workspace_id: string;
  repository_id: string;
  repository_path: string;
  task_id: string;
  attempt_id: string;
  base_commit?: string;
  allowed_paths: string[];
  denied_paths: string[];
  submodules: "DENY" | "PINNED";
}

export interface WorkspaceRef {
  schema_version: 1;
  workspace_id: string;
  repository_id: string;
  repository_root: string;
  task_id: string;
  attempt_id: string;
  base_commit: string;
  git_tree_id: string;
  tree_hash: string;
  branch: string;
  worktree_path: string;
  allowed_paths: string[];
  denied_paths: string[];
  main_worktree_dirty: boolean;
  main_head_at_prepare: string;
  main_status_hash_at_prepare: string;
  baseline_hash: string;
  prepared_at: string;
  sealed_at: string | null;
  sealed_snapshot_hash: string | null;
  cleanup_status: "ACTIVE" | "QUARANTINED";
}

export interface ChangedFile {
  path: string;
  additions: number | null;
  deletions: number | null;
  binary: boolean;
  size_bytes: number | null;
  symlink: boolean;
  dependency_file: boolean;
}

export interface WorkspaceStatus {
  workspace: WorkspaceRef;
  changed_files: ChangedFile[];
  path_policy: { decision: "ALLOW" | "BLOCK"; allowed: string[]; denied: string[] };
  symlink_violations: string[];
  main_branch_unchanged: boolean;
  main_worktree_status_unchanged: boolean;
}

export class GitWorktreeWorkspaceManager {
  private readonly root: string;
  private readonly worktreesRoot: string;
  private readonly metadataRoot: string;
  private readonly reportRoot: string;
  private readonly intentRoot: string;
  private readonly git: string;
  private readonly stabilityWindowMs: number;

  constructor(options: { root: string; git_executable?: string; stability_window_ms?: number }) {
    this.root = resolve(options.root);
    this.worktreesRoot = join(this.root, "worktrees");
    this.metadataRoot = join(this.root, "metadata");
    this.reportRoot = join(this.root, "reports");
    this.intentRoot = join(this.root, "preparation-intents");
    this.git = options.git_executable ?? "git";
    this.stabilityWindowMs = options.stability_window_ms ?? 100;
    for (const path of [this.root, this.worktreesRoot, this.metadataRoot, this.reportRoot, this.intentRoot]) mkdirSync(path, { recursive: true });
  }

  plannedPath(workspaceId: string): string { return join(this.worktreesRoot, `workspace-${shortHash(workspaceId)}`); }
  rootPath(): string { return this.root; }
  effectiveDeniedPaths(deniedPaths: readonly string[]): string[] { return [...new Set([...CONTROL_DENIED_PATHS, ...deniedPaths])]; }

  async prepare(request: WorkspacePrepareRequest): Promise<WorkspaceRef> {
    validateRequest(request);
    const requestedRoot = resolve(request.repository_path);
    if (!existsSync(requestedRoot) || !statSync(requestedRoot).isDirectory()) throw new Error("REPOSITORY_NOT_FOUND");
    if (lstatSync(requestedRoot).isSymbolicLink()) throw new Error("REPOSITORY_ROOT_SYMLINK");
    const repositoryRoot = realpathSync(requestedRoot);
    const topLevel = realpathSync((await this.gitRun(repositoryRoot, ["rev-parse", "--show-toplevel"])).stdout.trim());
    if (!samePath(topLevel, repositoryRoot)) throw new Error("REPOSITORY_PATH_IS_NOT_GIT_TOPLEVEL");
    if (existsSync(join(repositoryRoot, ".gitmodules")) && request.submodules === "DENY") throw new Error("SUBMODULES_DENIED");
    if (request.submodules === "PINNED" && existsSync(join(repositoryRoot, ".gitmodules"))) throw new Error("PINNED_SUBMODULE_PREPARATION_NOT_AVAILABLE");

    const mainHead = (await this.gitRun(repositoryRoot, ["rev-parse", "HEAD"])).stdout.trim();
    const baseInput = request.base_commit ?? mainHead;
    if (!/^[a-f0-9]{40,64}$/i.test(baseInput)) throw new Error("BASE_COMMIT_MUST_BE_PINNED_OBJECT_ID");
    const baseCommit = (await this.gitRun(repositoryRoot, ["rev-parse", "--verify", `${baseInput}^{commit}`])).stdout.trim();
    const gitTreeId = (await this.gitRun(repositoryRoot, ["rev-parse", `${baseCommit}^{tree}`])).stdout.trim();
    const mainStatus = (await this.gitRun(repositoryRoot, ["status", "--porcelain=v1", "-z"])).stdout;
    const path = this.plannedPath(request.workspace_id);
    if (existsSync(path)) throw new Error("WORKSPACE_PATH_ALREADY_EXISTS");
    const branch = `agent/${shortHash(request.task_id)}/${shortHash(request.attempt_id)}-${shortHash(request.workspace_id)}`;
    const denied = this.effectiveDeniedPaths(request.denied_paths);
    const preparedAt = new Date().toISOString();
    const intentPath = join(this.intentRoot, `${shortHash(request.workspace_id)}.json`);
    writeDurableJson(intentPath, {
      schema_version: 1,
      workspace_id: request.workspace_id,
      repository_root: repositoryRoot,
      worktree_path: path,
      branch,
      base_commit: baseCommit,
      created_at: preparedAt,
      status: "PREPARING",
    }, true);
    try {
      await this.gitRun(repositoryRoot, ["worktree", "add", "-b", branch, path, baseCommit], 120_000);
      const core = {
        repository_id: request.repository_id,
        repository_root: repositoryRoot,
        task_id: request.task_id,
        attempt_id: request.attempt_id,
        base_commit: baseCommit,
        git_tree_id: gitTreeId,
        tree_hash: canonicalSha256({ git_tree_id: gitTreeId }),
        branch,
        worktree_path: realpathSync(path),
        allowed_paths: [...request.allowed_paths],
        denied_paths: denied,
        main_worktree_dirty: mainStatus.length > 0,
        main_head_at_prepare: mainHead,
        main_status_hash_at_prepare: canonicalSha256(mainStatus),
      };
      const workspace: WorkspaceRef = {
        schema_version: 1,
        workspace_id: request.workspace_id,
        ...core,
        baseline_hash: canonicalSha256(core),
        prepared_at: preparedAt,
        sealed_at: null,
        sealed_snapshot_hash: null,
        cleanup_status: "ACTIVE",
      };
      this.writeMetadata(workspace);
      const violations = scanSymlinkEscapes(workspace.worktree_path);
      if (violations.length > 0) throw new Error(`WORKSPACE_SYMLINK_ESCAPE: ${violations.join(", ")}`);
      unlinkSync(intentPath);
      return workspace;
    } catch (error) {
      this.emergencyQuarantine({
        request,
        repository_root: repositoryRoot,
        base_commit: baseCommit,
        git_tree_id: gitTreeId,
        branch,
        worktree_path: path,
        main_head: mainHead,
        main_status: mainStatus,
        prepared_at: preparedAt,
        denied_paths: denied,
        reason: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  async inspect(workspaceId: string): Promise<WorkspaceStatus> {
    const workspace = this.readMetadata(workspaceId);
    const tracked = splitNull((await this.gitRun(workspace.worktree_path, ["diff", "--name-only", "-z", workspace.base_commit, "--"])).stdout);
    const untracked = splitNull((await this.gitRun(workspace.worktree_path, ["ls-files", "--others", "--exclude-standard", "-z"])).stdout);
    const names = [...new Set([...tracked, ...untracked].map(normalizeGitPath))].sort();
    const stats = parseNumstat((await this.gitRun(workspace.worktree_path, ["diff", "--numstat", "-z", workspace.base_commit, "--"])).stdout);
    const changedFiles = names.map(path => {
      const absolute = resolve(workspace.worktree_path, ...path.split("/"));
      const safe = isInside(workspace.worktree_path, absolute);
      const info = safe && existsSync(absolute) ? lstatSync(absolute) : null;
      const numstat = stats.get(path);
      return {
        path,
        additions: numstat?.additions ?? (untracked.includes(path) && info?.isFile() ? lineCount(absolute) : null),
        deletions: numstat?.deletions ?? (untracked.includes(path) ? 0 : null),
        binary: numstat?.binary ?? false,
        size_bytes: info?.isFile() ? info.size : null,
        symlink: info?.isSymbolicLink() ?? false,
        dependency_file: isDependencyFile(path),
      } satisfies ChangedFile;
    });
    const allowed: string[] = [];
    const denied: string[] = [];
    for (const file of changedFiles) {
      const decision = evaluatePathPolicy(file.path, workspace.allowed_paths, workspace.denied_paths);
      (decision.allowed ? allowed : denied).push(file.path);
    }
    const symlinkViolations = scanSymlinkEscapes(workspace.worktree_path);
    const mainHead = (await this.gitRun(workspace.repository_root, ["rev-parse", "HEAD"])).stdout.trim();
    const mainStatus = (await this.gitRun(workspace.repository_root, ["status", "--porcelain=v1", "-z"])).stdout;
    return {
      workspace,
      changed_files: changedFiles,
      path_policy: { decision: denied.length > 0 || symlinkViolations.length > 0 ? "BLOCK" : "ALLOW", allowed, denied },
      symlink_violations: symlinkViolations,
      main_branch_unchanged: mainHead === workspace.main_head_at_prepare,
      main_worktree_status_unchanged: canonicalSha256(mainStatus) === workspace.main_status_hash_at_prepare,
    };
  }

  list(): WorkspaceRef[] {
    return readdirSync(this.metadataRoot, { withFileTypes: true })
      .filter(entry => entry.isFile() && entry.name.endsWith(".json"))
      .map(entry => JSON.parse(readFileSync(join(this.metadataRoot, entry.name), "utf8")) as WorkspaceRef)
      .filter(value => value.schema_version === 1 && typeof value.workspace_id === "string")
      .sort((left, right) => left.prepared_at.localeCompare(right.prepared_at));
  }

  listPreparationIntents(): Array<Record<string, unknown>> {
    return readdirSync(this.intentRoot, { withFileTypes: true })
      .filter(entry => entry.isFile() && entry.name.endsWith(".json"))
      .map(entry => JSON.parse(readFileSync(join(this.intentRoot, entry.name), "utf8")) as Record<string, unknown>);
  }

  async quarantinePreparedOrIntent(workspaceId: string, reason: string): Promise<boolean> {
    try { await this.cleanup(workspaceId, { action: "QUARANTINE", reason }); return true; }
    catch { /* fall through to the preparation intent */ }
    const intentPath = join(this.intentRoot, `${shortHash(workspaceId)}.json`);
    if (!existsSync(intentPath)) return false;
    try {
      const intent = JSON.parse(readFileSync(intentPath, "utf8")) as Record<string, unknown>;
      if (intent.workspace_id !== workspaceId) return false;
      writeDurableJson(intentPath, { ...intent, status: "QUARANTINED", quarantine_reason: reason, quarantined_at: new Date().toISOString() });
      writeFileSync(join(this.reportRoot, `${shortHash(workspaceId)}-${Date.now()}.json`), JSON.stringify({
        workspace_id: workspaceId, action: "QUARANTINED", reason,
        worktree_path: intent.worktree_path ?? null, branch: intent.branch ?? null, created_at: new Date().toISOString(),
      }, null, 2), "utf8");
      return true;
    } catch { return false; }
  }

  async snapshot(workspaceId: string, reason: string): Promise<{ snapshot_id: string; hash: string; reason: string; created_at: string }> {
    if (!reason.trim()) throw new Error("Snapshot reason is required");
    const status = await this.inspect(workspaceId);
    const hash = await workspaceContentHash(status);
    return { snapshot_id: `workspace-snapshot:${hash.slice("sha256:".length, 32 + "sha256:".length)}`, hash, reason, created_at: new Date().toISOString() };
  }

  async exportPatch(workspaceId: string): Promise<{ media_type: "text/x-diff"; content: string; hash: string; changed_files: string[] }> {
    const status = await this.inspect(workspaceId);
    let content = (await this.gitRun(status.workspace.worktree_path, ["diff", "--binary", status.workspace.base_commit, "--"])).stdout;
    const untracked = splitNull((await this.gitRun(status.workspace.worktree_path, ["ls-files", "--others", "--exclude-standard", "-z"])).stdout);
    for (const path of untracked.sort()) {
      const absolute = resolve(status.workspace.worktree_path, ...path.split("/"));
      if (!isInside(status.workspace.worktree_path, absolute) || !existsSync(absolute)) continue;
      const info = lstatSync(absolute);
      if (!info.isFile() || info.size > 5_000_000) {
        content += `\ndiff --git a/${path} b/${path}\nnew file mode 100644\n[UNTRACKED BINARY OR LARGE FILE OMITTED]\n`;
        continue;
      }
      const source = readFileSync(absolute);
      if (source.includes(0)) {
        content += `\ndiff --git a/${path} b/${path}\nnew file mode 100644\n[BINARY FILE OMITTED]\n`;
        continue;
      }
      const lines = source.toString("utf8").split("\n");
      content += `\ndiff --git a/${path} b/${path}\nnew file mode 100644\n--- /dev/null\n+++ b/${path}\n@@ -0,0 +1,${Math.max(0, lines.length - 1)} @@\n`;
      content += lines.slice(0, -1).map(line => `+${line}\n`).join("");
    }
    return { media_type: "text/x-diff", content, hash: canonicalSha256(content), changed_files: status.changed_files.map(file => file.path) };
  }

  async seal(workspaceId: string): Promise<{ status: "WORKSPACE_SEALED"; snapshot_hash: string; main_branch_unchanged: boolean; path_policy: WorkspaceStatus["path_policy"] }> {
    const before = await this.inspect(workspaceId);
    const beforeHash = await workspaceContentHash(before);
    await new Promise(resolvePromise => setTimeout(resolvePromise, this.stabilityWindowMs));
    const after = await this.inspect(workspaceId);
    const afterHash = await workspaceContentHash(after);
    if (beforeHash !== afterHash) throw new Error("WORKSPACE_NOT_STABLE");
    const workspace = { ...after.workspace, sealed_at: new Date().toISOString(), sealed_snapshot_hash: afterHash };
    this.writeMetadata(workspace);
    return { status: "WORKSPACE_SEALED", snapshot_hash: afterHash, main_branch_unchanged: after.main_branch_unchanged, path_policy: after.path_policy };
  }

  async assertSeal(workspaceId: string, expectedSnapshotHash: string): Promise<{
    status: "WORKSPACE_SEAL_INTACT";
    snapshot_hash: string;
    main_branch_unchanged: boolean;
    main_worktree_status_unchanged: boolean;
  }> {
    const status = await this.inspect(workspaceId);
    if (!status.workspace.sealed_at || status.workspace.sealed_snapshot_hash !== expectedSnapshotHash) {
      throw new Error("WORKSPACE_SEAL_MISSING_OR_MISMATCHED");
    }
    const actual = await workspaceContentHash(status);
    if (actual !== expectedSnapshotHash) throw new Error("WORKSPACE_SEAL_BROKEN");
    return {
      status: "WORKSPACE_SEAL_INTACT",
      snapshot_hash: actual,
      main_branch_unchanged: status.main_branch_unchanged,
      main_worktree_status_unchanged: status.main_worktree_status_unchanged,
    };
  }

  async cleanup(workspaceId: string, policy: { action: "QUARANTINE"; reason: string }): Promise<{ action: "QUARANTINED"; report_path: string }> {
    const workspace = this.readMetadata(workspaceId);
    if (!policy.reason.trim()) throw new Error("Cleanup reason is required");
    const reportPath = join(this.reportRoot, `${shortHash(workspaceId)}-${Date.now()}.json`);
    writeFileSync(reportPath, JSON.stringify({ workspace_id: workspaceId, action: "QUARANTINED", reason: policy.reason, worktree_path: workspace.worktree_path, created_at: new Date().toISOString() }, null, 2), "utf8");
    this.writeMetadata({ ...workspace, cleanup_status: "QUARANTINED" });
    return { action: "QUARANTINED", report_path: reportPath };
  }

  private async gitRun(cwd: string, args: readonly string[], timeoutMs = 30_000): Promise<{ stdout: string; stderr: string }> {
    const child = Bun.spawn([this.git, ...args], { cwd, stdin: "ignore", stdout: "pipe", stderr: "pipe", env: gitEnvironment(), windowsHide: true });
    let timer: ReturnType<typeof setTimeout> | undefined;
    const outcome = await Promise.race([
      child.exited.then(() => "exit" as const),
      new Promise<"timeout">(resolveTimeout => { timer = setTimeout(() => resolveTimeout("timeout"), timeoutMs); }),
    ]);
    if (timer) clearTimeout(timer);
    if (outcome === "timeout") { child.kill(); throw new Error(`GIT_COMMAND_TIMEOUT: ${args[0] ?? ""}`); }
    const [stdout, stderr] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text()]);
    if (child.exitCode !== 0) throw new Error(`GIT_COMMAND_FAILED(${child.exitCode}): ${args[0] ?? ""}: ${stderr.slice(0, 4_000)}`);
    return { stdout, stderr };
  }

  private metadataPath(workspaceId: string): string { return join(this.metadataRoot, `${shortHash(workspaceId)}.json`); }
  private writeMetadata(workspace: WorkspaceRef): void { writeDurableJson(this.metadataPath(workspace.workspace_id), workspace); }
  private readMetadata(workspaceId: string): WorkspaceRef {
    const path = this.metadataPath(workspaceId);
    if (!existsSync(path)) throw new Error(`WORKSPACE_NOT_FOUND: ${workspaceId}`);
    const value = JSON.parse(readFileSync(path, "utf8")) as WorkspaceRef;
    if (value.workspace_id !== workspaceId || value.schema_version !== 1) throw new Error("WORKSPACE_METADATA_CORRUPT");
    return value;
  }

  private emergencyQuarantine(input: {
    request: WorkspacePrepareRequest;
    repository_root: string;
    base_commit: string;
    git_tree_id: string;
    branch: string;
    worktree_path: string;
    main_head: string;
    main_status: string;
    prepared_at: string;
    denied_paths: string[];
    reason: string;
  }): void {
    const core = {
      repository_id: input.request.repository_id,
      repository_root: input.repository_root,
      task_id: input.request.task_id,
      attempt_id: input.request.attempt_id,
      base_commit: input.base_commit,
      git_tree_id: input.git_tree_id,
      tree_hash: canonicalSha256({ git_tree_id: input.git_tree_id }),
      branch: input.branch,
      worktree_path: resolve(input.worktree_path),
      allowed_paths: [...input.request.allowed_paths],
      denied_paths: input.denied_paths,
      main_worktree_dirty: input.main_status.length > 0,
      main_head_at_prepare: input.main_head,
      main_status_hash_at_prepare: canonicalSha256(input.main_status),
    };
    const workspace: WorkspaceRef = {
      schema_version: 1,
      workspace_id: input.request.workspace_id,
      ...core,
      baseline_hash: canonicalSha256(core),
      prepared_at: input.prepared_at,
      sealed_at: null,
      sealed_snapshot_hash: null,
      cleanup_status: "QUARANTINED",
    };
    try { this.writeMetadata(workspace); } catch { /* preparation intent remains the durable recovery record */ }
    try {
      writeFileSync(join(this.reportRoot, `${shortHash(input.request.workspace_id)}-${Date.now()}.json`), JSON.stringify({
        workspace_id: input.request.workspace_id,
        action: "QUARANTINED",
        reason: `workspace preparation failed after intent persistence: ${input.reason}`,
        worktree_path: input.worktree_path,
        branch: input.branch,
        created_at: new Date().toISOString(),
      }, null, 2), "utf8");
    } catch { /* preparation intent is intentionally retained */ }
  }
}

function validateRequest(request: WorkspacePrepareRequest): void {
  if (!request.workspace_id.startsWith("workspace:") || !request.task_id.startsWith("task:") || !request.attempt_id.startsWith("attempt:")) throw new Error("INVALID_WORKSPACE_IDENTITY");
  if (request.allowed_paths.length === 0) throw new Error("WORKSPACE_ALLOWLIST_REQUIRED");
  for (const pattern of [...request.allowed_paths, ...request.denied_paths]) if (!canonicalRepositoryPath(pattern, true)) throw new Error(`INVALID_WORKSPACE_PATH_PATTERN: ${pattern}`);
}

function scanSymlinkEscapes(root: string): string[] {
  const violations: string[] = [];
  const visit = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (directory === root && entry.name === ".git") continue;
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        try {
          const target = realpathSync(path);
          if (!isInside(root, target)) violations.push(normalizeGitPath(relative(root, path)));
        } catch { violations.push(normalizeGitPath(relative(root, path))); }
      } else if (entry.isDirectory()) visit(path);
    }
  };
  visit(root);
  return violations.sort();
}

async function workspaceContentHash(status: WorkspaceStatus): Promise<string> {
  const files = status.changed_files.map(file => {
    const path = resolve(status.workspace.worktree_path, ...file.path.split("/"));
    let content_hash: string | null = null;
    if (existsSync(path) && lstatSync(path).isFile()) content_hash = `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
    return { ...file, content_hash };
  });
  return canonicalSha256({ files, path_policy: status.path_policy, symlink_violations: status.symlink_violations });
}

function parseNumstat(source: string): Map<string, { additions: number | null; deletions: number | null; binary: boolean }> {
  const result = new Map<string, { additions: number | null; deletions: number | null; binary: boolean }>();
  for (const record of source.split("\0").filter(Boolean)) {
    const [add, del, ...pathParts] = record.split("\t");
    const path = normalizeGitPath(pathParts.join("\t"));
    if (!path) continue;
    const binary = add === "-" || del === "-";
    result.set(path, { additions: binary ? null : Number(add), deletions: binary ? null : Number(del), binary });
  }
  return result;
}

function splitNull(value: string): string[] { return value.split("\0").filter(Boolean).map(normalizeGitPath); }
function normalizeGitPath(value: string): string { return value.replaceAll("\\", "/").replace(/^\.\//, ""); }
function lineCount(path: string): number { return readFileSync(path, "utf8").split(/\r?\n/).filter((_, index, array) => index < array.length - 1).length; }
function isDependencyFile(path: string): boolean { return /(^|\/)(package\.json|bun\.lockb?|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|requirements[^/]*\.txt|pyproject\.toml|Cargo\.toml|Cargo\.lock|go\.mod|go\.sum)$/.test(path); }
function shortHash(value: string): string { return createHash("sha256").update(value).digest("hex").slice(0, 10); }
function safeName(value: string): string { return value.replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 160); }
function samePath(left: string, right: string): boolean { return process.platform === "win32" ? left.toLowerCase() === right.toLowerCase() : left === right; }
function isInside(root: string, candidate: string): boolean {
  const rel = relative(resolve(root), resolve(candidate));
  return rel === "" || (!rel.startsWith("..") && !rel.includes(`..${sep}`) && !resolve(candidate).startsWith(`${sep}${sep}`));
}
function gitEnvironment(): Record<string, string> {
  const result: Record<string, string> = { GIT_TERMINAL_PROMPT: "0", GIT_CONFIG_NOSYSTEM: "1" };
  for (const name of ["PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"]) if (process.env[name]) result[name] = process.env[name]!;
  return result;
}

function writeDurableJson(path: string, value: unknown, exclusive = false): void {
  const target = exclusive ? path : `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  let descriptor: number | null = null;
  try {
    descriptor = openSync(target, "wx", 0o600);
    writeSync(descriptor, JSON.stringify(value, null, 2), undefined, "utf8");
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = null;
    if (!exclusive) renameSync(target, path);
  } catch (error) {
    if (descriptor !== null) try { closeSync(descriptor); } catch { /* best effort */ }
    if (!exclusive) try { unlinkSync(target); } catch { /* best effort */ }
    throw error;
  }
}
