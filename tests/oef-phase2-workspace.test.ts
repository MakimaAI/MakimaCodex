import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  GitWorktreeWorkspaceManager,
  LocalWorktreeEnvironment,
  evaluatePathPolicy,
} from "../src/oef/phase2";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* Git/Windows can briefly retain worktree handles */ }
  }
});

const git = process.platform === "win32" ? "C:\\Program Files\\Git\\cmd\\git.exe" : "git";

function root(): string {
  const value = mkdtempSync(join(tmpdir(), "oef-phase2-workspace-"));
  roots.push(value);
  return value;
}

function run(cwd: string, args: string[]): string {
  const result = Bun.spawnSync([git, ...args], { cwd, stdout: "pipe", stderr: "pipe", env: process.env });
  if (result.exitCode !== 0) throw new Error(new TextDecoder().decode(result.stderr));
  return new TextDecoder().decode(result.stdout).trim();
}

function repository(): { root: string; head: string } {
  const repo = join(root(), "repository");
  mkdirSync(join(repo, "src"), { recursive: true });
  mkdirSync(join(repo, ".github", "workflows"), { recursive: true });
  writeFileSync(join(repo, "src", "app.ts"), "export const value = 1;\n");
  writeFileSync(join(repo, ".github", "workflows", "ci.yml"), "name: ci\n");
  run(repo, ["init", "-b", "main"]);
  run(repo, ["config", "user.email", "phase2@example.invalid"]);
  run(repo, ["config", "user.name", "Phase 2 Test"]);
  run(repo, ["add", "."]);
  run(repo, ["commit", "-m", "baseline"]);
  return { root: repo, head: run(repo, ["rev-parse", "HEAD"]) };
}

describe("Phase 2 Git worktree workspace", () => {
  test("pins a separate branch/worktree to the requested base without copying dirty main state", async () => {
    const repo = repository();
    writeFileSync(join(repo.root, "src", "dirty-main.ts"), "main-only\n");
    const manager = new GitWorktreeWorkspaceManager({ root: join(root(), "manager"), git_executable: git });
    const workspace = await manager.prepare({
      workspace_id: "workspace:one",
      repository_id: "repo:test",
      repository_path: repo.root,
      task_id: "task:one",
      attempt_id: "attempt:one",
      base_commit: repo.head,
      allowed_paths: ["src/**", "tests/**"],
      denied_paths: [".github/**"],
      submodules: "DENY",
    });
    expect(workspace.base_commit).toBe(repo.head);
    expect(workspace.worktree_path).not.toBe(repo.root);
    expect(workspace.main_worktree_dirty).toBeTrue();
    expect(existsSync(join(workspace.worktree_path, "src", "dirty-main.ts"))).toBeFalse();
    expect(run(repo.root, ["rev-parse", "HEAD"])).toBe(repo.head);
    expect(run(workspace.worktree_path, ["rev-parse", "HEAD"])).toBe(repo.head);
  });

  test("evaluates actual tracked and untracked changes with deny taking precedence", async () => {
    const repo = repository();
    const manager = new GitWorktreeWorkspaceManager({ root: join(root(), "manager"), git_executable: git });
    const workspace = await manager.prepare({
      workspace_id: "workspace:policy", repository_id: "repo:test", repository_path: repo.root,
      task_id: "task:policy", attempt_id: "attempt:policy", base_commit: repo.head,
      allowed_paths: ["src/**", "tests/**", ".github/**"], denied_paths: [".github/**"], submodules: "DENY",
    });
    writeFileSync(join(workspace.worktree_path, "src", "app.ts"), "export const value = 2;\n");
    mkdirSync(join(workspace.worktree_path, "tests"), { recursive: true });
    writeFileSync(join(workspace.worktree_path, "tests", "app.test.ts"), "test('value', () => {});\n");
    writeFileSync(join(workspace.worktree_path, ".github", "workflows", "ci.yml"), "name: changed\n");

    const status = await manager.inspect(workspace.workspace_id);
    expect(status.changed_files.map(file => file.path)).toEqual([".github/workflows/ci.yml", "src/app.ts", "tests/app.test.ts"]);
    expect(status.path_policy.allowed).toEqual(["src/app.ts", "tests/app.test.ts"]);
    expect(status.path_policy.denied).toEqual([".github/workflows/ci.yml"]);
    expect(status.path_policy.decision).toBe("BLOCK");
    const patch = await manager.exportPatch(workspace.workspace_id);
    expect(patch.content).toContain("src/app.ts");
    expect(patch.content).toContain("tests/app.test.ts");
    expect(patch.hash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  test("blocks traversal-like paths and detects symlinks that escape the worktree", async () => {
    expect(evaluatePathPolicy("../outside", ["**"], [])).toEqual({ allowed: false, reason: "INVALID_PATH" });
    expect(evaluatePathPolicy("src/security/key.ts", ["src/**"], ["src/security/**"]))
      .toEqual({ allowed: false, reason: "DENIED_PATH" });
    const repo = repository();
    const managerRoot = root();
    const manager = new GitWorktreeWorkspaceManager({ root: join(managerRoot, "manager"), git_executable: git });
    const workspace = await manager.prepare({
      workspace_id: "workspace:link", repository_id: "repo:test", repository_path: repo.root,
      task_id: "task:link", attempt_id: "attempt:link", base_commit: repo.head,
      allowed_paths: ["src/**"], denied_paths: [], submodules: "DENY",
    });
    const outside = join(managerRoot, "outside");
    mkdirSync(outside);
    const link = join(workspace.worktree_path, "src", "escape-link");
    symlinkSync(outside, link, process.platform === "win32" ? "junction" : "dir");
    const status = await manager.inspect(workspace.workspace_id);
    expect(status.symlink_violations).toContain("src/escape-link");
    expect(status.path_policy.decision).toBe("BLOCK");
  });

  test("seals only a stable workspace and preserves it under quarantine cleanup", async () => {
    const repo = repository();
    const manager = new GitWorktreeWorkspaceManager({ root: join(root(), "manager"), git_executable: git, stability_window_ms: 20 });
    const workspace = await manager.prepare({
      workspace_id: "workspace:seal", repository_id: "repo:test", repository_path: repo.root,
      task_id: "task:seal", attempt_id: "attempt:seal", base_commit: repo.head,
      allowed_paths: ["src/**"], denied_paths: [], submodules: "DENY",
    });
    writeFileSync(join(workspace.worktree_path, "src", "app.ts"), "export const value = 3;\n");
    const sealed = await manager.seal(workspace.workspace_id);
    expect(sealed.status).toBe("WORKSPACE_SEALED");
    expect(sealed.snapshot_hash).toMatch(/^sha256:/);
    expect(sealed.main_branch_unchanged).toBeTrue();
    expect((await manager.assertSeal(workspace.workspace_id, sealed.snapshot_hash)).snapshot_hash).toBe(sealed.snapshot_hash);
    writeFileSync(join(workspace.worktree_path, "src", "app.ts"), "export const value = 4;\n");
    await expect(manager.assertSeal(workspace.workspace_id, sealed.snapshot_hash)).rejects.toThrow("WORKSPACE_SEAL_BROKEN");
    const cleanup = await manager.cleanup(workspace.workspace_id, { action: "QUARANTINE", reason: "failed verification" });
    expect(cleanup.action).toBe("QUARANTINED");
    expect(existsSync(workspace.worktree_path)).toBeTrue();
    expect(readFileSync(cleanup.report_path, "utf8")).toContain("failed verification");
  });

  test("persists a preparation intent before Git side effects and quarantines metadata-write failures", async () => {
    const repo = repository();
    const managerRoot = join(root(), "manager");
    const workspaceId = "workspace:metadata-failure";
    const metadataCollision = join(managerRoot, "metadata", `${createHash("sha256").update(workspaceId).digest("hex").slice(0, 10)}.json`);
    mkdirSync(metadataCollision, { recursive: true });
    const manager = new GitWorktreeWorkspaceManager({ root: managerRoot, git_executable: git });
    await expect(manager.prepare({
      workspace_id: workspaceId, repository_id: "repo:test", repository_path: repo.root,
      task_id: "task:metadata-failure", attempt_id: "attempt:metadata-failure", base_commit: repo.head,
      allowed_paths: ["src/**"], denied_paths: [], submodules: "DENY",
    })).rejects.toThrow();
    expect(existsSync(manager.plannedPath(workspaceId))).toBeTrue();
    expect(manager.listPreparationIntents()).toEqual([expect.objectContaining({ workspace_id: workspaceId, status: "PREPARING" })]);
    expect(await manager.quarantinePreparedOrIntent(workspaceId, "startup recovery")).toBeTrue();
    expect(manager.listPreparationIntents()).toEqual([expect.objectContaining({ workspace_id: workspaceId, status: "QUARANTINED" })]);
  });

  test("describes local worktree isolation honestly and rejects high-risk execution", async () => {
    const environment = new LocalWorktreeEnvironment({ git_executable: git });
    expect(environment.enforcement()).toEqual({
      filesystem: "OBSERVED",
      network: "ADVISORY",
      process: "OBSERVED",
      sandbox: false,
    });
    await expect(environment.prepare({ workspace_path: root(), risk: "critical" })).rejects.toThrow("INSUFFICIENT_SANDBOX_ENFORCEMENT");
    const prepared = await environment.prepare({ workspace_path: root(), risk: "low" });
    expect(prepared.provider).toBe("local-worktree");
    expect(prepared.fingerprint).toMatch(/^sha256:/);
  });

  test("keeps worker ref names within Windows path budgets for long entity identifiers", async () => {
    const repo = repository();
    const manager = new GitWorktreeWorkspaceManager({ root: join(root(), "manager"), git_executable: git });
    const workspace = await manager.prepare({
      workspace_id: `workspace:${"w".repeat(180)}`,
      repository_id: "repo:test",
      repository_path: repo.root,
      task_id: `task:${"t".repeat(180)}`,
      attempt_id: `attempt:${"a".repeat(180)}`,
      base_commit: repo.head,
      allowed_paths: ["src/**"],
      denied_paths: [],
      submodules: "DENY",
    });
    expect(workspace.branch.length).toBeLessThan(80);
    expect(run(workspace.worktree_path, ["rev-parse", "HEAD"])).toBe(repo.head);
  });
});
