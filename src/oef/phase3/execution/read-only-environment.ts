import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { containsLikelyPhase1Secret } from "../../phase1/core/security/secrets";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";

export interface PreparedReviewEnvironment {
  environment_id: string;
  root: string;
  source: string;
  evidence: string;
  artifacts: string;
  temp: string;
  source_manifest_hash: string;
  permissions: {
    source_write: "denied";
    evidence_write: "denied";
    artifacts_write: "denied";
    temp_write: "allowed";
    network: "denied";
    credentials: "denied";
  };
}

interface InternalEnvironment { prepared: PreparedReviewEnvironment; manifests: Record<"source" | "evidence" | "artifacts", string> }

export class ReadOnlyReviewEnvironment {
  private readonly root: string;
  private readonly environments = new Map<string, InternalEnvironment>();

  constructor(options: { root: string }) {
    this.root = resolve(options.root);
    mkdirSync(this.root, { recursive: true });
  }

  prepare(input: { source: string; evidence: string; artifacts: string }): PreparedReviewEnvironment {
    const sources = {
      source: requireDirectory(input.source),
      evidence: requireDirectory(input.evidence),
      artifacts: requireDirectory(input.artifacts),
    };
    const environmentId = `review-environment:${randomBytes(12).toString("hex")}`;
    const directory = join(this.root, environmentId.replace(":", "_"));
    if (existsSync(directory)) throw new Error("REVIEW_ENVIRONMENT_COLLISION");
    mkdirSync(directory, { recursive: false });
    const target = {
      source: join(directory, "source"),
      evidence: join(directory, "evidence"),
      artifacts: join(directory, "artifacts"),
      temp: join(directory, "temp"),
    };
    try {
      for (const name of ["source", "evidence", "artifacts"] as const) {
        mkdirSync(target[name], { recursive: false });
        copyReviewTree(sources[name], target[name]);
      }
      mkdirSync(target.temp, { recursive: false });
      const manifests = {
        source: treeHash(target.source),
        evidence: treeHash(target.evidence),
        artifacts: treeHash(target.artifacts),
      };
      for (const name of ["source", "evidence", "artifacts"] as const) denyWrites(target[name]);
      const prepared: PreparedReviewEnvironment = {
        environment_id: environmentId,
        root: directory,
        ...target,
        source_manifest_hash: manifests.source,
        permissions: {
          source_write: "denied",
          evidence_write: "denied",
          artifacts_write: "denied",
          temp_write: "allowed",
          network: "denied",
          credentials: "denied",
        },
      };
      this.environments.set(environmentId, { prepared, manifests });
      return prepared;
    } catch (error) {
      restoreWrites(directory);
      rmSync(directory, { recursive: true, force: true });
      throw error;
    }
  }

  get(environmentId: string): PreparedReviewEnvironment {
    const environment = this.environments.get(environmentId);
    if (!environment) throw new Error(`REVIEW_ENVIRONMENT_NOT_FOUND: ${environmentId}`);
    return environment.prepared;
  }

  assertIntegrity(environmentId: string): true {
    const environment = this.environments.get(environmentId);
    if (!environment) throw new Error(`REVIEW_ENVIRONMENT_NOT_FOUND: ${environmentId}`);
    for (const name of ["source", "evidence", "artifacts"] as const) {
      if (treeHash(environment.prepared[name]) !== environment.manifests[name]) throw new Error(`REVIEW_${name.toUpperCase()}_INTEGRITY_VIOLATION`);
    }
    return true;
  }

  release(environmentId: string): void {
    const environment = this.environments.get(environmentId);
    if (!environment) return;
    restoreWrites(environment.prepared.root);
    rmSync(environment.prepared.root, { recursive: true, force: true });
    this.environments.delete(environmentId);
  }
}

function requireDirectory(path: string): string {
  const resolved = resolve(path);
  if (!existsSync(resolved) || !lstatSync(resolved).isDirectory()) throw new Error(`REVIEW_INPUT_DIRECTORY_NOT_FOUND: ${resolved}`);
  return resolved;
}

export function computeReviewTreeHash(root: string): string {
  return treeHash(requireDirectory(root));
}

export function computeReviewDependencyHash(root: string): string {
  const directory = requireDirectory(root);
  const files = ["package.json", "bun.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"]
    .filter(path => existsSync(join(directory, path)))
    .map(path => ({ path, content: readFileSync(join(directory, path), "utf8") }));
  return canonicalSha256(files);
}

export function createReviewSnapshotFileIndex(root: string): Array<{ path: string; file_hash: string; line_count: number }> {
  const directory = requireDirectory(root);
  const result: Array<{ path: string; file_hash: string; line_count: number }> = [];
  const visit = (current: string): void => {
    for (const entry of readdirSync(current, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
      const path = join(current, entry.name);
      const name = relative(directory, path).split(sep).join("/");
      if (entry.name === ".git" || entry.name === ".codex" || entry.name === ".opencodex") continue;
      if (isSensitiveReviewPath(name)) throw new Error(`REVIEW_INPUT_SENSITIVE_PATH_FORBIDDEN: ${name}`);
      if (entry.isDirectory()) { visit(path); continue; }
      if (!entry.isFile()) throw new Error("REVIEW_ENVIRONMENT_SPECIAL_FILE_FORBIDDEN");
      const content = readFileSync(path);
      if (containsLikelyPhase1Secret(content.toString("utf8"))) throw new Error(`REVIEW_INPUT_SECRET_DETECTED: ${name}`);
      const text = content.toString("utf8");
      result.push({
        path: name,
        file_hash: `sha256:${createHash("sha256").update(content).digest("hex")}`,
        line_count: text.length === 0 ? 0 : text.split(/\r?\n/).length - (text.endsWith("\n") ? 1 : 0),
      });
    }
  };
  visit(directory);
  return result;
}

function treeHash(root: string): string {
  const hash = createHash("sha256");
  const visit = (directory: string): void => {
    const entries = readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const path = join(directory, entry.name);
      const name = relative(root, path).split(sep).join("/");
      if (entry.name === ".git" || entry.name === ".codex" || entry.name === ".opencodex") continue;
      if (isSensitiveReviewPath(name)) throw new Error(`REVIEW_INPUT_SENSITIVE_PATH_FORBIDDEN: ${name}`);
      if (entry.isSymbolicLink()) throw new Error("REVIEW_ENVIRONMENT_SYMLINK_FORBIDDEN");
      if (entry.isDirectory()) { hash.update(`d:${name}\n`); visit(path); }
      else if (entry.isFile()) {
        const content = readFileSync(path);
        if (containsLikelyPhase1Secret(content.toString("utf8"))) throw new Error(`REVIEW_INPUT_SECRET_DETECTED: ${name}`);
        hash.update(`f:${name}:`); hash.update(content); hash.update("\n");
      }
      else throw new Error("REVIEW_ENVIRONMENT_SPECIAL_FILE_FORBIDDEN");
    }
  };
  visit(root);
  return `sha256:${hash.digest("hex")}`;
}

function copyReviewTree(sourceRoot: string, targetRoot: string): void {
  const visit = (source: string, target: string, relativePath: string): void => {
    const entries = readdirSync(source, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const path = relativePath ? `${relativePath}/${entry.name}` : entry.name;
      if (entry.name === ".git" || entry.name === ".codex" || entry.name === ".opencodex") continue;
      if (isSensitiveReviewPath(path)) throw new Error(`REVIEW_INPUT_SENSITIVE_PATH_FORBIDDEN: ${path}`);
      const sourcePath = join(source, entry.name);
      const targetPath = join(target, entry.name);
      if (entry.isSymbolicLink()) throw new Error("REVIEW_ENVIRONMENT_SYMLINK_FORBIDDEN");
      if (entry.isDirectory()) { mkdirSync(targetPath); visit(sourcePath, targetPath, path); continue; }
      if (!entry.isFile()) throw new Error("REVIEW_ENVIRONMENT_SPECIAL_FILE_FORBIDDEN");
      const content = readFileSync(sourcePath);
      if (containsLikelyPhase1Secret(content.toString("utf8"))) throw new Error(`REVIEW_INPUT_SECRET_DETECTED: ${path}`);
      writeFileSync(targetPath, content);
    }
  };
  visit(sourceRoot, targetRoot, "");
}

function isSensitiveReviewPath(path: string): boolean {
  const normalized = path.toLowerCase();
  const name = normalized.split("/").at(-1)!;
  return name === ".env" || name.startsWith(".env.")
    || ["credentials", "credentials.json", "id_rsa", "id_ed25519", "netrc", ".npmrc", ".pypirc"].includes(name)
    || normalized.startsWith(".ssh/") || normalized.includes("/.ssh/")
    || normalized.startsWith("secrets/") || normalized.includes("/secrets/");
}

function denyWrites(path: string): void {
  if (process.platform === "win32") {
    const identity = windowsIdentity();
    const entries = listTree(path);
    for (const file of entries.files) {
      const readOnly = Bun.spawnSync(["icacls", file, "/inheritance:r", "/grant:r", `${identity}:R`], { stdout: "pipe", stderr: "pipe" });
      if (readOnly.exitCode !== 0) throw new Error("REVIEW_READ_ONLY_ENFORCEMENT_FAILED");
    }
    for (const directory of entries.directories.sort((left, right) => right.length - left.length)) {
      const readOnly = Bun.spawnSync(["icacls", directory, "/inheritance:r", "/grant:r", `${identity}:(RX)`], { stdout: "pipe", stderr: "pipe" });
      if (readOnly.exitCode !== 0) throw new Error("REVIEW_READ_ONLY_ENFORCEMENT_FAILED");
    }
    return;
  }
  walkPostOrder(path, item => chmodSync(item, lstatSync(item).isDirectory() ? 0o555 : 0o444));
}

function listTree(root: string): { directories: string[]; files: string[] } {
  const directories: string[] = [root];
  const files: string[] = [];
  const visit = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) { directories.push(path); visit(path); }
      else if (entry.isFile()) files.push(path);
      else throw new Error("REVIEW_ENVIRONMENT_SPECIAL_FILE_FORBIDDEN");
    }
  };
  visit(root);
  return { directories, files };
}

function restoreWrites(path: string): void {
  if (!existsSync(path)) return;
  if (process.platform === "win32") {
    try {
      Bun.spawnSync(["icacls", path, "/reset", "/T", "/C"], { stdout: "ignore", stderr: "ignore" });
      Bun.spawnSync(["icacls", path, "/inheritance:e", "/T", "/C"], { stdout: "ignore", stderr: "ignore" });
    } catch { /* best-effort restoration before scoped cleanup */ }
    return;
  }
  try { walkPostOrder(path, item => chmodSync(item, lstatSync(item).isDirectory() ? 0o755 : 0o644)); } catch { /* cleanup path */ }
}

function walkPostOrder(root: string, operation: (path: string) => void): void {
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) walkPostOrder(path, operation);
    else operation(path);
  }
  operation(root);
}

let cachedWindowsIdentity: string | null = null;
function windowsIdentity(): string {
  if (cachedWindowsIdentity) return cachedWindowsIdentity;
  const result = Bun.spawnSync(["whoami"], { stdout: "pipe", stderr: "pipe" });
  if (result.exitCode !== 0) throw new Error("REVIEW_WINDOWS_IDENTITY_UNAVAILABLE");
  const identity = result.stdout.toString("utf8").trim();
  if (!identity) throw new Error("REVIEW_WINDOWS_IDENTITY_UNAVAILABLE");
  cachedWindowsIdentity = identity;
  return identity;
}
