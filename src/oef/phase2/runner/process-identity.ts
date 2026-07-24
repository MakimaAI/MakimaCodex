import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";

export interface ObservedProcessIdentity {
  pid: number;
  os_start_identity: string;
  executable_path: string;
  executable_hash: string;
}

export interface PersistedProcessIdentity extends ObservedProcessIdentity {
  started_at: string;
  target_executable_hash: string;
  runner_nonce: string;
  attestation_path: string;
  recovery_identity?: ProcessRecoveryIdentity;
}

export interface ProcessRecoveryIdentity {
  execution_id: string;
  attempt_id: string;
  workspace_path: string;
}

export function inspectProcessIdentity(pid: number): ObservedProcessIdentity | null {
  if (!Number.isInteger(pid) || pid <= 0) return null;
  try {
    if (process.platform === "win32") {
      const command = `$p=Get-Process -Id ${pid} -ErrorAction Stop; @{start=$p.StartTime.ToUniversalTime().ToString('o');path=$p.Path}|ConvertTo-Json -Compress`;
      const result = Bun.spawnSync(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command], {
        stdin: "ignore", stdout: "pipe", stderr: "ignore", windowsHide: true,
      });
      if (result.exitCode !== 0) return null;
      const value = JSON.parse(new TextDecoder().decode(result.stdout)) as { start?: string; path?: string };
      if (!value.start || !value.path) return null;
      return {
        pid,
        os_start_identity: new Date(value.start).toISOString(),
        executable_path: realpathSync(value.path),
        executable_hash: executableHash(value.path),
      };
    }
    if (process.platform === "linux") {
      const source = readFileSync(`/proc/${pid}/stat`, "utf8").trim();
      const fieldsAfterCommand = source.slice(source.lastIndexOf(")") + 2).split(/\s+/);
      const startTicks = fieldsAfterCommand[19];
      const executablePath = realpathSync(`/proc/${pid}/exe`);
      if (!startTicks) return null;
      return {
        pid,
        os_start_identity: `linux-proc-start:${startTicks}`,
        executable_path: executablePath,
        executable_hash: executableHash(executablePath),
      };
    }
    return null;
  } catch { return null; }
}

export function verifyPersistedProcessIdentity(identity: PersistedProcessIdentity): boolean {
  const observed = inspectProcessIdentity(identity.pid);
  if (!observed
    || observed.os_start_identity !== identity.os_start_identity
    || observed.executable_hash !== identity.executable_hash) return false;
  try {
    const proof = JSON.parse(readFileSync(identity.attestation_path, "utf8")) as Partial<PersistedProcessIdentity>;
    return proof.pid === identity.pid
      && proof.os_start_identity === identity.os_start_identity
      && proof.executable_hash === identity.executable_hash
      && proof.runner_nonce === identity.runner_nonce;
  } catch { return false; }
}

export function executableHash(path: string): string {
  try { return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`; }
  catch { return `sha256:${createHash("sha256").update(path).digest("hex")}`; }
}
