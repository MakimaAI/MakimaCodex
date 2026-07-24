import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const KILL_SWITCH_STATES = [
  "RUNNING", "PAUSE_NEW_EXECUTIONS", "CANCEL_RUNNING_LOW_RISK", "CANCEL_ALL", "DISABLE_RUNTIME", "DISABLE_NETWORK", "READ_ONLY_MODE",
] as const;
export type KillSwitchState = typeof KILL_SWITCH_STATES[number];

interface KillSwitchRecord { schema_version: 1; state: KillSwitchState; reason: string; actor: string; changed_at: string }

export class RunnerKillSwitchStore {
  private readonly statePath: string;
  private readonly auditPath: string;
  private readonly actor: string;
  constructor(options: { root: string; actor: string }) {
    mkdirSync(options.root, { recursive: true });
    this.statePath = join(options.root, "state.json");
    this.auditPath = join(options.root, "audit.jsonl");
    this.actor = options.actor;
    if (!existsSync(this.statePath)) {
      writeFileSync(this.statePath, JSON.stringify({ schema_version: 1, state: "RUNNING", reason: "initial", actor: this.actor, changed_at: new Date().toISOString() }), "utf8");
    }
  }

  set(state: KillSwitchState, reason: string): void {
    if (!(KILL_SWITCH_STATES as readonly string[]).includes(state) || !reason.trim()) throw new Error("Invalid kill switch change");
    const record: KillSwitchRecord = { schema_version: 1, state, reason: reason.trim(), actor: this.actor, changed_at: new Date().toISOString() };
    writeFileSync(this.statePath, JSON.stringify(record), "utf8");
    appendFileSync(this.auditPath, `${JSON.stringify(record)}\n`, "utf8");
  }

  current(): KillSwitchRecord {
    const value = JSON.parse(readFileSync(this.statePath, "utf8")) as KillSwitchRecord;
    if (value.schema_version !== 1 || !(KILL_SWITCH_STATES as readonly string[]).includes(value.state)) throw new Error("KILL_SWITCH_STATE_CORRUPT");
    return value;
  }
  canStart(): { allowed: true } | { allowed: false; reason: Exclude<KillSwitchState, "RUNNING"> } {
    const state = this.current().state;
    return state === "RUNNING" ? { allowed: true } : { allowed: false, reason: state };
  }
  audit(): KillSwitchRecord[] {
    if (!existsSync(this.auditPath)) return [];
    return readFileSync(this.auditPath, "utf8").split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line) as KillSwitchRecord);
  }
}
