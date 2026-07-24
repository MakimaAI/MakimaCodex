import { Database } from "bun:sqlite";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { assertExecutionBindingSetIntegrity, assertRoutingPlanIntegrity, type ExecutionBindingSet, type HandoffPackage, type RoutingContextSnapshot, type RoutingPlan, type RoutingPolicy, type TaskFingerprint, type TeamPlan } from "../core/domain";

export interface RoutingEvent { event_id: string; event_type: string; subject_id: string; payload: Record<string, unknown>; occurred_at: string }

export class SqliteRoutingStore {
  private readonly database: Database;
  constructor(options: { databasePath: string }) {
    this.database = new Database(options.databasePath, { create: true, strict: true });
    this.database.exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
    this.migrate();
  }
  close(): void { this.database.close(); }
  transaction<T>(operation: () => T): T { return this.database.transaction(operation).immediate(); }

  saveTaskFingerprint(value: TaskFingerprint): void { this.immutableInsert("phase5_task_fingerprints", "fingerprint_id", value.fingerprint_id, "content_hash", value.fingerprint_hash, "payload_json", value, ["task_id", value.task_id, "revision", value.revision]); }
  getTaskFingerprint(taskId: string): TaskFingerprint | null { return this.one<TaskFingerprint>("SELECT payload_json FROM phase5_task_fingerprints WHERE task_id=? ORDER BY revision DESC LIMIT 1", taskId); }
  getTaskFingerprintById(id: string): TaskFingerprint | null { return this.one<TaskFingerprint>("SELECT payload_json FROM phase5_task_fingerprints WHERE fingerprint_id=?", id); }
  getTaskFingerprintByHash(hash: string): TaskFingerprint | null { return this.one<TaskFingerprint>("SELECT payload_json FROM phase5_task_fingerprints WHERE content_hash=?", hash); }

  saveTeamPlan(value: TeamPlan): void { this.immutableInsert("phase5_team_plans", "team_plan_id", value.team_plan_id, "content_hash", value.team_plan_hash, "payload_json", value, ["task_id", value.task_id, "revision", value.revision]); }
  getTeamPlan(id: string): TeamPlan | null { return this.one<TeamPlan>("SELECT payload_json FROM phase5_team_plans WHERE team_plan_id=?", id); }
  getLatestTeamPlanForTask(taskId: string): TeamPlan | null { return this.one<TeamPlan>("SELECT payload_json FROM phase5_team_plans WHERE task_id=? ORDER BY revision DESC LIMIT 1", taskId); }
  getTeamPlanByHash(hash: string): TeamPlan | null { return this.one<TeamPlan>("SELECT payload_json FROM phase5_team_plans WHERE content_hash=?", hash); }

  saveRoutingContext(value: RoutingContextSnapshot): void { this.immutableInsert("phase5_routing_context_snapshots", "routing_context_id", value.context_id, "content_hash", value.context_hash, "payload_json", value); }
  getRoutingContextByHash(hash: string): RoutingContextSnapshot | null { return this.one<RoutingContextSnapshot>("SELECT payload_json FROM phase5_routing_context_snapshots WHERE content_hash=?", hash); }
  saveRoutingPolicy(value: RoutingPolicy): void { this.immutableInsert("phase5_routing_policies", "routing_policy_id", `${value.policy_id}@${value.version}`, "content_hash", value.policy_hash, "payload_json", value); }
  getRoutingPolicyByHash(hash: string): RoutingPolicy | null { return this.one<RoutingPolicy>("SELECT payload_json FROM phase5_routing_policies WHERE content_hash=?", hash); }

  saveRoutingPlan(value: RoutingPlan): void {
    assertRoutingPlanIntegrity(value);
    this.database.query("INSERT OR IGNORE INTO phase5_routing_plan_snapshots (plan_hash, routing_plan_id, revision, status, payload_json) VALUES (?, ?, ?, ?, ?)").run(value.plan_hash, value.routing_plan_id, value.revision, value.status, json(value));
    this.database.query(`INSERT INTO phase5_routing_plans (routing_plan_id, revision, task_id, status, content_hash, payload_json) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(routing_plan_id, revision) DO UPDATE SET status=excluded.status, content_hash=excluded.content_hash, payload_json=excluded.payload_json`).run(value.routing_plan_id, value.revision, value.task_id, value.status, value.plan_hash, json(value));
  }
  getRoutingPlan(id: string): RoutingPlan | null { const value = this.one<RoutingPlan>("SELECT payload_json FROM phase5_routing_plans WHERE routing_plan_id=? ORDER BY revision DESC LIMIT 1", id); if (value) assertRoutingPlanIntegrity(value); return value; }
  getRoutingPlanDecision(id: string): RoutingPlan | null { const value = this.one<RoutingPlan>("SELECT payload_json FROM phase5_routing_plan_snapshots WHERE routing_plan_id=? AND status='POLICY_VALIDATED' ORDER BY rowid LIMIT 1", id); if (value) assertRoutingPlanIntegrity(value); return value; }
  getLatestRoutingPlanForTask(taskId: string): RoutingPlan | null { return this.one<RoutingPlan>("SELECT payload_json FROM phase5_routing_plans WHERE task_id=? ORDER BY rowid DESC LIMIT 1", taskId); }

  saveBindingSet(value: ExecutionBindingSet): void {
    assertExecutionBindingSetIntegrity(value);
    if (value.revision > 1) { const prior = this.database.query("SELECT content_hash FROM phase5_execution_binding_sets WHERE routing_plan_id=? AND revision=?").get(value.routing_plan_id, value.revision - 1) as { content_hash: string } | null; if (!prior || prior.content_hash !== value.previous_revision_hash) throw new Error("BINDING_SET_PREVIOUS_REVISION_MISMATCH"); }
    this.immutableInsert("phase5_execution_binding_sets", "binding_set_id", `${value.binding_set_id}@${value.revision}`, "content_hash", value.binding_set_hash, "payload_json", value, ["routing_plan_id", value.routing_plan_id, "revision", value.revision]);
  }
  getLatestBindingSet(routingPlanId: string): ExecutionBindingSet | null { const values = this.many<ExecutionBindingSet>("SELECT payload_json FROM phase5_execution_binding_sets WHERE routing_plan_id=? ORDER BY revision", routingPlanId); let previous: ExecutionBindingSet | null = null; for (const value of values) { assertExecutionBindingSetIntegrity(value); if (previous && value.previous_revision_hash !== previous.binding_set_hash) throw new Error("BINDING_SET_PREVIOUS_REVISION_MISMATCH"); previous = value; } return previous; }
  saveHandoff(value: HandoffPackage): void { this.immutableInsert("phase5_handoff_packages", "handoff_id", value.handoff_id, "content_hash", value.handoff_hash, "payload_json", value); }
  saveOutcome(value: { routing_outcome_id: string; task_id: string; outcome_hash: string; [key: string]: unknown }): void { this.immutableInsert("phase5_routing_outcomes", "routing_outcome_id", value.routing_outcome_id, "content_hash", value.outcome_hash, "payload_json", value, ["task_id", value.task_id]); }
  getOutcomeForTask(taskId: string): Record<string, unknown> | null { return this.one<Record<string, unknown>>("SELECT payload_json FROM phase5_routing_outcomes WHERE task_id=? ORDER BY rowid DESC LIMIT 1", taskId); }

  appendEvent(event: RoutingEvent): boolean {
    const result = this.database.query("INSERT OR IGNORE INTO phase5_routing_events (event_id, event_type, subject_id, occurred_at, payload_json) VALUES (?, ?, ?, ?, ?)").run(event.event_id, event.event_type, event.subject_id, event.occurred_at, json(event));
    return result.changes === 1;
  }
  listEvents(): RoutingEvent[] { return this.many<RoutingEvent>("SELECT payload_json FROM phase5_routing_events ORDER BY rowid"); }

  reserveBudget(input: { pool_id: string; limit: number; routing_plan_id: string; amount: number; idempotency_key: string; now: string }): { reservation_id: string; amount: number } {
    return this.transaction(() => {
      this.database.query("INSERT OR IGNORE INTO phase5_budget_pools (pool_id, capacity) VALUES (?, ?)").run(input.pool_id, input.limit);
      const pool = this.database.query("SELECT capacity FROM phase5_budget_pools WHERE pool_id=?").get(input.pool_id) as { capacity: number } | null;
      if (!pool || pool.capacity !== input.limit) throw new Error("BUDGET_POOL_LIMIT_CONFLICT");
      const prior = this.database.query("SELECT reservation_id, amount FROM phase5_budget_reservations WHERE pool_id=? AND idempotency_key=?").get(input.pool_id, input.idempotency_key) as { reservation_id: string; amount: number } | null;
      if (prior) return prior;
      const usage = this.database.query("SELECT COALESCE(SUM(amount),0) AS used FROM phase5_budget_reservations WHERE pool_id=?").get(input.pool_id) as { used: number };
      if (usage.used + input.amount > pool.capacity) throw new Error("BUDGET_RESERVATION_FAILED");
      const reservation = { reservation_id: `budget-reservation:${canonicalSha256({ pool: input.pool_id, key: input.idempotency_key }).slice(7, 27)}`, amount: input.amount };
      this.database.query("INSERT INTO phase5_budget_reservations (reservation_id, pool_id, routing_plan_id, idempotency_key, amount, reserved_at) VALUES (?, ?, ?, ?, ?, ?)").run(reservation.reservation_id, input.pool_id, input.routing_plan_id, input.idempotency_key, input.amount, input.now);
      return reservation;
    });
  }

  private immutableInsert(table: string, idColumn: string, id: string, hashColumn: string, hash: string, jsonColumn: string, value: unknown, extras: Array<string | number> = []): void {
    const extraColumns: string[] = []; const extraValues: Array<string | number> = [];
    for (let index = 0; index < extras.length; index += 2) { extraColumns.push(String(extras[index])); extraValues.push(extras[index + 1]!); }
    const existing = this.database.query(`SELECT ${hashColumn} AS hash FROM ${table} WHERE ${idColumn}=?`).get(id) as { hash: string } | null;
    if (existing && existing.hash !== hash) throw new Error("PHASE5_IMMUTABLE_RECORD_CONFLICT");
    const columns = [idColumn, ...extraColumns, hashColumn, jsonColumn];
    this.database.query(`INSERT OR IGNORE INTO ${table} (${columns.join(",")}) VALUES (${columns.map(() => "?").join(",")})`).run(id, ...extraValues, hash, json(value));
  }
  private one<T>(sql: string, ...parameters: Array<string | number>): T | null { const row = this.database.query(sql).get(...parameters) as Record<string, string> | null; return row ? JSON.parse(Object.values(row)[0]!) as T : null; }
  private many<T>(sql: string, ...parameters: Array<string | number>): T[] { return (this.database.query(sql).all(...parameters) as Array<Record<string, string>>).map(row => JSON.parse(Object.values(row)[0]!) as T); }
  private migrate(): void {
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS phase5_task_fingerprints (fingerprint_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, revision INTEGER NOT NULL, content_hash TEXT NOT NULL, payload_json TEXT NOT NULL, UNIQUE(task_id, revision));
      CREATE TABLE IF NOT EXISTS phase5_role_definitions (role_definition_id TEXT PRIMARY KEY, content_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase5_agent_profiles (agent_profile_id TEXT PRIMARY KEY, content_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase5_team_blueprints (team_blueprint_id TEXT PRIMARY KEY, content_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase5_team_plans (team_plan_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, revision INTEGER NOT NULL, content_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase5_candidates (candidate_id TEXT PRIMARY KEY, content_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase5_candidate_sets (candidate_set_id TEXT PRIMARY KEY, content_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase5_routing_context_snapshots (routing_context_id TEXT PRIMARY KEY, content_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase5_routing_policies (routing_policy_id TEXT PRIMARY KEY, content_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase5_routing_decisions (routing_decision_id TEXT PRIMARY KEY, content_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase5_routing_plans (routing_plan_id TEXT NOT NULL, revision INTEGER NOT NULL, task_id TEXT NOT NULL, status TEXT NOT NULL, content_hash TEXT NOT NULL, payload_json TEXT NOT NULL, PRIMARY KEY(routing_plan_id, revision));
      CREATE TABLE IF NOT EXISTS phase5_routing_plan_snapshots (plan_hash TEXT PRIMARY KEY, routing_plan_id TEXT NOT NULL, revision INTEGER NOT NULL, status TEXT NOT NULL, payload_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase5_fallback_graphs (fallback_graph_id TEXT PRIMARY KEY, content_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase5_execution_binding_sets (binding_set_id TEXT PRIMARY KEY, routing_plan_id TEXT NOT NULL, revision INTEGER NOT NULL, content_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase5_handoff_packages (handoff_id TEXT PRIMARY KEY, content_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase5_routing_outcomes (routing_outcome_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, content_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase5_routing_incidents (routing_incident_id TEXT PRIMARY KEY, content_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase5_routing_overrides (routing_override_id TEXT PRIMARY KEY, content_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase5_routing_events (event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL, subject_id TEXT NOT NULL, occurred_at TEXT NOT NULL, payload_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase5_offline_replay_jobs (replay_job_id TEXT PRIMARY KEY, content_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase5_budget_pools (pool_id TEXT PRIMARY KEY, capacity REAL NOT NULL CHECK(capacity >= 0));
      CREATE TABLE IF NOT EXISTS phase5_budget_reservations (reservation_id TEXT PRIMARY KEY, pool_id TEXT NOT NULL, routing_plan_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, amount REAL NOT NULL CHECK(amount >= 0), reserved_at TEXT NOT NULL, UNIQUE(pool_id, idempotency_key), FOREIGN KEY(pool_id) REFERENCES phase5_budget_pools(pool_id));
    `);
  }
}
export class SqliteBudgetAuthority {
  constructor(private readonly store: SqliteRoutingStore, private readonly options: { poolId: string; limit: number }) {}
  async reserve(input: { routing_plan_id: string; amount: number; idempotency_key: string; now: string }): Promise<{ reservation_id: string; amount: number }> {
    return this.store.reserveBudget({ pool_id: this.options.poolId, limit: this.options.limit, ...input });
  }
}
function json(value: unknown): string { return JSON.stringify(value); }
