import { Database } from "bun:sqlite";
import type {
  AliasRecord, ArtifactRef, AuditEvent, BenchmarkSuite, CapabilityClaim, CapabilityObservation, EvaluationRun,
  ExecutionConfiguration, ModelVersion, RequalificationJob, RoleProfile, RoleScorecard,
} from "../core/domain";

export class SqliteModelLabStore {
  private readonly database: Database;

  constructor(options: { databasePath: string }) {
    this.database = new Database(options.databasePath, { create: true, strict: true });
    this.database.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
    this.migrate();
  }

  close(): void { this.database.close(); }
  transaction<T>(operation: () => T): T { return this.database.transaction(operation).immediate(); }

  saveModelVersion(model: ModelVersion): void {
    const existing = this.getModelVersion(model.model_version_id);
    if (existing && existing.metadata_hash !== model.metadata_hash) {
      this.database.query("INSERT OR IGNORE INTO phase4_model_version_revisions (model_version_id, metadata_hash, model_json) VALUES (?, ?, ?)")
        .run(existing.model_version_id, existing.metadata_hash, json(existing));
    }
    this.database.query(`INSERT INTO phase4_model_versions (model_version_id, provider_id, family_id, metadata_hash, model_json)
      VALUES (?, ?, ?, ?, ?) ON CONFLICT(model_version_id) DO UPDATE SET metadata_hash=excluded.metadata_hash, model_json=excluded.model_json`)
      .run(model.model_version_id, model.provider_id, model.family_id, model.metadata_hash, json(model));
    this.database.query("INSERT OR IGNORE INTO phase4_model_version_revisions (model_version_id, metadata_hash, model_json) VALUES (?, ?, ?)")
      .run(model.model_version_id, model.metadata_hash, json(model));
  }
  getModelVersion(id: string): ModelVersion | null { return this.one<ModelVersion>("SELECT model_json FROM phase4_model_versions WHERE model_version_id = ?", id); }
  listModelVersions(): ModelVersion[] { return this.many<ModelVersion>("SELECT model_json FROM phase4_model_versions ORDER BY model_version_id"); }
  listModelVersionRevisions(id: string): ModelVersion[] { return this.many<ModelVersion>("SELECT model_json FROM phase4_model_version_revisions WHERE model_version_id = ? ORDER BY rowid", id); }

  saveAlias(alias: AliasRecord): void {
    this.database.query(`INSERT INTO phase4_alias_history (provider_id, alias, revision, alias_json) VALUES (?, ?, ?, ?)`)
      .run(alias.provider_id, alias.alias, alias.revision, json(alias));
    this.database.query(`INSERT INTO phase4_aliases (provider_id, alias, alias_json) VALUES (?, ?, ?)
      ON CONFLICT(provider_id, alias) DO UPDATE SET alias_json=excluded.alias_json`).run(alias.provider_id, alias.alias, json(alias));
  }
  getAlias(providerId: string, alias: string): AliasRecord | null {
    return this.one<AliasRecord>("SELECT alias_json FROM phase4_aliases WHERE provider_id = ? AND alias = ?", providerId, alias);
  }
  listAliases(): AliasRecord[] { return this.many<AliasRecord>("SELECT alias_json FROM phase4_aliases ORDER BY provider_id, alias"); }

  saveExecutionConfiguration(config: ExecutionConfiguration): void {
    const existing = this.getExecutionConfiguration(config.execution_config_id);
    if (existing && existing.configuration_hash !== config.configuration_hash) throw new Error("EXECUTION_CONFIGURATION_IMMUTABLE");
    this.database.query(`INSERT OR IGNORE INTO phase4_execution_configurations (execution_config_id, model_version_id, config_hash, config_json, stale, quarantined) VALUES (?, ?, ?, ?, 0, 0)`)
      .run(config.execution_config_id, config.model.version_id, config.configuration_hash, json(config));
  }
  getExecutionConfiguration(id: string): ExecutionConfiguration | null { return this.one<ExecutionConfiguration>("SELECT config_json FROM phase4_execution_configurations WHERE execution_config_id = ?", id); }
  listExecutionConfigurations(): ExecutionConfiguration[] { return this.many<ExecutionConfiguration>("SELECT config_json FROM phase4_execution_configurations ORDER BY execution_config_id"); }
  isConfigurationStale(id: string): boolean { return this.flag("SELECT stale AS value FROM phase4_execution_configurations WHERE execution_config_id = ?", id); }
  isConfigurationQuarantined(id: string): boolean { return this.flag("SELECT quarantined AS value FROM phase4_execution_configurations WHERE execution_config_id = ?", id); }
  markConfigurationsStaleForModel(modelVersionId: string): string[] {
    const rows = this.database.query("SELECT execution_config_id FROM phase4_execution_configurations WHERE model_version_id = ? AND stale = 0").all(modelVersionId) as Array<{ execution_config_id: string }>;
    this.database.query("UPDATE phase4_execution_configurations SET stale = 1 WHERE model_version_id = ?").run(modelVersionId);
    for (const row of rows) this.database.query("UPDATE phase4_scorecards SET lifecycle_status = 'stale' WHERE execution_config_id = ? AND lifecycle_status = 'valid'").run(row.execution_config_id);
    return rows.map(row => row.execution_config_id);
  }
  quarantineConfiguration(id: string): void {
    this.database.query("UPDATE phase4_execution_configurations SET quarantined = 1 WHERE execution_config_id = ?").run(id);
    this.database.query("UPDATE phase4_scorecards SET lifecycle_status = 'quarantined' WHERE execution_config_id = ?").run(id);
  }

  saveRoleProfile(role: RoleProfile): void {
    const existing = this.getRoleProfile(role.id, role.version);
    if (existing && existing.content_hash !== role.content_hash) throw new Error("ROLE_PROFILE_VERSION_IMMUTABLE");
    this.database.query("INSERT OR IGNORE INTO phase4_role_profiles (role_id, version, content_hash, role_json) VALUES (?, ?, ?, ?)").run(role.id, role.version, role.content_hash, json(role));
  }
  getRoleProfile(id: string, version?: string): RoleProfile | null {
    return version
      ? this.one<RoleProfile>("SELECT role_json FROM phase4_role_profiles WHERE role_id = ? AND version = ?", id, version)
      : this.one<RoleProfile>("SELECT role_json FROM phase4_role_profiles WHERE role_id = ? ORDER BY version DESC LIMIT 1", id);
  }
  listRoleProfiles(): RoleProfile[] { return this.many<RoleProfile>("SELECT role_json FROM phase4_role_profiles ORDER BY role_id, version"); }

  saveBenchmarkSuite(suite: BenchmarkSuite): void {
    const existing = this.getBenchmarkSuite(suite.benchmark_suite_id, suite.version);
    if (existing && existing.content_hash !== suite.content_hash) throw new Error("BENCHMARK_SUITE_VERSION_IMMUTABLE");
    this.database.query("INSERT OR IGNORE INTO phase4_benchmark_suites (suite_id, version, content_hash, suite_json) VALUES (?, ?, ?, ?)").run(suite.benchmark_suite_id, suite.version, suite.content_hash, json(suite));
  }
  getBenchmarkSuite(id: string, version: string): BenchmarkSuite | null { return this.one<BenchmarkSuite>("SELECT suite_json FROM phase4_benchmark_suites WHERE suite_id = ? AND version = ?", id, version); }
  listBenchmarkSuites(): BenchmarkSuite[] { return this.many<BenchmarkSuite>("SELECT suite_json FROM phase4_benchmark_suites ORDER BY suite_id, version"); }

  saveObservation(observation: CapabilityObservation): void {
    this.database.query("INSERT OR IGNORE INTO phase4_capability_observations (observation_id, execution_config_id, capability, observed_at, observation_json) VALUES (?, ?, ?, ?, ?)")
      .run(observation.observation_id, observation.execution_config_id, observation.capability, observation.observed_at, json(observation));
  }
  listObservations(configId: string): CapabilityObservation[] { return this.many<CapabilityObservation>("SELECT observation_json FROM phase4_capability_observations WHERE execution_config_id = ? ORDER BY observed_at DESC, rowid DESC", configId); }
  saveCapabilityClaim(claim: CapabilityClaim): void {
    this.database.query("INSERT OR IGNORE INTO phase4_capability_claims (claim_id, model_version_id, capability, claim_json) VALUES (?, ?, ?, ?)")
      .run(claim.claim_id, claim.model_version_id, claim.capability, json(claim));
  }
  listCapabilityClaims(modelVersionId: string): CapabilityClaim[] { return this.many<CapabilityClaim>("SELECT claim_json FROM phase4_capability_claims WHERE model_version_id=? ORDER BY capability, claim_id", modelVersionId); }

  saveEvaluationRun(run: EvaluationRun): void {
    const existing = this.getEvaluationRunByIdempotencyKey(run.idempotency_key);
    if (existing && existing.evaluation_run_id !== run.evaluation_run_id) throw new Error("EVALUATION_IDEMPOTENCY_CONFLICT");
    this.database.query(`INSERT INTO phase4_evaluation_runs (evaluation_run_id, idempotency_key, status, run_json) VALUES (?, ?, ?, ?)
      ON CONFLICT(evaluation_run_id) DO UPDATE SET status=excluded.status, run_json=excluded.run_json`)
      .run(run.evaluation_run_id, run.idempotency_key, run.status, json(run));
  }
  insertEvaluationRunIfAbsent(run: EvaluationRun): boolean {
    const result = this.database.query("INSERT OR IGNORE INTO phase4_evaluation_runs (evaluation_run_id, idempotency_key, status, run_json) VALUES (?, ?, ?, ?)")
      .run(run.evaluation_run_id, run.idempotency_key, run.status, json(run));
    return result.changes === 1;
  }
  getEvaluationRun(id: string): EvaluationRun | null { return this.one<EvaluationRun>("SELECT run_json FROM phase4_evaluation_runs WHERE evaluation_run_id = ?", id); }
  getEvaluationRunByIdempotencyKey(key: string): EvaluationRun | null { return this.one<EvaluationRun>("SELECT run_json FROM phase4_evaluation_runs WHERE idempotency_key = ?", key); }
  listEvaluationRuns(): EvaluationRun[] { return this.many<EvaluationRun>("SELECT run_json FROM phase4_evaluation_runs ORDER BY evaluation_run_id"); }
  claimEvaluationAttempt(input: { attemptId: string; runId: string; owner: string; now: string; leaseExpiresAt: string }): { status: "claimed" | "busy" | "completed"; attempt?: EvaluationRun["attempts"][number] } {
    return this.transaction(() => {
      const row = this.database.query("SELECT status, lease_owner, lease_expires_at, attempt_json FROM phase4_evaluation_attempts WHERE attempt_id = ?").get(input.attemptId) as { status: string; lease_owner: string | null; lease_expires_at: string | null; attempt_json: string | null } | null;
      if (!row) {
        this.database.query("INSERT INTO phase4_evaluation_attempts (attempt_id, evaluation_run_id, status, lease_owner, lease_expires_at, attempt_json) VALUES (?, ?, 'CLAIMED', ?, ?, NULL)")
          .run(input.attemptId, input.runId, input.owner, input.leaseExpiresAt);
        return { status: "claimed" };
      }
      if (row.status === "COMPLETED" && row.attempt_json) return { status: "completed", attempt: JSON.parse(row.attempt_json) as EvaluationRun["attempts"][number] };
      const expired = row.lease_expires_at !== null && Date.parse(row.lease_expires_at) <= Date.parse(input.now);
      if (row.status === "AVAILABLE" || row.lease_owner === input.owner || expired) {
        this.database.query("UPDATE phase4_evaluation_attempts SET status='CLAIMED', lease_owner=?, lease_expires_at=? WHERE attempt_id=?").run(input.owner, input.leaseExpiresAt, input.attemptId);
        return { status: "claimed" };
      }
      return { status: "busy" };
    });
  }
  completeEvaluationAttempt(attempt: EvaluationRun["attempts"][number], owner: string): void {
    const result = this.database.query("UPDATE phase4_evaluation_attempts SET status='COMPLETED', attempt_json=?, lease_owner=NULL, lease_expires_at=NULL WHERE attempt_id=? AND status='CLAIMED' AND lease_owner=?")
      .run(json(attempt), attempt.attempt_id, owner);
    if (result.changes !== 1) {
      const existing = this.database.query("SELECT attempt_json FROM phase4_evaluation_attempts WHERE attempt_id=? AND status='COMPLETED'").get(attempt.attempt_id) as { attempt_json: string } | null;
      if (!existing || json(JSON.parse(existing.attempt_json)) !== json(attempt)) throw new Error("EVALUATION_ATTEMPT_COMPLETION_CONFLICT");
    }
  }
  listEvaluationAttempts(runId: string): EvaluationRun["attempts"] {
    return this.many<EvaluationRun["attempts"][number]>("SELECT attempt_json FROM phase4_evaluation_attempts WHERE evaluation_run_id=? AND status='COMPLETED' ORDER BY attempt_id", runId);
  }
  releaseAbandonedEvaluationClaims(isAlive: (pid: number) => boolean): number {
    const rows = this.database.query("SELECT attempt_id, lease_owner FROM phase4_evaluation_attempts WHERE status='CLAIMED'").all() as Array<{ attempt_id: string; lease_owner: string | null }>;
    let released = 0;
    for (const row of rows) {
      const match = row.lease_owner?.match(/^process:(\d+)(?::|$)/); const pid = match ? Number(match[1]) : NaN;
      if (Number.isInteger(pid) && isAlive(pid)) continue;
      released += Number(this.database.query("UPDATE phase4_evaluation_attempts SET status='AVAILABLE', lease_owner=NULL, lease_expires_at=NULL WHERE attempt_id=? AND status='CLAIMED'").run(row.attempt_id).changes);
    }
    return released;
  }

  saveScorecard(card: RoleScorecard): void {
    const existing = this.getScorecard(card.scorecard_id);
    if (existing && existing.scorecard_hash !== card.scorecard_hash) throw new Error("SCORECARD_IMMUTABLE");
    this.database.query(`INSERT OR IGNORE INTO phase4_scorecards (scorecard_id, role_id, execution_config_id, lifecycle_status, valid_until, scorecard_json) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(card.scorecard_id, card.role_profile_ref.id, card.execution_config_ref.id, card.lifecycle.status, card.lifecycle.valid_until, json(card));
  }
  getScorecard(id: string): RoleScorecard | null { return this.one<RoleScorecard>("SELECT scorecard_json FROM phase4_scorecards WHERE scorecard_id = ?", id); }
  listScorecards(roleId?: string): RoleScorecard[] {
    return roleId ? this.many<RoleScorecard>("SELECT scorecard_json FROM phase4_scorecards WHERE role_id = ? ORDER BY scorecard_id", roleId) : this.many<RoleScorecard>("SELECT scorecard_json FROM phase4_scorecards ORDER BY scorecard_id");
  }

  saveArtifact(artifact: ArtifactRef): void { this.database.query("INSERT OR IGNORE INTO phase4_artifacts (artifact_id, artifact_json) VALUES (?, ?)").run(artifact.artifact_id, json(artifact)); }
  getArtifact(id: string): ArtifactRef | null { return this.one<ArtifactRef>("SELECT artifact_json FROM phase4_artifacts WHERE artifact_id = ?", id); }

  saveRequalificationJob(job: RequalificationJob): void {
    this.database.query("INSERT OR IGNORE INTO phase4_requalification_jobs (job_id, execution_config_id, job_json) VALUES (?, ?, ?)").run(job.job_id, job.execution_config_id, json(job));
  }
  listRequalificationJobs(): RequalificationJob[] { return this.many<RequalificationJob>("SELECT job_json FROM phase4_requalification_jobs ORDER BY job_id"); }

  appendAudit(event: AuditEvent): void { this.database.query("INSERT OR IGNORE INTO phase4_audit_events (event_id, event_type, subject_id, event_json) VALUES (?, ?, ?, ?)").run(event.event_id, event.event_type, event.subject_id, json(event)); }
  listAuditEvents(): AuditEvent[] { return this.many<AuditEvent>("SELECT event_json FROM phase4_audit_events ORDER BY rowid"); }

  private one<T>(sql: string, ...params: Array<string | number>): T | null {
    const row = this.database.query(sql).get(...params) as { [key: string]: string } | null;
    if (!row) return null;
    return JSON.parse(Object.values(row)[0]!) as T;
  }
  private many<T>(sql: string, ...params: Array<string | number>): T[] {
    const rows = this.database.query(sql).all(...params) as Array<{ [key: string]: string }>;
    return rows.map(row => JSON.parse(Object.values(row)[0]!) as T);
  }
  private flag(sql: string, id: string): boolean {
    const row = this.database.query(sql).get(id) as { value: number } | null;
    return row?.value === 1;
  }
  private migrate(): void {
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS phase4_model_versions (model_version_id TEXT PRIMARY KEY, provider_id TEXT NOT NULL, family_id TEXT NOT NULL, metadata_hash TEXT NOT NULL, model_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase4_model_version_revisions (model_version_id TEXT NOT NULL, metadata_hash TEXT NOT NULL, model_json TEXT NOT NULL, PRIMARY KEY(model_version_id, metadata_hash));
      CREATE TABLE IF NOT EXISTS phase4_aliases (provider_id TEXT NOT NULL, alias TEXT NOT NULL, alias_json TEXT NOT NULL, PRIMARY KEY(provider_id, alias));
      CREATE TABLE IF NOT EXISTS phase4_alias_history (provider_id TEXT NOT NULL, alias TEXT NOT NULL, revision INTEGER NOT NULL, alias_json TEXT NOT NULL, PRIMARY KEY(provider_id, alias, revision));
      CREATE TABLE IF NOT EXISTS phase4_execution_configurations (execution_config_id TEXT PRIMARY KEY, model_version_id TEXT NOT NULL, config_hash TEXT NOT NULL, config_json TEXT NOT NULL, stale INTEGER NOT NULL CHECK(stale IN (0,1)), quarantined INTEGER NOT NULL CHECK(quarantined IN (0,1)));
      CREATE TABLE IF NOT EXISTS phase4_role_profiles (role_id TEXT NOT NULL, version TEXT NOT NULL, content_hash TEXT NOT NULL, role_json TEXT NOT NULL, PRIMARY KEY(role_id, version));
      CREATE TABLE IF NOT EXISTS phase4_benchmark_suites (suite_id TEXT NOT NULL, version TEXT NOT NULL, content_hash TEXT NOT NULL, suite_json TEXT NOT NULL, PRIMARY KEY(suite_id, version));
      CREATE TABLE IF NOT EXISTS phase4_capability_observations (observation_id TEXT PRIMARY KEY, execution_config_id TEXT NOT NULL, capability TEXT NOT NULL, observed_at TEXT NOT NULL DEFAULT '', observation_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase4_capability_claims (claim_id TEXT PRIMARY KEY, model_version_id TEXT NOT NULL, capability TEXT NOT NULL, claim_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase4_evaluation_runs (evaluation_run_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, status TEXT NOT NULL, run_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase4_evaluation_attempts (attempt_id TEXT PRIMARY KEY, evaluation_run_id TEXT NOT NULL, status TEXT NOT NULL, lease_owner TEXT, lease_expires_at TEXT, attempt_json TEXT);
      CREATE TABLE IF NOT EXISTS phase4_scorecards (scorecard_id TEXT PRIMARY KEY, role_id TEXT NOT NULL, execution_config_id TEXT NOT NULL, lifecycle_status TEXT NOT NULL, valid_until TEXT NOT NULL, scorecard_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase4_artifacts (artifact_id TEXT PRIMARY KEY, artifact_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase4_requalification_jobs (job_id TEXT PRIMARY KEY, execution_config_id TEXT NOT NULL, job_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS phase4_audit_events (event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL, subject_id TEXT NOT NULL, event_json TEXT NOT NULL);
    `);
    const observationColumns = this.database.query("PRAGMA table_info(phase4_capability_observations)").all() as Array<{ name: string }>;
    if (!observationColumns.some(column => column.name === "observed_at")) this.database.exec("ALTER TABLE phase4_capability_observations ADD COLUMN observed_at TEXT NOT NULL DEFAULT ''");
  }
}

function json(value: unknown): string { return JSON.stringify(value); }
