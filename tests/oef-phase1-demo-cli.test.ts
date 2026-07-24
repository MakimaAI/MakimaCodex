import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runPhase1Demo } from "../src/oef/phase1";
import { cmdOefDomain } from "../src/cli/oef";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* child process fixture may still flush WAL */ }
  }
});

const newRoot = (): string => {
  const root = mkdtempSync(join(tmpdir(), "oef-phase1-demo-"));
  roots.push(root);
  return root;
};

describe("Phase 1 end-to-end demo", () => {
  test("proves denial, repair, acceptance, restart persistence, timeline, and integrity", () => {
    const report = runPhase1Demo({ home: newRoot() });
    expect(report).toMatchObject({
      schema_version: 1,
      policy_denied_before_missing_evidence: true,
      accepted_after_required_evidence: true,
      reached_terminal_done: true,
      restart_state_preserved: true,
      restart_timeline_preserved: true,
      integrity: {
        valid: true,
        events: { hash_chain_valid: true },
        artifacts: { integrity_valid: true },
        active_contract: { hash_valid: true },
      },
    });
    expect(report.timeline.length).toBeGreaterThanOrEqual(12);
    expect(report.summary).toMatchObject({ latest_verdict: "ACCEPT" });
    const verdictEvents = report.timeline.filter(item => item.event_type === "verdict.issued");
    expect(verdictEvents.at(-1)?.payload).toMatchObject({
      secondary_state_changes: { superseded_verdict_ids: [expect.stringMatching(/^verdict:/)] },
    });
  });
});

describe("Phase 1 minimal CLI", () => {
  test("executes the CLI dispatcher directly for coverage and JSON output", async () => {
    const home = newRoot();
    const previousHome = process.env.OPENCODEX_OEF_HOME;
    const previousLog = console.log;
    const output: string[] = [];
    process.env.OPENCODEX_OEF_HOME = home;
    console.log = (...values: unknown[]) => output.push(values.map(String).join(" "));
    try {
      expect(await cmdOefDomain("oef-demo", ["--json"])).toBe(0);
      expect(JSON.parse(output.at(-1)!)).toMatchObject({ reached_terminal_done: true });
    } finally {
      console.log = previousLog;
      if (previousHome === undefined) delete process.env.OPENCODEX_OEF_HOME;
      else process.env.OPENCODEX_OEF_HOME = previousHome;
    }
  });

  test("creates and reads a persistent task in separate processes with JSON output", () => {
    const home = newRoot();
    const cwd = join(import.meta.dir, "..");
    const env = { ...process.env, OPENCODEX_OEF_HOME: home };
    const run = (...args: string[]) => Bun.spawnSync({
      cmd: [process.execPath, "src/cli/index.ts", ...args],
      cwd,
      env,
      stdout: "pipe",
      stderr: "pipe",
    });

    const created = run(
      "task", "create",
      "--title", "CLI persistent task",
      "--workflow", "software-development@1.0.0",
      "--policy", "safe-default@1.0.0",
      "--json",
    );
    expect(created.exitCode, created.stderr.toString()).toBe(0);
    const createdJson = JSON.parse(created.stdout.toString()) as { task_id: string; aggregate_version: number };
    expect(createdJson.task_id).toMatch(/^task:/);
    expect(createdJson.aggregate_version).toBe(1);

    const shown = run("task", "show", createdJson.task_id, "--json");
    expect(shown.exitCode, shown.stderr.toString()).toBe(0);
    expect(JSON.parse(shown.stdout.toString())).toMatchObject({
      task_id: createdJson.task_id,
      title: "CLI persistent task",
      status: "OPEN",
      stage: "intake",
      workflow_ref: { id: "software-development", version: "1.0.0" },
      policy_pack_ref: { id: "safe-default", version: "1.0.0" },
    });

    const timeline = run("task", "timeline", createdJson.task_id, "--json");
    expect(timeline.exitCode, timeline.stderr.toString()).toBe(0);
    expect(JSON.parse(timeline.stdout.toString())).toEqual([
      expect.objectContaining({ event_type: "task.created", aggregate_version: 1 }),
    ]);

    const integrity = run("integrity", "verify", createdJson.task_id, "--json");
    expect(integrity.exitCode, integrity.stderr.toString()).toBe(0);
    expect(JSON.parse(integrity.stdout.toString())).toMatchObject({ valid: true });
  });

  test("drives contract, transition, evidence, verdict, and integrity commands end to end", () => {
    const home = newRoot();
    const cwd = join(import.meta.dir, "..");
    const env = { ...process.env, OPENCODEX_OEF_HOME: home };
    const run = (...args: string[]) => Bun.spawnSync({
      cmd: [process.execPath, "src/cli/index.ts", ...args, "--json"],
      cwd,
      env,
      stdout: "pipe",
      stderr: "pipe",
    });
    const json = (result: ReturnType<typeof run>) => {
      expect(result.exitCode, result.stderr.toString()).toBe(0);
      return JSON.parse(result.stdout.toString()) as Record<string, any>;
    };

    const task = json(run(
      "task", "create",
      "--title", "Full CLI task",
      "--workflow", "software-development@1.0.0",
      "--policy", "safe-default@1.0.0",
    ));
    const contractPath = join(home, "contract.json");
    writeFileSync(contractPath, JSON.stringify({
      schema_version: 1,
      task_id: task.task_id,
      revision: 1,
      title: "Full CLI contract",
      goal: { summary: "Exercise every Phase 1 CLI write path." },
      scope: { included: ["CLI"], excluded: ["Model execution"] },
      constraints: ["No secrets."],
      acceptance_criteria: [{
        key: "tests",
        statement: "CLI test evidence passes.",
        required_evidence: ["opencodex.test-result"],
      }],
      risk: { level: "low", reasons: [] },
      budgets: { max_attempts: 1, max_parallel_writers: 1, max_cost_units: 1 },
      extensions: {},
    }), "utf8");
    const createdContract = json(run("contract", "create", "--task", task.task_id, "--file", contractPath));
    expect(createdContract.status).toBe("DRAFT");
    expect(json(run("contract", "propose", "--task", task.task_id, "--revision", "1")).status).toBe("PROPOSED");
    expect(json(run(
      "contract", "approve",
      "--task", task.task_id,
      "--revision", "1",
      "--rationale", "Approved by CLI test.",
    )).status).toBe("APPROVED");

    expect(json(run("task", "transition", task.task_id, "--to", "specification")).stage).toBe("specification");
    expect(json(run("task", "transition", task.task_id, "--to", "planning")).stage).toBe("planning");

    const evidencePath = join(home, "test-result.json");
    writeFileSync(evidencePath, JSON.stringify({ passed: true }), "utf8");
    const evidence = json(run(
      "evidence", "add",
      "--task", task.task_id,
      "--criterion", "tests",
      "--type", "opencodex.test-result",
      "--file", evidencePath,
      "--commit", "cli-test-commit",
    ));
    expect(evidence.status).toBe("RECORDED");
    expect(json(run(
      "evidence", "verify",
      "--task", task.task_id,
      "--evidence", evidence.evidence_id,
    )).status).toBe("VERIFIED");
    expect(json(run(
      "verdict", "issue",
      "--task", task.task_id,
      "--decision", "ACCEPT",
      "--rationale", "Required evidence is verified.",
      "--commit", "cli-test-commit",
    ))).toMatchObject({ decision: "ACCEPT", status: "CURRENT" });
    expect(json(run("integrity", "verify", task.task_id))).toMatchObject({ valid: true });
  });

  test("exposes explicit workflow migration, block/unblock, and contract rejection", () => {
    const home = newRoot();
    const cwd = join(import.meta.dir, "..");
    const env = { ...process.env, OPENCODEX_OEF_HOME: home };
    const run = (...args: string[]) => Bun.spawnSync({
      cmd: [process.execPath, "src/cli/index.ts", ...args, "--json"],
      cwd,
      env,
      stdout: "pipe",
      stderr: "pipe",
    });
    const json = (result: ReturnType<typeof run>) => {
      expect(result.exitCode, result.stderr.toString()).toBe(0);
      return JSON.parse(result.stdout.toString()) as Record<string, any>;
    };
    const task = json(run(
      "task", "create",
      "--title", "Migration CLI task",
      "--workflow", "software-development@1.0.0",
      "--policy", "safe-default@1.0.0",
    ));
    const mapPath = join(home, "stage-map.json");
    writeFileSync(mapPath, JSON.stringify({
      intake: "intake",
      specification: "specification",
      planning: "design",
      execution: "execution",
      verification: "verification",
      review: "review",
      merge: "merge",
      done: "done",
    }), "utf8");
    const migrated = json(run(
      "task", "migrate-workflow", task.task_id,
      "--from", "software-development@1.0.0",
      "--to", "software-development@1.1.0",
      "--stage-map", mapPath,
      "--rationale", "Adopt explicit design stage.",
    ));
    expect(migrated.workflow_ref.version).toBe("1.1.0");
    expect(json(run("task", "block", task.task_id, "--reason", "Waiting.")).status).toBe("BLOCKED");
    expect(json(run("task", "unblock", task.task_id, "--reason", "Ready.")).status).toBe("OPEN");

    const contractPath = join(home, "rejected.json");
    writeFileSync(contractPath, JSON.stringify({
      schema_version: 1,
      task_id: task.task_id,
      revision: 1,
      title: "Rejected",
      goal: { summary: "Exercise CLI rejection." },
      scope: { included: ["Reject"], excluded: [] },
      constraints: [],
      acceptance_criteria: [{ key: "reject", statement: "Reject.", required_evidence: [] }],
      risk: { level: "low", reasons: [] },
      budgets: { max_attempts: 1, max_parallel_writers: 1, max_cost_units: 1 },
      extensions: {},
    }), "utf8");
    json(run("contract", "create", "--task", task.task_id, "--file", contractPath));
    json(run("contract", "propose", "--task", task.task_id, "--revision", "1"));
    expect(json(run(
      "contract", "reject",
      "--task", task.task_id,
      "--revision", "1",
      "--rationale", "Scope needs work.",
    )).status).toBe("REJECTED");
  });
});
