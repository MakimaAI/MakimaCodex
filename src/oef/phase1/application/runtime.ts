import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { LocalArtifactStore } from "../artifacts/local/local-artifact-store";
import { createSortableIdGenerator, type IdGenerator } from "../core/shared/ids";
import { SqliteOefStore } from "../persistence/sqlite-store";
import { OefCommandBus } from "./commands/command-bus";
import type { AuthenticatedPrincipal } from "./security/principal";

const workflowUrls = [
  new URL("../../../../workflows/software-development@1.0.0.json", import.meta.url),
  new URL("../../../../workflows/software-development@1.1.0.json", import.meta.url),
];
const policyUrl = new URL("../../../../policies/safe-default@1.0.0.json", import.meta.url);

const comparable = (value: string): string => process.platform === "win32" ? value.toLowerCase() : value;

export interface Phase1Runtime {
  home: string;
  ids: IdGenerator;
  store: SqliteOefStore;
  artifacts: LocalArtifactStore;
  bus: OefCommandBus;
  close(): void;
}

export function resolvePhase1Home(explicit?: string): string {
  const requested = resolve(explicit ?? process.env.OPENCODEX_OEF_HOME ?? join(process.cwd(), ".opencodex"));
  if (existsSync(requested) && lstatSync(requested).isSymbolicLink()) {
    throw new Error("OEF home cannot be a symlink");
  }
  mkdirSync(requested, { recursive: true });
  const actual = realpathSync(requested);
  if (comparable(actual) !== comparable(requested)) throw new Error("OEF home resolves through a symlink");
  return actual;
}

export function createPhase1Runtime(options: {
  home?: string;
  ids?: IdGenerator;
  clock?: () => string;
  principals?: readonly AuthenticatedPrincipal[];
} = {}): Phase1Runtime {
  const home = resolvePhase1Home(options.home);
  const ids = options.ids ?? createSortableIdGenerator();
  const store = new SqliteOefStore({ databasePath: join(home, "oef.sqlite") });
  try {
    const artifacts = new LocalArtifactStore({ root: join(home, "artifacts"), ids });
    for (const workflowUrl of workflowUrls) {
      store.installWorkflow(JSON.parse(readFileSync(workflowUrl, "utf8")));
    }
    store.installPolicy(JSON.parse(readFileSync(policyUrl, "utf8")));
    const principals = options.principals ?? [
      {
        actor: { type: "human", id: "human:local-owner" },
        roles: ["human_owner", "task_operator", "verifier"],
      },
      {
        actor: { type: "system", id: "system:local-cli" },
        roles: ["task_operator", "verifier"],
      },
    ];
    const bus = new OefCommandBus({ store, artifactStore: artifacts, ids, clock: options.clock, principals });
    return {
      home,
      ids,
      store,
      artifacts,
      bus,
      close: () => store.close(),
    };
  } catch (error) {
    store.close();
    throw error;
  }
}
