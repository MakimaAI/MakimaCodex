import { join } from "node:path";
import { createPhase1Runtime, type Phase1Runtime } from "../../phase1/application/runtime";
import type { AuthenticatedPrincipal } from "../../phase1/application/security/principal";
import { Phase2CommandBus, type Phase2Principal } from "./command-bus";
import { createPhase2IdGenerator, type Phase2IdGenerator } from "../core/ids";
import { SqlitePhase2Store } from "../persistence/sqlite-store";

export interface Phase2Runtime {
  home: string;
  phase1: Phase1Runtime;
  ids: Phase2IdGenerator;
  store: SqlitePhase2Store;
  bus: Phase2CommandBus;
  close(): void;
}

export function createPhase2Runtime(options: {
  home?: string;
  ids?: Phase2IdGenerator;
  clock?: () => string;
  phase1Principals?: readonly AuthenticatedPrincipal[];
  principals?: readonly Phase2Principal[];
} = {}): Phase2Runtime {
  const phase1 = createPhase1Runtime({ home: options.home, clock: options.clock, principals: options.phase1Principals });
  try {
    const ids = options.ids ?? createPhase2IdGenerator();
    const store = new SqlitePhase2Store({ databasePath: join(phase1.home, "oef.sqlite") });
    const principals = options.principals ?? [
      {
        actor: { type: "human", id: "human:local-owner" },
        roles: ["assignment_admin", "execution_operator", "runner_host"],
      },
      {
        actor: { type: "system", id: "system:local-runner" },
        roles: ["runner_host"],
      },
    ];
    const bus = new Phase2CommandBus({ store, phase1: phase1.store, ids, principals, clock: options.clock });
    return {
      home: phase1.home,
      phase1,
      ids,
      store,
      bus,
      close() {
        store.close();
        phase1.close();
      },
    };
  } catch (error) {
    phase1.close();
    throw error;
  }
}
