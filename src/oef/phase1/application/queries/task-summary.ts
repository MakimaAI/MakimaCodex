import type { ArtifactStore } from "../../artifacts/interfaces/artifact-store";
import type { OefCommandStore } from "../ports/oef-store";
import { validCurrentVerdictIds } from "./verdict-validity";

export function readTaskSummary(input: {
  taskId: string;
  store: OefCommandStore;
  artifactStore: ArtifactStore;
}): Record<string, unknown> | null {
  const task = input.store.getTask(input.taskId);
  if (!task) return null;
  const validVerdicts = validCurrentVerdictIds({
    task,
    store: input.store,
    artifactStore: input.artifactStore,
  });
  return input.store.refreshTaskSummary(input.taskId, validVerdicts);
}
