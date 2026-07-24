import { backupConfigBeforeOpenAiTierMigration, saveConfig } from "../config";
import { isDeepStrictEqual } from "node:util";
import type { OcxConfig } from "../types";
import { projectOpenAiTierMigration } from "./openai-tiers";

export interface OpenAiTierStartupDeps {
  project: typeof projectOpenAiTierMigration;
  backup: () => void;
  save: (config: OcxConfig) => void;
}

const DEFAULT_DEPS: OpenAiTierStartupDeps = {
  project: projectOpenAiTierMigration,
  backup: backupConfigBeforeOpenAiTierMigration,
  save: saveConfig,
};

function changesOnlyVersionMarker(current: OcxConfig, projected: OcxConfig): boolean {
  if (current.openaiProviderTierVersion === projected.openaiProviderTierVersion) return false;
  const { openaiProviderTierVersion: _currentVersion, ...currentRest } = current;
  const { openaiProviderTierVersion: _projectedVersion, ...projectedRest } = projected;
  const persistentShape = (value: object): unknown => JSON.parse(JSON.stringify(value));
  return isDeepStrictEqual(persistentShape(currentRest), persistentShape(projectedRest));
}

export function runOpenAiTierStartupMigration(
  config: OcxConfig,
  deps: OpenAiTierStartupDeps = DEFAULT_DEPS,
): OcxConfig {
  const projection = deps.project(config);
  if (!projection.changed) return projection.config;
  if (!changesOnlyVersionMarker(config, projection.config)) deps.backup();
  deps.save(projection.config);
  for (const warning of projection.warnings) console.warn(`[openai-provider-migration] ${warning}`);
  return projection.config;
}
