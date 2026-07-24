import type { TKey } from "../i18n/shared";

export interface SubagentModelRow {
  id: string;
  classification: "native" | "routed";
  selected: boolean;
  v2Eligible: boolean;
  bridgeRequired: boolean;
  bridgeReady: boolean;
  ready: boolean;
  reasoningEfforts: string[];
  warnings: string[];
}

export interface SubagentBridgeState {
  installed: boolean;
  registered: boolean;
  enabled: boolean;
  tokenPresent: boolean;
  tokenSecure: boolean | null;
  marketplaceReady: boolean;
  mcpReady: boolean;
  installedReady: boolean;
  ready: boolean;
  liveReady: boolean;
  restartRequired: boolean;
  warnings: string[];
}

interface SubagentModelsState {
  available: string[];
  chosen: string[];
  models: SubagentModelRow[];
  bridge: SubagentBridgeState | null;
  warnings: string[];
}

export const EMPTY_BRIDGE: SubagentBridgeState = {
  installed: false,
  registered: false,
  enabled: false,
  tokenPresent: false,
  tokenSecure: null,
  marketplaceReady: false,
  mcpReady: false,
  installedReady: false,
  ready: false,
  liveReady: false,
  restartRequired: false,
  warnings: [],
};

export function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

export function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

export function normalizeBridge(value: unknown): SubagentBridgeState {
  if (!isRecord(value)) return EMPTY_BRIDGE;
  return {
    installed: value.installed === true,
    registered: value.registered === true,
    enabled: value.enabled === true,
    tokenPresent: value.tokenPresent === true,
    tokenSecure: typeof value.tokenSecure === "boolean" ? value.tokenSecure : null,
    marketplaceReady: value.marketplaceReady === true,
    mcpReady: value.mcpReady === true,
    installedReady: value.installedReady === true,
    ready: value.ready === true,
    liveReady: value.liveReady === true,
    restartRequired: value.restartRequired === true,
    warnings: stringList(value.warnings),
  };
}

export function normalizeSubagentModelsResponse(value: unknown): SubagentModelsState {
  const response = isRecord(value) ? value : {};
  const available = stringList(response.available);
  const availableSet = new Set(available);
  const chosen = stringList(response.chosen).filter(model => availableSet.has(model));
  const models = Array.isArray(response.models)
    ? response.models.filter((row): row is SubagentModelRow => isRecord(row) && typeof row.id === "string")
    : [];
  return {
    available,
    chosen,
    models,
    bridge: isRecord(response.bridge) ? normalizeBridge(response.bridge) : null,
    warnings: stringList(response.warnings),
  };
}

export function mergeSubagentModelRows<T extends { id: string }>(previous: readonly T[], updates: readonly T[]): T[] {
  const byId = new Map(updates.map(row => [row.id, row]));
  return previous.map(row => byId.get(row.id) ?? row);
}

export function modelCompatibilityKey(row: Pick<SubagentModelRow, "classification" | "v2Eligible" | "bridgeReady">): TKey {
  if (!row.v2Eligible) return "sub.modelV1Required";
  if (row.classification === "routed" && !row.bridgeReady) return "sub.modelBridgeRequired";
  return "sub.modelV2Ready";
}

export function bridgeHealthItems(bridge: SubagentBridgeState): Array<{ labelKey: TKey; valueKey: TKey; ready: boolean }> {
  const secure = bridge.tokenPresent && bridge.tokenSecure === true;
  return [
    { labelKey: "sub.bridgeInstalled", valueKey: bridge.installed ? "sub.bridgeInstalledYes" : "sub.bridgeMissing", ready: bridge.installed },
    { labelKey: "sub.bridgeRegistered", valueKey: bridge.registered ? "sub.bridgeRegisteredYes" : "sub.bridgeRegisteredNo", ready: bridge.registered },
    { labelKey: "sub.bridgeEnabled", valueKey: bridge.enabled ? "sub.bridgeEnabledYes" : "sub.bridgeDisabled", ready: bridge.enabled },
    {
      labelKey: "sub.bridgeSecurity",
      valueKey: !bridge.tokenPresent
        ? "sub.bridgeMissing"
        : bridge.tokenSecure === true
          ? "sub.bridgeSecuritySecure"
          : bridge.tokenSecure === false
            ? "sub.bridgeSecurityInsecure"
            : "sub.bridgeSecurityUnknown",
      ready: secure,
    },
  ];
}

const WARNING_KEYS: Array<[string, TKey]> = [
  ["Bridge plugin is not installed.", "sub.bridgeWarningNotInstalled"],
  ["Bridge MCP launcher is missing or invalid.", "sub.bridgeWarningMcpInvalid"],
  ["Bridge marketplace entry is missing.", "sub.bridgeWarningMarketplace"],
  ["Bridge marketplace is invalid or foreign-owned.", "sub.bridgeWarningMarketplace"],
  ["Bridge Codex registration is missing or invalid.", "sub.bridgeWarningRegistration"],
  ["Bridge authentication token is missing or invalid.", "sub.bridgeWarningTokenMissing"],
  ["Bridge authentication token permissions are insecure.", "sub.bridgeWarningTokenInsecure"],
  ["Bridge authentication token security is unknown.", "sub.bridgeWarningTokenUnknown"],
  ["Bridge is disabled in opencodex config.", "sub.bridgeWarningDisabled"],
  ["Subagent bridge is disabled.", "sub.bridgeWarningDisabled"],
  ["Routed model is not selected for the V2 subagent roster.", "sub.bridgeWarningModelNotSelected"],
  ["Subagent bridge is not ready.", "sub.bridgeWarningNotReady"],
  ["Model is not V2-eligible in the active Codex catalog.", "sub.bridgeWarningV1Required"],
];

export function safeBridgeWarningKeys(warnings: readonly string[]): TKey[] {
  return [...new Set(warnings.map(warning => WARNING_KEYS.find(([message]) => message === warning)?.[1] ?? "sub.bridgeWarningUnknown"))];
}
