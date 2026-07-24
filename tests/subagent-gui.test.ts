import { describe, expect, test } from "bun:test";
import { createElement, Fragment, type ReactElement } from "../gui/node_modules/react";
import { renderToStaticMarkup } from "../gui/node_modules/react-dom/server";
import * as subagentView from "../gui/src/pages/subagent-view";
import { de } from "../gui/src/i18n/de";
import { en } from "../gui/src/i18n/en";
import { ko } from "../gui/src/i18n/ko";
import { I18nContext, interpolate, type TFn } from "../gui/src/i18n/shared";
import { zh } from "../gui/src/i18n/zh";

const view = subagentView as Record<string, any>;

function renderEnglish(element: ReactElement): string {
  const t: TFn = (key, vars) => interpolate(en[key], vars);
  return renderToStaticMarkup(createElement(I18nContext.Provider, {
    value: { locale: "en", setLocale: () => {}, t },
  }, element));
}

async function loadPresentation(): Promise<Record<string, any>> {
  const modulePath = "../gui/src/pages/SubagentBridgePresentation";
  return import(modulePath).catch(() => ({}));
}

describe("Subagents bridge view state", () => {
  test("model compatibility is independent of selection and follows the catalog/bridge gates", () => {
    expect(typeof view.modelCompatibilityKey).toBe("function");
    expect(view.modelCompatibilityKey({ classification: "routed", selected: true, v2Eligible: false, bridgeReady: false })).toBe("sub.modelV1Required");
    expect(view.modelCompatibilityKey({ classification: "routed", selected: false, v2Eligible: true, bridgeReady: false })).toBe("sub.modelBridgeRequired");
    expect(view.modelCompatibilityKey({ classification: "routed", selected: false, v2Eligible: true, bridgeReady: true })).toBe("sub.modelV2Ready");
    expect(view.modelCompatibilityKey({ classification: "native", selected: false, v2Eligible: true, bridgeReady: true })).toBe("sub.modelV2Ready");
  });

  test("bridge health exposes installation, registration, enabled, and security states", () => {
    expect(typeof view.bridgeHealthItems).toBe("function");
    expect(view.bridgeHealthItems({
      installed: false,
      registered: true,
      enabled: false,
      tokenPresent: true,
      tokenSecure: null,
      marketplaceReady: true,
      mcpReady: true,
      ready: false,
      warnings: [],
    })).toEqual([
      { labelKey: "sub.bridgeInstalled", valueKey: "sub.bridgeMissing", ready: false },
      { labelKey: "sub.bridgeRegistered", valueKey: "sub.bridgeRegisteredYes", ready: true },
      { labelKey: "sub.bridgeEnabled", valueKey: "sub.bridgeDisabled", ready: false },
      { labelKey: "sub.bridgeSecurity", valueKey: "sub.bridgeSecurityUnknown", ready: false },
    ]);
  });

  test("API warnings are mapped to localized safe copy and never rendered verbatim", () => {
    expect(typeof view.safeBridgeWarningKeys).toBe("function");
    const warning = "Bridge plugin target C:\\Users\\secret is invalid.";
    const keys = view.safeBridgeWarningKeys([
      "Bridge plugin is not installed.",
      "Bridge authentication token permissions are insecure.",
      warning,
    ]);
    expect(keys).toEqual([
      "sub.bridgeWarningNotInstalled",
      "sub.bridgeWarningTokenInsecure",
      "sub.bridgeWarningUnknown",
    ]);
    expect(JSON.stringify(keys)).not.toContain("C:\\Users\\secret");
  });

  test("response normalization preserves chosen/available behavior while retaining V2 metadata", () => {
    expect(typeof view.normalizeSubagentModelsResponse).toBe("function");
    const result = view.normalizeSubagentModelsResponse({
      available: ["gpt-native", "vendor/model"],
      chosen: ["vendor/model", "removed/model"],
      models: [{
        id: "vendor/model",
        classification: "routed",
        selected: true,
        v2Eligible: true,
        bridgeRequired: true,
        bridgeReady: false,
        ready: false,
        reasoningEfforts: ["high"],
        warnings: [],
      }],
      bridge: {
        installed: true,
        registered: false,
        enabled: true,
        tokenPresent: true,
        tokenSecure: true,
        marketplaceReady: true,
        mcpReady: true,
        ready: false,
        liveReady: false,
        restartRequired: true,
        warnings: [],
      },
      warnings: ["Bridge Codex registration is missing or invalid."],
    });
    expect(result.available).toEqual(["gpt-native", "vendor/model"]);
    expect(result.chosen).toEqual(["vendor/model"]);
    expect(result.models[0]).toMatchObject({ id: "vendor/model", v2Eligible: true, bridgeReady: false });
    expect(result.bridge).toMatchObject({
      installed: true,
      registered: false,
      ready: false,
      liveReady: false,
      restartRequired: true,
    });
    expect(result.warnings).toEqual(["Bridge Codex registration is missing or invalid."]);
  });

  test("legacy chosen/available responses preserve the picker and mark bridge metadata unavailable", () => {
    const result = view.normalizeSubagentModelsResponse({
      available: ["gpt-native", "vendor/model"],
      chosen: ["vendor/model", "removed/model"],
    });
    expect(result.available).toEqual(["gpt-native", "vendor/model"]);
    expect(result.chosen).toEqual(["vendor/model"]);
    expect(result.models).toEqual([]);
    expect(result.bridge).toBeNull();
    expect(result.warnings).toEqual([]);
  });

  test("save metadata merges only returned rows without dropping the available roster", () => {
    expect(typeof view.mergeSubagentModelRows).toBe("function");
    const previous = [
      { id: "vendor/a", selected: true, ready: false },
      { id: "vendor/b", selected: false, ready: true },
    ];
    const updated = [{ id: "vendor/a", selected: true, ready: true }];
    expect(view.mergeSubagentModelRows(previous, updated)).toEqual([
      { id: "vendor/a", selected: true, ready: true },
      { id: "vendor/b", selected: false, ready: true },
    ]);
  });
});

describe("Subagents bridge localization and safe guidance", () => {
  const requiredKeys = [
    "sub.bridgeTitle",
    "sub.bridgeHealthy",
    "sub.bridgeNeedsAttention",
    "sub.bridgeInstalled",
    "sub.bridgeRegistered",
    "sub.bridgeEnabled",
    "sub.bridgeSecurity",
    "sub.bridgeInstalledYes",
    "sub.bridgeMissing",
    "sub.bridgeRegisteredYes",
    "sub.bridgeRegisteredNo",
    "sub.bridgeEnabledYes",
    "sub.bridgeDisabled",
    "sub.bridgeSecuritySecure",
    "sub.bridgeSecurityInsecure",
    "sub.bridgeSecurityUnknown",
    "sub.bridgeInstallGuidance",
    "sub.bridgeRestartGuidance",
    "sub.bridgeWarnings",
    "sub.bridgeWarningNotInstalled",
    "sub.bridgeWarningMcpInvalid",
    "sub.bridgeWarningMarketplace",
    "sub.bridgeWarningRegistration",
    "sub.bridgeWarningTokenMissing",
    "sub.bridgeWarningTokenInsecure",
    "sub.bridgeWarningTokenUnknown",
    "sub.bridgeWarningDisabled",
    "sub.bridgeWarningModelNotSelected",
    "sub.bridgeWarningNotReady",
    "sub.bridgeWarningV1Required",
    "sub.bridgeWarningUnknown",
    "sub.modelV2Ready",
    "sub.modelV1Required",
    "sub.modelBridgeRequired",
  ] as const;

  test("all locale modules contain every bridge and compatibility key", () => {
    for (const locale of [en, de, ko, zh]) {
      for (const key of requiredKeys) expect(locale[key as keyof typeof locale]).toBeTruthy();
    }
  });

  test("rendered ready, not-ready, and legacy states show safe localized behavior without an install action", async () => {
    const presentation = await loadPresentation();
    expect(typeof presentation.SubagentBridgePresentation).toBe("function");
    expect(typeof presentation.SubagentCompatibilityBadge).toBe("function");

    const ready = view.normalizeSubagentModelsResponse({
      available: ["vendor/ready", "vendor/v1"],
      chosen: ["vendor/ready"],
      models: [
        { id: "vendor/ready", classification: "routed", selected: false, v2Eligible: true, bridgeRequired: true, bridgeReady: true, ready: false, reasoningEfforts: ["high"], warnings: [] },
        { id: "vendor/v1", classification: "routed", selected: true, v2Eligible: false, bridgeRequired: true, bridgeReady: false, ready: false, reasoningEfforts: [], warnings: [] },
      ],
      bridge: { installed: true, registered: true, enabled: true, tokenPresent: true, tokenSecure: true, marketplaceReady: true, mcpReady: true, ready: true, warnings: [] },
      warnings: [],
    });
    const readyMarkup = renderEnglish(createElement(Fragment, null,
      createElement(presentation.SubagentBridgePresentation, { bridge: ready.bridge, warnings: ready.warnings }),
      ...ready.models.map((row: unknown) => createElement(presentation.SubagentCompatibilityBadge, { key: (row as { id: string }).id, row })),
    ));
    expect(readyMarkup).toContain("V2 subagent bridge");
    expect(readyMarkup).toContain("Healthy");
    expect(readyMarkup).toContain("V2 ready");
    expect(readyMarkup).toContain("V1 required");
    expect(readyMarkup).not.toContain("ocx subagents bridge install");
    expect(readyMarkup).not.toContain("ocx restart");

    const rawWarning = "Bridge plugin target C:\\Users\\secret\\payload-message is invalid.";
    const notReady = view.normalizeSubagentModelsResponse({
      available: ["vendor/blocked"],
      chosen: ["vendor/blocked"],
      models: [{ id: "vendor/blocked", classification: "routed", selected: true, v2Eligible: true, bridgeRequired: true, bridgeReady: false, ready: false, reasoningEfforts: ["high"], warnings: [] }],
      bridge: { installed: false, registered: false, enabled: false, tokenPresent: false, tokenSecure: null, marketplaceReady: false, mcpReady: false, ready: false, warnings: [] },
      warnings: [rawWarning],
    });
    const notReadyMarkup = renderEnglish(createElement(Fragment, null,
      createElement(presentation.SubagentBridgePresentation, { bridge: notReady.bridge, warnings: notReady.warnings }),
      createElement(presentation.SubagentCompatibilityBadge, { row: notReady.models[0] }),
    ));
    expect(notReadyMarkup).toContain("Needs attention");
    expect(notReadyMarkup).toContain("Bridge required");
    expect(notReadyMarkup).toContain("The bridge reported an additional issue");
    expect(notReadyMarkup).not.toContain(rawWarning);
    expect(notReadyMarkup).toContain('<code class="chip">ocx subagents bridge install</code>');
    expect(notReadyMarkup).toContain('<code class="chip">ocx restart</code>');
    expect(notReadyMarkup).not.toMatch(/<(button|form)\b/);

    const restartOnly = view.normalizeSubagentModelsResponse({
      available: [],
      chosen: [],
      models: [],
      bridge: {
        installed: true,
        registered: true,
        enabled: false,
        tokenPresent: true,
        tokenSecure: true,
        marketplaceReady: true,
        mcpReady: true,
        installedReady: true,
        ready: false,
        liveReady: false,
        restartRequired: true,
        warnings: [],
      },
      warnings: [],
    });
    const restartOnlyMarkup = renderEnglish(createElement(
      presentation.SubagentBridgePresentation,
      { bridge: restartOnly.bridge, warnings: restartOnly.warnings },
    ));
    expect(restartOnlyMarkup).toContain('<code class="chip">ocx restart</code>');
    expect(restartOnlyMarkup).not.toContain("ocx subagents bridge install");

    const legacy = view.normalizeSubagentModelsResponse({ available: ["vendor/model"], chosen: ["vendor/model"] });
    const legacyMarkup = renderEnglish(createElement(presentation.SubagentBridgePresentation, { bridge: legacy.bridge, warnings: legacy.warnings }));
    expect(legacyMarkup).toBe("");
    expect(legacyMarkup).not.toContain("ocx subagents bridge install");
    expect(legacyMarkup).not.toContain("ocx restart");
  });
});
