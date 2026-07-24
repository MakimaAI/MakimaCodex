import { describe, expect, test } from "bun:test";
import {
  rawReasoningPatchForAdapter,
  supportsRawReasoningSetting,
} from "../gui/src/provider-workspace/raw-reasoning";
import { de } from "../gui/src/i18n/de";
import { en } from "../gui/src/i18n/en";
import { ko } from "../gui/src/i18n/ko";
import { zh } from "../gui/src/i18n/zh";

describe("provider raw reasoning setting UI", () => {
  test("all locales include the raw reasoning label and safety warning", () => {
    for (const locale of [en, de, ko, zh]) {
      expect(locale["pws.showRawReasoning"]).toBeTruthy();
      expect(locale["pws.showRawReasoningWarning"]).toBeTruthy();
    }
  });

  test("ProviderSettings eligibility and PATCH payload are openai-chat only", () => {
    expect(supportsRawReasoningSetting("openai-chat")).toBe(true);
    for (const adapter of ["openai-responses", "anthropic", "google", "cursor"]) {
      expect(supportsRawReasoningSetting(adapter)).toBe(false);
      expect(rawReasoningPatchForAdapter(adapter, true)).toEqual({});
    }
    expect(rawReasoningPatchForAdapter("openai-chat", true)).toEqual({ showRawReasoning: true });
    expect(rawReasoningPatchForAdapter("openai-chat", false)).toEqual({ showRawReasoning: false });
  });
});
