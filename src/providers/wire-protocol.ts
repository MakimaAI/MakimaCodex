import type { OcxProviderConfig } from "../types";

/** Models whose upstream requires Anthropic wire format despite their provider's configured adapter. */
const ANTHROPIC_WIRE_MODELS: Readonly<Record<string, ReadonlySet<string>>> = {
  "opencode-go": new Set(["minimax-m2.5", "minimax-m2.7", "minimax-m3"]),
};

/** Resolve the effective adapter name used on the wire for one provider/model pair. */
export function resolveWireAdapterName(providerName: string, modelId: string, configuredAdapter: string): string {
  return ANTHROPIC_WIRE_MODELS[providerName]?.has(modelId) ? "anthropic" : configuredAdapter;
}

/** Single catalog/runtime eligibility rule for raw-reasoning promotion. */
export function rawReasoningPromotionEnabled(
  providerName: string,
  modelId: string,
  provider: Pick<OcxProviderConfig, "adapter" | "showRawReasoning">,
): boolean {
  return provider.showRawReasoning === true
    && resolveWireAdapterName(providerName, modelId, provider.adapter) === "openai-chat";
}
