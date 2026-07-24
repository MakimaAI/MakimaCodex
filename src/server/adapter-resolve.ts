import { createAnthropicAdapter } from "../adapters/anthropic";
import { createAzureAdapter } from "../adapters/azure";
import { createCursorAdapter } from "../adapters/cursor";
import { createGoogleAdapter } from "../adapters/google";
import { createKiroAdapter } from "../adapters/kiro";
import { createMimoFreeAdapter } from "../adapters/mimo-free";
import { createOpenAIChatAdapter } from "../adapters/openai-chat";
import { createResponsesPassthroughAdapter } from "../adapters/openai-responses";
import { resolveWireAdapterName } from "../providers/wire-protocol";
import type { OcxProviderConfig } from "../types";

/** Return a provider config whose adapter is forced to "anthropic" when the model id is wire-pinned. */
export function resolveWireProtocolOverride(providerName: string, modelId: string, providerConfig: OcxProviderConfig): OcxProviderConfig {
  const adapter = resolveWireAdapterName(providerName, modelId, providerConfig.adapter);
  return adapter === providerConfig.adapter ? providerConfig : { ...providerConfig, adapter };
}

/** Build the provider adapter for a resolved provider config. */
export function resolveAdapter(providerConfig: OcxProviderConfig, cacheRetention?: "none" | "short" | "long") {
  switch (providerConfig.adapter) {
    case "openai-chat":
      return createOpenAIChatAdapter(providerConfig);
    case "anthropic":
      return createAnthropicAdapter(providerConfig, cacheRetention);
    case "openai-responses":
      return createResponsesPassthroughAdapter(providerConfig);
    case "google":
      return createGoogleAdapter(providerConfig);
    case "kiro":
      return createKiroAdapter(providerConfig);
    case "azure":
    case "azure-openai":
      return createAzureAdapter(providerConfig);
    case "cursor":
      return createCursorAdapter(providerConfig);
    case "mimo-free":
      return createMimoFreeAdapter(providerConfig);
    default:
      throw new Error(`Unknown adapter: ${providerConfig.adapter}`);
  }
}
