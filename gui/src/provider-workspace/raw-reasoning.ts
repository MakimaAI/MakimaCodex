export function supportsRawReasoningSetting(adapter: string): boolean {
  return adapter === "openai-chat";
}

export function rawReasoningPatchForAdapter(
  adapter: string,
  showRawReasoning: boolean,
): { showRawReasoning?: boolean } {
  return supportsRawReasoningSetting(adapter) ? { showRawReasoning } : {};
}
