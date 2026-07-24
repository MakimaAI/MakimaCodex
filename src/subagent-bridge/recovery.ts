import { slugsEquivalent } from "../providers/slug-codec";
import { subagentHandoffStore, type CodexAgentMessageType, type SubagentHandoffStore } from "./handoff-store";

const MESSAGE_TYPE_LINE = /^Message Type:\s*(NEW_TASK|MESSAGE)\s*$/m;

type InvalidRecoveryReason = "malformed_envelope" | "unsupported_envelope_version" | "multiple_envelopes";
type RecoveryResult =
  | { status: "unchanged" }
  | { status: "invalid"; reason: InvalidRecoveryReason }
  | { status: "missing" }
  | { status: "recovered"; count: number };

type AgentMessageMetadata =
  | { status: "unchanged" }
  | { status: "invalid"; reason: InvalidRecoveryReason }
  | {
      status: "candidate";
      target: string;
      messageType: CodexAgentMessageType;
      content: unknown[];
      encryptedPartIndex: number;
    };

function selectedRoutedModel(model: unknown, selectedModels: readonly string[]): model is string {
  return typeof model === "string"
    && model.includes("/")
    && selectedModels.some(selected => slugsEquivalent(selected, model));
}

function classifyFernetEnvelope(value: unknown): "current" | "malformed" | "unsupported_version" {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+={0,2}$/.test(value)) return "malformed";
  const unpadded = value.replace(/=+$/, "");
  if (unpadded.length % 4 === 1) return "malformed";
  try {
    const decoded = Buffer.from(unpadded, "base64url");
    if (decoded.toString("base64url") !== unpadded
      || decoded.byteLength < 73
      || (decoded.byteLength - 57) % 16 !== 0) return "malformed";
    return decoded[0] === 0x80 ? "current" : "unsupported_version";
  } catch {
    return "malformed";
  }
}

function agentMessageMetadata(item: unknown): AgentMessageMetadata {
  if (!item || typeof item !== "object" || (item as { type?: unknown }).type !== "agent_message") {
    return { status: "unchanged" };
  }
  const candidate = item as { recipient?: unknown; content?: unknown };
  if (!Array.isArray(candidate.content)) return { status: "unchanged" };
  const preamble = candidate.content
    .flatMap(part => part && typeof part === "object" && (part as { type?: unknown }).type === "input_text" && typeof (part as { text?: unknown }).text === "string"
      ? [(part as { text: string }).text]
      : [])
    .join("\n");
  const match = MESSAGE_TYPE_LINE.exec(preamble);
  if (!match) return { status: "unchanged" };
  const encryptedParts = candidate.content.flatMap((part, index) => (
    part && typeof part === "object"
    && (part as { type?: unknown }).type === "encrypted_content"
      ? [{ index, value: (part as { encrypted_content?: unknown }).encrypted_content }]
      : []
  ));
  if (encryptedParts.length === 0) return { status: "unchanged" };
  if (encryptedParts.length !== 1) return { status: "invalid", reason: "multiple_envelopes" };
  const envelope = classifyFernetEnvelope(encryptedParts[0]!.value);
  if (envelope === "malformed" || typeof candidate.recipient !== "string") {
    return { status: "invalid", reason: "malformed_envelope" };
  }
  if (envelope === "unsupported_version") {
    return { status: "invalid", reason: "unsupported_envelope_version" };
  }
  return {
    status: "candidate",
    target: candidate.recipient,
    messageType: match[1] as CodexAgentMessageType,
    content: candidate.content,
    encryptedPartIndex: encryptedParts[0]!.index,
  };
}

function selectedRoutedAgentMessageMetadata(
  body: unknown,
  options: { enabled: boolean; selectedModels: readonly string[] },
): AgentMessageMetadata {
  if (!options.enabled || !body || typeof body !== "object") return { status: "unchanged" };
  const raw = body as { model?: unknown; input?: unknown };
  if (!selectedRoutedModel(raw.model, options.selectedModels) || !Array.isArray(raw.input)) {
    return { status: "unchanged" };
  }
  return agentMessageMetadata(raw.input[raw.input.length - 1]);
}

/** True only when recovery could mutate this request and therefore needs a ciphertext copy. */
export function hasSelectedRoutedSubagentHandoffCandidate(
  body: unknown,
  options: { enabled: boolean; selectedModels: readonly string[] },
): boolean {
  return selectedRoutedAgentMessageMetadata(body, options).status === "candidate";
}

export function recoverSelectedRoutedSubagentRequest(
  body: unknown,
  options: { enabled: boolean; selectedModels: readonly string[]; store?: SubagentHandoffStore },
): RecoveryResult {
  const candidate = selectedRoutedAgentMessageMetadata(body, options);
  if (candidate.status !== "candidate") return candidate;

  const raw = body as { model: string };
  const store = options.store ?? subagentHandoffStore;
  const handoff = store.consume(candidate.target, candidate.messageType, raw.model);
  if (!handoff) return { status: "missing" };
  candidate.content[candidate.encryptedPartIndex] = { type: "input_text", text: handoff.message };
  return { status: "recovered", count: 1 };
}
