import { formatClineWorkOsAccessToken } from "../oauth/cline";

export type ClineCatalogProvider = "cline" | "cline-pass";

interface ClineCatalogItem {
  id: string;
}

interface ClineCatalogPayload {
  recommended?: unknown;
  free?: unknown;
  clinePass?: unknown;
}

function modelIds(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map(item => {
      if (!item || typeof item !== "object") return undefined;
      const id = (item as Partial<ClineCatalogItem>).id;
      return typeof id === "string" && id.trim() ? id.trim() : undefined;
    })
    .filter((id): id is string => id !== undefined);
}

function localClinePassId(id: string): string {
  return id.startsWith("cline-pass/") ? id.slice("cline-pass/".length) : id;
}

export function normalizeClineCatalog(
  raw: unknown,
  provider: ClineCatalogProvider,
): string[] | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const payload = raw as ClineCatalogPayload;
  const primary = provider === "cline"
    ? modelIds(payload.recommended)
    : modelIds(payload.clinePass).map(localClinePassId);
  const free = modelIds(payload.free).map(id => provider === "cline-pass" ? localClinePassId(id) : id);
  const ids = [...new Set([...primary, ...free])];
  return ids.length > 0 ? ids : undefined;
}

export function toClineWireModelId(provider: string, modelId: string): string {
  if (provider !== "cline-pass" || modelId.includes("/")) return modelId;
  return `cline-pass/${modelId}`;
}

export async function fetchClineCatalog(
  provider: ClineCatalogProvider,
  accessToken?: string,
): Promise<string[] | undefined> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (accessToken) {
    const bearer = provider === "cline"
      ? formatClineWorkOsAccessToken(accessToken)
      : accessToken;
    headers.Authorization = `Bearer ${bearer}`;
  }
  const response = await fetch("https://api.cline.bot/api/v1/ai/cline/recommended-models", {
    headers,
    signal: AbortSignal.timeout(8000),
  });
  if (!response.ok) return undefined;
  const payload = await response.json().catch(() => undefined) as unknown;
  return normalizeClineCatalog(payload, provider);
}
