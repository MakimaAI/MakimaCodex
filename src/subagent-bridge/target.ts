const BRIDGE_TASK_LEAF_RE = /^[a-z0-9](?:[a-z0-9_]{0,39})?_[0-9a-f]{12}$/;
const CANONICAL_SEGMENT_RE = /^[a-z0-9_]+$/;

export interface VerifiedSubagentTarget {
  value: string;
  leaf: string;
  canonical: boolean;
}

export function parseVerifiedSubagentTarget(value: string): VerifiedSubagentTarget | null {
  if (value !== value.trim() || value.length > 1024) return null;
  if (BRIDGE_TASK_LEAF_RE.test(value)) return { value, leaf: value, canonical: false };
  if (!value.startsWith("/root/")) return null;
  const segments = value.split("/");
  if (segments[0] !== "" || segments[1] !== "root" || segments.length < 3) return null;
  if (segments.slice(2).some(segment => !CANONICAL_SEGMENT_RE.test(segment))) return null;
  const leaf = segments.at(-1)!;
  return BRIDGE_TASK_LEAF_RE.test(leaf) ? { value, leaf, canonical: true } : null;
}

export function verifiedSubagentTargetsMatch(left: string, right: string): boolean {
  const parsedLeft = parseVerifiedSubagentTarget(left);
  const parsedRight = parseVerifiedSubagentTarget(right);
  if (!parsedLeft || !parsedRight) return false;
  if (parsedLeft.canonical && parsedRight.canonical) return parsedLeft.value === parsedRight.value;
  return parsedLeft.leaf === parsedRight.leaf;
}
