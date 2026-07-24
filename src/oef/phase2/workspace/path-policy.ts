const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

export function canonicalRepositoryPath(value: string, allowGlob = false): string | null {
  if (!value || value !== value.trim() || value.length > 2_000 || CONTROL_CHARACTERS.test(value)) return null;
  const normalized = value.replaceAll("\\", "/");
  if (normalized.startsWith("/") || normalized.startsWith("//") || /^[A-Za-z]:/.test(normalized) || normalized.includes("//")) return null;
  const segments = normalized.split("/");
  if (segments.length > 256 || segments.some(segment => !segment || segment === "." || segment === "..")) return null;
  if (!allowGlob && segments.some(segment => segment.includes("*") || segment.includes("?"))) return null;
  if (allowGlob && segments.some(segment => segment.includes("***") || (segment.includes("**") && segment !== "**") || segment.includes("?"))) return null;
  return segments.join("/");
}

export function evaluatePathPolicy(
  pathInput: string,
  allowedPatternsInput: readonly string[],
  deniedPatternsInput: readonly string[],
): { allowed: true; reason: "ALLOWED_PATH" } | { allowed: false; reason: "INVALID_PATH" | "DENIED_PATH" | "NOT_ALLOWED" } {
  const path = canonicalRepositoryPath(pathInput);
  const allowedPatterns = allowedPatternsInput.map(pattern => canonicalRepositoryPath(pattern, true));
  const deniedPatterns = deniedPatternsInput.map(pattern => canonicalRepositoryPath(pattern, true));
  if (!path || allowedPatterns.some(pattern => pattern === null) || deniedPatterns.some(pattern => pattern === null)) {
    return { allowed: false, reason: "INVALID_PATH" };
  }
  if ((deniedPatterns as string[]).some(pattern => globMatches(path, pattern))) return { allowed: false, reason: "DENIED_PATH" };
  if (!(allowedPatterns as string[]).some(pattern => globMatches(path, pattern))) return { allowed: false, reason: "NOT_ALLOWED" };
  return { allowed: true, reason: "ALLOWED_PATH" };
}

function globMatches(path: string, pattern: string): boolean {
  const pathSegments = path.split("/");
  const patternSegments = pattern.split("/");
  const memo = new Map<string, boolean>();
  const visit = (pathIndex: number, patternIndex: number): boolean => {
    const key = `${pathIndex}:${patternIndex}`;
    const cached = memo.get(key);
    if (cached !== undefined) return cached;
    if (patternIndex === patternSegments.length) return pathIndex === pathSegments.length;
    const patternSegment = patternSegments[patternIndex]!;
    if (patternSegment === "**") {
      for (let next = pathIndex; next <= pathSegments.length; next += 1) {
        if (visit(next, patternIndex + 1)) { memo.set(key, true); return true; }
      }
      memo.set(key, false);
      return false;
    }
    const matches = pathIndex < pathSegments.length
      && segmentMatches(pathSegments[pathIndex]!, patternSegment)
      && visit(pathIndex + 1, patternIndex + 1);
    memo.set(key, matches);
    return matches;
  };
  return visit(0, 0);
}

function segmentMatches(value: string, pattern: string): boolean {
  const source = pattern.split("*").map(part => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("[^/]*");
  return new RegExp(`^${source}$`).test(value);
}
