export interface ReviewSchemaUpcaster {
  readonly from_version: number;
  readonly to_version: number;
  readonly upcast: (record: Readonly<Record<string, unknown>>) => Record<string, unknown>;
}

export function upcastReviewRecord(
  input: unknown,
  currentVersion: number,
  upcasters: readonly ReviewSchemaUpcaster[],
): Readonly<Record<string, unknown>> {
  if (!isRecord(input) || !isSchemaVersion(input.schema_version) || !isSchemaVersion(currentVersion)) {
    throw new Error("SCHEMA_UPCAST_INPUT_INVALID");
  }
  if (input.schema_version > currentVersion) throw new Error("SCHEMA_VERSION_UNSUPPORTED");

  const bySource = new Map<number, ReviewSchemaUpcaster>();
  for (const upcaster of upcasters) {
    if (!isSchemaVersion(upcaster.from_version) || upcaster.to_version !== upcaster.from_version + 1 || bySource.has(upcaster.from_version)) {
      throw new Error("SCHEMA_UPCASTER_INVALID");
    }
    bySource.set(upcaster.from_version, upcaster);
  }

  let record = cloneRecord(input);
  while (record.schema_version !== currentVersion) {
    const sourceVersion = record.schema_version;
    if (!isSchemaVersion(sourceVersion)) throw new Error("SCHEMA_UPCAST_OUTPUT_INVALID");
    const upcaster = bySource.get(sourceVersion);
    if (!upcaster) throw new Error("SCHEMA_UPCAST_PATH_MISSING");
    const next = upcaster.upcast(deepFreeze(cloneRecord(record)));
    if (!isRecord(next) || next.schema_version !== upcaster.to_version) throw new Error("SCHEMA_UPCAST_OUTPUT_INVALID");
    record = cloneRecord(next);
  }
  return deepFreeze(record);
}

function isSchemaVersion(value: unknown): value is number {
  return Number.isInteger(value) && Number(value) >= 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function cloneRecord(value: Record<string, unknown>): Record<string, unknown> {
  return structuredClone(value) as Record<string, unknown>;
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}
