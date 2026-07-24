export interface StoredEventLike {
  event_type: string;
  event_schema_version: number;
  [key: string]: unknown;
}

export interface EventUpcaster {
  supports(type: string, version: number): boolean;
  upcast(event: StoredEventLike): StoredEventLike;
}

export const legacyActorUpcaster: EventUpcaster = {
  supports(_type, version) {
    return version === 0;
  },
  upcast(event) {
    const { actor_id: actorId, ...rest } = event;
    return {
      ...rest,
      event_schema_version: 1,
      actor: {
        type: typeof actorId === "string" && actorId.startsWith("human:") ? "human" : "system",
        id: typeof actorId === "string" && actorId.trim() ? actorId : "system:legacy-upcaster",
      },
    };
  },
};

export function upcastStoredEvent(
  input: StoredEventLike,
  upcasters: readonly EventUpcaster[] = [legacyActorUpcaster],
): StoredEventLike {
  let current = structuredClone(input);
  const seen = new Set<number>();
  while (current.event_schema_version !== 1) {
    if (seen.has(current.event_schema_version)) throw new Error("Event upcaster cycle detected");
    seen.add(current.event_schema_version);
    const upcaster = upcasters.find(candidate => candidate.supports(current.event_type, current.event_schema_version));
    if (!upcaster) throw new Error(`No upcaster for ${current.event_type}@${current.event_schema_version}`);
    const next = upcaster.upcast(current);
    if (next.event_schema_version === current.event_schema_version) throw new Error("Event upcaster did not advance schema version");
    current = next;
  }
  return current;
}
