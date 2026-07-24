import { z } from "zod";
import { actorSchema, type Actor } from "../shared/actor";
import { canonicalSha256 } from "../contract/task-contract";

export interface DomainEvent {
  event_id: string;
  event_type: string;
  event_schema_version: number;
  aggregate: { type: "task"; id: string; version: number };
  actor: Actor;
  trace: { trace_id: string; correlation_id: string; causation_id: string };
  occurred_at: string;
  recorded_at: string;
  payload: Record<string, unknown>;
  integrity: { previous_event_hash: string | null; event_hash: string };
}

export const domainEventSchema = z.object({
  event_id: z.string().trim().min(1),
  event_type: z.string().trim().min(1),
  event_schema_version: z.literal(1),
  aggregate: z.object({
    type: z.literal("task"),
    id: z.string().regex(/^task:[A-Za-z0-9][A-Za-z0-9._:@/-]*$/),
    version: z.number().int().positive(),
  }).strict(),
  actor: actorSchema,
  trace: z.object({
    trace_id: z.string().trim().min(1),
    correlation_id: z.string().trim().min(1),
    causation_id: z.string().trim().min(1),
  }).strict(),
  occurred_at: z.string().datetime(),
  recorded_at: z.string().datetime(),
  payload: z.record(z.string(), z.unknown()),
  integrity: z.object({
    previous_event_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/).nullable(),
    event_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  }).strict(),
}).strict();

export function parseDomainEvent(input: unknown): DomainEvent {
  return domainEventSchema.parse(input) as DomainEvent;
}

export function eventHashInput(event: Omit<DomainEvent, "integrity"> & {
  integrity: { previous_event_hash: string | null };
}): unknown {
  return event;
}

export function createDomainEvent(input: {
  eventId: string;
  eventType: string;
  aggregateId: string;
  aggregateVersion: number;
  actor: Actor;
  traceId: string;
  causationId: string;
  occurredAt: string;
  recordedAt: string;
  payload: Record<string, unknown>;
  previousEventHash: string | null;
}): DomainEvent {
  const withoutHash = {
    event_id: input.eventId,
    event_type: input.eventType,
    event_schema_version: 1,
    aggregate: { type: "task" as const, id: input.aggregateId, version: input.aggregateVersion },
    actor: input.actor,
    trace: {
      trace_id: input.traceId,
      correlation_id: input.aggregateId,
      causation_id: input.causationId,
    },
    occurred_at: input.occurredAt,
    recorded_at: input.recordedAt,
    payload: input.payload,
    integrity: { previous_event_hash: input.previousEventHash },
  };
  return {
    ...withoutHash,
    integrity: {
      ...withoutHash.integrity,
      event_hash: canonicalSha256(eventHashInput(withoutHash)),
    },
  };
}

export function verifyDomainEventHash(event: DomainEvent): boolean {
  const { event_hash: _eventHash, ...integrity } = event.integrity;
  return canonicalSha256(eventHashInput({ ...event, integrity })) === event.integrity.event_hash;
}
