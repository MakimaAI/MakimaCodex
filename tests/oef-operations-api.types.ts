import { SqliteOperationsStore, type CancellationCapabilityVerifier } from "../src/oef/operations";

declare const store: SqliteOperationsStore;
declare const verifier: CancellationCapabilityVerifier;

const options: ConstructorParameters<typeof SqliteOperationsStore>[0] = { databasePath: "operations.sqlite", cancellationCapabilityVerifier: verifier };
void options;
const cancellation: Parameters<SqliteOperationsStore["cancel"]>[0] = { scope_id: "scope:alpha", job_id: "operation:one", owner: "worker:a", now: "2026-07-24T12:00:00.000Z" };
void store.cancel(cancellation);
