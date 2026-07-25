CREATE TABLE IF NOT EXISTS memory_vector_generations (
  generation_id TEXT PRIMARY KEY,
  profile_key TEXT NOT NULL,
  profile_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'RETIRED')),
  created_at TEXT NOT NULL,
  metadata_json TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS memory_vector_one_active_generation
  ON memory_vector_generations(status)
  WHERE status = 'ACTIVE';

CREATE TABLE IF NOT EXISTS memory_vector_entries (
  generation_id TEXT NOT NULL,
  revision_id TEXT NOT NULL,
  memory_id TEXT NOT NULL,
  vector_json TEXT NOT NULL,
  vector_norm REAL NOT NULL CHECK(vector_norm > 0),
  metadata_json TEXT NOT NULL,
  PRIMARY KEY(generation_id, revision_id),
  FOREIGN KEY(generation_id) REFERENCES memory_vector_generations(generation_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS memory_vector_entries_memory
  ON memory_vector_entries(memory_id, generation_id);

INSERT OR IGNORE INTO memory_index_registry(index_id, kind, status, version, metadata_json)
VALUES ('vector@local', 'vector', 'EMPTY', '0.0.0', '{}');
