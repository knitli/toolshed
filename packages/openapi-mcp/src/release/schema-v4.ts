import type { DatabaseSync } from "node:sqlite";

/** Compatibility-era schema name for immutable v4/v5 SQLite and D1 transport. */
export const RELEASE_SCHEMA_V4 = `
PRAGMA foreign_keys = ON;

CREATE TABLE release_metadata (
  catalog_id TEXT NOT NULL COLLATE BINARY,
  release_id TEXT NOT NULL COLLATE BINARY,
  format INTEGER NOT NULL CHECK (format IN (4, 5)),
  contract INTEGER NOT NULL CHECK (contract = 1),
  generation INTEGER NOT NULL CHECK (generation >= 0),
  issuer TEXT NOT NULL COLLATE BINARY,
  key_id TEXT NOT NULL COLLATE BINARY,
  policy_id TEXT NOT NULL COLLATE BINARY,
  allowed_origins_json TEXT NOT NULL,
  compiled_at TEXT NOT NULL,
  compiler_version TEXT NOT NULL,
  source_uri TEXT NOT NULL,
  source_revision TEXT NOT NULL,
  source_content_sha256 TEXT NOT NULL CHECK (
    length(source_content_sha256) = 64
    AND source_content_sha256 NOT GLOB '*[^0-9a-f]*'
  ),
  reference_graph_digest TEXT NOT NULL CHECK (
    length(reference_graph_digest) = 64
    AND reference_graph_digest NOT GLOB '*[^0-9a-f]*'
  ),
  manifest_json TEXT NOT NULL,
  signature_algorithm TEXT NOT NULL CHECK (signature_algorithm = 'Ed25519'),
  signature_key_id TEXT NOT NULL COLLATE BINARY,
  signature TEXT NOT NULL,
  PRIMARY KEY (catalog_id, release_id)
) WITHOUT ROWID;

CREATE TABLE operations (
  catalog_id TEXT NOT NULL COLLATE BINARY,
  release_id TEXT NOT NULL COLLATE BINARY,
  record_id TEXT NOT NULL COLLATE BINARY CHECK (
    record_id GLOB 'operation:*' AND length(record_id) <= 651
  ),
  record_json TEXT NOT NULL,
  logical_digest TEXT NOT NULL CHECK (
    length(logical_digest) = 64
    AND logical_digest NOT GLOB '*[^0-9a-f]*'
  ),
  api TEXT NOT NULL COLLATE BINARY,
  operation_id TEXT NOT NULL COLLATE BINARY,
  summary TEXT,
  path TEXT NOT NULL,
  search_text TEXT NOT NULL,
  PRIMARY KEY (catalog_id, release_id, record_id),
  FOREIGN KEY (catalog_id, release_id)
    REFERENCES release_metadata(catalog_id, release_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE INDEX operations_release_api
  ON operations (catalog_id, release_id, api, record_id);

CREATE VIRTUAL TABLE operations_fts USING fts5(
  record_id, operation_id, summary, path, api, search_text,
  content='operations', content_rowid='rowid'
);

CREATE TABLE schemas (
  catalog_id TEXT NOT NULL COLLATE BINARY,
  release_id TEXT NOT NULL COLLATE BINARY,
  record_id TEXT NOT NULL COLLATE BINARY CHECK (
    record_id GLOB 'schema:*' AND length(record_id) <= 669
  ),
  record_json TEXT NOT NULL,
  logical_digest TEXT NOT NULL CHECK (
    length(logical_digest) = 64
    AND logical_digest NOT GLOB '*[^0-9a-f]*'
  ),
  PRIMARY KEY (catalog_id, release_id, record_id),
  FOREIGN KEY (catalog_id, release_id)
    REFERENCES release_metadata(catalog_id, release_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
) WITHOUT ROWID;
`;

export function createReleaseSchemaV4(database: DatabaseSync): void {
  database.exec(RELEASE_SCHEMA_V4);
}

export function populateOperationsFtsV4(database: DatabaseSync): void {
  database.exec(`
    INSERT INTO operations_fts
      (rowid, record_id, operation_id, summary, path, api, search_text)
    SELECT rowid, record_id, operation_id, summary, path, api, search_text
    FROM operations
  `);
}
