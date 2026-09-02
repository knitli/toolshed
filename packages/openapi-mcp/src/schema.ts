import type { DatabaseSync } from "node:sqlite";

/** Bumped when the artifact layout changes incompatibly. Servers refuse unknown versions. */
export const FORMAT_VERSION = 3;

// `fts5` MUST be lower-case: D1 rejects `FTS5` as "not authorized".
const DDL = `
CREATE TABLE operations (
  qualified_id    TEXT PRIMARY KEY,
  api             TEXT NOT NULL,
  operation_id    TEXT NOT NULL,
  method          TEXT NOT NULL,
  path            TEXT NOT NULL,
  safety          TEXT NOT NULL CHECK (safety IN ('read','write')),
  risk            TEXT NOT NULL CHECK (risk IN ('routine','high')),
  operation_type  TEXT,
  pageable        INTEGER NOT NULL DEFAULT 0,
  deprecated      INTEGER NOT NULL DEFAULT 0,
  permissions     TEXT,
  perm_confidence TEXT,
  privilege_level INTEGER,
  summary         TEXT,
  tags            TEXT,
  params_json     TEXT NOT NULL,
  search_text     TEXT NOT NULL,
  body_ref        TEXT,
  body_schema     TEXT,
  body_media_type TEXT,
  server_url      TEXT NOT NULL
);

CREATE INDEX operations_api ON operations (api);
CREATE INDEX operations_safety ON operations (api, safety, risk);

CREATE VIRTUAL TABLE operations_fts USING fts5(
  qualified_id, operation_id, summary, path, tags, api, search_text,
  content='operations', content_rowid='rowid'
);

CREATE TABLE schemas (
  api  TEXT NOT NULL,
  name TEXT NOT NULL,
  json TEXT NOT NULL,
  PRIMARY KEY (api, name)
);

CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`;

/** Creates every table, index, and virtual table the artifact needs. */
export function createSchema(db: DatabaseSync): void {
  db.exec(DDL);
}
