import { Database } from "bun:sqlite";
import { describe, expect, test } from "bun:test";
import { createSchema, FORMAT_VERSION } from "../src/schema.ts";

describe("createSchema", () => {
  test("creates every table the artifact needs", () => {
    const db = new Database(":memory:");
    createSchema(db);
    const names = db
      .query<{ name: string }, []>(
        "SELECT name FROM sqlite_master WHERE type IN ('table','view') ORDER BY name",
      )
      .all()
      .map((r) => r.name);
    expect(names).toContain("operations");
    expect(names).toContain("operations_fts");
    expect(names).toContain("schemas");
    expect(names).toContain("meta");
  });

  test("fts5 index supports bm25 ranking", () => {
    const db = new Database(":memory:");
    createSchema(db);
    db.run(
      `INSERT INTO operations
       (qualified_id, api, operation_id, method, path, safety, risk,
        pageable, deprecated, params_json, server_url)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
      "g:users.ListMessages", "g", "users.ListMessages", "GET",
      "/users/{id}/messages", "read", "routine", 0, 0, "[]",
      "https://graph.microsoft.com",
    );
    db.run(
      `INSERT INTO operations_fts (rowid, qualified_id, operation_id, summary, path, tags, api)
       SELECT rowid, qualified_id, operation_id, summary, path, tags, api FROM operations`,
    );
    const hits = db
      .query<{ qualified_id: string }, [string]>(
        `SELECT o.qualified_id FROM operations_fts f
         JOIN operations o ON o.rowid = f.rowid
         WHERE operations_fts MATCH ? ORDER BY bm25(operations_fts)`,
      )
      .all("messages");
    expect(hits.map((h) => h.qualified_id)).toEqual(["g:users.ListMessages"]);
  });

  test("rejects a duplicate qualified_id", () => {
    const db = new Database(":memory:");
    createSchema(db);
    const insert = () =>
      db.run(
        `INSERT INTO operations
         (qualified_id, api, operation_id, method, path, safety, risk,
          pageable, deprecated, params_json, server_url)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
        "g:dup", "g", "dup", "GET", "/dup", "read", "routine", 0, 0, "[]", "https://x",
      );
    insert();
    expect(insert).toThrow();
  });

  test("FORMAT_VERSION is a positive integer", () => {
    expect(Number.isInteger(FORMAT_VERSION)).toBe(true);
    expect(FORMAT_VERSION).toBeGreaterThan(0);
  });
});
