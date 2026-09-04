import { describe, expect, test } from "bun:test";
import { DatabaseSync } from "node:sqlite";
import { createSchema, LEGACY_FORMAT_VERSION } from "../src/schema.ts";

const insertOp = (
  db: DatabaseSync,
  values: [string, string, string, string, string, string, string, number, number, string, string, string],
) =>
  db
    .prepare(
      `INSERT INTO operations
       (qualified_id, api, operation_id, method, path, safety, risk,
        pageable, deprecated, params_json, search_text, server_url)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
    )
    .run(...values);

describe("createSchema", () => {
  test("creates every table the artifact needs", () => {
    const db = new DatabaseSync(":memory:");
    createSchema(db);
    const names = db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type IN ('table','view') ORDER BY name",
      )
      .all()
      .map((r) => r.name as string);
    expect(names).toContain("operations");
    expect(names).toContain("operations_fts");
    expect(names).toContain("schemas");
    expect(names).toContain("meta");
  });

  test("fts5 index supports bm25 ranking", () => {
    const db = new DatabaseSync(":memory:");
    createSchema(db);
    insertOp(db, [
      "g:users.ListMessages", "g", "users.ListMessages", "GET",
      "/users/{id}/messages", "read", "routine", 0, 0, "[]",
      "users list messages users id messages", "https://graph.microsoft.com",
    ]);
    db.exec(
      `INSERT INTO operations_fts (rowid, qualified_id, operation_id, summary, path, tags, api, search_text)
       SELECT rowid, qualified_id, operation_id, summary, path, tags, api, search_text FROM operations`,
    );
    const hits = db
      .prepare(
        `SELECT o.qualified_id FROM operations_fts f
         JOIN operations o ON o.rowid = f.rowid
         WHERE operations_fts MATCH ? ORDER BY bm25(operations_fts)`,
      )
      .all("messages")
      .map((r) => r.qualified_id as string);
    expect(hits).toEqual(["g:users.ListMessages"]);
  });

  test("word-split search_text makes a camelCase operation findable", () => {
    const db = new DatabaseSync(":memory:");
    createSchema(db);
    insertOp(db, [
      "g:me.sendMail", "g", "me.sendMail", "POST", "/me/sendMail",
      "write", "routine", 0, 0, "[]",
      "me send mail me send mail", "https://graph.microsoft.com",
    ]);
    db.exec(
      `INSERT INTO operations_fts (rowid, qualified_id, operation_id, summary, path, tags, api, search_text)
       SELECT rowid, qualified_id, operation_id, summary, path, tags, api, search_text FROM operations`,
    );
    const hits = db
      .prepare(
        `SELECT o.qualified_id FROM operations_fts f
         JOIN operations o ON o.rowid = f.rowid
         WHERE operations_fts MATCH ? ORDER BY bm25(operations_fts)`,
      )
      .all("send mail")
      .map((r) => r.qualified_id as string);
    expect(hits).toEqual(["g:me.sendMail"]);
  });

  test("rejects a duplicate qualified_id", () => {
    const db = new DatabaseSync(":memory:");
    createSchema(db);
    const insert = () =>
      insertOp(db, [
        "g:dup", "g", "dup", "GET", "/dup", "read", "routine", 0, 0, "[]", "dup", "https://x",
      ]);
    insert();
    expect(insert).toThrow();
  });

  test("LEGACY_FORMAT_VERSION is 3", () => {
    expect(LEGACY_FORMAT_VERSION).toBe(3);
  });
});
