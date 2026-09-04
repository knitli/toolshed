import { Database } from "bun:sqlite";
import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, rmSync, unlinkSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { compile } from "../src/compile.ts";
import { LEGACY_FORMAT_VERSION } from "../src/schema.ts";

const OUT = `${import.meta.dir}/tmp-compile.sqlite`;
const opts = {
  specPath: `${import.meta.dir}/../fixtures/tiny-api.yaml`,
  api: "tiny",
  outPath: OUT,
  permissionsPath: `${import.meta.dir}/../fixtures/tiny-permissions.json`,
};

afterEach(() => {
  try {
    unlinkSync(OUT);
  } catch {
    /* already gone */
  }
  try {
    rmSync(`${OUT}.building`, { recursive: true });
  } catch {
    /* already gone */
  }
});

describe("compile", () => {
  test("a successful compile leaves no build file behind", async () => {
    await compile(opts);
    expect(existsSync(`${OUT}.building`)).toBe(false);
    expect(existsSync(OUT)).toBe(true);
  });

  test("a failed rebuild leaves the previous artifact intact", async () => {
    await compile(opts);
    const before = await Bun.file(OUT).arrayBuffer();

    // Block the sibling the rebuild writes into, so the compile fails after
    // the point where an in-place rebuild would already have destroyed OUT.
    mkdirSync(`${OUT}.building`);
    expect(compile(opts)).rejects.toThrow();

    const after = await Bun.file(OUT).arrayBuffer();
    expect(new Uint8Array(after)).toEqual(new Uint8Array(before));
    const db = new Database(OUT, { readonly: true });
    expect(
      db.query<{ n: number }, []>("SELECT COUNT(*) n FROM operations").get()?.n,
    ).toBe(6);
    db.close();
  });

  test("writes every operation and schema", async () => {
    const result = await compile(opts);
    expect(result.operations).toBe(6);
    expect(result.schemas).toBe(2);
    expect(result.mapped).toBeGreaterThan(0);

    const db = new Database(OUT, { readonly: true });
    expect(
      db.query<{ n: number }, []>("SELECT COUNT(*) n FROM operations").get()?.n,
    ).toBe(6);
    expect(
      db.query<{ n: number }, []>("SELECT COUNT(*) n FROM schemas").get()?.n,
    ).toBe(2);
    db.close();
  });

  test("populates the fts index so search returns the right operation", async () => {
    await compile(opts);
    const db = new Database(OUT, { readonly: true });
    const hits = db
      .query<{ qualified_id: string }, [string]>(
        `SELECT o.qualified_id FROM operations_fts f
         JOIN operations o ON o.rowid = f.rowid
         WHERE operations_fts MATCH ? ORDER BY bm25(operations_fts) LIMIT 5`,
      )
      .all("widget");
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.map((h) => h.qualified_id)).toContain(
      "tiny:widgets.CreateWidget",
    );
    db.close();
  });

  test("records provenance in meta, namespaced per api", async () => {
    await compile(opts);
    const db = new Database(OUT, { readonly: true });
    const meta = Object.fromEntries(
      db
        .query<{ key: string; value: string }, []>(
          "SELECT key, value FROM meta",
        )
        .all()
        .map((r) => [r.key, r.value]),
    );
    expect(meta.format_version).toBe(String(LEGACY_FORMAT_VERSION));
    // `apis` is the mounted-API list; per-api keys are namespaced so a second
    // mount (Task 12) cannot collide with the first.
    expect(JSON.parse(meta.apis)).toEqual(["tiny"]);
    expect(meta["tiny.source_path"]).toContain("tiny-api.yaml");
    expect(meta["tiny.compiled_at"]).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    db.close();
  });

  test("works without a permissions dataset", async () => {
    const result = await compile({ ...opts, permissionsPath: undefined });
    expect(result.operations).toBe(6);
    expect(result.mapped).toBe(0);

    const db = new Database(OUT, { readonly: true });
    const write = db
      .query<{ risk: string }, [string]>(
        "SELECT risk FROM operations WHERE qualified_id = ?",
      )
      .get("tiny:widgets.CreateWidget");
    // Unmapped writes must default to high, never silently to routine.
    expect(write?.risk).toBe("high");
    db.close();
  });

  test("produces identical rows across runs", async () => {
    const rowsOf = async () => {
      await compile(opts);
      const db = new Database(OUT, { readonly: true });
      const rows = db
        .query<Record<string, unknown>, []>(
          `SELECT qualified_id, method, path, safety, risk, pageable, deprecated,
                  permissions, perm_confidence, privilege_level, params_json, body_ref
           FROM operations ORDER BY qualified_id`,
        )
        .all();
      db.close();
      return rows;
    };
    const first = await rowsOf();
    unlinkSync(OUT);
    const second = await rowsOf();
    // meta.compiled_at is a timestamp and differs by design; every row must not.
    expect(second).toEqual(first);
    expect(first).toHaveLength(6);
  });

  test("leaves no half-built artifact when a mid-transaction step fails", async () => {
    // Force the fts5 population step (the last DML before meta) to throw,
    // simulating a failure after schema creation and every row insert.
    const originalExec = DatabaseSync.prototype.exec;
    DatabaseSync.prototype.exec = function (this: DatabaseSync, sql: string) {
      if (sql.includes("INSERT INTO operations_fts")) {
        throw new Error("simulated mid-transaction failure");
      }
      return originalExec.call(this, sql);
    } as typeof DatabaseSync.prototype.exec;

    try {
      await expect(compile(opts)).rejects.toThrow(
        "simulated mid-transaction failure",
      );
    } finally {
      DatabaseSync.prototype.exec = originalExec;
    }

    // The failure happened inside the sibling build file, which is removed on
    // the way out. Nothing is published: no schema-only artifact, no empty
    // database, and no leftover build file for the next run to trip over.
    expect(existsSync(OUT)).toBe(false);
    expect(existsSync(`${OUT}.building`)).toBe(false);
  });
});
