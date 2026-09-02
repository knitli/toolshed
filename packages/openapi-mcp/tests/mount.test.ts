import { Database } from "bun:sqlite";
import { afterEach, describe, expect, test } from "bun:test";
import { unlinkSync } from "node:fs";
import { compile } from "../src/compile.ts";

const OUT = `${import.meta.dir}/tmp-mount.sqlite`;
const TINY = `${import.meta.dir}/../fixtures/tiny-api.yaml`;
const OTHER = `${import.meta.dir}/../fixtures/other-api.yaml`;

afterEach(() => {
  try { unlinkSync(OUT); } catch { /* already gone */ }
});

describe("mounting a second api", () => {
  test("appending keeps the first api's rows", async () => {
    await compile({ specPath: TINY, api: "tiny", outPath: OUT });
    await compile({ specPath: OTHER, api: "other", outPath: OUT, append: true });

    const db = new Database(OUT, { readonly: true });
    expect(
      db.query<{ n: number }, []>("SELECT COUNT(*) n FROM operations").get()?.n,
    ).toBe(9);
    const apis = db
      .query<{ api: string }, []>("SELECT DISTINCT api FROM operations ORDER BY api")
      .all()
      .map((r) => r.api);
    expect(apis).toEqual(["other", "tiny"]);
    db.close();
  });

  test("appending keeps the fts external-content index consistent", async () => {
    await compile({ specPath: TINY, api: "tiny", outPath: OUT });
    await compile({ specPath: OTHER, api: "other", outPath: OUT, append: true });

    // Not readonly: fts5's integrity-check command runs as a write statement
    // even though it only verifies. A mismatch between operations_fts and its
    // external content table (e.g. a shadow column left out of an INSERT)
    // makes this throw.
    const db = new Database(OUT);
    expect(() =>
      db.run("INSERT INTO operations_fts(operations_fts) VALUES('integrity-check')"),
    ).not.toThrow();
    db.close();
  });

  test("word-split search_text finds a camelCase operation by its split words", async () => {
    await compile({ specPath: TINY, api: "tiny", outPath: OUT });
    await compile({ specPath: OTHER, api: "other", outPath: OUT, append: true });

    const db = new Database(OUT, { readonly: true });
    const hits = db
      .query<{ qualified_id: string }, [string]>(
        `SELECT o.qualified_id FROM operations_fts f
         JOIN operations o ON o.rowid = f.rowid
         WHERE operations_fts MATCH ? ORDER BY bm25(operations_fts)`,
      )
      .all("send mail");
    expect(hits.map((h) => h.qualified_id)).toEqual(["other:me.sendMail"]);
    db.close();
  });

  test("records both apis in meta", async () => {
    await compile({ specPath: TINY, api: "tiny", outPath: OUT });
    await compile({ specPath: OTHER, api: "other", outPath: OUT, append: true });

    const db = new Database(OUT, { readonly: true });
    const meta = Object.fromEntries(
      db.query<{ key: string; value: string }, []>("SELECT key, value FROM meta")
        .all()
        .map((r) => [r.key, r.value]),
    );
    expect(JSON.parse(meta.apis).sort()).toEqual(["other", "tiny"]);
    expect(meta["other.source_path"]).toContain("other-api.yaml");
    expect(meta["tiny.source_path"]).toContain("tiny-api.yaml");
    db.close();
  });

  test("search can be scoped to one api", async () => {
    await compile({ specPath: TINY, api: "tiny", outPath: OUT });
    await compile({ specPath: OTHER, api: "other", outPath: OUT, append: true });

    const db = new Database(OUT, { readonly: true });
    const hits = db
      .query<{ qualified_id: string }, [string, string]>(
        `SELECT o.qualified_id FROM operations_fts f
         JOIN operations o ON o.rowid = f.rowid
         WHERE operations_fts MATCH ? AND o.api = ?
         ORDER BY bm25(operations_fts)`,
      )
      .all("list", "other");
    expect(hits.map((h) => h.qualified_id)).toEqual(["other:zones.ListZones"]);
    db.close();
  });

  test("refuses to mount the same api twice, and the original rows survive", async () => {
    await compile({ specPath: TINY, api: "tiny", outPath: OUT });
    await expect(
      compile({ specPath: TINY, api: "tiny", outPath: OUT, append: true }),
    ).rejects.toThrow(/already mounted/);

    const db = new Database(OUT, { readonly: true });
    expect(
      db.query<{ n: number }, []>("SELECT COUNT(*) n FROM operations").get()?.n,
    ).toBe(6);
    const apis = db
      .query<{ api: string }, []>("SELECT DISTINCT api FROM operations")
      .all()
      .map((r) => r.api);
    expect(apis).toEqual(["tiny"]);
    const meta = db
      .query<{ value: string }, [string]>("SELECT value FROM meta WHERE key = ?")
      .get("apis")?.value;
    expect(JSON.parse(meta ?? "[]")).toEqual(["tiny"]);
    db.close();
  });

  test("refuses to append to an artifact with a different format_version, and the original rows survive", async () => {
    await compile({ specPath: TINY, api: "tiny", outPath: OUT });
    const db = new Database(OUT);
    db.run("UPDATE meta SET value = '999' WHERE key = 'format_version'");
    db.close();
    await expect(
      compile({ specPath: OTHER, api: "other", outPath: OUT, append: true }),
    ).rejects.toThrow(/format_version/);

    const readback = new Database(OUT, { readonly: true });
    expect(
      readback.query<{ n: number }, []>("SELECT COUNT(*) n FROM operations").get()?.n,
    ).toBe(6);
    const apis = readback
      .query<{ api: string }, []>("SELECT DISTINCT api FROM operations")
      .all()
      .map((r) => r.api);
    expect(apis).toEqual(["tiny"]);
    readback.close();
  });

  test("append on a missing file fails rather than silently creating one", async () => {
    expect(
      compile({ specPath: OTHER, api: "other", outPath: OUT, append: true }),
    ).rejects.toThrow(/does not exist/);
  });
});
