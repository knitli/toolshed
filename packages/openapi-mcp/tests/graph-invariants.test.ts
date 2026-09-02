import { Database } from "bun:sqlite";
import { describe, expect, test } from "bun:test";
import { unlinkSync } from "node:fs";
import { compile } from "../src/compile";

const SPEC = process.env.OPENAPI_MCP_GRAPH_SPEC;
const OUT = `${import.meta.dir}/tmp-graph.sqlite`;

describe.skipIf(!SPEC)("Microsoft Graph invariants", () => {
  test("compiles the full v1.0 surface within budget", async () => {
    const started = Date.now();
    const result = await compile({
      specPath: SPEC as string,
      api: "graph",
      outPath: OUT,
    });

    // Counts measured 2026-09-01 against msgraph-metadata@master.
    expect(result.operations).toBe(17777);
    expect(result.schemas).toBe(5127);
    // Parsing alone is ~650 ms; the whole compile must stay well under CI patience.
    expect(Date.now() - started).toBeLessThan(120_000);

    const db = new Database(OUT, { readonly: true });

    // Every operationId is unique, so no row was silently dropped.
    expect(
      db.query<{ n: number }, []>(
        "SELECT COUNT(DISTINCT operation_id) n FROM operations",
      ).get()?.n,
    ).toBe(17777);

    // Safety invariant: no mutating method may be stored as a read unless an
    // override produced it. Overrides only ever apply to POST. This query
    // excludes POST by construction, so it can only ever see the rows the
    // override list is not allowed to touch — kept for that narrower check,
    // but the override's actual effect is asserted below.
    expect(
      db.query<{ n: number }, []>(
        `SELECT COUNT(*) n FROM operations
         WHERE safety = 'read' AND method NOT IN ('GET','HEAD','POST')`,
      ).get()?.n,
    ).toBe(0);

    // The override list (READ_OVERRIDE_SUFFIXES) applies only to POST:
    // assert its real effect rather than a query that excludes every POST
    // it could touch. Count measured 2026-09-01 against the real spec.
    expect(
      db.query<{ n: number }, []>(
        "SELECT COUNT(*) n FROM operations WHERE safety = 'read' AND method = 'POST'",
      ).get()?.n,
    ).toBe(101);

    // Graph v1.0's OpenAPI document declares no `/$batch` path (batch is
    // documented outside the spec), so this is expected to be empty; the
    // write+high classification itself is covered by the fixture tests
    // (tiny-api.yaml has one, asserted in Task 5). Kept as a guard in case
    // a future revision adds `$batch` to the document.
    const batch = db
      .query<{ safety: string; risk: string }, []>(
        "SELECT safety, risk FROM operations WHERE path LIKE '%$batch'",
      )
      .all();
    expect(batch.length).toBe(0);
    if (batch.length > 0) {
      expect(batch.every((b) => b.safety === "write" && b.risk === "high")).toBe(true);
    }

    // Pageable and deprecated counts measured on the same revision.
    expect(
      db.query<{ n: number }, []>(
        "SELECT COUNT(*) n FROM operations WHERE pageable = 1",
      ).get()?.n,
    ).toBe(2760);
    expect(
      db.query<{ n: number }, []>(
        "SELECT COUNT(*) n FROM operations WHERE deprecated = 1",
      ).get()?.n,
    ).toBe(85);

    // Search must actually find something for a plain-language query.
    const hits = db
      .query<{ qualified_id: string }, [string]>(
        `SELECT o.qualified_id FROM operations_fts f
         JOIN operations o ON o.rowid = f.rowid
         WHERE operations_fts MATCH ? ORDER BY bm25(operations_fts) LIMIT 10`,
      )
      .all("message");
    expect(hits.length).toBeGreaterThan(0);

    db.close();
    unlinkSync(OUT);
  }, 180_000);
});
