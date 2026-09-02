import { describe, expect, test } from "bun:test";
import { loadSpec } from "../src/load";
import { extractSchemas } from "../src/schemas";

const FIXTURE = `${import.meta.dir}/../fixtures/tiny-api.yaml`;

describe("extractSchemas", () => {
  test("stores one row per component schema", async () => {
    const rows = extractSchemas(await loadSpec(FIXTURE), "tiny");
    expect(rows).toHaveLength(2);
    expect(rows.map((r) => r.name).sort()).toEqual([
      "#/components/schemas/Owner",
      "#/components/schemas/Widget",
    ]);
  });

  test("leaves nested $refs unresolved", async () => {
    const rows = extractSchemas(await loadSpec(FIXTURE), "tiny");
    const widget = rows.find((r) => r.name.endsWith("/Widget"));
    const parsed = JSON.parse(widget?.json ?? "{}");
    expect(parsed.properties.owner).toEqual({
      $ref: "#/components/schemas/Owner",
    });
  });

  test("namespaces rows by api", async () => {
    const rows = extractSchemas(await loadSpec(FIXTURE), "tiny");
    expect(rows.every((r) => r.api === "tiny")).toBe(true);
  });

  test("returns an empty list when there are no components", async () => {
    const doc = await loadSpec(FIXTURE);
    doc.components = undefined;
    expect(extractSchemas(doc, "tiny")).toEqual([]);
  });

  test("tracks the given api rather than a fixed value", async () => {
    const rows = extractSchemas(await loadSpec(FIXTURE), "other");
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.every((r) => r.api === "other")).toBe(true);
  });
});
