import { describe, expect, test } from "bun:test";
import type { OpenApiDoc } from "../src/load";
import { loadSpec } from "../src/load";
import { extractOperations, MAX_SUMMARY } from "../src/operations";

const FIXTURE = `${import.meta.dir}/../fixtures/tiny-api.yaml`;
const load = async () => extractOperations(await loadSpec(FIXTURE), "tiny");
const byId = async (id: string) => {
  const op = (await load()).find((o) => o.qualifiedId === id);
  if (!op) throw new Error(`missing ${id}`);
  return op;
};

describe("extractOperations", () => {
  test("extracts one record per method per path", async () => {
    expect(await load()).toHaveLength(6);
  });

  test("qualified ids are namespaced by api", async () => {
    const ids = (await load()).map((o) => o.qualifiedId).sort();
    expect(ids).toContain("tiny:widgets.ListWidgets");
  });

  test("carries method, path, summary and tags", async () => {
    const op = await byId("tiny:widgets.ListWidgets");
    expect(op.method).toBe("GET");
    expect(op.path).toBe("/widgets");
    expect(op.summary).toBe("List widgets");
    expect(op.tags).toBe("widgets");
  });

  test("detects x-ms-pageable", async () => {
    expect((await byId("tiny:widgets.ListWidgets")).pageable).toBe(true);
    expect((await byId("tiny:widgets.widget.GetWidget")).pageable).toBe(false);
  });

  test("detects deprecated", async () => {
    expect((await byId("tiny:widgets.widget.DeleteWidget")).deprecated).toBe(true);
    expect((await byId("tiny:widgets.ListWidgets")).deprecated).toBe(false);
  });

  test("stores requestBody as an unresolved $ref", async () => {
    const op = await byId("tiny:widgets.CreateWidget");
    expect(op.bodyRef).toBe("#/components/schemas/Widget");
  });

  test("applies safety classification including overrides", async () => {
    expect((await byId("tiny:widgets.ListWidgets")).safety).toBe("read");
    expect((await byId("tiny:widgets.CreateWidget")).safety).toBe("write");
    expect((await byId("tiny:widgets.getByIds")).safety).toBe("read");
    expect((await byId("tiny:batch.Batch")).safety).toBe("write");
  });

  test("$batch is high risk", async () => {
    expect((await byId("tiny:batch.Batch")).risk).toBe("high");
  });

  test("collects path parameters", async () => {
    const op = await byId("tiny:widgets.widget.GetWidget");
    const params = JSON.parse(op.paramsJson) as Array<{ name: string; required: boolean }>;
    expect(params).toHaveLength(1);
    expect(params[0].name).toBe("widget-id");
    expect(params[0].required).toBe(true);
  });

  test("merges path-item-level parameters with operation-level parameters", async () => {
    // 10,101 of Microsoft Graph's 11,493 paths declare parameters at the
    // path-item level, not the operation level — tiny-api.yaml never does,
    // so this must be an inline doc, not a fixture mutation.
    const doc: OpenApiDoc = {
      openapi: "3.0.4",
      servers: [{ url: "https://tiny.example.com" }],
      paths: {
        "/widgets/{widget-id}/parts": {
          parameters: [
            { name: "widget-id", in: "path", required: true, schema: { type: "string" } },
          ],
          get: {
            operationId: "widgets.widget.ListParts",
            parameters: [
              { name: "limit", in: "query", required: false, schema: { type: "integer" } },
            ],
            responses: { "200": { description: "ok" } },
          },
        },
      },
    };
    const op = extractOperations(doc, "tiny").find(
      (o) => o.qualifiedId === "tiny:widgets.widget.ListParts",
    );
    if (!op) throw new Error("missing tiny:widgets.widget.ListParts");
    const names = (JSON.parse(op.paramsJson) as Array<{ name: string }>)
      .map((p) => p.name)
      .sort();
    expect(names).toEqual(["limit", "widget-id"]);
  });

  test("uses the document server url", async () => {
    expect((await byId("tiny:widgets.ListWidgets")).serverUrl).toBe(
      "https://tiny.example.com",
    );
  });

  test("truncates summaries at MAX_SUMMARY", async () => {
    const doc = await loadSpec(FIXTURE);
    doc.paths["/widgets"].get.summary = "x".repeat(MAX_SUMMARY + 50);
    const op = extractOperations(doc, "tiny").find(
      (o) => o.qualifiedId === "tiny:widgets.ListWidgets",
    );
    expect(op?.summary?.length).toBe(MAX_SUMMARY);
  });

  test("throws on a duplicate operationId", async () => {
    const doc = await loadSpec(FIXTURE);
    doc.paths["/widgets"].get.operationId = "widgets.CreateWidget";
    expect(() => extractOperations(doc, "tiny")).toThrow(/duplicate/i);
  });

  test("throws when an operation has no operationId", async () => {
    const doc = await loadSpec(FIXTURE);
    doc.paths["/widgets"].get.operationId = undefined;
    expect(() => extractOperations(doc, "tiny")).toThrow(/operationId/);
  });

  test("throws on an operation-level servers override", () => {
    // Real documents (Microsoft Graph included) never declare these — this
    // must be an inline doc, not a fixture mutation. The compiler fails
    // closed rather than silently emitting the wrong server_url.
    const doc: OpenApiDoc = {
      openapi: "3.0.4",
      servers: [{ url: "https://tiny.example.com" }],
      paths: {
        "/widgets": {
          get: {
            operationId: "widgets.ListWidgets",
            servers: [{ url: "https://override.example.com" }],
            responses: { "200": { description: "ok" } },
          },
        },
      },
    };
    expect(() => extractOperations(doc, "tiny")).toThrow(/servers/);
  });

  test("throws on a path-item-level servers override", () => {
    const doc: OpenApiDoc = {
      openapi: "3.0.4",
      servers: [{ url: "https://tiny.example.com" }],
      paths: {
        "/widgets": {
          servers: [{ url: "https://override.example.com" }],
          get: {
            operationId: "widgets.ListWidgets",
            responses: { "200": { description: "ok" } },
          },
        },
      },
    };
    expect(() => extractOperations(doc, "tiny")).toThrow(/servers/);
  });
});
