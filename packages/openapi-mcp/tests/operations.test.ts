import { describe, expect, test } from "bun:test";
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
});
