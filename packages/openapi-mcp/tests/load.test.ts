import { describe, expect, test } from "bun:test";
import { loadSpec } from "../src/load";

const FIXTURE = `${import.meta.dir}/../fixtures/tiny-api.yaml`;

describe("loadSpec", () => {
  test("parses YAML", async () => {
    const doc = await loadSpec(FIXTURE);
    expect(doc.openapi).toBe("3.0.4");
    expect(Object.keys(doc.paths)).toHaveLength(4);
  });

  test("parses JSON with the same result", async () => {
    const yaml = await loadSpec(FIXTURE);
    const jsonPath = `${import.meta.dir}/tmp-load.json`;
    await Bun.write(jsonPath, JSON.stringify(yaml));
    const json = await loadSpec(jsonPath);
    expect(json).toEqual(yaml);
  });

  test("rejects a document with no paths", async () => {
    const bad = `${import.meta.dir}/tmp-bad.json`;
    await Bun.write(bad, JSON.stringify({ openapi: "3.0.4" }));
    expect(loadSpec(bad)).rejects.toThrow(/paths/);
  });
});
