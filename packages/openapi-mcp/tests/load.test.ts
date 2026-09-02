import { describe, expect, test } from "bun:test";
import { loadSpec } from "../src/load.ts";

const FIXTURE = `${import.meta.dir}/../fixtures/tiny-api.yaml`;

describe("loadSpec", () => {
  test("parses YAML", async () => {
    const doc = await loadSpec(FIXTURE);
    expect(doc.openapi).toBe("3.0.4");
    expect(Object.keys(doc.paths)).toHaveLength(4);
  });

  test("gives stable results when the same doc is re-serialized as JSON", async () => {
    const yaml = await loadSpec(FIXTURE);
    const jsonPath = `${import.meta.dir}/tmp-load.json`;
    await Bun.write(jsonPath, JSON.stringify(yaml));
    const json = await loadSpec(jsonPath);
    expect(json).toEqual(yaml);
  });

  test("routes .json files through JSON.parse, not the YAML parser", async () => {
    // Block-style YAML is valid YAML but invalid JSON (no braces, unquoted
    // keys). If the .json branch dispatched to Bun.YAML.parse instead of
    // JSON.parse, this would parse cleanly and the throw would never fire.
    const path = `${import.meta.dir}/tmp-block-yaml.json`;
    await Bun.write(path, "openapi: 3.0.4\npaths:\n  /x: {}\n");
    await expect(loadSpec(path)).rejects.toThrow();
  });

  test("rejects a document with no paths", async () => {
    const bad = `${import.meta.dir}/tmp-bad.json`;
    await Bun.write(bad, JSON.stringify({ openapi: "3.0.4" }));
    expect(loadSpec(bad)).rejects.toThrow(/paths/);
  });
});
