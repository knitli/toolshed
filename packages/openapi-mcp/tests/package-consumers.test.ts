import { expect, test } from "bun:test";

test("runtime exposes the Phase 2 contract versions", async () => {
  const runtime = await import("../src/runtime/index.ts");
  expect(runtime.ARTIFACT_FORMAT_VERSION).toBe(4);
  expect(runtime.RUNTIME_CONTRACT_VERSION).toBe(1);
  expect(runtime.PREPARED_CALL_VERSION).toBe(1);
});

test("runtime bundles for a Worker target without Node shims", async () => {
  const result = await Bun.build({
    entrypoints: [`${import.meta.dir}/../test-consumers/worker.ts`],
    target: "browser",
    throw: false,
  });

  expect(result.success).toBe(true);
  expect(result.logs.map(String).join("\n")).not.toMatch(/node:|bun:/);
});
