import { expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

interface PackageExportTarget {
  readonly default: string;
  readonly types: string;
}

function sourceEntrypointFor(target: string): string {
  return join(
    import.meta.dir,
    "..",
    target.replace(/^\.\/dist\//, "src/").replace(/(?:\.d)?\.ts$|\.js$/, ".ts"),
  );
}

test("every advertised package export has an emit-capable source entrypoint", () => {
  const packageJson = JSON.parse(
    readFileSync(join(import.meta.dir, "..", "package.json"), "utf8"),
  ) as { readonly exports: Readonly<Record<string, PackageExportTarget>> };

  for (const [subpath, entrypoint] of Object.entries(packageJson.exports)) {
    expect(sourceEntrypointFor(entrypoint.default), subpath).toSatisfy(
      existsSync,
    );
    expect(sourceEntrypointFor(entrypoint.types), subpath).toSatisfy(
      existsSync,
    );
  }
});

test("runtime exposes the Phase 2 contract versions", async () => {
  const runtime = await import("../src/runtime/index.ts");
  expect(runtime.ARTIFACT_FORMAT_VERSION).toBe(4);
  expect(runtime.RUNTIME_CONTRACT_VERSION).toBe(1);
  expect(runtime.PREPARED_CALL_VERSION).toBe(1);
  expect(runtime.MAX_SEARCH_QUERY_BYTES).toBe(4 * 1024);
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

test("Worker consumer type-checks the portable contract", () => {
  const result = Bun.spawnSync({
    cmd: [
      `${import.meta.dir}/../node_modules/.bin/tsc`,
      "--noEmit",
      "--ignoreConfig",
      "--target",
      "esnext",
      "--module",
      "nodenext",
      "--moduleResolution",
      "nodenext",
      "--allowImportingTsExtensions",
      "--strict",
      "--skipLibCheck",
      `${import.meta.dir}/../test-consumers/worker.ts`,
    ],
    stderr: "pipe",
  });

  expect(result.exitCode).toBe(0);
});
