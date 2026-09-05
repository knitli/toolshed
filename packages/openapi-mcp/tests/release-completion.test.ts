import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const child = fileURLToPath(
  new URL("./helpers/release-completion-fifo.mjs", import.meta.url),
);

for (const mode of ["ordinary", "static-fifo", "swap-fifo"]) {
  for (const sidecar of ["manifest.json", "manifest.sig"]) {
    test(`release completion ${mode} at ${sidecar} finishes without blocking`, () => {
      const directory = mkdtempSync(join(tmpdir(), "openapi-completion-fifo-"));
      try {
        // A parent-enforced deadline can interrupt a blocked native open even
        // when the child's event loop cannot run its own timers.
        const result = spawnSync(
          "node",
          ["--experimental-transform-types", child, directory, mode, sidecar],
          { encoding: "utf8", timeout: 2_000, killSignal: "SIGKILL" },
        );
        expect(result.error).toBeUndefined();
        expect(result.signal).toBeNull();
        expect(result.status).toBe(0);
        expect(JSON.parse(result.stdout)).toEqual({
          outcome: mode === "ordinary" ? "completed" : "rejected",
          ...(mode === "ordinary" ? {} : { code: "MANIFEST_INVALID" }),
        });
      } finally {
        // spawnSync has reaped the child before we remove this test's files.
        rmSync(directory, { recursive: true, force: true });
      }
    });
  }
}
