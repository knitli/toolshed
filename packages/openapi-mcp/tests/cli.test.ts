import { afterEach, describe, expect, test } from "bun:test";
import { unlinkSync } from "node:fs";

const CLI = `${import.meta.dir}/../src/cli.ts`;
const OUT = `${import.meta.dir}/tmp-cli.sqlite`;
const SPEC = `${import.meta.dir}/../fixtures/tiny-api.yaml`;

afterEach(() => {
  for (const f of [OUT, `${OUT}.sig`]) {
    try {
      unlinkSync(f);
    } catch {
      /* already gone */
    }
  }
});

const run = async (args: string[]) => {
  const proc = Bun.spawn(["bun", CLI, ...args], {
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  return { code: await proc.exited, stdout, stderr };
};

describe("cli", () => {
  test("compiles a spec and reports counts", async () => {
    const r = await run(["compile", "--spec", SPEC, "--api", "tiny", "--out", OUT]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("6 operations");
    expect(await Bun.file(OUT).exists()).toBe(true);
  });

  test("exits non-zero when --spec is missing", async () => {
    const r = await run(["compile", "--api", "tiny", "--out", OUT]);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toContain("--spec");
  });

  test("exits non-zero on an unknown subcommand", async () => {
    const r = await run(["frobnicate"]);
    expect(r.code).not.toBe(0);
  });

  test("keygen prints a usable keypair", async () => {
    const r = await run(["keygen"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("BEGIN PUBLIC KEY");
    expect(r.stdout).toContain("BEGIN PRIVATE KEY");
  });
});
