import { afterEach, describe, expect, test } from "bun:test";
import { statSync, unlinkSync } from "node:fs";
import { generateKeypair, signArtifact } from "../src/sign.ts";

const CLI = `${import.meta.dir}/../src/cli.ts`;
const OUT = `${import.meta.dir}/tmp-cli.sqlite`;
const SPEC = `${import.meta.dir}/../fixtures/tiny-api.yaml`;
const PUB = `${import.meta.dir}/openapi-mcp.pub`;
const KEY = `${import.meta.dir}/openapi-mcp.key`;
const SIG = `${import.meta.dir}/tmp-cli.sig`;

afterEach(() => {
  for (const f of [OUT, `${OUT}.sig`, PUB, KEY, SIG]) {
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
    expect(r.stderr).toContain("--spec is required");
  });

  test("exits non-zero on an unknown subcommand", async () => {
    const r = await run(["frobnicate"]);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toContain('unknown command "frobnicate"');
  });

  test("compile runtime failures print a clean error with no stack trace", async () => {
    const r = await run([
      "compile",
      "--spec",
      `${import.meta.dir}/does-not-exist.yaml`,
      "--api",
      "tiny",
      "--out",
      OUT,
    ]);
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("error:");
    expect(r.stderr).not.toContain(" at ");
    expect(r.stderr).not.toContain(CLI);
  });

  test("keygen writes separate public and private key files", async () => {
    const r = await run(["keygen", "--out", import.meta.dir]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain(PUB);
    expect(r.stdout).toContain(KEY);
    expect(await Bun.file(PUB).text()).toContain("BEGIN PUBLIC KEY");
    expect(await Bun.file(KEY).text()).toContain("BEGIN PRIVATE KEY");
  });

  test("keygen writes the private key file with 0600 permissions", async () => {
    const r = await run(["keygen", "--out", import.meta.dir]);
    expect(r.code).toBe(0);
    expect(statSync(KEY).mode & 0o777).toBe(0o600);
  });

  test("keygen refuses to overwrite existing key files", async () => {
    const first = await run(["keygen", "--out", import.meta.dir]);
    expect(first.code).toBe(0);
    const second = await run(["keygen", "--out", import.meta.dir]);
    expect(second.code).toBe(1);
    expect(second.stderr).toContain("error:");
    expect(second.stderr).toContain("exists");
  });

  test("verify accepts a good signature and rejects a tampered artifact", async () => {
    const { publicKeyPem, privateKeyPem } = generateKeypair();
    await Bun.write(OUT, "artifact bytes");
    const sig = await signArtifact(OUT, privateKeyPem);
    await Bun.write(SIG, sig);
    await Bun.write(PUB, publicKeyPem);

    const good = await run(["verify", "--artifact", OUT, "--sig", SIG, "--pub", PUB]);
    expect(good.code).toBe(0);
    expect(good.stdout.trim()).toBe("valid");

    await Bun.write(OUT, "tampered bytes");
    const bad = await run(["verify", "--artifact", OUT, "--sig", SIG, "--pub", PUB]);
    expect(bad.code).toBe(1);
    expect(bad.stdout.trim()).toBe("invalid");
  });
});
