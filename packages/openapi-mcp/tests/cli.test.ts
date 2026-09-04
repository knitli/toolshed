import { afterEach, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { generateKeypair, signArtifact } from "../src/sign.ts";

const CLI = `${import.meta.dir}/../src/cli.ts`;
const OUT = `${import.meta.dir}/tmp-cli.sqlite`;
const SPEC = `${import.meta.dir}/../fixtures/tiny-api.yaml`;
const PUB = `${import.meta.dir}/openapi-mcp.pub`;
const KEY = `${import.meta.dir}/openapi-mcp.key`;
const SIG = `${import.meta.dir}/tmp-cli.sig`;
const V4_ROOTS: string[] = [];

afterEach(() => {
  for (const f of [OUT, `${OUT}.sig`, PUB, KEY, SIG]) {
    try {
      unlinkSync(f);
    } catch {
      /* already gone */
    }
  }
  for (const root of V4_ROOTS.splice(0))
    rmSync(root, { recursive: true, force: true });
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

function v4Fixture(): { root: string; args: string[]; release: string } {
  const root = mkdtempSync(join(import.meta.dir, "tmp-cli-v4-"));
  V4_ROOTS.push(root);
  const spec = join(root, "spec.json");
  const key = join(root, "signing-key.pem");
  const release = "release-cli";
  writeFileSync(
    spec,
    JSON.stringify({
      openapi: "3.1.0",
      info: { title: "CLI", version: "1" },
      servers: [{ url: "https://api.example.test" }],
      paths: {},
    }),
  );
  writeFileSync(key, generateKeypair().privateKeyPem, { mode: 0o600 });
  return {
    root,
    release,
    args: [
      "compile-release",
      "--spec",
      spec,
      "--source-label",
      "cli-fixture",
      "--source-revision",
      "abc123",
      "--catalog",
      "tiny",
      "--release",
      release,
      "--generation",
      "1",
      "--issuer",
      "test-issuer",
      "--key-id",
      "test-key",
      "--policy-id",
      "test-policy",
      "--allowed-origin",
      "https://api.example.test",
      "--out",
      root,
      "--sign-key",
      key,
    ],
  };
}

describe("cli", () => {
  test("compiles a spec and reports counts", async () => {
    const r = await run([
      "compile",
      "--spec",
      SPEC,
      "--api",
      "tiny",
      "--out",
      OUT,
    ]);
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

  test("keygen rolls back the public key when only the private key exists", async () => {
    await Bun.write(KEY, "pre-existing private key");
    const r = await run(["keygen", "--out", import.meta.dir]);
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("exists");
    // The freshly generated public key must not be left behind mismatched.
    expect(existsSync(PUB)).toBe(false);
  });

  test("malformed flags print a clean error with no stack trace", async () => {
    const r = await run(["verify", "--bogus"]);
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("error:");
    expect(r.stderr).not.toContain(" at ");
    expect(r.stderr).not.toContain(CLI);
  });

  test("keygen refuses to write through a pre-planted dangling symlink", async () => {
    const trap = "/tmp/does-not-exist-openapi-mcp-symlink-target";
    symlinkSync(trap, KEY);
    const r = await run(["keygen", "--out", import.meta.dir]);
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("error:");
    expect(r.stderr).toContain("exists");
    // The private key must never be written through the symlink.
    expect(existsSync(trap)).toBe(false);
  });

  test("verify accepts a good signature and rejects a tampered artifact", async () => {
    const { publicKeyPem, privateKeyPem } = generateKeypair();
    await Bun.write(OUT, "artifact bytes");
    const sig = await signArtifact(OUT, privateKeyPem);
    await Bun.write(SIG, sig);
    await Bun.write(PUB, publicKeyPem);

    const good = await run([
      "verify",
      "--artifact",
      OUT,
      "--sig",
      SIG,
      "--pub",
      PUB,
    ]);
    expect(good.code).toBe(0);
    expect(good.stdout.trim()).toBe("valid");

    await Bun.write(OUT, "tampered bytes");
    const bad = await run([
      "verify",
      "--artifact",
      OUT,
      "--sig",
      SIG,
      "--pub",
      PUB,
    ]);
    expect(bad.code).toBe(1);
    expect(bad.stdout.trim()).toBe("invalid");
  });

  test("compile-release requires every frozen identity and signing flag", async () => {
    const { args } = v4Fixture();
    for (const flag of [
      "--spec",
      "--source-revision",
      "--catalog",
      "--release",
      "--generation",
      "--issuer",
      "--key-id",
      "--policy-id",
      "--allowed-origin",
      "--out",
      "--sign-key",
    ]) {
      const index = args.indexOf(flag);
      const candidate = [...args.slice(0, index), ...args.slice(index + 2)];
      const result = await run(candidate);
      expect(result.code, flag).toBe(1);
      expect(result.stderr, flag).toContain(`${flag} is required`);
    }
  });

  test("compile-release requires exactly one source identity", async () => {
    const { args } = v4Fixture();
    const label = args.indexOf("--source-label");
    const neither = [...args.slice(0, label), ...args.slice(label + 2)];
    const missing = await run(neither);
    expect(missing.code).toBe(1);
    expect(missing.stderr).toContain(
      "exactly one of --source-uri or --source-label",
    );

    const both = await run([
      ...args,
      "--source-uri",
      "https://specs.example.test/openapi.json",
    ]);
    expect(both.code).toBe(1);
    expect(both.stderr).toContain(
      "exactly one of --source-uri or --source-label",
    );
  });

  test("compile-release requires reference root and map together", async () => {
    const { args, root } = v4Fixture();
    for (const extra of [
      ["--reference-root", root],
      ["--reference-map", join(root, "map.json")],
    ]) {
      const result = await run([...args, ...extra]);
      expect(result.code).toBe(1);
      expect(result.stderr).toContain(
        "--reference-root and --reference-map must be supplied together",
      );
    }
  });

  test("help labels exact-file compile and verify behavior as legacy v3", async () => {
    const result = await run([]);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("compile ");
    expect(result.stderr).toContain("legacy v3");
    expect(result.stderr).toContain("legacy v3 exact-file signature");
  });

  test("compile-release diagnostics redact signing keys and local paths", async () => {
    const { args, root } = v4Fixture();
    const keyIndex = args.indexOf("--sign-key") + 1;
    const secretPath = join(root, "secret-key-canary.pem");
    const candidate = [...args];
    candidate[keyIndex] = secretPath;
    const result = await run(candidate);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("error:");
    expect(result.stderr).not.toContain(secretPath);
    expect(result.stderr).not.toContain("secret-key-canary");
    expect(result.stderr).not.toContain("BEGIN PRIVATE KEY");
    expect(result.stderr).not.toContain(CLI);
  });

  test("compile-release visibly escapes terminal controls in rejected media types", async () => {
    const { args, root } = v4Fixture();
    const hostileMediaType = "bad\u001b]52;c;clipboard\u0007\u202E.txt";
    writeFileSync(
      join(root, "spec.json"),
      JSON.stringify({
        openapi: "3.1.0",
        info: { title: "CLI", version: "1" },
        servers: [{ url: "https://api.example.test" }],
        paths: {
          "/items": {
            post: {
              operationId: "createItem",
              requestBody: {
                content: { [hostileMediaType]: { schema: { type: "object" } } },
              },
              responses: { "204": { description: "Created" } },
            },
          },
        },
      }),
    );

    const result = await run(args);
    const diagnostic = result.stderr.trimEnd();

    expect(result.code).toBe(1);
    expect(diagnostic).toContain("error: media type");
    expect(diagnostic).toContain("bad\\u001B]52;c;clipboard\\u0007\\u202E.txt");
    for (const unsafe of ["\u001b", "\u0007", "\u202e"])
      expect(diagnostic).not.toContain(unsafe);
  });

  test("compile-release diagnostics escape line, C1, and invisible controls in member text", async () => {
    const { args, root } = v4Fixture();
    const hostileMediaType = "bad\n\u0085\u200B\u2066member";
    writeFileSync(
      join(root, "spec.json"),
      JSON.stringify({
        openapi: "3.1.0",
        info: { title: "CLI", version: "1" },
        servers: [{ url: "https://api.example.test" }],
        paths: {
          "/items": {
            post: {
              operationId: "createItem",
              requestBody: {
                content: { [hostileMediaType]: { schema: { type: "object" } } },
              },
              responses: { "204": { description: "Created" } },
            },
          },
        },
      }),
    );

    const result = await run(args);
    const diagnostic = result.stderr.trimEnd();

    expect(result.code).toBe(1);
    expect(diagnostic).toContain("bad\\u000A\\u0085\\u200B\\u2066member");
    for (const unsafe of ["\n", "\u0085", "\u200b", "\u2066"])
      expect(diagnostic).not.toContain(unsafe);
  });

  test("compile-release emits real artifacts and refuses an existing release", async () => {
    const { args, root, release } = v4Fixture();
    const first = await run(args);
    expect(first.code).toBe(0);
    expect(first.stdout.trim()).toBe(
      `compiled immutable v4 release ${release}`,
    );
    expect(readdirSync(root).sort()).toEqual(
      [
        `${release}.manifest.json`,
        `${release}.manifest.sig`,
        `${release}.sqlite`,
        "signing-key.pem",
        "spec.json",
      ].sort(),
    );

    const second = await run(args);
    expect(second.code).toBe(1);
    expect(second.stderr).toContain("release target already exists");
  });
});
