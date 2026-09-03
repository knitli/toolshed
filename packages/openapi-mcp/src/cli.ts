#!/usr/bin/env node
import { readFile, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { type ParseArgsConfig, parseArgs } from "node:util";
import { compile } from "./compile.ts";
import { generateKeypair, signArtifact, verifyArtifact } from "./sign.ts";

const USAGE = `openapi-mcp — compile OpenAPI documents into signed MCP artifacts

  compile --spec <path> --api <name> --out <path> [--append] [--permissions <path>] [--sign-key <path>]
  verify --artifact <path> --sig <path> --pub <path>
  keygen [--out <dir>]
`;

function fail(message: string, opts: { usage?: boolean } = {}): never {
  console.error(
    opts.usage === false ? `error: ${message}` : `error: ${message}\n\n${USAGE}`,
  );
  process.exit(1);
}

/** parseArgs throws on unknown flags and missing values; route that through fail. */
function parseOrFail<T extends ParseArgsConfig>(config: T) {
  try {
    return parseArgs(config);
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  }
}

const [command, ...rest] = process.argv.slice(2);

if (command === "keygen") {
  const { values } = parseOrFail({
    args: rest,
    options: { out: { type: "string" } },
    strict: true,
  });
  const dir = values.out ?? ".";
  const pubPath = join(dir, "openapi-mcp.pub");
  const keyPath = join(dir, "openapi-mcp.key");
  try {
    const { publicKeyPem, privateKeyPem } = generateKeypair();
    // "wx" fails with EEXIST on any existing file *or* symlink (dangling or
    // not) instead of following it — existsSync + a separate write would
    // both race and let a pre-planted symlink redirect these bytes.
    await writeFile(pubPath, publicKeyPem, { flag: "wx" });
    try {
      await writeFile(keyPath, privateKeyPem, { flag: "wx", mode: 0o600 });
    } catch (err) {
      // All-or-nothing: never leave a public key with no matching private key.
      await unlink(pubPath).catch(() => {});
      throw err;
    }
  } catch (err) {
    const e = err as NodeJS.ErrnoException;
    if (e.code === "EEXIST") fail(`${e.path} exists`, { usage: false });
    fail(e instanceof Error ? e.message : String(e), { usage: false });
  }
  console.log(pubPath);
  console.log(keyPath);
  process.exit(0);
}

if (command === "verify") {
  const { values } = parseOrFail({
    args: rest,
    options: {
      artifact: { type: "string" },
      sig: { type: "string" },
      pub: { type: "string" },
    },
    strict: true,
  });
  if (!values.artifact) fail("--artifact is required");
  if (!values.sig) fail("--sig is required");
  if (!values.pub) fail("--pub is required");

  let ok: boolean;
  try {
    const sigB64 = (await readFile(values.sig, "utf8")).trim();
    const pubPem = await readFile(values.pub, "utf8");
    ok = await verifyArtifact(values.artifact, sigB64, pubPem);
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err), { usage: false });
  }
  console.log(ok ? "valid" : "invalid");
  process.exit(ok ? 0 : 1);
}

if (command !== "compile") {
  fail(command ? `unknown command "${command}"` : "no command given");
}

const { values } = parseOrFail({
  args: rest,
  options: {
    spec: { type: "string" },
    api: { type: "string" },
    out: { type: "string" },
    append: { type: "boolean" },
    permissions: { type: "string" },
    "sign-key": { type: "string" },
  },
  strict: true,
});

if (!values.spec) fail("--spec is required");
if (!values.api) fail("--api is required");
if (!values.out) fail("--out is required");

const started = Date.now();
try {
  const result = await compile({
    specPath: values.spec,
    api: values.api,
    outPath: values.out,
    append: values.append === true,
    permissionsPath: values.permissions,
  });

  console.log(
    `compiled ${result.operations} operations, ${result.schemas} schemas ` +
      `(${result.mapped} permission-mapped) in ${Date.now() - started} ms -> ${values.out}`,
  );

  if (values["sign-key"]) {
    const privateKeyPem = await readFile(values["sign-key"], "utf8");
    const sig = await signArtifact(values.out, privateKeyPem);
    await writeFile(`${values.out}.sig`, sig);
    console.log(`signed -> ${values.out}.sig`);
  }
} catch (err) {
  fail(err instanceof Error ? err.message : String(err), { usage: false });
}
