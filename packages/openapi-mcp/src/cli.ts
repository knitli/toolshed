#!/usr/bin/env node
import { readFile, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { type ParseArgsConfig, parseArgs } from "node:util";
import { compile } from "./compile.ts";
import { compileRelease } from "./release/compile-release.ts";
import { publishRelease } from "./release/publish.ts";
import { generateKeypair, signArtifact, verifyArtifact } from "./sign.ts";

const USAGE = `openapi-mcp — compile OpenAPI documents into signed MCP artifacts

  compile --spec <path> --api <name> --out <path> [--append] [--permissions <path>] [--sign-key <path>]  (legacy v3)
  compile-release --spec <path> (--source-uri <https-uri> | --source-label <label>) --source-revision <revision>
    --catalog <id> --release <id> --generation <n> --issuer <id> --key-id <id>
    --policy-id <id> --allowed-origin <https-origin> --out <directory> --sign-key <path>
    [--permissions <path>] [--reference-root <path> --reference-map <path>]
  verify --artifact <path> --sig <path> --pub <path>  (legacy v3 exact-file signature)
  keygen [--out <dir>]
`;

const DIAGNOSTIC_UNSAFE_CHARACTERS =
  // biome-ignore lint/suspicious/noControlCharactersInRegex: diagnostics must visibly encode terminal controls.
  /[\u0000-\u001F\u007F-\u009F\u2028\u2029\p{Cf}]/gu;

function renderDiagnostic(message: string): string {
  return message.replace(DIAGNOSTIC_UNSAFE_CHARACTERS, (character) => {
    const codePoint = character.codePointAt(0);
    if (codePoint === undefined) return "�";
    return `\\u${codePoint.toString(16).toUpperCase().padStart(4, "0")}`;
  });
}

function fail(message: string, opts: { usage?: boolean } = {}): never {
  console.error(
    opts.usage === false
      ? `error: ${renderDiagnostic(message)}`
      : `error: ${renderDiagnostic(message)}\n\n${USAGE}`,
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

if (command === "compile-release") {
  const { values } = parseOrFail({
    args: rest,
    options: {
      spec: { type: "string" },
      "source-uri": { type: "string" },
      "source-label": { type: "string" },
      "source-revision": { type: "string" },
      catalog: { type: "string" },
      release: { type: "string" },
      generation: { type: "string" },
      issuer: { type: "string" },
      "key-id": { type: "string" },
      "policy-id": { type: "string" },
      "allowed-origin": { type: "string", multiple: true },
      out: { type: "string" },
      "sign-key": { type: "string" },
      permissions: { type: "string" },
      "reference-root": { type: "string" },
      "reference-map": { type: "string" },
    },
    strict: true,
  });
  for (const [flag, value] of [
    ["--spec", values.spec],
    ["--source-revision", values["source-revision"]],
    ["--catalog", values.catalog],
    ["--release", values.release],
    ["--generation", values.generation],
    ["--issuer", values.issuer],
    ["--key-id", values["key-id"]],
    ["--policy-id", values["policy-id"]],
    ["--allowed-origin", values["allowed-origin"]?.[0]],
    ["--out", values.out],
    ["--sign-key", values["sign-key"]],
  ] as const)
    if (!value) fail(`${flag} is required`);
  if (
    (values["source-uri"] === undefined) ===
    (values["source-label"] === undefined)
  ) {
    fail("exactly one of --source-uri or --source-label is required");
  }
  if (
    (values["reference-root"] === undefined) !==
    (values["reference-map"] === undefined)
  ) {
    fail("--reference-root and --reference-map must be supplied together");
  }
  const generation = Number(values.generation);
  if (!Number.isSafeInteger(generation) || generation < 0)
    fail("--generation must be a non-negative safe integer");
  try {
    const privateKeyPem = await readFile(
      values["sign-key"] as string,
      "utf8",
    ).catch((error) => {
      throw new Error("signing key could not be read", { cause: error });
    });
    const provenance =
      values["source-uri"] !== undefined
        ? { sourceUri: values["source-uri"] }
        : { sourceLabel: values["source-label"] as string };
    const compiled = await compileRelease({
      ...provenance,
      specPath: values.spec as string,
      sourceRevision: values["source-revision"] as string,
      catalogId: values.catalog as string,
      releaseId: values.release as string,
      generation,
      issuer: values.issuer as string,
      keyId: values["key-id"] as string,
      policyId: values["policy-id"] as string,
      allowedOrigins: values["allowed-origin"] as string[],
      outDir: values.out as string,
      privateKeyPem,
      permissionsPath: values.permissions,
      referenceRoot: values["reference-root"],
      referenceMapPath: values["reference-map"],
    });
    await publishRelease(compiled, { directory: values.out as string });
    console.log(`compiled immutable v4 release ${values.release}`);
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err), { usage: false });
  }
  process.exit(0);
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
