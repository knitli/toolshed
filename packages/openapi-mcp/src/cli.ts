#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { compile } from "./compile.ts";
import { generateKeypair, signArtifact } from "./sign.ts";

const USAGE = `openapi-mcp — compile OpenAPI documents into signed MCP artifacts

  compile --spec <path> --api <name> --out <path> [--append] [--permissions <path>] [--sign-key <path>]
  keygen
`;

function fail(message: string): never {
  console.error(`error: ${message}\n\n${USAGE}`);
  process.exit(1);
}

const [command, ...rest] = process.argv.slice(2);

if (command === "keygen") {
  const { publicKeyPem, privateKeyPem } = generateKeypair();
  console.log(publicKeyPem);
  console.log(privateKeyPem);
  process.exit(0);
}

if (command !== "compile") {
  fail(command ? `unknown command "${command}"` : "no command given");
}

const { values } = parseArgs({
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
