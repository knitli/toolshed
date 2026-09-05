import { beforeAll, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const packageRoot = resolve(import.meta.dir, "..");
const repository = resolve(packageRoot, "../..");
let root: string;
let tarball: string;
let files: string[];

async function run(cmd: string[], cwd: string): Promise<string> {
  const child = Bun.spawn(cmd, {
    cwd,
    stdout: "pipe",
    stderr: "pipe",
    env: {
      ...process.env,
      npm_config_cache: join(root, "npm-cache"),
      BUN_INSTALL_CACHE_DIR: join(root, "bun-cache"),
    },
  });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  if (status !== 0)
    throw new Error(
      `${cmd.join(" ")} (exit ${status})\n${stdout}\n${stderr}\nEvidence: ${root}`,
    );
  return stdout;
}

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), "openapi-mcp-consumers-"));
  tarball = process.env.OPENAPI_MCP_TARBALL
    ? resolve(process.env.OPENAPI_MCP_TARBALL)
    : join(root, "openapi-mcp.tgz");
  if (!process.env.OPENAPI_MCP_TARBALL) {
    await run(["bun", "run", "build"], packageRoot);
    await run(
      ["bun", "pm", "pack", "--filename", tarball, "--quiet"],
      packageRoot,
    );
  }
  files = (await run(["tar", "-tzf", tarball], root)).trim().split("\n");
  await run(["tar", "-xzf", tarball, "-C", root], root);
  const sha256 = createHash("sha256")
    .update(await readFile(tarball))
    .digest("hex");
  const evidence = { tarball, sha256, root, files };
  await writeFile(
    join(root, "pack-evidence.json"),
    `${JSON.stringify(evidence, null, 2)}\n`,
  );
  console.log(
    `Packed consumer evidence: ${JSON.stringify({ tarball, sha256, root })}`,
  );
}, 120_000);

test("tarball contains executable exports, declarations and both complete licenses", async () => {
  const manifest = JSON.parse(
    await readFile(join(root, "package/package.json"), "utf8"),
  );
  for (const subpath of [
    "./compiler",
    "./runtime",
    "./sqlite",
    "./stdio",
    "./conformance",
  ]) {
    const entry = manifest.exports[subpath];
    expect(entry, subpath).toBeDefined();
    expect(files).toContain(`package/${entry.default.slice(2)}`);
    expect(files).toContain(`package/${entry.types.slice(2)}`);
  }
  expect(files).toContain("package/dist/cli.js");
  expect(files).toContain("package/README.md");
  expect(files).toContain("package/LICENSE-MIT");
  expect(files).toContain("package/LICENSE-APACHE");
  // SHA-256 of the unmodified official apache.org/licenses/LICENSE-2.0.txt.
  expect(
    createHash("sha256")
      .update(await readFile(join(root, "package/LICENSE-APACHE")))
      .digest("hex"),
  ).toBe("cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30");
  expect(await readFile(join(root, "package/LICENSE-MIT"), "utf8")).toBe(
    await readFile(join(repository, "LICENSE"), "utf8"),
  );
  expect(await readFile(join(root, "package/LICENSE-APACHE"), "utf8")).toBe(
    await readFile(join(packageRoot, "LICENSE-APACHE"), "utf8"),
  );
  expect(
    files.filter(
      (file) =>
        !/^(package\/(dist\/.*|package\.json|README\.md|LICENSE(?:-MIT|-APACHE)?))$/.test(
          file,
        ),
    ),
  ).toEqual([]);
  expect(files.join("\n")).not.toMatch(
    /\.(?:sqlite|db|pem|key|tgz)$|test-consumers|\/fixtures\/|\.env/m,
  );
  expect(manifest.engines.node).toBe(">=24.16.0 <25");
  expect(manifest.engines.bun).not.toContain("catalog:");
  expect(manifest.devEngines).toBeUndefined();
  expect(manifest.publishConfig.provenance).toBe(true);
});

async function install(name: string): Promise<string> {
  const consumer = join(root, name);
  await mkdir(consumer);
  await writeFile(
    join(consumer, "package.json"),
    JSON.stringify({
      name: `openapi-mcp-${name}-consumer`,
      private: true,
      type: "module",
    }),
  );
  await run(
    name === "bun"
      ? ["bun", "add", "--ignore-scripts", tarball]
      : [
          "npm",
          "install",
          "--ignore-scripts",
          "--no-audit",
          "--no-fund",
          "--registry=https://registry.npmjs.org",
          tarball,
        ],
    consumer,
  );
  return consumer;
}

for (const runtime of ["node", "bun"]) {
  test(`${runtime} installs the exact tarball and executes compiler, SQLite, runtime, stdio and rollback`, async () => {
    const consumer = await install(runtime);
    await copyFile(
      join(packageRoot, "test-consumers/node.mts"),
      join(consumer, "node.mts"),
    );
    await copyFile(
      join(packageRoot, "test-consumers/bun.ts"),
      join(consumer, "bun.ts"),
    );
    const output = await run(
      [runtime, runtime === "node" ? "node.mts" : "bun.ts"],
      consumer,
    );
    expect(JSON.parse(output)).toMatchObject({
      format: 5,
      runtime: 1,
      prepared: 2,
      search: true,
      rollback: true,
      cli: true,
    });
    await writeFile(join(consumer, "consumer-result.json"), output);
  }, 180_000);
}

test("installed Worker declarations compile without host types and bundle without local adapters", async () => {
  const consumer = await install("worker");
  await copyFile(
    join(packageRoot, "test-consumers/worker.ts"),
    join(consumer, "worker.ts"),
  );
  await writeFile(
    join(consumer, "tsconfig.json"),
    JSON.stringify({
      compilerOptions: {
        target: "ES2023",
        module: "NodeNext",
        moduleResolution: "NodeNext",
        lib: ["ES2023", "WebWorker"],
        types: [],
        strict: true,
        noEmit: true,
        skipLibCheck: false,
      },
      files: ["worker.ts"],
    }),
  );
  await run(
    [
      resolve(packageRoot, "node_modules/.bin/tsc"),
      "-p",
      join(consumer, "tsconfig.json"),
    ],
    consumer,
  );
  await run(
    ["bun", "build", "./worker.ts", "--target=browser", "--outdir=build"],
    consumer,
  );
  const outputs = await readdir(join(consumer, "build"));
  expect(outputs.length).toBeGreaterThan(0);
  for (const output of outputs) {
    expect(await readFile(join(consumer, "build", output), "utf8")).not.toMatch(
      /(?:node:|bun:|@modelcontextprotocol|undici)/,
    );
  }
  await writeFile(
    join(consumer, "consumer-result.json"),
    JSON.stringify({
      workerDeclarations: true,
      browserBundle: true,
      actualD1: "pending",
    }),
  );
}, 180_000);
