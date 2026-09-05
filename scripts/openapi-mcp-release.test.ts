import { expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createReleaseAdapter,
  verifyAuditBinding,
} from "./openapi-mcp-release.mjs";

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "openapi-release-test-"));
  const cwd = join(root, "repository/packages/openapi-mcp");
  const runnerTemp = join(root, "runner");
  await mkdir(cwd, { recursive: true });
  await mkdir(runnerTemp);
  await mkdir(join(root, "repository/.github/workflows"), { recursive: true });
  await writeFile(
    join(root, "repository/.github/workflows/release.yml"),
    "name: Release\n",
  );
  await writeFile(
    join(cwd, "package.json"),
    JSON.stringify({
      name: "@knitli/openapi-mcp",
      version: "0.0.0",
      private: false,
      repository: {
        type: "git",
        url: "https://github.com/knitli/toolshed",
        directory: "packages/openapi-mcp",
      },
      publishConfig: {
        registry: "https://registry.npmjs.org/",
        access: "public",
        provenance: true,
      },
      engines: { node: ">=24.16.0 <25", bun: ">=1.4.0" },
    }),
  );
  const calls: { command: string[]; cwd: string }[] = [];
  const adapter = createReleaseAdapter({
    run: async (command: string[], options: { cwd: string }) => {
      calls.push({ command, cwd: options.cwd });
      if (command[0] === "bun" && command[1] === "pm")
        await writeFile(
          command[command.indexOf("--filename") + 1],
          "exact tested tarball",
        );
    },
    verifyNpm: async () => {},
  });
  const context = {
    cwd,
    env: {
      RUNNER_TEMP: runnerTemp,
      GITHUB_ACTIONS: "true",
      GITHUB_REPOSITORY: "knitli/toolshed",
      GITHUB_REF: "refs/heads/main",
      GITHUB_WORKFLOW_REF:
        "knitli/toolshed/.github/workflows/release.yml@refs/heads/main",
      GITHUB_SHA: "a".repeat(40),
      GITHUB_RUN_ID: "123",
      GITHUB_RUN_ATTEMPT: "1",
      ACTIONS_ID_TOKEN_REQUEST_URL:
        "https://token.actions.githubusercontent.com",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "fixture-only",
      OPENAPI_MCP_RELEASE_ENVIRONMENT: "npmrelease",
      OPENAPI_MCP_OIDC_READY: "true",
    },
    nextRelease: { version: "1.2.3", channel: undefined },
    options: {},
    logger: { log() {} },
  };
  return { root, cwd, runnerTemp, adapter, context, calls };
}

test("release prepares nextRelease.version with Bun and publishes only the tested absolute tarball from clean runner temp", async () => {
  const f = await fixture();
  await f.adapter.verifyConditions({}, f.context);
  await f.adapter.prepare({}, f.context);
  expect(
    JSON.parse(await readFile(join(f.cwd, "package.json"), "utf8")).version,
  ).toBe("1.2.3");
  const packed = f.calls.find((call) => call.command[1] === "pm");
  const tarball =
    packed?.command[(packed?.command.indexOf("--filename") ?? -1) + 1];
  expect(tarball?.startsWith(f.runnerTemp)).toBe(true);
  const result = await f.adapter.publish({}, f.context);
  const publish = f.calls.find((call) => call.command[0] === "npm");
  expect(publish?.command).toEqual([
    "npm",
    "publish",
    tarball,
    "--access",
    "public",
    "--tag",
    "latest",
    "--provenance",
    "--registry=https://registry.npmjs.org/",
  ]);
  expect(publish?.cwd.startsWith(f.runnerTemp)).toBe(true);
  expect(publish?.cwd).not.toBe(f.cwd);
  expect(result.version).toBe("1.2.3");
  expect(f.calls.some((call) => call.command[1] === "test")).toBe(true);
});

test("release refuses absent and modified prepared tarballs before npm can run", async () => {
  const f = await fixture();
  await expect(f.adapter.publish({}, f.context)).rejects.toThrow(
    "tested tarball",
  );
  await f.adapter.verifyConditions({}, f.context);
  await f.adapter.prepare({}, f.context);
  const packed = f.calls.find((call) => call.command[1] === "pm");
  if (!packed) throw new Error("No pack command was executed");
  await writeFile(
    packed.command[packed.command.indexOf("--filename") + 1],
    "tampered bytes",
  );
  await expect(f.adapter.publish({}, f.context)).rejects.toThrow("digest");
  expect(f.calls.filter((call) => call.command[0] === "npm")).toEqual([]);
});

test("bootstrap cleanup checks environment mappings while allowing harmless token documentation", async () => {
  const f = await fixture();
  const workflow = join(f.root, "repository/.github/workflows/release.yml");
  await writeFile(
    workflow,
    "# Remove NODE_AUTH_TOKEN: before release\nname: Release\n",
  );
  await f.adapter.verifyConditions({}, f.context);
  await writeFile(
    workflow,
    // biome-ignore lint/suspicious/noTemplateCurlyInString: literal GitHub Actions expression is fixture input.
    'jobs:\n  bootstrap:\n    steps:\n      - env: {"NODE_AUTH_TOKEN": "${{ secrets.OPENAPI_MCP_BOOTSTRAP_TOKEN }}"}\n',
  );
  await expect(f.adapter.verifyConditions({}, f.context)).rejects.toThrow(
    "bootstrap token wiring",
  );
});

test("audit gate requires the verified package, tested tarball digest, source commit and exact workflow run", () => {
  const expected = {
    version: "1.2.3",
    sha512: "b".repeat(128),
    sourceCommit: "a".repeat(40),
    runId: "123",
    runAttempt: "1",
  };
  const statement = {
    predicateType: "https://slsa.dev/provenance/v1",
    subject: [
      {
        name: "pkg:npm/%40knitli/openapi-mcp@1.2.3",
        digest: { sha512: expected.sha512 },
      },
    ],
    predicate: {
      buildDefinition: {
        externalParameters: {
          workflow: {
            repository: "https://github.com/knitli/toolshed",
            path: ".github/workflows/release.yml",
            ref: "refs/heads/main",
          },
        },
        resolvedDependencies: [
          { digest: { gitCommit: expected.sourceCommit } },
        ],
      },
      runDetails: {
        metadata: {
          invocationId:
            "https://github.com/knitli/toolshed/actions/runs/123/attempts/1",
        },
      },
    },
  };
  const audit = {
    invalid: [],
    missing: [],
    verified: [
      {
        name: "@knitli/openapi-mcp",
        version: "1.2.3",
        registry: "https://registry.npmjs.org/",
        attestationBundles: [
          {
            predicateType: statement.predicateType,
            bundle: {
              dsseEnvelope: {
                payload: Buffer.from(JSON.stringify(statement)).toString(
                  "base64",
                ),
              },
            },
          },
        ],
      },
    ],
  };
  expect(verifyAuditBinding(audit, expected).sourceCommit).toBe(
    expected.sourceCommit,
  );
  for (const bad of [
    { ...expected, sha512: "c".repeat(128) },
    { ...expected, sourceCommit: "d".repeat(40) },
    { ...expected, runId: "124" },
    { ...expected, version: "1.2.4" },
  ]) {
    expect(() => verifyAuditBinding(audit, bad)).toThrow();
  }
  expect(() =>
    verifyAuditBinding({ ...audit, invalid: [{}] }, expected),
  ).toThrow();
  expect(() =>
    verifyAuditBinding({ ...audit, verified: [] }, expected),
  ).toThrow();
});

test("manual bootstrap dispatch cannot run unrelated releases or stable publication", async () => {
  const workflow = Bun.YAML.parse(
    await readFile(
      new URL("../.github/workflows/release.yml", import.meta.url),
      "utf8",
    ),
  ) as {
    jobs: Record<
      string,
      {
        if: string;
        needs?: string | string[];
        steps?: { name?: string; if?: string }[];
      }
    >;
  };
  const context = {
    github: {
      event_name: "workflow_dispatch",
      ref: "refs/heads/main",
      actor: "approved-owner",
    },
    vars: {
      OPENAPI_MCP_OIDC_READY: "true",
      OPENAPI_MCP_BOOTSTRAP_ENABLED: "true",
      OPENAPI_MCP_BOOTSTRAP_OWNER: "approved-owner",
    },
    inputs: { bootstrap: true, approved_owner: "approved-owner" },
  };
  // This workflow uses only conjunctions, exact equality, and boolean inputs.
  // Unknown expression syntax fails the test instead of silently evaluating it.
  function value(expression: string): unknown {
    if (/^'[^']*'$/.test(expression)) return expression.slice(1, -1);
    if (!/^(github|vars|inputs)\.[A-Za-z_]+$/.test(expression))
      throw new Error(`Unsupported expression: ${expression}`);
    const [object, key] = expression.split(".");
    return (context as unknown as Record<string, Record<string, unknown>>)[
      object
    ][key];
  }
  function runs(name: string): boolean {
    const job = workflow.jobs[name];
    const enabled = job.if.split(" && ").every((term) => {
      const operands = term.split(" == ");
      return operands.length === 2
        ? value(operands[0]) === value(operands[1])
        : value(term) === true;
    });
    const needs = job.needs
      ? Array.isArray(job.needs)
        ? job.needs
        : [job.needs]
      : [];
    return enabled && needs.every(runs);
  }
  for (const job of ["release", "release-marketplace", "release-openapi-mcp"])
    expect(runs(job)).toBe(false);
  expect(runs("bootstrap-openapi-mcp-pack")).toBe(true);
  expect(runs("bootstrap-openapi-mcp-publish")).toBe(true);
  context.github.actor = "unapproved-actor";
  expect(runs("bootstrap-openapi-mcp-publish")).toBe(false);
  context.github.event_name = "push";
  expect(runs("release")).toBe(true);
  expect(runs("release-openapi-mcp")).toBe(true);
  expect(runs("release-marketplace")).toBe(true);
  expect(runs("bootstrap-openapi-mcp-publish")).toBe(false);
  for (const name of [
    "Release exact tested openapi-mcp tarball through OIDC",
    "Verify fresh public install and registry attestations",
  ]) {
    const step = workflow.jobs["release-openapi-mcp"].steps?.find(
      (candidate) => candidate.name === name,
    );
    if (!step?.if)
      throw new Error("Publication must have an explicit readiness gate");
    const [left, right] = step.if.split(" == ");
    expect(value(left) === value(right)).toBe(true);
    context.vars.OPENAPI_MCP_OIDC_READY = "false";
    expect(value(left) === value(right)).toBe(false);
    expect(runs("release-openapi-mcp")).toBe(true);
    expect(runs("release-marketplace")).toBe(true);
    context.vars.OPENAPI_MCP_OIDC_READY = "true";
  }
});

test("release rejects token authentication, bootstrap version, wrong package and wrong workflow context", async () => {
  for (const change of [
    (f: Awaited<ReturnType<typeof fixture>>) => {
      Object.assign(f.context.env, { NODE_AUTH_TOKEN: "fixture-only" });
    },
    (f: Awaited<ReturnType<typeof fixture>>) => {
      f.context.nextRelease.version = "0.0.0";
    },
    (f: Awaited<ReturnType<typeof fixture>>) => {
      f.context.env.GITHUB_REPOSITORY = "someone/else";
    },
    async (f: Awaited<ReturnType<typeof fixture>>) => {
      await writeFile(
        join(f.cwd, "package.json"),
        JSON.stringify({ name: "other-package" }),
      );
    },
  ]) {
    const f = await fixture();
    await change(f);
    await expect(f.adapter.verifyConditions({}, f.context)).rejects.toThrow();
    expect(f.calls).toEqual([]);
  }
});
