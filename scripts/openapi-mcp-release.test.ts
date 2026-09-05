import { expect, spyOn, test } from "bun:test";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as release from "./openapi-mcp-release.mjs";
import {
  createReleaseAdapter,
  verifyAuditBinding,
} from "./openapi-mcp-release.mjs";

test("registry readiness retries packument visibility and accepts only the exact release", async () => {
  expect(typeof release.waitForRegistryVersion).toBe("function");
  const responses = [
    new Response(null, { status: 404 }),
    Response.json({ name: "@knitli/openapi-mcp", versions: {} }),
    Response.json({
      name: "@knitli/openapi-mcp",
      versions: {
        "1.2.3": { name: "@knitli/openapi-mcp", version: "1.2.3" },
      },
    }),
  ];
  const delays: number[] = [];
  let requests = 0;
  await release.waitForRegistryVersion("1.2.3", {
    fetch: async (url: string, options: RequestInit) => {
      expect(url).toBe("https://registry.npmjs.org/@knitli%2fopenapi-mcp");
      expect(options.headers).toEqual({
        Accept: "application/vnd.npm.install-v1+json",
      });
      expect(options.signal).toBeInstanceOf(AbortSignal);
      requests++;
      const response = responses.shift();
      if (!response) throw new Error("Unexpected extra registry request");
      return response;
    },
    sleep: async (delay: number) => {
      delays.push(delay);
    },
  });
  expect(requests).toBe(3);
  expect(delays).toEqual([10000, 10000]);
});

test("registry readiness exhausts six visibility attempts without a final sleep", async () => {
  for (const response of [
    () => new Response(null, { status: 404 }),
    () => Response.json({ name: "@knitli/openapi-mcp", versions: {} }),
  ]) {
    let requests = 0;
    const delays: number[] = [];
    await expect(
      release.waitForRegistryVersion("1.2.3", {
        fetch: async () => {
          requests++;
          return response();
        },
        sleep: async (ms: number) => {
          delays.push(ms);
        },
      }),
    ).rejects.toThrow("6 attempts");
    expect(requests).toBe(6);
    expect(delays).toEqual([10000, 10000, 10000, 10000, 10000]);
  }
});

test("registry readiness rejects malformed or mismatched metadata and other HTTP errors immediately", async () => {
  for (const response of [
    new Response("not json"),
    Response.json(null),
    Response.json({ name: "other", versions: {} }),
    Response.json({ name: "@knitli/openapi-mcp" }),
    Response.json({ name: "@knitli/openapi-mcp", versions: [] }),
    Response.json({ name: "@knitli/openapi-mcp", versions: { "1.2.3": null } }),
    Response.json({
      name: "@knitli/openapi-mcp",
      versions: { "1.2.3": { name: "other", version: "1.2.3" } },
    }),
    Response.json({
      name: "@knitli/openapi-mcp",
      versions: { "1.2.3": { name: "@knitli/openapi-mcp", version: "1.2.4" } },
    }),
    new Response(null, { status: 401 }),
    new Response(null, { status: 429 }),
    new Response(null, { status: 500 }),
  ]) {
    let requests = 0;
    let sleeps = 0;
    await expect(
      release.waitForRegistryVersion("1.2.3", {
        fetch: async () => {
          requests++;
          return response;
        },
        sleep: async () => {
          sleeps++;
        },
      }),
    ).rejects.toThrow();
    expect(requests).toBe(1);
    expect(sleeps).toBe(0);
  }
});

test("registry readiness fails closed on network errors and request or body timeouts", async () => {
  for (const stage of ["network", "request", "body"]) {
    const controller = new AbortController();
    const timeout = spyOn(AbortSignal, "timeout").mockImplementation((ms) => {
      expect(ms).toBe(10000);
      return controller.signal;
    });
    let requests = 0;
    let sleeps = 0;
    try {
      await expect(
        Promise.race([
          release.waitForRegistryVersion("1.2.3", {
            fetch: async () => {
              requests++;
              if (stage === "network") throw new Error("network failure");
              if (stage === "request") {
                setTimeout(
                  () =>
                    controller.abort(
                      new DOMException("timed out", "TimeoutError"),
                    ),
                  0,
                );
                return new Promise<Response>(() => {});
              }
              return new Response(
                new ReadableStream({
                  start(stream) {
                    stream.enqueue(new TextEncoder().encode('{"name":'));
                    setTimeout(
                      () =>
                        controller.abort(
                          new DOMException("timed out", "TimeoutError"),
                        ),
                      0,
                    );
                  },
                }),
              );
            },
            sleep: async () => {
              sleeps++;
            },
          }),
          new Promise((_, reject) =>
            setTimeout(
              () => reject(new Error("body read escaped its deadline")),
              100,
            ),
          ),
        ]),
      ).rejects.toThrow(stage === "network" ? "network failure" : "timed out");
      expect(requests).toBe(1);
      expect(sleeps).toBe(0);
    } finally {
      timeout.mockRestore();
    }
  }
});

test("registry readiness rejects non-exact versions before making requests", async () => {
  for (const version of [undefined, "", "latest", "^1.2.3", "1.2.3/other"]) {
    let requests = 0;
    await expect(
      release.waitForRegistryVersion(version, {
        fetch: async () => {
          requests++;
          throw new Error("unexpected request");
        },
      }),
    ).rejects.toThrow("exact stable version");
    expect(requests).toBe(0);
  }
});

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
  expect(f.calls.filter((call) => call.command[1] === "publish")).toHaveLength(
    1,
  );
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
    'jobs:\n  bootstrap:\n    if: false\n    steps:\n      - env: {"NODE_AUTH_TOKEN": "${{ secrets.OPENAPI_MCP_BOOTSTRAP_TOKEN }}"}\n',
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

test("OIDC-only workflow rejects manual releases and gates publication and verification on readiness", async () => {
  const workflow = Bun.YAML.parse(
    await readFile(
      new URL("../.github/workflows/release.yml", import.meta.url),
      "utf8",
    ),
  ) as {
    on: Record<string, unknown>;
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
  expect(workflow.on.workflow_dispatch).toBeUndefined();
  expect(Object.keys(workflow.jobs).sort()).toEqual([
    "release",
    "release-marketplace",
    "release-openapi-mcp",
  ]);
  context.github.event_name = "push";
  expect(runs("release")).toBe(true);
  expect(runs("release-openapi-mcp")).toBe(true);
  expect(runs("release-marketplace")).toBe(true);
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
  const f = await fixture();
  await writeFile(
    join(f.root, "repository/.github/workflows/release.yml"),
    await readFile(
      new URL("../.github/workflows/release.yml", import.meta.url),
    ),
  );
  await f.adapter.verifyConditions({}, f.context);
});

test("public verification waits before install and stops installation when readiness fails", async () => {
  const workflow = Bun.YAML.parse(
    await readFile(
      new URL("../.github/workflows/release.yml", import.meta.url),
      "utf8",
    ),
  ) as {
    jobs: Record<string, { steps: { name?: string; run?: string }[] }>;
  };
  const script = workflow.jobs["release-openapi-mcp"].steps.find(
    (step) =>
      step.name === "Verify fresh public install and registry attestations",
  )?.run;
  if (!script) throw new Error("Missing public verification step");
  const withoutReadiness = script
    .split("\n")
    .filter((line) => !line.includes(" wait-for-version "))
    .join("\n");
  const commands = `
node() {
  if [ "$1" = "-p" ]; then printf '1.2.3\\n'; return; fi
  case "$2" in
    wait-for-version)
      test "$3" = "1.2.3"
      printf 'wait 1.2.3\\n' >> "$TRACE"
      if [ "$FAIL_READINESS" = "true" ]; then return 41; fi
      touch "$READY"
      ;;
    verify-audit)
      test "$5" = "1.2.3"
      printf 'verify-audit\\n' >> "$TRACE"
      printf '{}\\n'
      ;;
    *)
      test "$1" = "node.mts"
      printf 'consumer\\n' >> "$TRACE"
      printf '{}\\n'
      ;;
  esac
}
npm() {
  case "$1" in
    init) printf 'init\\n' >> "$TRACE" ;;
    install)
      if [ ! -f "$READY" ]; then printf 'install-before-readiness\\n' >> "$TRACE"; return 42; fi
      test "$*" = 'install --ignore-scripts --save-exact --registry=https://registry.npmjs.org/ @knitli/openapi-mcp@1.2.3'
      printf 'install 1.2.3\\n' >> "$TRACE"
      ;;
    audit)
      test "$*" = 'audit signatures --json --include-attestations'
      printf 'audit\\n' >> "$TRACE"
      printf '{}\\n'
      ;;
    *) return 43 ;;
  esac
}
sha256sum() { printf 'checksum\\n' >> "$TRACE"; printf 'fixture-checksum\\n'; }
`;
  for (const scenario of [
    {
      script,
      failure: "false",
      exit: 0,
      effects:
        "init\nwait 1.2.3\ninstall 1.2.3\naudit\nverify-audit\nconsumer\nchecksum\n",
    },
    { script, failure: "true", exit: 41, effects: "init\nwait 1.2.3\n" },
    {
      script: withoutReadiness,
      failure: "false",
      exit: 42,
      effects: "init\ninstall-before-readiness\n",
    },
  ]) {
    const root = await mkdtemp(join(tmpdir(), "openapi-verification-step-"));
    await mkdir(join(root, "openapi-mcp-release"));
    await writeFile(
      join(root, "openapi-mcp-release/tested-artifact.json"),
      '{"version":"1.2.3"}',
    );
    await mkdir(join(root, "packages/openapi-mcp/test-consumers"), {
      recursive: true,
    });
    await writeFile(
      join(root, "packages/openapi-mcp/test-consumers/node.mts"),
      "// fixture consumer\n",
    );
    const trace = join(root, "trace");
    const child = Bun.spawn(
      [
        "/bin/bash",
        "--noprofile",
        "--norc",
        "-e",
        "-o",
        "pipefail",
        "-c",
        commands + scenario.script,
      ],
      {
        env: {
          PATH: "/usr/bin:/bin",
          RUNNER_TEMP: root,
          GITHUB_WORKSPACE: root,
          TRACE: trace,
          READY: join(root, "ready"),
          FAIL_READINESS: scenario.failure,
        },
        stdout: "pipe",
        stderr: "pipe",
      },
    );
    expect(await child.exited).toBe(scenario.exit);
    expect(await readFile(trace, "utf8")).toBe(scenario.effects);
  }
});

test("release rejects token authentication, bootstrap version, wrong package and wrong workflow context", async () => {
  for (const change of [
    (f: Awaited<ReturnType<typeof fixture>>) => {
      Object.assign(f.context.env, { NODE_AUTH_TOKEN: "fixture-only" });
    },
    (f: Awaited<ReturnType<typeof fixture>>) => {
      Object.assign(f.context.env, { NPM_TOKEN: "" });
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
