import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageName = "@knitli/openapi-mcp";
const registry = "https://registry.npmjs.org/";
const { parse: parseYaml } = createRequire(
  new URL("../packages/openapi-mcp/package.json", import.meta.url),
)("yaml");
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** Wait only for packument visibility; installation and verification can still fail. */
export async function waitForRegistryVersion(version, dependencies = {}) {
  if (typeof version !== "string" || !/^\d+\.\d+\.\d+$/.test(version))
    throw new Error("Registry readiness requires an exact stable version");
  const fetchRegistry = dependencies.fetch ?? fetch;
  const sleep =
    dependencies.sleep ?? ((ms) => new Promise((done) => setTimeout(done, ms)));
  for (let attempt = 0; attempt < 6; attempt++) {
    const signal = AbortSignal.timeout(10000);
    let onAbort;
    let response;
    let metadata;
    try {
      [response, metadata] = await Promise.race([
        (async () => {
          const result = await fetchRegistry(
            `${registry}@knitli%2fopenapi-mcp`,
            {
              headers: { Accept: "application/vnd.npm.install-v1+json" },
              signal,
            },
          );
          return [
            result,
            result.status === 200 ? await result.json() : undefined,
          ];
        })(),
        new Promise((_, reject) => {
          onAbort = () => reject(signal.reason);
          signal.addEventListener("abort", onAbort, { once: true });
          if (signal.aborted) onAbort();
        }),
      ]);
    } finally {
      signal.removeEventListener("abort", onAbort);
    }
    if (response.status === 200) {
      if (
        !metadata ||
        metadata.name !== packageName ||
        !metadata.versions ||
        typeof metadata.versions !== "object" ||
        Array.isArray(metadata.versions)
      )
        throw new Error("Malformed or mismatched registry packument");
      if (Object.hasOwn(metadata.versions, version)) {
        const entry = metadata.versions[version];
        if (!entry || entry.name !== packageName || entry.version !== version)
          throw new Error(
            "Registry entry does not match the exact package version",
          );
        return;
      }
    } else if (response.status !== 404)
      throw new Error(`Registry request failed with HTTP ${response.status}`);
    if (attempt < 5) await sleep(10000);
  }
  throw new Error(
    `Registry version ${version} was not visible after 6 attempts`,
  );
}

/** Bind npm's successfully verified audit output to this exact release.
 * This is not a cryptographic verifier: the caller MUST first require npm audit
 * signatures --json --include-attestations to exit zero on a fresh public install.
 */
export function verifyAuditBinding(audit, expected) {
  if (
    !Array.isArray(audit.invalid) ||
    audit.invalid.length ||
    !Array.isArray(audit.missing) ||
    audit.missing.length
  ) {
    throw new Error("npm signature audit has missing or invalid evidence");
  }
  const entry = audit.verified?.find(
    (item) =>
      item.name === packageName &&
      item.version === expected.version &&
      item.registry === registry,
  );
  if (!entry) throw new Error("Exact package has no verified npm attestation");
  const payloads = (entry.attestationBundles ?? [])
    .filter((item) => item.predicateType === "https://slsa.dev/provenance/v1")
    .map((item) =>
      JSON.parse(
        Buffer.from(item.bundle.dsseEnvelope.payload, "base64").toString(
          "utf8",
        ),
      ),
    );
  const matched = payloads.some((statement) => {
    const definition = statement.predicate?.buildDefinition;
    const workflow = definition?.externalParameters?.workflow;
    return (
      statement.predicateType === "https://slsa.dev/provenance/v1" &&
      statement.subject?.some(
        (subject) =>
          subject.name ===
            `pkg:npm/%40knitli/openapi-mcp@${expected.version}` &&
          subject.digest?.sha512 === expected.sha512,
      ) &&
      workflow?.repository === "https://github.com/knitli/toolshed" &&
      workflow.path === ".github/workflows/release.yml" &&
      workflow.ref === "refs/heads/main" &&
      definition.resolvedDependencies?.some(
        (source) => source.digest?.gitCommit === expected.sourceCommit,
      ) &&
      statement.predicate.runDetails?.metadata?.invocationId ===
        `https://github.com/knitli/toolshed/actions/runs/${expected.runId}/attempts/${expected.runAttempt}`
    );
  });
  if (!matched)
    throw new Error(
      "Verified provenance does not bind the tested tarball, source commit and workflow run",
    );
  return { package: packageName, ...expected };
}

async function run(command, options) {
  await new Promise((accept, reject) => {
    const child = spawn(command[0], command.slice(1), {
      ...options,
      stdio: "inherit",
    });
    child.on("error", reject);
    child.on("exit", (code) =>
      code === 0
        ? accept()
        : reject(new Error(`${command[0]} failed (${code})`)),
    );
  });
}

function releaseVersion(context) {
  const version = context.nextRelease?.version;
  if (
    !/^\d+\.\d+\.\d+$/.test(version ?? "") ||
    version === "0.0.0" ||
    context.nextRelease.channel
  ) {
    throw new Error(
      "Only a concrete stable version after bootstrap may publish on latest",
    );
  }
  return version;
}

async function checkContext(context) {
  const env = context.env;
  if (Object.hasOwn(env, "NPM_TOKEN") || Object.hasOwn(env, "NODE_AUTH_TOKEN"))
    throw new Error(
      "Steady-state release must use OIDC without token environment variables",
    );
  if (
    env.GITHUB_ACTIONS !== "true" ||
    env.GITHUB_REPOSITORY !== "knitli/toolshed" ||
    env.GITHUB_REF !== "refs/heads/main" ||
    env.GITHUB_WORKFLOW_REF !==
      "knitli/toolshed/.github/workflows/release.yml@refs/heads/main" ||
    env.OPENAPI_MCP_RELEASE_ENVIRONMENT !== "npmrelease" ||
    env.OPENAPI_MCP_OIDC_READY !== "true" ||
    !env.ACTIONS_ID_TOKEN_REQUEST_URL ||
    !env.ACTIONS_ID_TOKEN_REQUEST_TOKEN ||
    !/^[0-9a-f]{40}$/.test(env.GITHUB_SHA ?? "") ||
    !env.GITHUB_RUN_ID ||
    !isAbsolute(env.RUNNER_TEMP ?? "")
  ) {
    throw new Error(
      "Protected npmrelease GitHub OIDC context and observed publisher readiness are required",
    );
  }
  const manifest = JSON.parse(
    await readFile(join(context.cwd, "package.json"), "utf8"),
  );
  if (
    manifest.name !== packageName ||
    manifest.private !== false ||
    manifest.repository?.url !== "https://github.com/knitli/toolshed" ||
    manifest.repository?.directory !== "packages/openapi-mcp" ||
    manifest.publishConfig?.provenance !== true ||
    manifest.publishConfig?.access !== "public" ||
    manifest.publishConfig?.registry !== registry ||
    manifest.devEngines !== undefined ||
    Object.values(manifest.engines ?? {}).some((value) =>
      String(value).includes("catalog:"),
    )
  ) {
    throw new Error(
      "Published package identity, metadata and concrete engines must match the release allowlist",
    );
  }
  const workflow = parseYaml(
    await readFile(
      resolve(context.cwd, "../../.github/workflows/release.yml"),
      "utf8",
    ),
  );
  const environments = [
    workflow.env,
    ...Object.values(workflow.jobs ?? {}).flatMap((job) => [
      job.env,
      ...(job.steps ?? []).map((step) => step.env),
    ]),
  ];
  if (
    environments.some((environment) =>
      Object.entries(environment ?? {}).some(
        ([key, value]) =>
          key === "NODE_AUTH_TOKEN" ||
          key === "NPM_TOKEN" ||
          String(value).includes("secrets.OPENAPI_MCP_BOOTSTRAP_TOKEN"),
      ),
    )
  ) {
    throw new Error(
      "Remove bootstrap token wiring and revoke its secret before steady-state publication",
    );
  }
  if (context.nextRelease) releaseVersion(context);
  return manifest;
}

/** A small lifecycle adapter; subprocess injection is used only by release-gate tests. */
export function createReleaseAdapter(dependencies = {}) {
  const execute = dependencies.run ?? run;
  let prepared;
  let cleanDirectory;
  let cleanEnv;
  return {
    async verifyConditions(_config, context) {
      const manifest = await checkContext(context);
      cleanDirectory = await mkdtemp(
        join(context.env.RUNNER_TEMP, "openapi-mcp-npm-"),
      );
      cleanEnv = Object.fromEntries(
        Object.entries(context.env).filter(
          ([key]) => !/^npm_config_/i.test(key),
        ),
      );
      cleanEnv.npm_config_userconfig = join(cleanDirectory, "user.npmrc");
      cleanEnv.npm_config_globalconfig = join(cleanDirectory, "global.npmrc");
      cleanEnv.npm_config_cache = join(cleanDirectory, "cache");
      await writeFile(cleanEnv.npm_config_userconfig, "");
      await writeFile(cleanEnv.npm_config_globalconfig, "");
      // Only public registry metadata is copied; no workspace config or secret file.
      await writeFile(
        join(cleanDirectory, "package.json"),
        JSON.stringify({
          name: manifest.name,
          version: manifest.version,
          private: false,
          repository: manifest.repository,
          publishConfig: manifest.publishConfig,
          engines: manifest.engines,
        }),
      );
      const verifyNpm =
        dependencies.verifyNpm ??
        (await import("@semantic-release/npm")).verifyConditions;
      // Installed npm plugin verifies OIDC by package-specific token exchange.
      // Successful exchange returns before token-only whoami verification.
      await verifyNpm(
        { npmPublish: true },
        { ...context, cwd: cleanDirectory, env: cleanEnv },
      );
    },
    async prepare(_config, context) {
      const manifest = await checkContext(context);
      if (!cleanDirectory)
        throw new Error(
          "OIDC verification must finish before preparing a tested tarball",
        );
      const version = releaseVersion(context);
      // npm version cannot run inside this repository's intentional Bun policy.
      // semantic-release supplies the version; generated release routing is retained.
      manifest.version = version;
      await writeFile(
        join(context.cwd, "package.json"),
        `${JSON.stringify(manifest, null, 2)}\n`,
      );
      const directory = join(context.env.RUNNER_TEMP, "openapi-mcp-release");
      await mkdir(directory, { recursive: true });
      const tarball = join(directory, `knitli-openapi-mcp-${version}.tgz`);
      await execute(["bun", "run", "build"], {
        cwd: context.cwd,
        env: context.env,
      });
      await execute(["bun", "pm", "pack", "--filename", tarball, "--quiet"], {
        cwd: context.cwd,
        env: context.env,
      });
      const digest = hash(await readFile(tarball));
      await execute(
        ["bun", "test", "packages/openapi-mcp/tests/package-consumers.test.ts"],
        {
          cwd: resolve(context.cwd, "../.."),
          env: { ...context.env, OPENAPI_MCP_TARBALL: tarball },
        },
      );
      if (hash(await readFile(tarball)) !== digest)
        throw new Error("Tarball digest changed during consumer tests");
      prepared = {
        tarball,
        sha256: digest,
        version,
        sourceCommit: context.env.GITHUB_SHA,
        workflow: context.env.GITHUB_WORKFLOW_REF,
        runId: context.env.GITHUB_RUN_ID,
      };
      await writeFile(
        join(directory, "tested-artifact.json"),
        `${JSON.stringify(prepared, null, 2)}\n`,
      );
      await writeFile(
        join(directory, "SHA256SUMS"),
        `${digest}  ${tarball.split("/").at(-1)}\n`,
      );
    },
    async publish(_config, context) {
      if (!prepared)
        throw new Error("No tested tarball is available for publication");
      await checkContext(context);
      if (
        releaseVersion(context) !== prepared.version ||
        context.env.GITHUB_SHA !== prepared.sourceCommit ||
        hash(await readFile(prepared.tarball)) !== prepared.sha256
      )
        throw new Error(
          "Prepared tarball version/source/digest does not match",
        );
      await execute(
        [
          "npm",
          "publish",
          prepared.tarball,
          "--access",
          "public",
          "--tag",
          "latest",
          "--provenance",
          `--registry=${registry}`,
        ],
        {
          cwd: cleanDirectory,
          env: cleanEnv,
        },
      );
      if (hash(await readFile(prepared.tarball)) !== prepared.sha256)
        throw new Error("Tarball digest changed during publication");
      return {
        name: "npm package (@latest dist-tag)",
        url: `https://www.npmjs.com/package/${packageName}/v/${prepared.version}`,
        version: prepared.version,
      };
    },
  };
}

const adapter = createReleaseAdapter();
export const verifyConditions = adapter.verifyConditions;
export const prepare = adapter.prepare;
export const publish = adapter.publish;

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url) &&
  process.argv[2] === "verify-audit"
) {
  const [auditPath, tarball, version] = process.argv.slice(3);
  const auditBytes = await readFile(auditPath);
  const verified = verifyAuditBinding(JSON.parse(auditBytes), {
    version,
    sha512: createHash("sha512")
      .update(await readFile(tarball))
      .digest("hex"),
    sourceCommit: process.env.GITHUB_SHA,
    runId: process.env.GITHUB_RUN_ID,
    runAttempt: process.env.GITHUB_RUN_ATTEMPT,
  });
  console.log(
    JSON.stringify({ ...verified, auditSha256: hash(auditBytes) }, null, 2),
  );
} else if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url) &&
  process.argv[2] === "wait-for-version"
) {
  await waitForRegistryVersion(process.argv[3]);
} else if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const packageRoot = resolve(
    fileURLToPath(new URL("../packages/openapi-mcp/", import.meta.url)),
  );
  const manifest = JSON.parse(
    await readFile(join(packageRoot, "package.json"), "utf8"),
  );
  const plugins = manifest.release.plugins.map((entry) =>
    Array.isArray(entry) && entry[0] === "@semantic-release/npm"
      ? [adapter, entry[1]]
      : entry,
  );
  const { default: semanticRelease } = await import("semantic-release");
  await semanticRelease(
    { ...manifest.release, plugins },
    { cwd: packageRoot, env: process.env },
  );
}
