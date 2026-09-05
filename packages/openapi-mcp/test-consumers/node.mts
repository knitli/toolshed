import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createPublicKey, sign } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { compileRelease, generateKeypair } from "@knitli/openapi-mcp/compiler";
import { runRuntimeConformanceSuite } from "@knitli/openapi-mcp/conformance";
import {
  ARTIFACT_FORMAT_VERSION,
  type AuthorizedTransport,
  admitManifest,
  type CredentialSnapshot,
  canonicalJson,
  createOpenApiRuntime,
  digestPreparedCall,
  PREPARED_CALL_VERSION,
  type PreparedCall,
  type PreparedDispatch,
  RUNTIME_CONTRACT_VERSION,
  verifyStoredRecord,
} from "@knitli/openapi-mcp/runtime";
import {
  createCredentialProvider,
  createLocalDispatchBoundary,
  FileGenerationStore,
  SqliteCatalogStore,
} from "@knitli/openapi-mcp/sqlite";
import {
  createOpenApiMcpServer,
  parseOpenApiStdioConfig,
} from "@knitli/openapi-mcp/stdio";
import {
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  InMemoryTransport,
  type JSONRPCMessage,
  PROTOCOL_VERSION_META_KEY,
} from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";

assert.equal(ARTIFACT_FORMAT_VERSION, 5);
assert.equal(RUNTIME_CONTRACT_VERSION, 1);
assert.equal(PREPARED_CALL_VERSION, 2);
for (const exported of [
  digestPreparedCall,
  createOpenApiMcpServer,
  runRuntimeConformanceSuite,
])
  assert.equal(typeof exported, "function");
const releaseKey = generateKeypair();
const rollbackKey = generateKeypair();
const publicKey = (pem: string) =>
  createPublicKey(pem)
    .export({ format: "der", type: "spki" })
    .toString("base64url");
const root = resolve("fixture");
await mkdir(root, { mode: 0o700 });
const specPath = resolve(root, "spec.json");
await writeFile(
  specPath,
  JSON.stringify({
    openapi: "3.1.0",
    info: { title: "Consumer", version: "1" },
    servers: [{ url: "https://api.example.test" }],
    paths: {
      "/widgets": {
        get: {
          operationId: "listWidgets",
          summary: "List widgets",
          responses: {
            "200": {
              description: "Widgets",
              content: {
                "application/json": {
                  schema: { type: "array", items: { type: "string" } },
                },
              },
            },
          },
        },
      },
    },
  }),
);
const options = {
  specPath,
  sourceLabel: "packed-consumer",
  sourceRevision: "fixture-1",
  catalogId: "consumer",
  issuer: "consumer-owner",
  keyId: "release-1",
  policyId: "reads",
  allowedOrigins: ["https://api.example.test"],
  outDir: root,
  privateKeyPem: releaseKey.privateKeyPem,
};
const prior = await compileRelease({
  ...options,
  releaseId: "known-good",
  generation: 1,
});
const next = await compileRelease({
  ...options,
  releaseId: "candidate",
  generation: 2,
});
const trust = {
  releaseKeys: [
    {
      issuer: options.issuer,
      keyId: options.keyId,
      publicKey: publicKey(releaseKey.publicKeyPem),
    },
  ],
  rollbackKeys: [
    {
      issuer: options.issuer,
      keyId: "rollback-1",
      publicKey: publicKey(rollbackKey.publicKeyPem),
    },
  ],
};
const generations = new FileGenerationStore(resolve(root, "generations.json"));
const store = new SqliteCatalogStore(prior.paths.sqlite);
const nextStore = new SqliteCatalogStore(next.paths.sqlite);
const profile = {
  profileId: "packed-read",
  revision: 1,
  allowedOrigins: options.allowedOrigins,
  auth: { type: "bearer-env" as const, env: "PACKED_READ_FIXTURE_TOKEN" },
};
const credentials = await createCredentialProvider(profile, {
  manifestOrigins: options.allowedOrigins,
  environment: {
    PACKED_READ_FIXTURE_TOKEN: "test-only-packed-read-credential",
  },
});
try {
  const envelope = await store.getManifest(
    prior.manifest.catalogId,
    prior.manifest.releaseId,
  );
  const nextEnvelope = await nextStore.getManifest(
    next.manifest.catalogId,
    next.manifest.releaseId,
  );
  assert.ok(envelope);
  assert.ok(nextEnvelope);
  const admitted = await admitManifest(envelope, trust, generations);
  const runtime = createOpenApiRuntime({
    store,
    trust,
    generations,
    destinationPolicy: {
      async allows(origin) {
        return origin === "https://api.example.test";
      },
    },
    credentialBinding: credentials.bindingResolver,
  });
  assert.equal(
    (await runtime.search({ query: "widgets" })).operations.length,
    1,
  );
  await assert.rejects(() =>
    admitManifest(
      {
        ...nextEnvelope,
        signature: { ...nextEnvelope.signature, signature: "AA" },
      },
      trust,
      generations,
    ),
  );
  assert.equal(
    (await runtime.search({ query: "widgets" })).operations.length,
    1,
  );
  const candidates = await store.searchCandidates({
    query: "widgets",
    limit: 1,
  });
  const record = await store.getOperation(
    prior.manifest.catalogId,
    prior.manifest.releaseId,
    candidates[0].operationId,
  );
  assert.ok(record);
  assert.equal((await verifyStoredRecord(admitted, record)).method, "GET");
  // Exercise the public MCP read tool with the real runtime and credentials.
  // Only the outbound transport is injected; no external socket is opened.
  const authorizer = {
    async authorize() {
      return {
        status: "denied" as const,
        reason: "Read-only consumer fixture",
      };
    },
    async consume() {
      throw new Error("Unexpected action authorization");
    },
    async requestStateVerifier(): Promise<never> {
      throw new Error("Unexpected action continuation");
    },
  };
  const boundary = createLocalDispatchBoundary(authorizer, {
    profile,
    allowsManifestOrigin: ({ manifestDigest, origin }) =>
      manifestDigest === admitted.manifestDigest &&
      origin === "https://api.example.test",
  });
  const plans = new WeakMap<
    object,
    { call: PreparedCall; snapshot: CredentialSnapshot }
  >();
  const transport: AuthorizedTransport = {
    async prepareDispatch(call, snapshot) {
      assert.equal(call.method, "GET");
      assert.equal(call.relativeUrl, "/widgets");
      assert.equal(call.releaseId, "known-good");
      assert.equal(call.manifestDigest, admitted.manifestDigest);
      assert.equal(
        call.credentialProfileDigest,
        snapshot.binding.profileDigest,
      );
      const plan = Object.freeze({}) as PreparedDispatch;
      plans.set(plan, { call, snapshot });
      return plan;
    },
    verifyPlan(plan, call, binding) {
      const state = plans.get(plan);
      assert.ok(state);
      assert.equal(state.call.preparedCallDigest, call.preparedCallDigest);
      assert.equal(state.snapshot.binding.bindingDigest, binding.bindingDigest);
    },
    async dispatchRead(plan) {
      const state = plans.get(plan);
      assert.ok(state);
      plans.delete(plan);
      return {
        kind: "success",
        statusCode: 200,
        headers: {},
        body: new TextEncoder().encode(
          JSON.stringify({
            releaseId: state.call.releaseId,
            manifestDigest: state.call.manifestDigest,
            operationId: state.call.operationId,
            widgets: ["fixture-widget"],
          }),
        ),
      };
    },
    async dispatchAction() {
      throw new Error("Unexpected action dispatch");
    },
  };
  const [wire, serverTransport] = InMemoryTransport.createLinkedPair();
  const handle = serveStdio(
    () =>
      createOpenApiMcpServer({
        searchRuntime: runtime,
        authorizer,
        routes: [
          {
            catalogId: "consumer",
            releaseId: "known-good",
            apiNamespaces: ["consumer"],
            runtime,
            credentials,
            boundary: { ...boundary, transport },
          },
        ],
      }),
    { transport: serverTransport },
  );
  let requestId = 0;
  async function request(method: string, params: Record<string, unknown> = {}) {
    const id = ++requestId;
    const pending = Promise.withResolvers<JSONRPCMessage>();
    const timer = setTimeout(
      () => pending.reject(new Error("Packed MCP read timed out")),
      10_000,
    );
    wire.onmessage = (message) => {
      if ("id" in message && message.id === id) pending.resolve(message);
    };
    wire.onerror = pending.reject;
    try {
      await wire.send({
        jsonrpc: "2.0",
        id,
        method,
        params: {
          ...params,
          _meta: {
            [PROTOCOL_VERSION_META_KEY]: "2026-07-28",
            [CLIENT_INFO_META_KEY]: {
              name: "packed-read-consumer",
              version: "1",
            },
            [CLIENT_CAPABILITIES_META_KEY]: {},
          },
        },
      } as JSONRPCMessage);
      return await pending.promise;
    } finally {
      clearTimeout(timer);
    }
  }
  let recoveredRead: {
    releaseId: string;
    manifestDigest: string;
    operationId: string;
    widgets: string[];
  };
  try {
    await wire.start();
    const discovery = await request("server/discover");
    assert.ok("result" in discovery);
    const search = await runtime.search({ query: "widgets" });
    const response = await request("tools/call", {
      name: "read",
      arguments: { operation: search.operations[0].operation, arguments: {} },
    });
    assert.ok("result" in response);
    const result = response.result as {
      isError?: boolean;
      content: { type: string; text: string }[];
    };
    assert.notEqual(result.isError, true, JSON.stringify(result));
    const outcome = JSON.parse(result.content[0].text);
    assert.equal(outcome.kind, "success");
    assert.equal(outcome.statusCode, 200);
    recoveredRead = JSON.parse(outcome.body);
    assert.deepEqual(recoveredRead, {
      releaseId: "known-good",
      manifestDigest: admitted.manifestDigest,
      operationId: "operation:consumer:listWidgets",
      widgets: ["fixture-widget"],
    });
  } finally {
    await handle.close();
    await wire.close();
    await boundary.close();
  }
  await admitManifest(nextEnvelope, trust, generations);
  await assert.rejects(() => admitManifest(envelope, trust, generations), {
    code: "MANIFEST_ROLLBACK_REJECTED",
  });
  // Existing v1 signed rollback contract; stdio has no envelope attachment option.
  const unsigned = {
    id: "consumer-rollback-1",
    catalogId: prior.manifest.catalogId,
    issuer: options.issuer,
    currentHighestGeneration: 2,
    targetGeneration: 1,
    targetManifestDigest: admitted.manifestDigest,
    reason: "Packed consumer recovery exercise",
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    keyId: "rollback-1",
    algorithm: "Ed25519" as const,
  };
  const rollback = {
    ...unsigned,
    signature: sign(
      null,
      Buffer.from(
        `knitli.openapi-mcp.rollback-authorization.v1\0${canonicalJson(unsigned)}`,
      ),
      rollbackKey.privateKeyPem,
    ).toString("base64url"),
  };
  await admitManifest({ ...envelope, rollback }, trust, generations);
  assert.equal(
    (await runtime.search({ query: "widgets" })).operations.length,
    1,
  );
  const state = await generations.get(prior.manifest.catalogId, options.issuer);
  assert.equal(state?.highestGeneration, 2);
  assert.equal(state?.activeGeneration, 1);
  assert.deepEqual(state?.consumedRollbackAuthorizationIds, [
    "consumer-rollback-1",
  ]);
  await admitManifest(
    envelope,
    trust,
    new FileGenerationStore(resolve(root, "generations.json")),
  );
  const config = parseOpenApiStdioConfig({
    version: 1,
    generationStatePath: resolve(root, "generations.json"),
    catalogs: [
      {
        catalogId: "consumer",
        releaseId: "known-good",
        path: prior.paths.sqlite,
        profileId: "local",
      },
    ],
    trust,
    allowedOrigins: options.allowedOrigins,
    profiles: [
      {
        profileId: "local",
        revision: 1,
        allowedOrigins: options.allowedOrigins,
        auth: { type: "bearer-env", env: "PACKED_CONSUMER_TOKEN" },
      },
    ],
  });
  assert.equal(config.catalogs[0].releaseId, "known-good");
  const keys = resolve(root, "cli-keys");
  await mkdir(keys);
  execFileSync(
    resolve("node_modules/.bin/openapi-mcp"),
    ["keygen", "--out", keys],
    { encoding: "utf8" },
  );
  console.log(
    JSON.stringify({
      format: 5,
      runtime: 1,
      prepared: 2,
      search: true,
      rollback: true,
      cli: true,
      publicReadAfterRejectedAdmission: recoveredRead,
      priorGeneration: 1,
      priorReleaseId: prior.manifest.releaseId,
      priorManifestDigest: admitted.manifestDigest,
      highestGeneration: state?.highestGeneration,
      activeGeneration: state?.activeGeneration,
    }),
  );
} finally {
  await credentials.close();
  store.close();
  nextStore.close();
}
