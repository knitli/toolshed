import { expect, test } from "bun:test";
import {
  type CatalogId,
  type CatalogStore,
  type CredentialProfileBinding,
  canonicalJson,
  createOpenApiRuntime,
  encodeOperationRef,
  type GenerationState,
  type GenerationStore,
  type GenerationTransition,
  type ManifestEnvelope,
  type ManifestTrust,
  type OperationRecordV4,
  type PreparedCall,
  type ReleaseId,
  type ReleaseManifestV4,
  type Sha256,
  type StoredRecord,
  sha256,
  verifyPreparedCall,
} from "../src/runtime/index.ts";

const catalogId = "tiny" as CatalogId;
const releaseId = "release-1" as ReleaseId;
const digestA = "a".repeat(64) as Sha256;
const digestB = "b".repeat(64) as Sha256;
const encoder = new TextEncoder();

class MemoryGenerations implements GenerationStore {
  state: GenerationState | null = null;
  accepts = 0;
  throwOnGet = false;
  async get(): Promise<GenerationState | null> {
    if (this.throwOnGet) throw new Error("/secret/generation.sqlite");
    return this.state;
  }
  async accept(
    _catalog: CatalogId,
    _issuer: string,
    transition: GenerationTransition,
  ): Promise<GenerationState | null> {
    this.accepts += 1;
    if ((this.state?.revision ?? null) !== transition.expectedRevision)
      return null;
    this.state = transition.next;
    return this.state;
  }
}

function operation(name: string, method: "GET" | "POST"): OperationRecordV4 {
  return {
    id: `operation:tiny:${name}`,
    api: "tiny",
    operationId: name,
    method,
    path: method === "GET" ? "/widgets" : "/widgets",
    origin: "https://api.example.test",
    summary: name,
    tags: [],
    deprecated: false,
    parameters: [],
    requestBody: null,
    schemaIds: [],
    advisory: { safety: method === "GET" ? "action" : "read" },
  };
}

async function stored(record: OperationRecordV4) {
  return {
    id: record.id,
    logicalDigest: await sha256(
      "knitli.openapi-mcp.operation-record.v5",
      record,
    ),
    record,
  } as StoredRecord<OperationRecordV4>;
}

function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

async function fixture() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ]);
  const publicKey = base64url(
    new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)),
  );
  const trust: ManifestTrust = {
    releaseKeys: [{ issuer: "issuer.example", keyId: "key-1", publicKey }],
    rollbackKeys: [],
  };
  const rows = [
    await stored(operation("listWidgets", "GET")),
    await stored(operation("createWidget", "POST")),
  ];
  const manifest: ReleaseManifestV4 = {
    format: 5,
    contract: 1,
    catalogId,
    releaseId,
    generation: 1,
    issuer: "issuer.example",
    keyId: "key-1",
    policyId: "default",
    allowedOrigins: ["https://api.example.test"],
    compiledAt: "2026-09-04T12:00:00.000Z",
    compilerVersion: "4.0.0",
    source: {
      uri: "https://specs.example.test/tiny.json",
      revision: "git:1234",
      contentSha256: digestA,
      referenceGraphDigest: digestB,
    },
    records: Object.fromEntries(
      rows.map((row) => [row.id, row.logicalDigest]),
    ) as ReleaseManifestV4["records"],
  };
  const manifestJson = canonicalJson(manifest as never);
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      "Ed25519",
      pair.privateKey,
      encoder.encode(`knitli.openapi-mcp.release-manifest.v5\0${manifestJson}`),
    ),
  );
  const envelope: ManifestEnvelope = {
    manifestJson,
    signature: {
      algorithm: "Ed25519",
      keyId: "key-1",
      signature: base64url(signature),
    },
  };
  const manifestDigest = await sha256(
    "knitli.openapi-mcp.release-manifest.v5",
    manifest as never,
  );
  const generations = new MemoryGenerations();
  generations.state = {
    revision: 1,
    highestGeneration: manifest.generation,
    highestManifestDigest: manifestDigest,
    activeGeneration: manifest.generation,
    activeManifestDigest: manifestDigest,
    consumedRollbackAuthorizationIds: [],
  };
  let operationReads = 0;
  let schemaReads = 0;
  let policyReads = 0;
  let slotReads = 0;
  let allowed = true;
  let policyError = false;
  let onPolicy: (() => void) | undefined;
  let profileId = "tiny-user";
  let profileDigest = digestA;
  let slots: readonly { placement: "header" | "query"; name: string }[] = [];
  let bindingOverride: unknown;
  let slotError = false;
  const store: CatalogStore = {
    async getManifest() {
      return envelope;
    },
    async searchCandidates() {
      return [];
    },
    async getOperation(_catalog, _release, id) {
      operationReads += 1;
      return rows.find((row) => row.id === id) ?? null;
    },
    async getSchemas() {
      schemaReads += 1;
      return [];
    },
  };
  const runtime = createOpenApiRuntime({
    store,
    trust,
    generations,
    destinationPolicy: {
      async allows(origin) {
        policyReads += 1;
        expect(origin).toBe("https://api.example.test");
        onPolicy?.();
        if (policyError) throw new Error("secret policy detail");
        return allowed;
      },
    },
    credentialBinding: {
      async resolve(context) {
        slotReads += 1;
        expect(Object.isFrozen(context)).toBe(true);
        expect(JSON.stringify(context)).not.toMatch(/token|secret|credential/i);
        if (slotError) throw new Error("secret slot detail");
        return (bindingOverride ?? {
          profileId,
          profileDigest,
          slots,
        }) as CredentialProfileBinding;
      },
    },
  });
  const reference = (id: OperationRecordV4["id"]) =>
    `opref.v1.${base64url(
      encoder.encode(
        canonicalJson({
          catalogId,
          manifestDigest,
          operationId: id,
          releaseId,
        }),
      ),
    )}` as PreparedCall["operationId"] & string;
  return {
    generations,
    envelope,
    reference,
    rows,
    runtime,
    downstreamCalls() {
      return { operationReads, schemaReads, policyReads, slotReads };
    },
    setAllowed(value: boolean) {
      allowed = value;
    },
    setPolicyError(value: boolean) {
      policyError = value;
    },
    setPolicyHook(value: (() => void) | undefined) {
      onPolicy = value;
    },
    setSlots(value: typeof slots) {
      slots = value;
    },
    setProfile(value: { profileId: string; profileDigest: Sha256 }) {
      profileId = value.profileId;
      profileDigest = value.profileDigest;
    },
    setBindingResult(value: unknown) {
      bindingOverride = value;
    },
    setSlotError(value: boolean) {
      slotError = value;
    },
  };
}

test("exports complete preparation surface", async () => {
  const module = await import("../src/runtime/index.ts");
  for (const name of [
    "classifyOperation",
    "serializeArguments",
    "digestPreparedCall",
    "verifyPreparedCall",
  ])
    expect(typeof module[name as keyof typeof module]).toBe("function");
});

test("prepares credential-free read and action calls through the correct tool", async () => {
  const value = await fixture();
  const read = await value.runtime.prepareRead({
    operation: value.reference("operation:tiny:listWidgets"),
    arguments: {},
  });
  expect(read.safety).toBe("read");
  expect(read.actionKind).toBeNull();
  expect(JSON.stringify(read)).not.toMatch(
    /authorization|token|secret|grant|subject/i,
  );
  await verifyPreparedCall(read);
  const action = await value.runtime.prepareAction({
    operation: value.reference("operation:tiny:createWidget"),
    arguments: {},
  });
  expect(action).toMatchObject({
    safety: "action",
    actionKind: "create",
    cardinality: { kind: "unknown" },
  });
  await expect(
    value.runtime.prepareRead({
      operation: value.reference("operation:tiny:createWidget"),
      arguments: {},
    }),
  ).rejects.toMatchObject({ code: "TOOL_SAFETY_MISMATCH" });
});

test("rejects malformed references, page tokens, and hostile input accessors", async () => {
  const value = await fixture();
  await expect(
    value.runtime.prepareRead({ operation: "bad" as never, arguments: {} }),
  ).rejects.toMatchObject({ code: "OPERATION_REF_INVALID" });
  await expect(
    value.runtime.prepareRead({
      operation: encodeOperationRef({
        catalogId,
        releaseId,
        operationId: "operation:tiny:listWidgets",
        manifestDigest: "f".repeat(64) as Sha256,
      }),
      arguments: {},
    }),
  ).rejects.toMatchObject({ code: "RECORD_NOT_ADMITTED" });
  await expect(
    value.runtime.prepareRead({
      operation: value.reference("operation:tiny:listWidgets"),
      arguments: {},
      pageToken: "unbound",
    }),
  ).rejects.toMatchObject({ code: "INPUT_INVALID" });
  let touched = 0;
  const hostile = Object.defineProperty({ arguments: {} }, "operation", {
    enumerable: true,
    get: () => (touched += 1),
  });
  await expect(
    value.runtime.prepareRead(hostile as never),
  ).rejects.toMatchObject({ code: "INPUT_INVALID" });
  expect(touched).toBe(0);
});

test("requires an active release before downstream preparation work", async () => {
  const value = await fixture();
  value.generations.state = null;
  await expect(
    value.runtime.prepareRead({
      operation: value.reference("operation:tiny:listWidgets"),
      arguments: {},
    }),
  ).rejects.toMatchObject({ code: "RECORD_NOT_ADMITTED" });
  expect(value.generations.accepts).toBe(0);
  expect(value.downstreamCalls()).toEqual({
    operationReads: 0,
    schemaReads: 0,
    policyReads: 0,
    slotReads: 0,
  });
});

test("never mutates admission when preparation policy or safety fails", async () => {
  const value = await fixture();
  value.setAllowed(false);
  await expect(
    value.runtime.prepareRead({
      operation: value.reference("operation:tiny:listWidgets"),
      arguments: {},
    }),
  ).rejects.toMatchObject({ code: "DESTINATION_DENIED" });
  expect(value.generations.accepts).toBe(0);
  value.setAllowed(true);
  value.setPolicyError(true);
  await expect(
    value.runtime.prepareRead({
      operation: value.reference("operation:tiny:listWidgets"),
      arguments: {},
    }),
  ).rejects.toMatchObject({ code: "DESTINATION_DENIED" });
  expect(value.generations.accepts).toBe(0);
  value.setPolicyError(false);
  value.setSlotError(true);
  await expect(
    value.runtime.prepareRead({
      operation: value.reference("operation:tiny:listWidgets"),
      arguments: {},
    }),
  ).rejects.toMatchObject({ code: "AUTH_PROFILE_INVALID" });
  expect(value.generations.accepts).toBe(0);
  value.setSlotError(false);
  value.setSlots([{ placement: "header", name: "Accept" }]);
  await expect(
    value.runtime.prepareRead({
      operation: value.reference("operation:tiny:listWidgets"),
      arguments: {},
    }),
  ).rejects.toMatchObject({ code: "INPUT_INVALID" });
  expect(value.generations.accepts).toBe(0);
  value.setSlots([]);
  await expect(
    value.runtime.prepareAction({
      operation: value.reference("operation:tiny:listWidgets"),
      arguments: {},
    }),
  ).rejects.toMatchObject({ code: "TOOL_SAFETY_MISMATCH" });
  expect(value.generations.accepts).toBe(0);
});

test("credential binding result is an exact bounded own-data snapshot", async () => {
  const invalidResults: readonly unknown[] = [
    { profileId: "", profileDigest: digestA, slots: [] },
    { profileId: "a".repeat(129), profileDigest: digestA, slots: [] },
    { profileId: "unstable/profile", profileDigest: digestA, slots: [] },
    { profileId: "tiny-user", profileDigest: "A".repeat(64), slots: [] },
    { profileId: "tiny-user", profileDigest: digestA, slots: [], grantId: "g" },
    {
      profileId: "tiny-user",
      profileDigest: digestA,
      slots: [],
      tokenHash: digestB,
    },
  ];

  for (const result of invalidResults) {
    const value = await fixture();
    value.setBindingResult(result);
    await expect(
      value.runtime.prepareRead({
        operation: value.reference("operation:tiny:listWidgets"),
        arguments: {},
      }),
    ).rejects.toMatchObject({ code: "AUTH_PROFILE_INVALID" });
  }

  const value = await fixture();
  let touched = 0;
  value.setBindingResult(
    Object.defineProperty({ profileDigest: digestA, slots: [] }, "profileId", {
      enumerable: true,
      get: () => {
        touched += 1;
        return "tiny-user";
      },
    }),
  );
  await expect(
    value.runtime.prepareRead({
      operation: value.reference("operation:tiny:listWidgets"),
      arguments: {},
    }),
  ).rejects.toMatchObject({ code: "AUTH_PROFILE_INVALID" });
  expect(touched).toBe(0);
});

test("normalizes active-generation failures without leaking provider details", async () => {
  const value = await fixture();
  value.generations.throwOnGet = true;
  const error = await value.runtime
    .prepareRead({
      operation: value.reference("operation:tiny:listWidgets"),
      arguments: {},
    })
    .catch((caught) => caught);
  expect(error).toMatchObject({ code: "UPSTREAM_ERROR", retryable: true });
  expect(JSON.stringify(error)).not.toContain("generation.sqlite");
});

test("rechecks active state after host policy work", async () => {
  const value = await fixture();
  const active = value.generations.state as GenerationState;
  value.setPolicyHook(() => {
    value.generations.state = {
      ...active,
      revision: active.revision + 1,
      highestGeneration: 2,
      highestManifestDigest: digestB,
      activeGeneration: 2,
      activeManifestDigest: digestB,
    };
  });
  await expect(
    value.runtime.prepareRead({
      operation: value.reference("operation:tiny:listWidgets"),
      arguments: {},
    }),
  ).rejects.toMatchObject({ code: "RECORD_NOT_ADMITTED" });
  expect(value.generations.accepts).toBe(0);
});

test("binds the verified manifest digest when a store row mutates after verification", async () => {
  const value = await fixture();
  const verifiedDigest = value.rows[0].logicalDigest;
  value.setPolicyHook(() => {
    value.rows[0].logicalDigest = "f".repeat(64) as Sha256;
  });
  const call = await value.runtime.prepareRead({
    operation: value.reference("operation:tiny:listWidgets"),
    arguments: {},
  });
  expect(call.operationDigest).toBe(verifiedDigest);
});

test("revalidation is fresh, digest bound, and denies policy or slot changes", async () => {
  const value = await fixture();
  const call = await value.runtime.prepareRead({
    operation: value.reference("operation:tiny:listWidgets"),
    arguments: {},
  });
  const fresh = await value.runtime.revalidate(call);
  expect(fresh).not.toBe(call);
  expect(fresh).toEqual(call);

  value.setAllowed(false);
  await expect(value.runtime.revalidate(call)).rejects.toMatchObject({
    code: "DESTINATION_DENIED",
  });
  value.setAllowed(true);
  value.setSlots([{ placement: "query", name: "api_key" }]);
  await expect(value.runtime.revalidate(call)).rejects.toMatchObject({
    code: "RECORD_NOT_ADMITTED",
  });
});

test("revalidation denies same-slot credential profile substitution or revision", async () => {
  const value = await fixture();
  const call = await value.runtime.prepareRead({
    operation: value.reference("operation:tiny:listWidgets"),
    arguments: {},
  });

  expect(call).toMatchObject({
    version: 2,
    credentialProfileId: "tiny-user",
    credentialProfileDigest: digestA,
  });

  value.setProfile({ profileId: "other-user", profileDigest: digestA });
  await expect(value.runtime.revalidate(call)).rejects.toMatchObject({
    code: "RECORD_NOT_ADMITTED",
  });

  value.setProfile({
    profileId: "tiny-user",
    profileDigest: "f".repeat(64) as Sha256,
  });
  await expect(value.runtime.revalidate(call)).rejects.toMatchObject({
    code: "RECORD_NOT_ADMITTED",
  });
});

test("revalidation snapshots hostile calls and rejects record mutation", async () => {
  const value = await fixture();
  const call = await value.runtime.prepareRead({
    operation: value.reference("operation:tiny:listWidgets"),
    arguments: {},
  });
  let touched = 0;
  const hostile = { ...call } as Record<string, unknown>;
  Object.defineProperty(hostile, "catalogId", {
    enumerable: true,
    get: () => (touched += 1),
  });
  await expect(
    value.runtime.revalidate(hostile as never),
  ).rejects.toMatchObject({ code: "INPUT_INVALID" });
  expect(touched).toBe(0);
  value.rows[0].record = { ...value.rows[0].record, path: "/poisoned" };
  await expect(value.runtime.revalidate(call)).rejects.toMatchObject({
    code: "RECORD_DIGEST_MISMATCH",
  });
});

test("slot binding canonicalizes resolver order without folding query case", async () => {
  const value = await fixture();
  value.setSlots([
    { placement: "query", name: "A" },
    { placement: "query", name: "a" },
  ]);
  const call = await value.runtime.prepareRead({
    operation: value.reference("operation:tiny:listWidgets"),
    arguments: {},
  });
  value.setSlots([
    { placement: "query", name: "a" },
    { placement: "query", name: "A" },
  ]);
  expect(await value.runtime.revalidate(call)).toEqual(call);
});

test("manifest mutation denies a prepared call", async () => {
  const value = await fixture();
  const call = await value.runtime.prepareRead({
    operation: value.reference("operation:tiny:listWidgets"),
    arguments: {},
  });
  value.envelope.manifestJson = value.envelope.manifestJson.replace(
    '"compilerVersion":"4.0.0"',
    '"compilerVersion":"4.0.1"',
  );
  await expect(value.runtime.revalidate(call)).rejects.toMatchObject({
    code: "MANIFEST_SIGNATURE_INVALID",
  });
});

test("normalizes hostile active generation snapshots during revalidation", async () => {
  const value = await fixture();
  const call = await value.runtime.prepareRead({
    operation: value.reference("operation:tiny:listWidgets"),
    arguments: {},
  });
  value.generations.state = new Proxy(
    value.generations.state as GenerationState,
    {
      get() {
        throw new Error("/secret/generation.sqlite");
      },
    },
  );
  const error = await value.runtime.revalidate(call).catch((caught) => caught);
  expect(error).toMatchObject({ code: "UPSTREAM_ERROR", retryable: true });
  expect(JSON.stringify(error)).not.toContain("generation.sqlite");
});
