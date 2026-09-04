import { afterEach, expect, test } from "bun:test";
import type { BigIntStats, Stats } from "node:fs";
import {
  appendFile,
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  rename,
  rm,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import {
  type CatalogId,
  canonicalJson,
  DEFAULT_RUNTIME_LIMITS,
  type GenerationState,
  type GenerationStore,
  type GenerationTransition,
  type JsonObject,
  type ManifestEnvelope,
  type OperationRecordV4,
  type ReleaseManifestV4,
  type RollbackAuthorization,
  type RuntimeLimits,
  type Sha256,
  type StoredRecord,
  sha256,
} from "../src/runtime/index.ts";
import {
  type AdmittedManifest,
  admitManifest,
  type ManifestTrust,
} from "../src/runtime/manifest.ts";
import { canonicalJsonBounded } from "../src/runtime/strict-json.ts";
import { verifyStoredRecord } from "../src/runtime/verify-record.ts";
import {
  MAX_OPERATION_TAG_BYTES,
  MAX_OPERATION_TAG_BYTES_TOTAL,
  MAX_OPERATION_TAGS,
} from "../src/runtime/versions.ts";
import { FileGenerationStore } from "../src/sqlite/generation-store.ts";

const encoder = new TextEncoder();
const digestA = "a".repeat(64) as Sha256;
const digestB = "b".repeat(64) as Sha256;
const catalogId = "tiny" as CatalogId;
const operationId = "operation:tiny:users.list" as const;
const rollbackDomain = "knitli.openapi-mcp.rollback-authorization.v1\0";
const manifestDomain = "knitli.openapi-mcp.release-manifest.v4\0";
const temporaryDirectories: string[] = [];

afterEach(async () => {
  for (const directory of temporaryDirectories.splice(0)) {
    await rm(directory, { recursive: true, force: true });
  }
});

function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

async function keyPair(keyId: string, issuer = "issuer.example") {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ]);
  return {
    issuer,
    keyId,
    publicKey: base64url(
      new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)),
    ),
    privateKey: pair.privateKey,
  };
}

async function sign(privateKey: CryptoKey, payload: string): Promise<string> {
  const bytes = new Uint8Array(
    await crypto.subtle.sign("Ed25519", privateKey, encoder.encode(payload)),
  );
  return base64url(bytes);
}

function operation(
  overrides: Partial<OperationRecordV4> = {},
): OperationRecordV4 {
  return {
    id: operationId,
    api: "tiny",
    operationId: "users.list",
    method: "GET",
    path: "/users",
    origin: "https://api.example.com",
    summary: "List users",
    deprecated: false,
    parameters: [],
    requestBody: null,
    schemaIds: [],
    tags: [],
    advisory: {},
    ...overrides,
  };
}

async function operationDigest(value = operation()): Promise<Sha256> {
  return sha256("knitli.openapi-mcp.operation-record.v4", value);
}

async function manifest(
  overrides: Partial<ReleaseManifestV4> = {},
): Promise<ReleaseManifestV4> {
  return {
    format: 4,
    contract: 1,
    catalogId,
    releaseId: "release-7" as never,
    generation: 7,
    issuer: "issuer.example",
    keyId: "release-key",
    policyId: "default",
    allowedOrigins: ["https://api.example.com"],
    compiledAt: "2026-09-04T12:00:00.000Z",
    compilerVersion: "4.0.0",
    source: {
      uri: "https://specs.example.com/tiny.json",
      revision: "git:1234",
      contentSha256: digestA,
      referenceGraphDigest: digestB,
    },
    records: { [operationId]: await operationDigest() },
    ...overrides,
  };
}

async function signedEnvelope(
  value: ReleaseManifestV4,
  release: Awaited<ReturnType<typeof keyPair>>,
): Promise<ManifestEnvelope> {
  const manifestJson = canonicalJson(value);
  return {
    manifestJson,
    signature: {
      algorithm: "Ed25519",
      keyId: release.keyId,
      signature: await sign(
        release.privateKey,
        `${manifestDomain}${manifestJson}`,
      ),
    },
  };
}

async function rollbackAuthorization(
  value: ReleaseManifestV4,
  targetManifestDigest: Sha256,
  rollback: Awaited<ReturnType<typeof keyPair>>,
  overrides: Partial<RollbackAuthorization> = {},
): Promise<RollbackAuthorization> {
  const unsigned = {
    id: "rollback-7",
    catalogId: value.catalogId,
    issuer: value.issuer,
    currentHighestGeneration: 8,
    targetGeneration: value.generation,
    targetManifestDigest,
    reason: "known bad release",
    expiresAt: "2026-09-05T00:00:00.000Z",
    keyId: rollback.keyId,
    algorithm: "Ed25519" as const,
    ...overrides,
  };
  return {
    ...unsigned,
    signature: await sign(
      rollback.privateKey,
      `${rollbackDomain}${canonicalJson(unsigned)}`,
    ),
  };
}

class MemoryGenerationStore implements GenerationStore {
  readonly states = new Map<string, GenerationState>();
  accepts = 0;

  constructor(initial?: GenerationState) {
    if (initial) this.states.set("tiny\0issuer.example", initial);
  }

  async get(
    catalog: CatalogId,
    issuer: string,
  ): Promise<GenerationState | null> {
    return this.states.get(`${catalog}\0${issuer}`) ?? null;
  }

  async accept(
    catalog: CatalogId,
    issuer: string,
    transition: GenerationTransition,
  ): Promise<GenerationState | null> {
    const key = `${catalog}\0${issuer}`;
    const current = this.states.get(key) ?? null;
    if ((current?.revision ?? null) !== transition.expectedRevision)
      return null;
    this.accepts += 1;
    this.states.set(key, transition.next);
    return transition.next;
  }
}

function state(
  highestGeneration: number,
  highestManifestDigest: Sha256,
  activeGeneration = highestGeneration,
): GenerationState {
  return {
    revision: 3,
    highestGeneration,
    highestManifestDigest,
    activeGeneration,
    activeManifestDigest: highestManifestDigest,
    consumedRollbackAuthorizationIds: [],
  };
}

async function fixture() {
  const release = await keyPair("release-key");
  const rollback = await keyPair("rollback-key");
  const value = await manifest();
  const envelope = await signedEnvelope(value, release);
  const trust: ManifestTrust = {
    releaseKeys: [
      {
        issuer: release.issuer,
        keyId: release.keyId,
        publicKey: release.publicKey,
      },
    ],
    rollbackKeys: [
      {
        issuer: rollback.issuer,
        keyId: rollback.keyId,
        publicKey: rollback.publicKey,
      },
    ],
    now: () => new Date("2026-09-04T13:00:00.000Z"),
  };
  return { release, rollback, value, envelope, trust };
}

async function admitFixture(): Promise<AdmittedManifest> {
  const { envelope, trust } = await fixture();
  return admitManifest(envelope, trust, new MemoryGenerationStore());
}

test("bounded canonical JSON is byte-identical for signed-data values", () => {
  for (const value of [
    null,
    true,
    -0,
    1.25e-7,
    'quote" slash\\ controls\b\f\n\r\t\u000b',
    "Unicode 😀 é  ",
    [3, "two", { z: false, a: true }],
    { z: [1, 2], a: { y: "yes", x: "x" } },
  ]) {
    expect(
      canonicalJsonBounded(value, {
        maxBytes: 4096,
        maxDepth: 16,
        maxNodes: 100,
      }),
    ).toBe(canonicalJson(value));
  }
});

test("bounded canonical JSON stops at node budget before descending", () => {
  let descended = false;
  const poison = new Proxy(
    {},
    {
      getPrototypeOf() {
        descended = true;
        return Object.prototype;
      },
    },
  );
  expect(() =>
    canonicalJsonBounded(
      { a: true, b: poison },
      { maxBytes: 4096, maxDepth: 16, maxNodes: 2 },
    ),
  ).toThrow(/traversal/i);
  expect(descended).toBe(false);
});

test("admits a canonical exactly shaped v4 manifest and updates generation state", async () => {
  const { envelope, trust } = await fixture();
  const generations = new MemoryGenerationStore();
  const admitted = await admitManifest(envelope, trust, generations);
  const persisted = await generations.get(catalogId, "issuer.example");

  expect(admitted.manifest.generation).toBe(7);
  expect(admitted.manifestDigest).toMatch(/^[0-9a-f]{64}$/);
  expect(persisted).toEqual({
    revision: 0,
    highestGeneration: 7,
    highestManifestDigest: admitted.manifestDigest,
    activeGeneration: 7,
    activeManifestDigest: admitted.manifestDigest,
    consumedRollbackAuthorizationIds: [],
  });
});

test("signature verification canonicalizes harmless raw JSON whitespace and key order", async () => {
  const { release, trust, value } = await fixture();
  const canonical = canonicalJson(value);
  const envelope: ManifestEnvelope = {
    manifestJson: JSON.stringify(value, null, 2),
    signature: {
      algorithm: "Ed25519",
      keyId: release.keyId,
      signature: await sign(
        release.privateKey,
        `${manifestDomain}${canonical}`,
      ),
    },
  };
  await expect(
    admitManifest(envelope, trust, new MemoryGenerationStore()),
  ).resolves.toMatchObject({ manifest: { generation: 7 } });
});

test("rejects wrong issuer, release key, signature keyId, and signature before changing state", async () => {
  const { release, envelope, trust } = await fixture();
  const generations = new MemoryGenerationStore();
  const cases: Array<[ManifestEnvelope, ManifestTrust]> = [
    [
      envelope,
      {
        ...trust,
        releaseKeys: [{ ...trust.releaseKeys[0], issuer: "other.example" }],
      },
    ],
    [
      envelope,
      {
        ...trust,
        releaseKeys: [
          {
            ...trust.releaseKeys[0],
            publicKey: (await keyPair("other")).publicKey,
          },
        ],
      },
    ],
    [
      { ...envelope, signature: { ...envelope.signature, keyId: "other" } },
      trust,
    ],
    [
      {
        ...envelope,
        signature: {
          ...envelope.signature,
          signature: await sign(release.privateKey, "other"),
        },
      },
      trust,
    ],
  ];
  for (const [candidate, candidateTrust] of cases) {
    await expect(
      admitManifest(candidate, candidateTrust, generations),
    ).rejects.toMatchObject({ code: "MANIFEST_SIGNATURE_INVALID" });
  }
  expect(generations.accepts).toBe(0);
});

test("rejects malformed base64url release signatures", async () => {
  const { envelope, trust } = await fixture();
  await expect(
    admitManifest(
      {
        ...envelope,
        signature: { ...envelope.signature, signature: "not+base64" },
      },
      trust,
      new MemoryGenerationStore(),
    ),
  ).rejects.toMatchObject({ code: "MANIFEST_SIGNATURE_INVALID" });
});

test("requires manifest envelope fields to be own data with no extras", async () => {
  const { envelope, trust } = await fixture();
  await expect(
    admitManifest(
      { ...envelope, extra: true } as never,
      trust,
      new MemoryGenerationStore(),
    ),
  ).rejects.toMatchObject({ code: "MANIFEST_INVALID" });
  const inherited = Object.create(envelope) as ManifestEnvelope;
  await expect(
    admitManifest(inherited, trust, new MemoryGenerationStore()),
  ).rejects.toMatchObject({ code: "MANIFEST_INVALID" });
  let inheritedRollbackRead = false;
  const prototype = Object.create(null);
  Object.defineProperty(prototype, "rollback", {
    get: () => {
      inheritedRollbackRead = true;
      throw new Error("must not run");
    },
  });
  const accessorEnvelope = Object.assign(
    Object.create(prototype),
    envelope,
  ) as ManifestEnvelope;
  await expect(
    admitManifest(accessorEnvelope, trust, new MemoryGenerationStore()),
  ).rejects.toMatchObject({ code: "MANIFEST_INVALID" });
  expect(inheritedRollbackRead).toBe(false);
  const hiddenEnvelope = { ...envelope };
  Object.defineProperty(hiddenEnvelope, "hidden", { value: true });
  await expect(
    admitManifest(hiddenEnvelope, trust, new MemoryGenerationStore()),
  ).rejects.toMatchObject({ code: "MANIFEST_INVALID" });
  const hiddenSignature = { ...envelope.signature };
  Object.defineProperty(hiddenSignature, "hidden", { value: true });
  await expect(
    admitManifest(
      { ...envelope, signature: hiddenSignature },
      trust,
      new MemoryGenerationStore(),
    ),
  ).rejects.toMatchObject({ code: "MANIFEST_SIGNATURE_INVALID" });
});

test("requires exact manifest and source shapes with all required fields", async () => {
  const { release, trust, value } = await fixture();
  for (const candidate of [
    { ...value, extra: true },
    Object.fromEntries(
      Object.entries(value).filter(([key]) => key !== "records"),
    ),
    { ...value, source: { ...value.source, extra: true } },
    {
      ...value,
      source: {
        uri: value.source.uri,
        revision: value.source.revision,
        contentSha256: value.source.contentSha256,
      },
    },
  ]) {
    const manifestJson = canonicalJson(candidate as never);
    const envelope = {
      manifestJson,
      signature: {
        algorithm: "Ed25519" as const,
        keyId: release.keyId,
        signature: await sign(
          release.privateKey,
          `${manifestDomain}${manifestJson}`,
        ),
      },
    };
    await expect(
      admitManifest(envelope, trust, new MemoryGenerationStore()),
    ).rejects.toMatchObject({ code: "MANIFEST_INVALID" });
  }
});

test("rejects incompatible versions, malformed IDs, and malformed digests", async () => {
  const { release, trust, value } = await fixture();
  const cases = [
    { ...value, format: 3 },
    { ...value, contract: 2 },
    { ...value, catalogId: ".." },
    { ...value, releaseId: "bad/release" },
    { ...value, generation: -1 },
    { ...value, source: { ...value.source, referenceGraphDigest: "ABC" } },
    { ...value, records: { "operation:tiny:bad/id": digestA } },
  ];
  for (const candidate of cases) {
    let manifestJson: string;
    try {
      manifestJson = canonicalJson(candidate as never);
    } catch {
      manifestJson = JSON.stringify(candidate);
    }
    const envelope = {
      manifestJson,
      signature: {
        algorithm: "Ed25519" as const,
        keyId: release.keyId,
        signature: await sign(
          release.privateKey,
          `${manifestDomain}${manifestJson}`,
        ),
      },
    };
    await expect(
      admitManifest(envelope, trust, new MemoryGenerationStore()),
    ).rejects.toMatchObject({ code: "MANIFEST_INVALID" });
  }
});

test("enforces manifest bytes, record count, and nesting depth", async () => {
  const { envelope, trust, value, release } = await fixture();
  await expect(
    admitManifest(envelope, trust, new MemoryGenerationStore(), {
      maxManifestBytes: 20,
    } as never),
  ).rejects.toMatchObject({ code: "MANIFEST_INVALID" });
  await expect(
    admitManifest(envelope, trust, new MemoryGenerationStore(), {
      maxManifestRecords: 0,
    } as never),
  ).rejects.toThrow(
    new RangeError(
      "Runtime limit maxManifestRecords must only lower its default",
    ),
  );
  const deep = { ...value, source: { ...value.source, uri: "x" } };
  const manifestJson = canonicalJson(deep);
  const deepEnvelope = {
    manifestJson,
    signature: {
      algorithm: "Ed25519" as const,
      keyId: release.keyId,
      signature: await sign(
        release.privateKey,
        `${manifestDomain}${manifestJson}`,
      ),
    },
  };
  await expect(
    admitManifest(deepEnvelope, trust, new MemoryGenerationStore(), {
      maxJsonDepth: 1,
    } as never),
  ).rejects.toMatchObject({ code: "MANIFEST_INVALID" });
});

test("accepts only canonical HTTPS origins without paths, credentials, or normalization drift", async () => {
  const { release, trust, value } = await fixture();
  for (const origin of [
    "https://API.example.com",
    "https://api.example.com/",
    "https://user@api.example.com",
    "https://api.example.com/path",
    "http://api.example.com",
  ]) {
    const candidate = { ...value, allowedOrigins: [origin] };
    const manifestJson = canonicalJson(candidate);
    const envelope = {
      manifestJson,
      signature: {
        algorithm: "Ed25519" as const,
        keyId: release.keyId,
        signature: await sign(
          release.privateKey,
          `${manifestDomain}${manifestJson}`,
        ),
      },
    };
    await expect(
      admitManifest(envelope, trust, new MemoryGenerationStore()),
    ).rejects.toMatchObject({ code: "MANIFEST_INVALID" });
  }
  const duplicate = {
    ...value,
    allowedOrigins: ["https://api.example.com", "https://api.example.com"],
  };
  const manifestJson = canonicalJson(duplicate);
  const duplicateEnvelope = {
    manifestJson,
    signature: {
      algorithm: "Ed25519" as const,
      keyId: release.keyId,
      signature: await sign(
        release.privateKey,
        `${manifestDomain}${manifestJson}`,
      ),
    },
  };
  await expect(
    admitManifest(duplicateEnvelope, trust, new MemoryGenerationStore()),
  ).rejects.toMatchObject({ code: "MANIFEST_INVALID" });
});

test("equal generation with the same digest is idempotent", async () => {
  const { envelope, trust } = await fixture();
  const generations = new MemoryGenerationStore();
  const first = await admitManifest(envelope, trust, generations);
  const second = await admitManifest(envelope, trust, generations);
  expect(second.manifestDigest).toBe(first.manifestDigest);
  expect((await generations.get(catalogId, "issuer.example"))?.revision).toBe(
    0,
  );
});

test("equal generation with a different digest conflicts", async () => {
  const { envelope, trust, value, release } = await fixture();
  const generations = new MemoryGenerationStore();
  await admitManifest(envelope, trust, generations);
  const changed = await signedEnvelope(
    { ...value, policyId: "changed" },
    release,
  );
  await expect(
    admitManifest(changed, trust, generations),
  ).rejects.toMatchObject({ code: "MANIFEST_GENERATION_CONFLICT" });
});

test("a normally signed lower generation is rejected", async () => {
  const { envelope, trust } = await fixture();
  const generations = new MemoryGenerationStore(state(8, digestA));
  await expect(
    admitManifest(envelope, trust, generations),
  ).rejects.toMatchObject({ code: "MANIFEST_ROLLBACK_REJECTED" });
  expect(generations.accepts).toBe(0);
});

test("higher generations advance both high-water and active release", async () => {
  const { envelope, trust } = await fixture();
  const generations = new MemoryGenerationStore(state(6, digestA));
  const admitted = await admitManifest(envelope, trust, generations);
  expect(await generations.get(catalogId, "issuer.example")).toMatchObject({
    highestGeneration: 7,
    highestManifestDigest: admitted.manifestDigest,
    activeGeneration: 7,
    activeManifestDigest: admitted.manifestDigest,
  });
});

test("signed rollback changes active state, preserves high-water, and consumes its identity", async () => {
  const { envelope, trust, rollback, value } = await fixture();
  const manifestDigest = await sha256(
    "knitli.openapi-mcp.release-manifest.v4",
    value,
  );
  envelope.rollback = await rollbackAuthorization(
    value,
    manifestDigest,
    rollback,
  );
  const generations = new MemoryGenerationStore(state(8, digestA));
  await admitManifest(envelope, trust, generations);
  expect(await generations.get(catalogId, "issuer.example")).toEqual({
    revision: 4,
    highestGeneration: 8,
    highestManifestDigest: digestA,
    activeGeneration: 7,
    activeManifestDigest: manifestDigest,
    consumedRollbackAuthorizationIds: ["rollback-7"],
  });
});

test("persisted rollback target is restart-idempotent without replaying authorization", async () => {
  const path = await tempStatePath();
  const originalStore = new FileGenerationStore(path);
  const { envelope, trust, value } = await fixture();
  const targetDigest = await sha256(
    "knitli.openapi-mcp.release-manifest.v4",
    value,
  );
  const initial = { ...state(8, digestA), revision: 0 };
  await originalStore.accept(catalogId, "issuer.example", {
    expectedRevision: null,
    next: initial,
  });
  await originalStore.accept(catalogId, "issuer.example", {
    expectedRevision: 0,
    next: {
      ...initial,
      revision: 1,
      activeGeneration: 7,
      activeManifestDigest: targetDigest,
      consumedRollbackAuthorizationIds: ["rollback-7"],
    },
  });
  const restarted = new FileGenerationStore(path);
  await expect(
    admitManifest(
      { manifestJson: envelope.manifestJson, signature: envelope.signature },
      trust,
      restarted,
    ),
  ).resolves.toMatchObject({ manifestDigest: targetDigest });
  expect((await restarted.get(catalogId, "issuer.example"))?.revision).toBe(1);
});

test("inactive high-water release cannot reactivate without a strictly higher generation", async () => {
  const { release, trust } = await fixture();
  const highManifest = await manifest({
    generation: 8,
    releaseId: "release-8" as never,
  });
  const highDigest = await sha256(
    "knitli.openapi-mcp.release-manifest.v4",
    highManifest,
  );
  const highEnvelope = await signedEnvelope(highManifest, release);
  const store = new MemoryGenerationStore({
    revision: 4,
    highestGeneration: 8,
    highestManifestDigest: highDigest,
    activeGeneration: 7,
    activeManifestDigest: digestB,
    consumedRollbackAuthorizationIds: ["rollback-7"],
  });
  await expect(admitManifest(highEnvelope, trust, store)).rejects.toMatchObject(
    {
      code: "MANIFEST_ROLLBACK_REJECTED",
    },
  );
  expect((await store.get(catalogId, "issuer.example"))?.activeGeneration).toBe(
    7,
  );
  const newer = await manifest({
    generation: 9,
    releaseId: "release-9" as never,
  });
  await expect(
    admitManifest(await signedEnvelope(newer, release), trust, store),
  ).resolves.toMatchObject({ manifest: { generation: 9 } });
});

test("rollback exact shape rejects hidden properties", async () => {
  const { envelope, trust, rollback, value } = await fixture();
  const targetDigest = await sha256(
    "knitli.openapi-mcp.release-manifest.v4",
    value,
  );
  const authorization = await rollbackAuthorization(
    value,
    targetDigest,
    rollback,
  );
  Object.defineProperty(authorization, "hidden", { value: true });
  await expect(
    admitManifest(
      { ...envelope, rollback: authorization },
      trust,
      new MemoryGenerationStore(state(8, digestA)),
    ),
  ).rejects.toMatchObject({ code: "MANIFEST_ROLLBACK_REJECTED" });
});

test("configured manifest limits are honored through detachment before CAS", async () => {
  const { envelope, trust } = await fixture();
  const generations = new MemoryGenerationStore();
  const maxManifestBytes = encoder.encode(envelope.manifestJson).byteLength + 1;
  await expect(
    admitManifest(envelope, trust, generations, {
      maxManifestBytes,
      maxManifestRecords: 1,
    }),
  ).resolves.toMatchObject({ manifest: { generation: 7 } });
  expect(generations.accepts).toBe(1);
});

test("public manifest and record entry points resolve partial limits and reject invalid overrides", async () => {
  const { envelope, trust } = await fixture();
  const manifestOverrides = {
    maxManifestBytes: DEFAULT_RUNTIME_LIMITS.maxManifestBytes,
  } satisfies Partial<RuntimeLimits>;
  await expect(
    admitManifest(
      envelope,
      trust,
      new MemoryGenerationStore(),
      manifestOverrides,
    ),
  ).resolves.toMatchObject({ manifest: { generation: 7 } });
  await expect(
    admitManifest(envelope, trust, new MemoryGenerationStore(), {
      maxManifestBytes: 0,
    }),
  ).rejects.toThrow(
    new RangeError(
      "Runtime limit maxManifestBytes must only lower its default",
    ),
  );

  const admitted = await admitFixture();
  const record = operation();
  const row = {
    id: record.id,
    logicalDigest: await operationDigest(record),
    record,
  };
  const recordOverrides = {
    maxRecordBytes: DEFAULT_RUNTIME_LIMITS.maxRecordBytes,
  } satisfies Partial<RuntimeLimits>;
  await expect(
    verifyStoredRecord(admitted, row, recordOverrides),
  ).resolves.toEqual(record);
  await expect(
    verifyStoredRecord(admitted, row, { maxRecordBytes: 0 }),
  ).rejects.toThrow(
    new RangeError("Runtime limit maxRecordBytes must only lower its default"),
  );
});

test("public manifest and record entry points normalize malformed limit containers", async () => {
  const { envelope, trust } = await fixture();
  const admitted = await admitFixture();
  const record = operation();
  const row = {
    id: record.id,
    logicalDigest: await operationDigest(record),
    record,
  };
  const poisonedProxy = new Proxy(
    {},
    {
      ownKeys: () => {
        throw new Error("limits-entrypoint-secret");
      },
    },
  );
  const malformedMessage =
    "Runtime limits overrides must be an exact plain data object";
  await expect(
    admitManifest(envelope, trust, new MemoryGenerationStore(), [] as never),
  ).rejects.toThrow(new RangeError(malformedMessage));
  await expect(
    verifyStoredRecord(admitted, row, poisonedProxy as never),
  ).rejects.toThrow(new RangeError(malformedMessage));
});

test("rollback rejects expiry, replay, binding mismatches, malformed signature, and ordinary release keys", async () => {
  const { release, rollback, trust, value, envelope } = await fixture();
  const manifestDigest = await sha256(
    "knitli.openapi-mcp.release-manifest.v4",
    value,
  );
  const cases: Array<
    [
      Partial<RollbackAuthorization>,
      ManifestTrust,
      Awaited<ReturnType<typeof keyPair>>,
    ]
  > = [
    [{ expiresAt: "2026-09-04T12:00:00.000Z" }, trust, rollback],
    [{ currentHighestGeneration: 9 }, trust, rollback],
    [{ targetGeneration: 6 }, trust, rollback],
    [{ targetManifestDigest: digestA }, trust, rollback],
    [{ catalogId: "other" as never }, trust, rollback],
    [{ issuer: "other.example" }, trust, rollback],
    [{ signature: "not+base64" }, trust, rollback],
    [{ keyId: release.keyId }, trust, release],
  ];
  for (const [overrides, candidateTrust, signingKey] of cases) {
    const candidate = {
      ...envelope,
      rollback: await rollbackAuthorization(
        value,
        manifestDigest,
        signingKey,
        overrides,
      ),
    };
    await expect(
      admitManifest(
        candidate,
        candidateTrust,
        new MemoryGenerationStore(state(8, digestA)),
      ),
    ).rejects.toMatchObject({ code: "MANIFEST_ROLLBACK_REJECTED" });
  }
  const replayState = state(8, digestA);
  replayState.consumedRollbackAuthorizationIds = ["rollback-7"];
  const replay = {
    ...envelope,
    rollback: await rollbackAuthorization(value, manifestDigest, rollback),
  };
  await expect(
    admitManifest(replay, trust, new MemoryGenerationStore(replayState)),
  ).rejects.toMatchObject({ code: "MANIFEST_ROLLBACK_REJECTED" });
});

test("CAS conflict retries from fresh state without overwriting a concurrent higher generation", async () => {
  const { envelope, trust } = await fixture();
  const concurrent = state(9, digestB);
  let first = true;
  const store = new MemoryGenerationStore(state(6, digestA));
  const originalAccept = store.accept.bind(store);
  store.accept = async (catalog, issuer, transition) => {
    if (first) {
      first = false;
      store.states.set("tiny\0issuer.example", concurrent);
      return null;
    }
    return originalAccept(catalog, issuer, transition);
  };
  await expect(admitManifest(envelope, trust, store)).rejects.toMatchObject({
    code: "MANIFEST_ROLLBACK_REJECTED",
  });
  expect(await store.get(catalogId, "issuer.example")).toEqual(concurrent);
});

test("row digest and manifest membership are independently required", async () => {
  const admitted = await admitFixture();
  const record = operation();
  const row: StoredRecord<OperationRecordV4> = {
    id: record.id,
    logicalDigest: await operationDigest(record),
    record,
  };
  await expect(
    verifyStoredRecord(admitted, {
      ...row,
      record: { ...record, summary: "tampered" },
    }),
  ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
  const extra = operation({
    id: "operation:tiny:users.extra",
    operationId: "users.extra",
  });
  await expect(
    verifyStoredRecord(admitted, {
      id: extra.id,
      logicalDigest: await operationDigest(extra),
      record: extra,
    }),
  ).rejects.toMatchObject({ code: "RECORD_NOT_ADMITTED" });
  await expect(
    verifyStoredRecord(admitted, { ...row, logicalDigest: digestA }),
  ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
});

test("authenticates legacy v4 operation records before normalizing missing tags", async () => {
  const current = operation();
  const { tags: _tags, ...legacyRecord } = current;
  const legacyDigest = await sha256(
    "knitli.openapi-mcp.operation-record.v4",
    legacyRecord,
  );
  const { release, trust, value } = await fixture();
  const admitted = await admitManifest(
    await signedEnvelope(
      { ...value, records: { [current.id]: legacyDigest } },
      release,
    ),
    trust,
    new MemoryGenerationStore(),
  );

  const verified = await verifyStoredRecord(admitted, {
    id: current.id,
    logicalDigest: legacyDigest,
    record: legacyRecord,
  } as never);

  expect(verified).toEqual(current);
  expect(Object.isFrozen(verified)).toBe(true);
  expect(Object.isFrozen(verified.tags)).toBe(true);
});

test("requires bounded unique signed tags and binds them to the record digest", async () => {
  const invalidTags: readonly unknown[] = [
    ["duplicate", "duplicate"],
    Array.from(
      { length: MAX_OPERATION_TAGS + 1 },
      (_, index) => `tag-${index}`,
    ),
    ["😀".repeat(Math.floor(MAX_OPERATION_TAG_BYTES / 4) + 1)],
    [
      ...Array.from(
        { length: MAX_OPERATION_TAG_BYTES_TOTAL / MAX_OPERATION_TAG_BYTES },
        (_, index) =>
          `${index.toString().padStart(3, "0")}${"a".repeat(MAX_OPERATION_TAG_BYTES - 3)}`,
      ),
      "z",
    ],
  ];

  for (const tags of invalidTags) {
    const record = operation({ tags: tags as never });
    const { release, trust, value } = await fixture();
    const digest = await operationDigest(record);
    const admitted = await admitManifest(
      await signedEnvelope(
        { ...value, records: { [record.id]: digest } },
        release,
      ),
      trust,
      new MemoryGenerationStore(),
    );

    await expect(
      verifyStoredRecord(admitted, {
        id: record.id,
        logicalDigest: digest,
        record,
      }),
    ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
  }

  const record = operation({ tags: ["refund"] });
  const { release, trust, value } = await fixture();
  const digest = await operationDigest(record);
  const admitted = await admitManifest(
    await signedEnvelope(
      { ...value, records: { [record.id]: digest } },
      release,
    ),
    trust,
    new MemoryGenerationStore(),
  );

  await expect(
    verifyStoredRecord(admitted, {
      id: record.id,
      logicalDigest: digest,
      record,
    }),
  ).resolves.toEqual(record);
  await expect(
    verifyStoredRecord(admitted, {
      id: record.id,
      logicalDigest: digest,
      record: { ...record, tags: ["delete"] },
    }),
  ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
});

test("record verification rejects wrapper/record extras, ID disagreement, malformed IDs, and oversize rows", async () => {
  const admitted = await admitFixture();
  const record = operation();
  const row = {
    id: record.id,
    logicalDigest: await operationDigest(record),
    record,
  };
  await expect(
    verifyStoredRecord(admitted, { ...row, ftsRank: 1 } as never),
  ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
  await expect(
    verifyStoredRecord(admitted, {
      ...row,
      record: { ...record, extra: true },
    } as never),
  ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
  await expect(
    verifyStoredRecord(admitted, {
      ...row,
      id: "operation:tiny:other",
    } as never),
  ).rejects.toMatchObject({ code: "RECORD_NOT_ADMITTED" });
  await expect(
    verifyStoredRecord(admitted, {
      ...row,
      id: "operation:tiny:bad/id",
      record: { ...record, id: "operation:tiny:bad/id" },
    } as never),
  ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
  await expect(
    verifyStoredRecord(admitted, row, { maxRecordBytes: 8 } as never),
  ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
});

test("stored wrapper reflection traps are stable and never traverse its record", async () => {
  const admitted = await admitFixture();
  let recordTraversed = false;
  const record = new Proxy(operation(), {
    getPrototypeOf() {
      recordTraversed = true;
      return Object.prototype;
    },
  });
  const wrapper = { id: operationId, logicalDigest: digestA, record };
  const trapped = [
    new Proxy(wrapper, {
      getPrototypeOf() {
        throw new Error("wrapper prototype trap");
      },
    }),
    new Proxy(wrapper, {
      ownKeys() {
        throw new Error("wrapper ownKeys trap");
      },
    }),
    new Proxy(wrapper, {
      getOwnPropertyDescriptor() {
        throw new Error("wrapper descriptor trap");
      },
    }),
  ];
  for (const candidate of trapped) {
    await expect(
      verifyStoredRecord(admitted, candidate as never),
    ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
    expect(recordTraversed).toBe(false);
  }
});

test("stored wrapper extraction never invokes Proxy get traps", async () => {
  const admitted = await admitFixture();
  let invoked = false;
  const wrapper = new Proxy(
    { id: operationId, logicalDigest: digestA, record: operation() },
    {
      get() {
        invoked = true;
        throw new Error("wrapper get trap");
      },
    },
  );
  await expect(
    verifyStoredRecord(admitted, wrapper as never),
  ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
  expect(invoked).toBe(false);
});

test("unadmitted wrapper ID is rejected before hostile record traversal", async () => {
  const admitted = await admitFixture();
  let traversed = false;
  const poison = new Proxy(
    {},
    {
      getPrototypeOf() {
        traversed = true;
        return Object.prototype;
      },
    },
  );
  await expect(
    verifyStoredRecord(admitted, {
      id: "operation:tiny:users.extra",
      logicalDigest: digestA,
      record: poison,
    } as never),
  ).rejects.toMatchObject({ code: "RECORD_NOT_ADMITTED" });
  expect(traversed).toBe(false);
});

test("record bounds run before schema ID iteration on admitted rows", async () => {
  const admitted = await admitFixture();
  let iterated = false;
  const schemaIds = new Proxy([], {
    get(target, property, receiver) {
      if (property === Symbol.iterator) {
        iterated = true;
        throw new Error("schemaIds iterator must not run before bounds");
      }
      return Reflect.get(target, property, receiver);
    },
  });
  const record = { ...operation(), schemaIds };
  await expect(
    verifyStoredRecord(
      admitted,
      { id: record.id, logicalDigest: digestA, record },
      { maxRecordBytes: 1 } as never,
    ),
  ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
  expect(iterated).toBe(false);
});

test("record reflection traps remain in the record error domain", async () => {
  const admitted = await admitFixture();
  const records = [
    new Proxy(operation(), {
      getPrototypeOf() {
        throw new Error("hostile prototype trap");
      },
    }),
    new Proxy(operation(), {
      ownKeys() {
        throw new Error("hostile ownKeys trap");
      },
    }),
    new Proxy(operation(), {
      getOwnPropertyDescriptor() {
        throw new Error("hostile descriptor trap");
      },
    }),
  ];
  for (const record of records) {
    await expect(
      verifyStoredRecord(admitted, {
        id: operationId,
        logicalDigest: digestA,
        record,
      } as never),
    ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
  }
});

test("record byte bound aborts traversal before later poisoned values", async () => {
  const { release, trust, value } = await fixture();
  const admitted = await admitManifest(
    await signedEnvelope(
      { ...value, records: { [operationId]: digestA } },
      release,
    ),
    trust,
    new MemoryGenerationStore(),
  );
  let traversed = false;
  const poison = new Proxy(
    {},
    {
      getPrototypeOf() {
        traversed = true;
        return Object.prototype;
      },
    },
  );
  const record = operation({
    advisory: { aOversized: "x".repeat(1024), zPoison: poison },
  });
  await expect(
    verifyStoredRecord(
      admitted,
      { id: record.id, logicalDigest: digestA, record },
      { maxRecordBytes: 256 } as never,
    ),
  ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
  expect(traversed).toBe(false);
});

test("record depth bound aborts traversal before later poisoned values", async () => {
  const { release, trust, value } = await fixture();
  const admitted = await admitManifest(
    await signedEnvelope(
      { ...value, records: { [operationId]: digestA } },
      release,
    ),
    trust,
    new MemoryGenerationStore(),
  );
  let traversed = false;
  const poison = new Proxy(
    {},
    {
      getPrototypeOf() {
        traversed = true;
        return Object.prototype;
      },
    },
  );
  const record = operation({
    advisory: { aDeep: { one: { two: { three: true } } }, zPoison: poison },
  });
  await expect(
    verifyStoredRecord(
      admitted,
      { id: record.id, logicalDigest: digestA, record },
      { maxJsonDepth: 3 } as never,
    ),
  ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
  expect(traversed).toBe(false);
});

test("hostile record canonicalization errors stay in the record error domain", async () => {
  const admitted = await admitFixture();
  const record = operation();
  Object.defineProperty(record.advisory, "hidden", { value: true });
  await expect(
    verifyStoredRecord(admitted, {
      id: record.id,
      logicalDigest: digestA,
      record,
    }),
  ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
});

test("record verification binds operation ID fields and signed allowed origin", async () => {
  const mismatchedId = operation({ operationId: "users.other" });
  const { release, trust, value } = await fixture();
  const mismatchedDigest = await operationDigest(mismatchedId);
  const mismatchedEnvelope = await signedEnvelope(
    { ...value, records: { [mismatchedId.id]: mismatchedDigest } },
    release,
  );
  const mismatchedAdmitted = await admitManifest(
    mismatchedEnvelope,
    trust,
    new MemoryGenerationStore(),
  );
  await expect(
    verifyStoredRecord(mismatchedAdmitted, {
      id: mismatchedId.id,
      logicalDigest: mismatchedDigest,
      record: mismatchedId,
    }),
  ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
  const disallowedOrigin = operation({ origin: "https://other.example.com" });
  const disallowedDigest = await operationDigest(disallowedOrigin);
  const disallowedEnvelope = await signedEnvelope(
    { ...value, records: { [disallowedOrigin.id]: disallowedDigest } },
    release,
  );
  const disallowedAdmitted = await admitManifest(
    disallowedEnvelope,
    trust,
    new MemoryGenerationStore(),
  );
  await expect(
    verifyStoredRecord(disallowedAdmitted, {
      id: disallowedOrigin.id,
      logicalDigest: disallowedDigest,
      record: disallowedOrigin,
    }),
  ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
});

test("schema logical records use their own digest domain and are deeply frozen", async () => {
  const schema = {
    id: "schema:tiny:#/components/schemas/User" as const,
    schema: { type: "object", properties: { name: { type: "string" } } },
  };
  const digest = await sha256("knitli.openapi-mcp.schema-record.v4", schema);
  const { release, trust, value } = await fixture();
  const envelope = await signedEnvelope(
    { ...value, records: { [schema.id]: digest } },
    release,
  );
  const admitted = await admitManifest(
    envelope,
    trust,
    new MemoryGenerationStore(),
  );
  const verified = await verifyStoredRecord(admitted, {
    id: schema.id,
    logicalDigest: digest,
    record: schema,
  });
  expect(Object.isFrozen(verified.schema.properties.name)).toBe(true);
});

async function verifyAdmittedSchema(schema: JsonObject | boolean) {
  const id = "schema:tiny:#/components/schemas/VerifierFixture" as const;
  const record = { id, schema };
  const digest = await sha256("knitli.openapi-mcp.schema-record.v4", record);
  const { release, trust, value } = await fixture();
  const admitted = await admitManifest(
    await signedEnvelope({ ...value, records: { [id]: digest } }, release),
    trust,
    new MemoryGenerationStore(),
  );
  return verifyStoredRecord(admitted, { id, logicalDigest: digest, record });
}

test("stored schema records reject raw refs in schema-bearing children", async () => {
  const rawRef = { $ref: "#/components/schemas/Untyped" };
  const thenSchema: JsonObject = Object.create(null);
  Reflect.set(thenSchema, "then", rawRef);
  const cases: readonly [string, JsonObject][] = [
    ["single", { additionalProperties: rawRef }],
    ["contains", { contains: rawRef }],
    ["contentSchema", { contentSchema: rawRef }],
    ["else", { else: rawRef }],
    ["if", { if: rawRef }],
    ["items", { items: rawRef }],
    ["not", { not: rawRef }],
    ["propertyNames", { propertyNames: rawRef }],
    ["then", thenSchema],
    ["unevaluatedItems", { unevaluatedItems: rawRef }],
    ["unevaluatedProperties", { unevaluatedProperties: rawRef }],
    ["properties", { properties: { value: rawRef } }],
    ["$defs", { $defs: { value: rawRef } }],
    ["definitions", { definitions: { value: rawRef } }],
    ["dependentSchemas", { dependentSchemas: { value: rawRef } }],
    ["patternProperties", { patternProperties: { value: rawRef } }],
    ["prefixItems", { prefixItems: [rawRef] }],
    ["allOf", { allOf: [rawRef] }],
    ["anyOf", { anyOf: [rawRef] }],
    ["oneOf", { oneOf: [rawRef] }],
  ];
  for (const [location, schema] of cases) {
    await expect(verifyAdmittedSchema(schema), location).rejects.toMatchObject({
      code: "RECORD_DIGEST_MISMATCH",
    });
  }
});

test("stored schema records reject malformed schema-bearing containers", async () => {
  const cases: readonly [string, JsonObject][] = [
    ["array keyword with an object", { allOf: { type: "string" } }],
    ["map keyword with an array", { properties: [{ type: "string" }] }],
    ["single keyword with an array", { not: [{ type: "string" }] }],
    ["array keyword with a non-schema entry", { anyOf: [null] }],
    ["map keyword with a non-schema entry", { $defs: { value: 1 } }],
    ["single keyword with a non-schema value", { items: "string" }],
  ];
  for (const [location, schema] of cases) {
    await expect(verifyAdmittedSchema(schema), location).rejects.toMatchObject({
      code: "RECORD_DIGEST_MISMATCH",
    });
  }
});

test("stored schema records accept boolean subschemas in every container kind", async () => {
  const schema: JsonObject = {
    not: false,
    properties: { allowed: true },
    allOf: [true, false],
  };
  await expect(verifyAdmittedSchema(schema)).resolves.toMatchObject({ schema });
});

test("stored schema records accept boolean root schemas", async () => {
  await expect(verifyAdmittedSchema(true)).resolves.toMatchObject({
    schema: true,
  });
  await expect(verifyAdmittedSchema(false)).resolves.toMatchObject({
    schema: false,
  });
});

test("stored schema records preserve raw ref-shaped annotation data", async () => {
  const rawRef = { $ref: "#/components/schemas/Untyped" };
  const schema: JsonObject = {
    example: rawRef,
    default: rawRef,
    const: rawRef,
    enum: [rawRef],
    examples: [rawRef],
    discriminator: rawRef,
    "x-ref-shaped-data": rawRef,
  };
  const verified = await verifyAdmittedSchema(schema);
  expect(verified.schema).toEqual(schema);
});

test("verified logical records are detached and deeply frozen", async () => {
  const parameterSchemaId = "schema:api:#/components/schemas/Limit" as const;
  const record = operation({
    parameters: [
      {
        name: "limit",
        in: "query",
        required: false,
        deprecated: false,
        style: "form",
        explode: true,
        allowReserved: false,
        value: { kind: "schema", schemaId: parameterSchemaId },
      },
    ],
    schemaIds: [parameterSchemaId],
  });
  const digest = await operationDigest(record);
  const { release, trust, value } = await fixture();
  const envelope = await signedEnvelope(
    { ...value, records: { [record.id]: digest } },
    release,
  );
  const admitted = await admitManifest(
    envelope,
    trust,
    new MemoryGenerationStore(),
  );
  const verified = await verifyStoredRecord(admitted, {
    id: record.id,
    logicalDigest: digest,
    record,
  });
  expect(verified).not.toBe(record);
  expect(Object.isFrozen(verified)).toBe(true);
  expect(Object.isFrozen(verified.parameters)).toBe(true);
  expect(Object.isFrozen(verified.parameters[0].value)).toBe(true);
  (record.parameters[0] as Record<string, unknown>).name =
    "changed-after-verification";
  expect(verified.parameters[0].name).toBe("limit");
});

async function tempStatePath(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "openapi-mcp-generation-"));
  temporaryDirectories.push(directory);
  return join(directory, "generations.json");
}

async function withStateMutationAfterHandleStat<T>(
  path: string,
  mutation: () => Promise<void>,
  operation: () => Promise<T>,
): Promise<T> {
  const expected = await lstat(path, { bigint: true });
  const probe = await open(path, "r");
  const prototype = Object.getPrototypeOf(probe) as {
    stat: (...args: unknown[]) => Promise<BigIntStats | Stats>;
  };
  await probe.close();
  const originalStat = prototype.stat;
  let mutated = false;
  prototype.stat = async function (
    ...args: unknown[]
  ): Promise<BigIntStats | Stats> {
    const metadata = (await Reflect.apply(originalStat, this, args)) as
      | BigIntStats
      | Stats;
    if (
      !mutated &&
      typeof metadata.dev === "bigint" &&
      metadata.dev === expected.dev &&
      metadata.ino === expected.ino
    ) {
      mutated = true;
      await mutation();
    }
    return metadata;
  };
  try {
    return await operation();
  } finally {
    prototype.stat = originalStat;
    expect(mutated).toBe(true);
  }
}

function mutexPath(statePath: string): string {
  return join(dirname(statePath), `.${basename(statePath)}.mutex.sqlite3`);
}

function expectValidMutex(path: string): void {
  const database = new DatabaseSync(path, { readOnly: true });
  try {
    expect(database.prepare("PRAGMA user_version").get()).toEqual({
      user_version: 1,
    });
    expect(
      database
        .prepare(
          "SELECT singleton, format, marker FROM knitli_generation_mutex",
        )
        .all(),
    ).toEqual([
      {
        singleton: 1,
        format: 1,
        marker: "knitli.openapi-mcp.generation-mutex.v1",
      },
    ]);
  } finally {
    database.close();
  }
}

async function writeChildAcceptHelper(directory: string): Promise<string> {
  const helper = join(directory, "accept-child.ts");
  const moduleUrl = new URL(
    "../src/sqlite/generation-store.ts",
    import.meta.url,
  ).href;
  await writeFile(
    helper,
    `import { existsSync } from "node:fs";\nimport { FileGenerationStore } from ${JSON.stringify(moduleUrl)};\nconst [statePath, transitionJson, barrier] = process.argv.slice(2);\nwhile (!existsSync(barrier)) await Bun.sleep(1);\nconst result = await new FileGenerationStore(statePath).accept("tiny", "issuer.example", JSON.parse(transitionJson));\nprocess.stdout.write(JSON.stringify(result));\n`,
  );
  return helper;
}

async function childAccept(
  helper: string,
  cwd: string,
  statePath: string,
  transition: GenerationTransition,
  barrier: string,
): Promise<GenerationState | null> {
  const child = Bun.spawn(
    [process.execPath, helper, statePath, JSON.stringify(transition), barrier],
    { cwd, stdout: "pipe", stderr: "pipe" },
  );
  const output = new Response(child.stdout).text();
  const error = new Response(child.stderr).text();
  const exitCode = await child.exited;
  if (exitCode !== 0) throw new Error(await error);
  return JSON.parse(await output) as GenerationState | null;
}

async function waitForFile(path: string): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    try {
      await lstat(path);
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      await Bun.sleep(5);
    }
  }
  throw new Error(`Timed out waiting for ${basename(path)}`);
}

async function writeMutexHolderHelper(directory: string): Promise<string> {
  const helper = join(directory, "mutex-holder.ts");
  await writeFile(
    helper,
    `import { existsSync, writeFileSync } from "node:fs";\nimport { DatabaseSync } from "node:sqlite";\nconst [mutex, ready, release] = process.argv.slice(2);\nconst database = new DatabaseSync(mutex, { timeout: 2000 });\ndatabase.exec("BEGIN EXCLUSIVE");\nwriteFileSync(ready, "ready");\nwhile (!existsSync(release)) await Bun.sleep(5);\ndatabase.exec("COMMIT");\ndatabase.close();\n`,
  );
  return helper;
}

async function writeCrashCheckpointHelper(directory: string): Promise<string> {
  const helper = join(directory, "mutex-crash-checkpoint.ts");
  await writeFile(
    helper,
    `import { constants } from "node:fs";\nimport { open, rename } from "node:fs/promises";\nimport { dirname } from "node:path";\nimport { DatabaseSync } from "node:sqlite";\nconst [mutex, target, temporary, payload, checkpoint] = process.argv.slice(2);\nconst database = new DatabaseSync(mutex, { timeout: 2000 });\ndatabase.exec("BEGIN EXCLUSIVE");\nconst file = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);\nawait file.writeFile(payload);\nawait file.sync();\nawait file.close();\nif (checkpoint === "before-rename") process.kill(process.pid, "SIGKILL");\nawait rename(temporary, target);\nif (checkpoint === "after-rename") process.kill(process.pid, "SIGKILL");\nconst parent = await open(dirname(target), constants.O_RDONLY);\nawait parent.sync();\nawait parent.close();\nif (checkpoint === "after-sync") process.kill(process.pid, "SIGKILL");\ndatabase.exec("COMMIT");\nif (checkpoint === "after-commit") process.kill(process.pid, "SIGKILL");\n`,
  );
  return helper;
}

test("FileGenerationStore persists 0600 state and enforces CAS across concurrent accepts", async () => {
  const path = await tempStatePath();
  const store = new FileGenerationStore(path);
  const otherStore = new FileGenerationStore(path);
  const nextA = { ...state(1, digestA), revision: 0 };
  const nextB = { ...state(2, digestB), revision: 0 };
  const results = await Promise.all([
    store.accept(catalogId, "issuer.example", {
      expectedRevision: null,
      next: nextA,
    }),
    otherStore.accept(catalogId, "issuer.example", {
      expectedRevision: null,
      next: nextB,
    }),
  ]);
  expect(results.filter(Boolean)).toHaveLength(1);
  expect((await lstat(path)).mode & 0o777).toBe(0o600);
  expect(await store.get(catalogId, "issuer.example")).toEqual(
    results.find(Boolean),
  );
  expect(JSON.parse(await readFile(path, "utf8")).version).toBe(1);
});

test("FileGenerationStore provides OS-visible CAS across relative, absolute, and symlink-parent aliases", async () => {
  const path = await tempStatePath();
  const realDirectory = dirname(path);
  const harnessDirectory = await mkdtemp(
    join(tmpdir(), "openapi-mcp-generation-child-"),
  );
  temporaryDirectories.push(harnessDirectory);
  const linkedParent = join(harnessDirectory, "linked-parent");
  await symlink(realDirectory, linkedParent, "dir");
  const helper = await writeChildAcceptHelper(harnessDirectory);
  const barrier = join(harnessDirectory, "start");
  const transitions = Array.from({ length: 32 }, (_, index) => index + 1).map(
    (generation): GenerationTransition => ({
      expectedRevision: null,
      next: {
        ...state(generation, generation % 2 === 0 ? digestB : digestA),
        revision: 0,
      },
    }),
  );
  const attempts = transitions.map((transition, index) =>
    childAccept(
      helper,
      realDirectory,
      index % 3 === 0
        ? "generations.json"
        : index % 3 === 1
          ? path
          : join(linkedParent, "generations.json"),
      transition,
      barrier,
    ),
  );
  await Bun.sleep(50);
  await writeFile(barrier, "go");
  const results = await Promise.all(attempts);
  expect(results.filter((result) => result !== null)).toHaveLength(1);
  const persisted = await new FileGenerationStore(path).get(
    catalogId,
    "issuer.example",
  );
  expect(persisted).toEqual(results.find((result) => result !== null));
  expect((await lstat(mutexPath(path))).mode & 0o777).toBe(0o600);
  expect((await lstat(mutexPath(path))).nlink).toBe(1);
  expectValidMutex(mutexPath(path));
});

test("FileGenerationStore reports bounded typed contention while another process holds its mutex", async () => {
  const path = await tempStatePath();
  const store = new FileGenerationStore(path);
  await store.accept(catalogId, "issuer.example", {
    expectedRevision: null,
    next: { ...state(1, digestA), revision: 0 },
  });
  const harness = await mkdtemp(join(tmpdir(), "openapi-mcp-mutex-holder-"));
  temporaryDirectories.push(harness);
  const helper = await writeMutexHolderHelper(harness);
  const ready = join(harness, "ready");
  const release = join(harness, "release");
  const holder = Bun.spawn(
    [process.execPath, helper, mutexPath(path), ready, release],
    { stdout: "pipe", stderr: "pipe" },
  );
  await waitForFile(ready);
  const started = Date.now();
  const error = await store
    .accept(catalogId, "issuer.example", {
      expectedRevision: 0,
      next: { ...state(2, digestB), revision: 1 },
    })
    .then(
      () => null,
      (reason: unknown) => reason,
    );
  const elapsed = Date.now() - started;
  expect((error as Error | null)?.constructor.name).toBe(
    "GenerationStoreContentionError",
  );
  expect((error as Error | null)?.message).toBe(
    "Generation state mutex contention exceeded its bounded deadline",
  );
  expect(elapsed).toBeGreaterThanOrEqual(1_500);
  expect(elapsed).toBeLessThan(3_500);
  await writeFile(release, "release");
  expect(await holder.exited).toBe(0);

  const readPath = await tempStatePath();
  const readStore = new FileGenerationStore(readPath);
  await readStore.get(catalogId, "issuer.example");
  const readReady = join(harness, "read-ready");
  const readRelease = join(harness, "read-release");
  const readHolder = Bun.spawn(
    [process.execPath, helper, mutexPath(readPath), readReady, readRelease],
    { stdout: "pipe", stderr: "pipe" },
  );
  await waitForFile(readReady);
  const readError = await readStore.get(catalogId, "issuer.example").then(
    () => null,
    (reason: unknown) => reason,
  );
  expect((readError as Error | null)?.constructor.name).toBe(
    "GenerationStoreContentionError",
  );
  expect((readError as Error | null)?.message).toBe(
    "Generation state mutex contention exceeded its bounded deadline",
  );
  await writeFile(readRelease, "release");
  expect(await readHolder.exited).toBe(0);
}, 10_000);

test("FileGenerationStore mutex is released by the kernel after SIGKILL", async () => {
  const path = await tempStatePath();
  const store = new FileGenerationStore(path);
  await store.accept(catalogId, "issuer.example", {
    expectedRevision: null,
    next: { ...state(1, digestA), revision: 0 },
  });
  expectValidMutex(mutexPath(path));
  const harness = await mkdtemp(join(tmpdir(), "openapi-mcp-mutex-kill-"));
  temporaryDirectories.push(harness);
  const helper = await writeMutexHolderHelper(harness);
  const ready = join(harness, "ready");
  const holder = Bun.spawn(
    [process.execPath, helper, mutexPath(path), ready, join(harness, "never")],
    { stdout: "pipe", stderr: "pipe" },
  );
  await waitForFile(ready);
  holder.kill(9);
  expect(await holder.exited).not.toBe(0);
  await expect(
    store.accept(catalogId, "issuer.example", {
      expectedRevision: 0,
      next: { ...state(2, digestB), revision: 1 },
    }),
  ).resolves.toMatchObject({ highestGeneration: 2, revision: 1 });
});

test("FileGenerationStore crash checkpoints preserve a recoverable durable result", async () => {
  const harness = await mkdtemp(join(tmpdir(), "openapi-mcp-mutex-crash-"));
  temporaryDirectories.push(harness);
  const helper = await writeCrashCheckpointHelper(harness);
  for (const checkpoint of [
    "before-rename",
    "after-rename",
    "after-sync",
    "after-commit",
  ] as const) {
    const path = await tempStatePath();
    const store = new FileGenerationStore(path);
    const initial = { ...state(1, digestA), revision: 0 };
    const next = { ...state(2, digestB), revision: 1 };
    await store.accept(catalogId, "issuer.example", {
      expectedRevision: null,
      next: initial,
    });
    expectValidMutex(mutexPath(path));
    const payload = canonicalJson({
      entries: [{ catalogId, issuer: "issuer.example", state: next }],
      version: 1,
    });
    const child = Bun.spawn(
      [
        process.execPath,
        helper,
        mutexPath(path),
        path,
        `${path}.${checkpoint}.tmp`,
        payload,
        checkpoint,
      ],
      { stdout: "pipe", stderr: "pipe" },
    );
    expect(await child.exited).not.toBe(0);
    if (checkpoint === "before-rename") {
      await expect(
        store.accept(catalogId, "issuer.example", {
          expectedRevision: 0,
          next,
        }),
      ).resolves.toEqual(next);
    } else {
      expect(
        await store.accept(catalogId, "issuer.example", {
          expectedRevision: 0,
          next,
        }),
      ).toBeNull();
      expect(await store.get(catalogId, "issuer.example")).toEqual(next);
    }
    expectValidMutex(mutexPath(path));
  }
});

test("FileGenerationStore rejects security-history rewrites and undefined transitions", async () => {
  for (const invalidNext of [
    {
      ...state(7, digestB),
      revision: 2,
      consumedRollbackAuthorizationIds: ["used"],
    },
    {
      ...state(8, digestB),
      revision: 2,
      consumedRollbackAuthorizationIds: ["used"],
    },
    {
      ...state(8, digestA, 7),
      revision: 2,
      activeManifestDigest: digestB,
      consumedRollbackAuthorizationIds: ["other"],
    },
    {
      ...state(8, digestA, 6),
      revision: 2,
      activeManifestDigest: digestB,
      consumedRollbackAuthorizationIds: ["used"],
    },
  ]) {
    const path = await tempStatePath();
    const store = new FileGenerationStore(path);
    const initial = { ...state(8, digestA), revision: 0 };
    const rolledBack = {
      ...initial,
      revision: 1,
      activeGeneration: 7,
      activeManifestDigest: digestB,
      consumedRollbackAuthorizationIds: ["used"],
    };
    await store.accept(catalogId, "issuer.example", {
      expectedRevision: null,
      next: initial,
    });
    await store.accept(catalogId, "issuer.example", {
      expectedRevision: 0,
      next: rolledBack,
    });
    await expect(
      store.accept(catalogId, "issuer.example", {
        expectedRevision: 1,
        next: invalidNext,
      }),
    ).rejects.toThrow(/transition/i);
    expect(await store.get(catalogId, "issuer.example")).toEqual(rolledBack);
  }
});

test("FileGenerationStore accepts only creation, higher-normal, and rollback transition shapes", async () => {
  const path = await tempStatePath();
  const store = new FileGenerationStore(path);
  await expect(
    store.accept(catalogId, "issuer.example", {
      expectedRevision: null,
      next: {
        ...state(1, digestA),
        revision: 0,
        consumedRollbackAuthorizationIds: ["not-creation"],
      },
    }),
  ).rejects.toThrow(/transition/i);
  const created = { ...state(1, digestA), revision: 0 };
  expect(
    await store.accept(catalogId, "issuer.example", {
      expectedRevision: null,
      next: created,
    }),
  ).toEqual(created);
  const higher = { ...state(2, digestB), revision: 1 };
  expect(
    await store.accept(catalogId, "issuer.example", {
      expectedRevision: 0,
      next: higher,
    }),
  ).toEqual(higher);
  const rollback = {
    ...higher,
    revision: 2,
    activeGeneration: 1,
    activeManifestDigest: digestA,
    consumedRollbackAuthorizationIds: ["rollback-once"],
  };
  expect(
    await store.accept(catalogId, "issuer.example", {
      expectedRevision: 1,
      next: rollback,
    }),
  ).toEqual(rollback);
});

test("FileGenerationStore reconciles concurrent rollback retry without consuming twice", async () => {
  const path = await tempStatePath();
  const firstStore = new FileGenerationStore(path);
  const secondStore = new FileGenerationStore(path);
  const initial = { ...state(8, digestA), revision: 0 };
  expect(
    await firstStore.accept(catalogId, "issuer.example", {
      expectedRevision: null,
      next: initial,
    }),
  ).toEqual(initial);
  const { envelope, trust, rollback, value } = await fixture();
  const manifestDigest = await sha256(
    "knitli.openapi-mcp.release-manifest.v4",
    value,
  );
  envelope.rollback = await rollbackAuthorization(
    value,
    manifestDigest,
    rollback,
  );
  const results = await Promise.allSettled([
    admitManifest(envelope, trust, firstStore),
    admitManifest(envelope, trust, secondStore),
  ]);
  expect(
    results.filter((result) => result.status === "fulfilled"),
  ).toHaveLength(2);
  expect(await firstStore.get(catalogId, "issuer.example")).toMatchObject({
    revision: 1,
    consumedRollbackAuthorizationIds: ["rollback-7"],
  });
});

test("FileGenerationStore rejects impossible invariants, duplicate entries, and duplicate rollback identities", async () => {
  for (const payload of [
    {
      version: 1,
      entries: [
        {
          catalogId: "tiny",
          issuer: "issuer.example",
          state: { ...state(8, digestA), activeGeneration: 9 },
        },
      ],
    },
    {
      version: 1,
      entries: [
        {
          catalogId: "tiny",
          issuer: "issuer.example",
          state: {
            ...state(8, digestA),
            consumedRollbackAuthorizationIds: ["once", "once"],
          },
        },
      ],
    },
    {
      version: 1,
      entries: [
        {
          catalogId: "tiny",
          issuer: "issuer.example",
          state: state(8, digestA),
        },
        {
          catalogId: "tiny",
          issuer: "issuer.example",
          state: state(8, digestA),
        },
      ],
    },
  ]) {
    const path = await tempStatePath();
    await writeFile(path, JSON.stringify(payload), { mode: 0o600 });
    await expect(
      new FileGenerationStore(path).get(catalogId, "issuer.example"),
    ).rejects.toThrow();
  }
});

test("FileGenerationStore rejects symlink, non-regular, permissive, and corrupt state", async () => {
  const path = await tempStatePath();
  const target = `${path}.target`;
  await writeFile(target, '{"version":1,"entries":[]}');
  await chmod(target, 0o600);
  await symlink(target, path);
  await expect(
    new FileGenerationStore(path).get(catalogId, "issuer.example"),
  ).rejects.toThrow();

  const directoryPath = await tempStatePath();
  await mkdir(directoryPath);
  await expect(
    new FileGenerationStore(directoryPath).get(catalogId, "issuer.example"),
  ).rejects.toThrow();

  const permissive = await tempStatePath();
  await writeFile(permissive, '{"version":1,"entries":[]}');
  await chmod(permissive, 0o644);
  await expect(
    new FileGenerationStore(permissive).get(catalogId, "issuer.example"),
  ).rejects.toThrow();

  const corrupt = await tempStatePath();
  await writeFile(corrupt, "not json", { mode: 0o600 });
  await expect(
    new FileGenerationStore(corrupt).get(catalogId, "issuer.example"),
  ).rejects.toThrow();
});

test("FileGenerationStore rejects state growth after validating the open handle", async () => {
  const path = await tempStatePath();
  const payload = '{"entries":[],"version":1}';
  await writeFile(path, payload, { mode: 0o600 });
  await expect(
    withStateMutationAfterHandleStat(
      path,
      () => appendFile(path, " "),
      () => new FileGenerationStore(path).get(catalogId, "issuer.example"),
    ),
  ).rejects.toThrow(/changed|large|read/i);
});

test("FileGenerationStore rejects state truncation after validating the open handle", async () => {
  const path = await tempStatePath();
  const payload = '{"entries":[],"version":1}';
  await writeFile(path, payload, { mode: 0o600 });
  await expect(
    withStateMutationAfterHandleStat(
      path,
      () => truncate(path, Buffer.byteLength(payload) - 1),
      () => new FileGenerationStore(path).get(catalogId, "issuer.example"),
    ),
  ).rejects.toThrow(/changed|corrupt|read/i);
});

test("FileGenerationStore rejects pathname substitution after validating the open handle", async () => {
  const path = await tempStatePath();
  const payload = '{"entries":[],"version":1}';
  await writeFile(path, payload, { mode: 0o600 });
  await expect(
    withStateMutationAfterHandleStat(
      path,
      async () => {
        await rename(path, `${path}.original`);
        await writeFile(path, payload, { mode: 0o600 });
      },
      () => new FileGenerationStore(path).get(catalogId, "issuer.example"),
    ),
  ).rejects.toThrow(/changed|identity|read/i);
});

test("FileGenerationStore rejects a same-size rewrite after validating the open handle", async () => {
  const path = await tempStatePath();
  const durable = (value: GenerationState) =>
    canonicalJson({
      entries: [{ catalogId, issuer: "issuer.example", state: value }],
      version: 1,
    });
  const original = durable({ ...state(1, digestA), revision: 0 });
  const replacement = durable({ ...state(2, digestB), revision: 0 });
  expect(Buffer.byteLength(replacement)).toBe(Buffer.byteLength(original));
  await writeFile(path, original, { mode: 0o600 });
  await expect(
    withStateMutationAfterHandleStat(
      path,
      () => writeFile(path, replacement, { mode: 0o600 }),
      () => new FileGenerationStore(path).get(catalogId, "issuer.example"),
    ),
  ).rejects.toThrow(/changed|read/i);
});

test("FileGenerationStore accepts a valid state file at the exact byte limit", async () => {
  const path = await tempStatePath();
  const limit = 16 * 1024 * 1024;
  const payload = '{"entries":[],"version":1}';
  await writeFile(
    path,
    payload + " ".repeat(limit - Buffer.byteLength(payload)),
    {
      mode: 0o600,
    },
  );
  await expect(
    new FileGenerationStore(path).get(catalogId, "issuer.example"),
  ).resolves.toBeNull();
});

test("FileGenerationStore rejects a state file not owned by the effective user", async () => {
  const path = await tempStatePath();
  await writeFile(path, '{"version":1,"entries":[]}', { mode: 0o600 });
  const getuid = process.getuid;
  Object.defineProperty(process, "getuid", {
    configurable: true,
    value: () => getuid() + 1,
  });
  try {
    await expect(
      new FileGenerationStore(path).get(catalogId, "issuer.example"),
    ).rejects.toThrow(/owner/i);
  } finally {
    Object.defineProperty(process, "getuid", {
      configurable: true,
      value: getuid,
    });
  }
});

test("FileGenerationStore rejects identities its durable decoder cannot reload", async () => {
  const path = await tempStatePath();
  const store = new FileGenerationStore(path);
  const transition = {
    expectedRevision: null,
    next: { ...state(1, digestA), revision: 0 },
  };
  await expect(
    store.accept(".." as CatalogId, "issuer.example", transition),
  ).rejects.toThrow(/identity/i);
  await expect(
    store.accept(catalogId, "bad issuer", transition),
  ).rejects.toThrow(/identity/i);
  await expect(lstat(path)).rejects.toMatchObject({ code: "ENOENT" });
});

test("FileGenerationStore rejects unsafe parent permissions", async () => {
  const parentPath = await tempStatePath();
  const parent = dirname(parentPath);
  await chmod(parent, 0o777);
  try {
    await expect(
      new FileGenerationStore(parentPath).get(catalogId, "issuer.example"),
    ).rejects.toThrow(/parent/i);
  } finally {
    await chmod(parent, 0o700);
  }
});

test("FileGenerationStore rejects unsafe persistent mutex files and sidecars", async () => {
  async function initialized(): Promise<{ path: string; mutex: string }> {
    const path = await tempStatePath();
    await new FileGenerationStore(path).get(catalogId, "issuer.example");
    return { path, mutex: mutexPath(path) };
  }

  {
    const { path, mutex } = await initialized();
    await chmod(mutex, 0o644);
    await expect(
      new FileGenerationStore(path).get(catalogId, "issuer.example"),
    ).rejects.toThrow(/mutex/i);
  }
  {
    const { path, mutex } = await initialized();
    const target = `${mutex}.target`;
    await rename(mutex, target);
    await symlink(target, mutex);
    await expect(
      new FileGenerationStore(path).get(catalogId, "issuer.example"),
    ).rejects.toThrow(/mutex/i);
  }
  {
    const { path, mutex } = await initialized();
    await link(mutex, `${mutex}.alias`);
    await expect(
      new FileGenerationStore(path).get(catalogId, "issuer.example"),
    ).rejects.toThrow(/mutex/i);
  }
  {
    const { path, mutex } = await initialized();
    await rm(mutex);
    const database = new DatabaseSync(mutex);
    database.exec("CREATE TABLE unexpected(value TEXT)");
    database.close();
    await chmod(mutex, 0o600);
    await expect(
      new FileGenerationStore(path).get(catalogId, "issuer.example"),
    ).rejects.toThrow(/mutex/i);
  }
  {
    const { path, mutex } = await initialized();
    await rm(mutex);
    await writeFile(mutex, "not sqlite", { mode: 0o600 });
    await expect(
      new FileGenerationStore(path).get(catalogId, "issuer.example"),
    ).rejects.toThrow(/mutex/i);
  }
  {
    const { path, mutex } = await initialized();
    await rm(mutex);
    await writeFile(mutex, new Uint8Array(1024 * 1024 + 1), { mode: 0o600 });
    await expect(
      new FileGenerationStore(path).get(catalogId, "issuer.example"),
    ).rejects.toThrow(/mutex.*byte limit/i);
  }
  {
    const { path, mutex } = await initialized();
    await writeFile(`${mutex}-wal`, "unexpected", { mode: 0o600 });
    await expect(
      new FileGenerationStore(path).get(catalogId, "issuer.example"),
    ).rejects.toThrow(/mutex/i);
  }
});

test("FileGenerationStore clears only a crashed internal mutex initializer alias", async () => {
  const path = await tempStatePath();
  const store = new FileGenerationStore(path);
  await store.get(catalogId, "issuer.example");
  const mutex = mutexPath(path);
  const initializer = join(
    dirname(path),
    `.${basename(path)}.${process.pid}.${crypto.randomUUID()}.mutex-init`,
  );
  await link(mutex, initializer);
  expect((await lstat(mutex)).nlink).toBe(2);
  await expect(store.get(catalogId, "issuer.example")).resolves.toBeNull();
  expect((await lstat(mutex)).nlink).toBe(1);
  await expect(lstat(initializer)).rejects.toMatchObject({ code: "ENOENT" });
  expectValidMutex(mutex);
});

test("FileGenerationStore bounds state serialization before replacing durable state", async () => {
  const path = await tempStatePath();
  const limit = 16 * 1024 * 1024;
  const fixedId = (index: number) =>
    `r${String(index).padStart(6, "0")}${"x".repeat(110)}`;
  let count = Math.floor((limit - 1_000) / 120);
  const consumed = Array.from({ length: count }, (_, index) => fixedId(index));
  const durable = () =>
    canonicalJson({
      entries: [
        {
          catalogId,
          issuer: "issuer.example",
          state: {
            ...state(2, digestA),
            revision: 0,
            consumedRollbackAuthorizationIds: consumed,
          },
        },
      ],
      version: 1,
    });

  let text = durable();
  let remaining = limit - encoder.encode(text).byteLength;
  if (remaining > 130) {
    const additional = Math.floor((remaining - 1) / 120);
    consumed.push(
      ...Array.from({ length: additional }, (_, index) =>
        fixedId(count + index),
      ),
    );
    count += additional;
    text = durable();
    remaining = limit - encoder.encode(text).byteLength;
  }
  if (remaining <= 4) {
    consumed.pop();
    text = durable();
    remaining = limit - encoder.encode(text).byteLength;
  }
  const tuningLength = remaining - 4;
  expect(tuningLength).toBeGreaterThan(0);
  expect(tuningLength).toBeLessThanOrEqual(128);
  consumed.push(`t${"y".repeat(tuningLength - 1)}`);
  text = durable();
  expect(encoder.encode(text).byteLength).toBeLessThanOrEqual(limit);
  await writeFile(path, text, { mode: 0o600 });

  const store = new FileGenerationStore(path);
  await expect(
    store.accept(catalogId, "issuer.example", {
      expectedRevision: 0,
      next: {
        ...state(1, digestB),
        highestGeneration: 2,
        highestManifestDigest: digestA,
        revision: 1,
        consumedRollbackAuthorizationIds: [
          ...consumed,
          `overflow-${"z".repeat(110)}`,
        ],
      },
    }),
  ).rejects.toThrow(/size limit|persisted atomically/i);
  expect(await readFile(path, "utf8")).toBe(text);
});

test("FileGenerationStore preserves the prior file when atomic replacement fails", async () => {
  const path = await tempStatePath();
  const store = new FileGenerationStore(path);
  const initial = { ...state(1, digestA), revision: 0 };
  await store.accept(catalogId, "issuer.example", {
    expectedRevision: null,
    next: initial,
  });
  const before = await readFile(path, "utf8");
  const directory = join(path, "..");
  await chmod(directory, 0o500);
  try {
    await expect(
      store.accept(catalogId, "issuer.example", {
        expectedRevision: 0,
        next: { ...state(2, digestB), revision: 1 },
      }),
    ).rejects.toThrow();
  } finally {
    await chmod(directory, 0o700);
  }
  expect(await readFile(path, "utf8")).toBe(before);
});

test("FileGenerationStore leaves prior durable state intact when replacement cannot be admitted", async () => {
  const path = await tempStatePath();
  const store = new FileGenerationStore(path);
  const initial = { ...state(1, digestA), revision: 0 };
  expect(
    await store.accept(catalogId, "issuer.example", {
      expectedRevision: null,
      next: initial,
    }),
  ).toEqual(initial);
  const before = await readFile(path, "utf8");
  expect(
    await store.accept(catalogId, "issuer.example", {
      expectedRevision: null,
      next: { ...state(2, digestB), revision: 0 },
    }),
  ).toBeNull();
  expect(await readFile(path, "utf8")).toBe(before);
});
