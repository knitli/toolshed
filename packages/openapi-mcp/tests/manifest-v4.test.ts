import { afterEach, expect, test } from "bun:test";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type CatalogId,
  canonicalJson,
  type GenerationState,
  type GenerationStore,
  type GenerationTransition,
  type ManifestEnvelope,
  type OperationRecordV4,
  type ReleaseManifestV4,
  type RollbackAuthorization,
  type Sha256,
  type StoredRecord,
  sha256,
} from "../src/runtime/index.ts";
import {
  type AdmittedManifest,
  admitManifest,
  type ManifestTrust,
} from "../src/runtime/manifest.ts";
import { verifyStoredRecord } from "../src/runtime/verify-record.ts";
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
  ).rejects.toMatchObject({ code: "MANIFEST_INVALID" });
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
  ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
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

test("verified logical records are detached and deeply frozen", async () => {
  const record = operation({
    parameters: [{ name: "limit", schema: { type: "integer" } }],
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
  expect(Object.isFrozen(verified.parameters[0].schema)).toBe(true);
  (record.parameters[0] as Record<string, unknown>).name =
    "changed-after-verification";
  expect(verified.parameters[0].name).toBe("limit");
});

async function tempStatePath(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "openapi-mcp-generation-"));
  temporaryDirectories.push(directory);
  return join(directory, "generations.json");
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

test("FileGenerationStore makes rollback replay consumption atomic across instances", async () => {
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
  ).toHaveLength(1);
  const rejected = results.find(
    (result) => result.status === "rejected",
  ) as PromiseRejectedResult;
  expect(rejected.reason).toMatchObject({ code: "MANIFEST_ROLLBACK_REJECTED" });
  expect(
    (await firstStore.get(catalogId, "issuer.example"))
      ?.consumedRollbackAuthorizationIds,
  ).toEqual(["rollback-7"]);
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
    ).rejects.toThrow(/persisted atomically/i);
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
