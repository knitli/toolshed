import { expect, test } from "bun:test";
import {
  type AdmittedManifest,
  admitManifest,
  type CandidateRef,
  type CatalogId,
  type CatalogStore,
  canonicalJson,
  createOpenApiRuntime,
  DEFAULT_RUNTIME_LIMITS,
  decodeOperationRef,
  type GenerationState,
  type GenerationStore,
  type GenerationTransition,
  type ManifestEnvelope,
  type ManifestTrust,
  OpenApiMcpError,
  type OperationRecordV4,
  type ReleaseId,
  type RollbackAuthorization,
  type RuntimeLimits,
  resolveSchemaClosure,
  type SchemaRecordV4,
  type Sha256,
  type StoredRecord,
  sha256,
  type TypedSchemaId,
} from "../src/runtime/index.ts";

const catalogId = "tiny" as CatalogId;
const releaseId = "release-1" as ReleaseId;
const digestA = "a".repeat(64) as Sha256;
const digestB = "b".repeat(64) as Sha256;
const encoder = new TextEncoder();

class MemoryGenerationStore implements GenerationStore {
  state: GenerationState | null = null;

  async get(): Promise<GenerationState | null> {
    return this.state;
  }

  async accept(
    _catalogId: CatalogId,
    _issuer: string,
    transition: GenerationTransition,
  ): Promise<GenerationState | null> {
    if ((this.state?.revision ?? null) !== transition.expectedRevision)
      return null;
    this.state = transition.next;
    return this.state;
  }
}

function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

async function signingFixture() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ]);
  const rollbackPair = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const publicKey = base64url(
    new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)),
  );
  const rollbackPublicKey = base64url(
    new Uint8Array(
      await crypto.subtle.exportKey("spki", rollbackPair.publicKey),
    ),
  );
  const trust: ManifestTrust = {
    releaseKeys: [{ issuer: "issuer.example", keyId: "key-1", publicKey }],
    rollbackKeys: [
      {
        issuer: "issuer.example",
        keyId: "rollback-1",
        publicKey: rollbackPublicKey,
      },
    ],
    now: () => new Date("2026-09-04T12:00:00.000Z"),
  };
  return { pair, rollbackPair, trust };
}

async function envelope(
  manifest: AdmittedManifest["manifest"],
  privateKey: CryptoKey,
  rollback?: RollbackAuthorization,
): Promise<ManifestEnvelope> {
  const manifestJson = canonicalJson(manifest);
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      "Ed25519",
      privateKey,
      encoder.encode(`knitli.openapi-mcp.release-manifest.v4\0${manifestJson}`),
    ),
  );
  return {
    manifestJson,
    signature: {
      algorithm: "Ed25519",
      keyId: "key-1",
      signature: base64url(signature),
    },
    ...(rollback === undefined ? {} : { rollback }),
  };
}

async function rollbackAuthorization(
  manifest: AdmittedManifest["manifest"],
  targetManifestDigest: Sha256,
  privateKey: CryptoKey,
  currentHighestGeneration: number,
): Promise<RollbackAuthorization> {
  const unsigned = {
    id: "rollback-search-race",
    catalogId: manifest.catalogId,
    issuer: manifest.issuer,
    currentHighestGeneration,
    targetGeneration: manifest.generation,
    targetManifestDigest,
    reason: "concurrent release proved bad",
    expiresAt: "2026-09-05T00:00:00.000Z",
    keyId: "rollback-1",
    algorithm: "Ed25519" as const,
  };
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      "Ed25519",
      privateKey,
      encoder.encode(
        `knitli.openapi-mcp.rollback-authorization.v1\0${canonicalJson(unsigned)}`,
      ),
    ),
  );
  return { ...unsigned, signature: base64url(signature) };
}

function operation(
  name: string,
  overrides: Partial<OperationRecordV4> = {},
): OperationRecordV4 {
  return {
    id: `operation:tiny:${name}`,
    api: "tiny",
    operationId: name,
    method: "GET",
    path: `/widgets/${name}`,
    origin: "https://api.example.test",
    summary: name,
    deprecated: false,
    parameters: [],
    requestBody: null,
    schemaIds: [],
    advisory: { safety: "poisoned", origin: "must-not-leak" },
    ...overrides,
  };
}

async function storedOperation(
  value: OperationRecordV4,
): Promise<StoredRecord<OperationRecordV4>> {
  return {
    id: value.id,
    logicalDigest: await sha256(
      "knitli.openapi-mcp.operation-record.v4",
      value,
    ),
    record: value,
  };
}

async function storedSchema(
  id: TypedSchemaId,
  schema: SchemaRecordV4["schema"],
): Promise<StoredRecord<SchemaRecordV4>> {
  const record: SchemaRecordV4 = { id, schema };
  return {
    id,
    logicalDigest: await sha256("knitli.openapi-mcp.schema-record.v4", record),
    record,
  };
}

function admitted(
  records: Readonly<Record<string, Sha256>>,
  overrides: Partial<AdmittedManifest["manifest"]> = {},
): AdmittedManifest {
  return {
    manifestDigest: digestA,
    manifest: {
      format: 4,
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
      records: records as AdmittedManifest["manifest"]["records"],
      ...overrides,
    },
  };
}

async function searchFixture(values: readonly OperationRecordV4[]) {
  const rows = await Promise.all(values.map(storedOperation));
  const schemaIds = [
    ...new Set(values.flatMap((value) => [...value.schemaIds])),
  ];
  const schemaRows = await Promise.all(
    schemaIds.map((id) => storedSchema(id, { type: "string" })),
  );
  const candidates: CandidateRef[] = rows.map((row) => ({
    catalogId,
    releaseId,
    operationId: row.id,
  }));
  const calls: Array<{ query: string; api?: string; limit: number }> = [];
  const manifest = admitted(
    Object.fromEntries(
      [...rows, ...schemaRows].map((row) => [row.id, row.logicalDigest]),
    ),
  );
  const signing = await signingFixture();
  const signed = await envelope(manifest.manifest, signing.pair.privateKey);
  const store: CatalogStore = {
    async getManifest() {
      return signed;
    },
    async searchCandidates(query) {
      calls.push(query);
      return candidates;
    },
    async getOperation(_catalog, _release, id) {
      return rows.find((row) => row.id === id) ?? null;
    },
    async getSchemas(_catalog, _release, ids) {
      return schemaRows.filter((row) => ids.includes(row.id));
    },
  };
  const generations = new MemoryGenerationStore();
  return {
    calls,
    manifest,
    rows,
    schemaRows,
    runtime: createOpenApiRuntime({
      store,
      trust: signing.trust,
      generations,
    }),
    trust: signing.trust,
    generations,
    privateKey: signing.pair.privateKey,
    rollbackPrivateKey: signing.rollbackPair.privateKey,
    signed,
    store,
  };
}

test("search rejects blank and overlong queries before consulting the store", async () => {
  const { calls, runtime } = await searchFixture([operation("list")]);
  for (const query of ["", "   ", "x".repeat(1025)]) {
    await expect(runtime.search({ query })).rejects.toMatchObject({
      code: "INPUT_INVALID",
    });
  }
  expect(calls).toEqual([]);
});

test("search normalizes candidate transport throws and rejections", async () => {
  const fixture = await searchFixture([operation("list")]);
  const failures = [
    () => {
      throw new Error("Bearer sk-secret");
    },
    () => Promise.reject(new Error("/Users/secret/catalog.sqlite")),
  ];
  for (const searchCandidates of failures) {
    const runtime = createOpenApiRuntime({
      store: { ...fixture.store, searchCandidates } as CatalogStore,
      trust: fixture.trust,
      generations: new MemoryGenerationStore(),
    });
    const error = await runtime
      .search({ query: "widgets" })
      .catch((value) => value);
    expect(error).toEqual(
      new OpenApiMcpError(
        "UPSTREAM_ERROR",
        "Search candidate lookup is unavailable",
        { retryable: true },
      ),
    );
    expect(JSON.stringify(error)).not.toMatch(/sk-secret|Users|sqlite/);
  }
});

test("search enforces result bounds and defaults to ten", async () => {
  const { calls, runtime } = await searchFixture([operation("list")]);
  for (const limit of [0, 51, 1.5]) {
    await expect(
      runtime.search({ query: "widgets", limit }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
  }
  await runtime.search({ query: "widgets" });
  await runtime.search({ query: "widgets", limit: 50 });
  expect(calls.map((call) => call.limit)).toEqual([30, 150]);
});

test("search bounds its omitted result limit by the configured maximum", async () => {
  const fixture = await searchFixture([operation("list")]);
  const calls: Array<{ readonly limit: number }> = [];
  const runtime = createOpenApiRuntime({
    store: {
      ...fixture.store,
      async searchCandidates(query) {
        calls.push(query);
        return fixture.store.searchCandidates(query);
      },
    },
    trust: fixture.trust,
    generations: fixture.generations,
    limits: { maxSearchResults: 3 },
  });

  const result = await runtime.search({ query: "widgets" });

  expect(result.operations).toHaveLength(1);
  expect(calls).toEqual([{ api: undefined, query: "widgets", limit: 9 }]);
});

test("search drops poisoned candidates before returning any record field", async () => {
  const { rows, store, trust, generations } = await searchFixture([
    operation("delete"),
  ]);
  rows[0].record = { ...rows[0].record, method: "DELETE" };
  const runtime = createOpenApiRuntime({
    store,
    trust,
    generations,
  });
  const result = await runtime.search({ query: "widgets", limit: 10 });
  expect(result.operations).toEqual([]);
  expect(result.warnings).toContainEqual(
    expect.objectContaining({ code: "RECORD_DIGEST_MISMATCH" }),
  );
  expect(JSON.stringify(result)).not.toContain("DELETE");
});

test("search rejects candidate and admitted-manifest identity mismatches", async () => {
  const fixture = await searchFixture([operation("list")]);
  const mismatched = admitted(fixture.manifest.manifest.records, {
    releaseId: "another-release" as ReleaseId,
  });
  const signing = await signingFixture();
  const signed = await envelope(mismatched.manifest, signing.pair.privateKey);
  const store: CatalogStore = {
    ...fixture.store,
    async getManifest() {
      return signed;
    },
  };
  const runtime = createOpenApiRuntime({
    store,
    trust: signing.trust,
    generations: new MemoryGenerationStore(),
  });
  const result = await runtime.search({ query: "widgets" });
  expect(result.operations).toEqual([]);
  expect(result.warnings).toContainEqual(
    expect.objectContaining({ code: "RECORD_NOT_ADMITTED" }),
  );
});

test("search snapshots candidates without invoking accessors and rechecks admission", async () => {
  const fixture = await searchFixture([operation("list")]);
  let manifestReads = 0;
  let getterReads = 0;
  const valid = {
    catalogId,
    releaseId,
    operationId: fixture.rows[0].id,
  };
  const poisoned = {
    get catalogId() {
      getterReads += 1;
      return catalogId;
    },
    releaseId,
    operationId: fixture.rows[0].id,
  };
  const store: CatalogStore = {
    ...fixture.store,
    async getManifest(catalog, release) {
      manifestReads += 1;
      return fixture.store.getManifest(catalog, release);
    },
    async searchCandidates() {
      return [poisoned, valid];
    },
  };
  const runtime = createOpenApiRuntime({
    store,
    trust: fixture.trust,
    generations: fixture.generations,
  });
  const first = await runtime.search({ query: "widgets" });
  const second = await runtime.search({ query: "widgets" });
  expect(getterReads).toBe(0);
  expect(manifestReads).toBe(2);
  expect(first.operations).toHaveLength(1);
  expect(second.operations).toHaveLength(1);
  expect(first.warnings).toContainEqual(
    expect.objectContaining({ code: "RECORD_DIGEST_MISMATCH" }),
  );
});

test("search normalizes secret-bearing candidate-array reflection traps", async () => {
  const fixture = await searchFixture([operation("list")]);
  const store: CatalogStore = {
    ...fixture.store,
    async searchCandidates() {
      return new Proxy([], {
        getOwnPropertyDescriptor(_target, property) {
          if (property !== "length")
            return Reflect.getOwnPropertyDescriptor(_target, property);
          throw new Error("/Users/secret/catalog.sqlite");
        },
      });
    },
  };
  const runtime = createOpenApiRuntime({
    store,
    trust: fixture.trust,
    generations: fixture.generations,
  });
  await expect(runtime.search({ query: "widgets" })).rejects.toEqual(
    new OpenApiMcpError(
      "RECORD_DIGEST_MISMATCH",
      "Search candidate result is invalid",
    ),
  );
});

test("search captures candidate-array length once before bounded dense inspection", async () => {
  const fixture = await searchFixture([operation("list")]);
  let lengthReads = 0;
  const candidate = { catalogId, releaseId, operationId: fixture.rows[0].id };
  const candidates = new Proxy([candidate], {
    get(target, property, receiver) {
      if (property === "length") {
        lengthReads += 1;
        return lengthReads === 1 ? 1 : 151;
      }
      return Reflect.get(target, property, receiver);
    },
    getOwnPropertyDescriptor(target, property) {
      if (typeof property === "string" && /^[1-9][0-9]*$/.test(property)) {
        return {
          configurable: true,
          enumerable: true,
          value: candidate,
          writable: true,
        };
      }
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
  });
  const runtime = createOpenApiRuntime({
    store: {
      ...fixture.store,
      async searchCandidates() {
        return candidates;
      },
    },
    trust: fixture.trust,
    generations: fixture.generations,
  });
  expect((await runtime.search({ query: "widgets" })).operations).toHaveLength(
    1,
  );
  expect(lengthReads).toBe(0);
});

test("search hard-bounds distinct release admission attempts", async () => {
  const fixture = await searchFixture([operation("list")]);
  let manifestReads = 0;
  const candidates = Array.from({ length: 150 }, (_, index) => ({
    catalogId: `catalog-${String(index).padStart(3, "0")}` as CatalogId,
    releaseId: `release-${String(index).padStart(3, "0")}` as ReleaseId,
    operationId: fixture.rows[0].id,
  }));
  const store: CatalogStore = {
    ...fixture.store,
    async searchCandidates() {
      return candidates;
    },
    async getManifest() {
      manifestReads += 1;
      throw new Error("manifest unavailable");
    },
  };
  const result = await createOpenApiRuntime({
    store,
    trust: fixture.trust,
    generations: fixture.generations,
  }).search({ query: "widgets", limit: 50 });
  expect(manifestReads).toBe(8);
  expect(result.operations).toEqual([]);
  expect(result.warnings.length).toBeLessThanOrEqual(150);
  expect(
    result.warnings.filter(
      (item) => item.message === "Search release admission limit reached",
    ),
  ).toHaveLength(1);
  expect(JSON.stringify(result)).not.toContain("manifest unavailable");
});

test("four poisoned releases do not starve a valid fifth release", async () => {
  const fixture = await searchFixture([operation("list")]);
  let manifestReads = 0;
  const poisoned = Array.from({ length: 4 }, (_, index) => ({
    catalogId: `poison-${index}` as CatalogId,
    releaseId: `poison-${index}` as ReleaseId,
    operationId: fixture.rows[0].id,
  }));
  const store: CatalogStore = {
    ...fixture.store,
    async searchCandidates() {
      return [
        ...poisoned,
        { catalogId, releaseId, operationId: fixture.rows[0].id },
      ];
    },
    async getManifest(candidateCatalog, candidateRelease) {
      manifestReads += 1;
      if (candidateCatalog !== catalogId || candidateRelease !== releaseId)
        throw new Error("poisoned manifest");
      return fixture.signed;
    },
  };
  const result = await createOpenApiRuntime({
    store,
    trust: fixture.trust,
    generations: fixture.generations,
  }).search({ query: "widgets" });
  expect(manifestReads).toBe(5);
  expect(result.operations).toHaveLength(1);
});

test("a failed release key is remembered without consuming another attempt", async () => {
  const fixture = await searchFixture([operation("list")]);
  let manifestReads = 0;
  const store: CatalogStore = {
    ...fixture.store,
    async searchCandidates() {
      return [
        { catalogId, releaseId, operationId: "operation:tiny:first" },
        { catalogId, releaseId, operationId: "operation:tiny:second" },
      ];
    },
    async getManifest() {
      manifestReads += 1;
      throw new Error("poisoned manifest");
    },
  };
  await createOpenApiRuntime({
    store,
    trust: fixture.trust,
    generations: fixture.generations,
  }).search({ query: "widgets" });
  expect(manifestReads).toBe(1);
});

test("eight authenticated releases keep an earlier release reusable", async () => {
  const fixture = await searchFixture([operation("one"), operation("two")]);
  const signedByRelease = new Map<ReleaseId, ManifestEnvelope>([
    [releaseId, fixture.signed],
  ]);
  for (let generation = 2; generation <= 8; generation += 1) {
    const candidateRelease = `release-${generation}` as ReleaseId;
    const manifest = admitted(fixture.manifest.manifest.records, {
      releaseId: candidateRelease,
      generation,
    });
    signedByRelease.set(
      candidateRelease,
      await envelope(manifest.manifest, fixture.privateKey),
    );
  }
  let manifestReads = 0;
  const fillerCandidates = Array.from({ length: 7 }, (_, index) => ({
    catalogId,
    releaseId: `release-${index + 2}` as ReleaseId,
    operationId: fixture.rows[0].id,
  }));
  const result = await createOpenApiRuntime({
    store: {
      ...fixture.store,
      async searchCandidates() {
        return [
          { catalogId, releaseId, operationId: fixture.rows[0].id },
          ...fillerCandidates,
          {
            catalogId: "catalog-ninth" as CatalogId,
            releaseId: "release-ninth" as ReleaseId,
            operationId: fixture.rows[0].id,
          },
          { catalogId, releaseId, operationId: fixture.rows[1].id },
        ];
      },
      async getManifest(_candidateCatalog, candidateRelease) {
        manifestReads += 1;
        const signed = signedByRelease.get(candidateRelease);
        if (signed === undefined) throw new Error("manifest unavailable");
        return signed;
      },
      async getOperation(_candidateCatalog, candidateRelease, id) {
        if (candidateRelease !== releaseId) return null;
        return fixture.rows.find((row) => row.id === id) ?? null;
      },
    },
    trust: fixture.trust,
    generations: fixture.generations,
  }).search({ query: "widgets" });
  expect(manifestReads).toBe(8);
  expect(
    await Promise.all(
      result.operations.map(
        async (item) => (await decodeOperationRef(item.operation)).operationId,
      ),
    ),
  ).toEqual(["operation:tiny:one", "operation:tiny:two"]);
});

test("the eighth distinct valid release is admitted and the ninth is unfetched", async () => {
  const fixture = await searchFixture([operation("valid")]);
  const candidates: CandidateRef[] = [];
  const signedByCatalog = new Map<CatalogId, ManifestEnvelope>();
  for (let index = 1; index <= 9; index += 1) {
    const candidateCatalog = `catalog-${index}` as CatalogId;
    const candidateRelease = `release-${index}` as ReleaseId;
    const manifest = admitted(fixture.manifest.manifest.records, {
      catalogId: candidateCatalog,
      releaseId: candidateRelease,
    });
    candidates.push({
      catalogId: candidateCatalog,
      releaseId: candidateRelease,
      operationId: fixture.rows[0].id,
    });
    signedByCatalog.set(
      candidateCatalog,
      await envelope(manifest.manifest, fixture.privateKey),
    );
  }
  const manifestReads = new Map<CatalogId, number>();
  const states = new Map<CatalogId, GenerationState>();
  const generations: GenerationStore = {
    async get(candidateCatalog) {
      return states.get(candidateCatalog) ?? null;
    },
    async accept(candidateCatalog, _issuer, transition) {
      const current = states.get(candidateCatalog) ?? null;
      if ((current?.revision ?? null) !== transition.expectedRevision)
        return null;
      states.set(candidateCatalog, transition.next);
      return transition.next;
    },
  };
  const result = await createOpenApiRuntime({
    store: {
      ...fixture.store,
      async searchCandidates() {
        return candidates;
      },
      async getManifest(candidateCatalog) {
        manifestReads.set(
          candidateCatalog,
          (manifestReads.get(candidateCatalog) ?? 0) + 1,
        );
        return signedByCatalog.get(candidateCatalog) ?? null;
      },
    },
    trust: fixture.trust,
    generations,
  }).search({ query: "widgets" });

  expect(result.operations).toHaveLength(8);
  expect(states.size).toBe(8);
  expect(manifestReads.get("catalog-8" as CatalogId)).toBe(1);
  expect(manifestReads.has("catalog-9" as CatalogId)).toBe(false);
});

test("a store cannot spoof the release-budget control signal", async () => {
  const fixture = await searchFixture([operation("valid")]);
  const result = await createOpenApiRuntime({
    store: {
      ...fixture.store,
      async searchCandidates() {
        return [
          {
            catalogId: "spoof" as CatalogId,
            releaseId: "spoof" as ReleaseId,
            operationId: fixture.rows[0].id,
          },
          { catalogId, releaseId, operationId: fixture.rows[0].id },
        ];
      },
      async getManifest(candidateCatalog) {
        if (candidateCatalog === "spoof") {
          throw new OpenApiMcpError(
            "RECORD_NOT_ADMITTED",
            "Search release admission limit reached",
          );
        }
        return fixture.signed;
      },
    },
    trust: fixture.trust,
    generations: fixture.generations,
  }).search({ query: "widgets" });
  expect(result.operations).toHaveLength(1);
  expect(
    (await decodeOperationRef(result.operations[0].operation)).operationId,
  ).toBe("operation:tiny:valid");
});

test("search snapshots its exact input once and validates API identity grammar", async () => {
  const fixture = await searchFixture([operation("list")]);
  let getterReads = 0;
  const accessor = {
    get query() {
      getterReads += 1;
      return "widgets";
    },
  };
  for (const input of [
    accessor,
    { query: "widgets", extra: true },
    Object.assign(Object.create({ inherited: true }), { query: "widgets" }),
    { query: "widgets", api: "." },
    { query: "widgets", api: "bad:name" },
    { query: "widgets", api: "x".repeat(129) },
    new Proxy(
      { query: "widgets" },
      {
        ownKeys: () => {
          throw new Error("secret");
        },
      },
    ),
  ]) {
    await expect(fixture.runtime.search(input as never)).rejects.toEqual(
      new OpenApiMcpError("INPUT_INVALID", "Search input is invalid"),
    );
  }
  expect(getterReads).toBe(0);
  expect(fixture.calls).toEqual([]);
});

test("search revalidates active generation across advance and rollback", async () => {
  const fixture = await searchFixture([operation("list")]);
  const first = await fixture.runtime.search({ query: "widgets" });
  expect(first.operations).toHaveLength(1);

  const release2 = admitted(fixture.manifest.manifest.records, {
    releaseId: "release-2" as ReleaseId,
    generation: 2,
  });
  const signed2 = await envelope(release2.manifest, fixture.privateKey);
  const admitted2 = await admitManifest(
    signed2,
    fixture.trust,
    fixture.generations,
  );
  const afterAdvance = await fixture.runtime.search({ query: "widgets" });
  expect(afterAdvance.operations).toEqual([]);

  const previous = fixture.generations.state as GenerationState;
  fixture.generations.state = {
    ...previous,
    revision: previous.revision + 1,
    activeGeneration: 1,
    activeManifestDigest: (
      await decodeOperationRef(first.operations[0].operation)
    ).manifestDigest,
  };
  const release2Store: CatalogStore = {
    ...fixture.store,
    async searchCandidates() {
      return [
        {
          catalogId,
          releaseId: release2.manifest.releaseId,
          operationId: fixture.rows[0].id,
        },
      ];
    },
    async getManifest() {
      return signed2;
    },
  };
  const runtime = createOpenApiRuntime({
    store: release2Store,
    trust: fixture.trust,
    generations: fixture.generations,
  });
  const afterRollback = await runtime.search({ query: "widgets" });
  expect(afterRollback.operations).toEqual([]);
  expect(admitted2.manifestDigest).toBe(previous.activeManifestDigest);
});

test("search normalizes final generation-state recheck failures", async () => {
  const fixture = await searchFixture([operation("list")]);
  let reads = 0;
  const generations: GenerationStore = {
    async get(candidateCatalog, issuer) {
      reads += 1;
      if (reads > 1) throw new Error("Bearer sk-secret /Users/state.json");
      return fixture.generations.get(candidateCatalog, issuer);
    },
    async accept(candidateCatalog, issuer, transition) {
      return fixture.generations.accept(candidateCatalog, issuer, transition);
    },
  };
  const runtime = createOpenApiRuntime({
    store: fixture.store,
    trust: fixture.trust,
    generations,
  });
  const error = await runtime
    .search({ query: "widgets" })
    .catch((value) => value);
  expect(error).toEqual(
    new OpenApiMcpError("UPSTREAM_ERROR", "Generation state is unavailable", {
      retryable: true,
    }),
  );
  expect(JSON.stringify(error)).not.toMatch(/sk-secret|Users|state/);
});

test("search propagates generation accept failures as infrastructure errors", async () => {
  const fixture = await searchFixture([operation("list")]);
  const generations: GenerationStore = {
    async get() {
      return null;
    },
    async accept() {
      throw new Error("Bearer sk-secret /Users/state.json");
    },
  };

  const error = await createOpenApiRuntime({
    store: fixture.store,
    trust: fixture.trust,
    generations,
  })
    .search({ query: "widgets" })
    .catch((value) => value);

  expect(error).toEqual(
    new OpenApiMcpError("UPSTREAM_ERROR", "Generation state is unavailable", {
      retryable: true,
    }),
  );
  expect(JSON.stringify(error)).not.toMatch(/sk-secret|Users|state/);
});

test("search propagates post-proof generation reads as infrastructure errors", async () => {
  const fixture = await searchFixture([
    operation("active"),
    operation("conflict"),
  ]);
  await fixture.runtime.search({ query: "widgets" });
  const conflicting = admitted(
    { [fixture.rows[1].id]: fixture.rows[1].logicalDigest },
    { releaseId: "release-conflict" as ReleaseId },
  );
  const signedConflict = await envelope(
    conflicting.manifest,
    fixture.privateKey,
  );
  let reads = 0;
  const generations: GenerationStore = {
    async get(candidateCatalog, issuer) {
      reads += 1;
      if (reads === 2) throw new Error("Bearer sk-secret /Users/state.json");
      return fixture.generations.get(candidateCatalog, issuer);
    },
    async accept(candidateCatalog, issuer, transition) {
      return fixture.generations.accept(candidateCatalog, issuer, transition);
    },
  };

  const error = await createOpenApiRuntime({
    store: {
      ...fixture.store,
      async searchCandidates() {
        return [
          { catalogId, releaseId, operationId: fixture.rows[0].id },
          {
            catalogId,
            releaseId: conflicting.manifest.releaseId,
            operationId: fixture.rows[1].id,
          },
        ];
      },
      async getManifest(_candidateCatalog, candidateRelease) {
        return candidateRelease === releaseId ? fixture.signed : signedConflict;
      },
    },
    trust: fixture.trust,
    generations,
  })
    .search({ query: "widgets" })
    .catch((value) => value);

  expect(error).toEqual(
    new OpenApiMcpError("UPSTREAM_ERROR", "Generation state is unavailable", {
      retryable: true,
    }),
  );
  expect(reads).toBe(2);
  expect(JSON.stringify(error)).not.toMatch(/sk-secret|Users|state/);
});

test("one search returns only the generation still active after all candidates admit", async () => {
  const fixture = await searchFixture([operation("list")]);
  const release2 = admitted(fixture.manifest.manifest.records, {
    releaseId: "release-2" as ReleaseId,
    generation: 2,
  });
  const signed2 = await envelope(release2.manifest, fixture.privateKey);
  const store: CatalogStore = {
    ...fixture.store,
    async searchCandidates() {
      return [
        { catalogId, releaseId, operationId: fixture.rows[0].id },
        {
          catalogId,
          releaseId: release2.manifest.releaseId,
          operationId: fixture.rows[0].id,
        },
      ];
    },
    async getManifest(_catalog, release) {
      return release === releaseId ? fixture.signed : signed2;
    },
  };
  const runtime = createOpenApiRuntime({
    store,
    trust: fixture.trust,
    generations: fixture.generations,
  });
  const result = await runtime.search({ query: "widgets" });
  expect(result.operations).toHaveLength(1);
  expect(
    (await decodeOperationRef(result.operations[0].operation)).releaseId,
  ).toBe("release-2");
});

test("a CAS race cannot reinterpret a normal advance as an authorized rollback", async () => {
  const fixture = await searchFixture([operation("candidate")]);
  await fixture.runtime.search({ query: "widgets" });
  let state = fixture.generations.state as GenerationState;
  const release2 = admitted(fixture.manifest.manifest.records, {
    releaseId: "release-2" as ReleaseId,
    generation: 2,
  });
  const manifestDigest = await sha256(
    "knitli.openapi-mcp.release-manifest.v4",
    release2.manifest as never,
  );
  const rollback = await rollbackAuthorization(
    release2.manifest,
    manifestDigest,
    fixture.rollbackPrivateKey,
    3,
  );
  const signed2 = await envelope(
    release2.manifest,
    fixture.privateKey,
    rollback,
  );
  let accepts = 0;
  let operationReads = 0;
  const generations: GenerationStore = {
    async get() {
      return state;
    },
    async accept(_candidateCatalog, _issuer, transition) {
      accepts += 1;
      if (accepts === 1) {
        state = {
          ...state,
          revision: state.revision + 1,
          highestGeneration: 3,
          highestManifestDigest: "c".repeat(64) as Sha256,
          activeGeneration: 3,
          activeManifestDigest: "c".repeat(64) as Sha256,
        };
        return null;
      }
      state = transition.next;
      return state;
    },
  };
  const result = await createOpenApiRuntime({
    store: {
      ...fixture.store,
      async searchCandidates() {
        return [
          {
            catalogId,
            releaseId: release2.manifest.releaseId,
            operationId: fixture.rows[0].id,
          },
        ];
      },
      async getManifest() {
        return signed2;
      },
      async getOperation(...args) {
        operationReads += 1;
        return fixture.store.getOperation(...args);
      },
    },
    trust: fixture.trust,
    generations,
  }).search({ query: "widgets" });
  expect(operationReads).toBe(3);
  expect(accepts).toBe(1);
  expect(result.operations).toEqual([]);
  expect(state).toMatchObject({
    highestGeneration: 3,
    activeGeneration: 3,
    consumedRollbackAuthorizationIds: [],
  });
});

test("repeated CAS misses exhaust one search-wide complete-proof budget", async () => {
  const fixture = await searchFixture([operation("candidate")]);
  const release2 = admitted(fixture.manifest.manifest.records, {
    releaseId: "release-2" as ReleaseId,
    generation: 2,
  });
  const signed2 = await envelope(release2.manifest, fixture.privateKey);
  const state: GenerationState = {
    revision: 0,
    highestGeneration: 1,
    highestManifestDigest: digestA,
    activeGeneration: 1,
    activeManifestDigest: digestA,
    consumedRollbackAuthorizationIds: [],
  };
  let accepts = 0;
  let operationReads = 0;
  const attemptedRollbackIds: string[][] = [];
  const generations: GenerationStore = {
    async get() {
      return state;
    },
    async accept(_catalog, _issuer, transition) {
      accepts += 1;
      attemptedRollbackIds.push([
        ...transition.next.consumedRollbackAuthorizationIds,
      ]);
      return null;
    },
  };
  const store: CatalogStore = {
    ...fixture.store,
    async searchCandidates() {
      return [
        {
          catalogId,
          releaseId: release2.manifest.releaseId,
          operationId: fixture.rows[0].id,
        },
      ];
    },
    async getManifest() {
      return signed2;
    },
    async getOperation(...args) {
      operationReads += 1;
      return fixture.store.getOperation(...args);
    },
  };

  const result = await createOpenApiRuntime({
    store,
    trust: fixture.trust,
    generations,
  }).search({ query: "widgets" });

  expect(result.operations).toEqual([]);
  expect(result.warnings).toEqual([
    expect.objectContaining({ code: "RECORD_NOT_ADMITTED" }),
  ]);
  expect(accepts).toBe(8);
  expect(operationReads).toBe(9);
  expect(attemptedRollbackIds).toEqual(Array.from({ length: 8 }, () => []));
  expect(state).toEqual({
    revision: 0,
    highestGeneration: 1,
    highestManifestDigest: digestA,
    activeGeneration: 1,
    activeManifestDigest: digestA,
    consumedRollbackAuthorizationIds: [],
  });
});

test("group selection restarts from conflicting higher releases after a fallback CAS miss", async () => {
  const fixture = await searchFixture([
    operation("higher-a"),
    operation("higher-b"),
    operation("fallback"),
  ]);
  const higherA = admitted(
    { [fixture.rows[0].id]: fixture.rows[0].logicalDigest },
    { releaseId: "release-3a" as ReleaseId, generation: 3 },
  );
  const higherB = admitted(
    { [fixture.rows[1].id]: fixture.rows[1].logicalDigest },
    { releaseId: "release-3b" as ReleaseId, generation: 3 },
  );
  const fallback = admitted(
    { [fixture.rows[2].id]: fixture.rows[2].logicalDigest },
    { releaseId: "release-2" as ReleaseId, generation: 2 },
  );
  const higherADigest = await sha256(
    "knitli.openapi-mcp.release-manifest.v4",
    higherA.manifest as never,
  );
  const fallbackDigest = await sha256(
    "knitli.openapi-mcp.release-manifest.v4",
    fallback.manifest as never,
  );
  const fallbackRollback = await rollbackAuthorization(
    fallback.manifest,
    fallbackDigest,
    fixture.rollbackPrivateKey,
    3,
  );
  const signedByRelease = new Map<ReleaseId, ManifestEnvelope>([
    [
      higherA.manifest.releaseId,
      await envelope(higherA.manifest, fixture.privateKey),
    ],
    [
      higherB.manifest.releaseId,
      await envelope(higherB.manifest, fixture.privateKey),
    ],
    [
      fallback.manifest.releaseId,
      await envelope(fallback.manifest, fixture.privateKey, fallbackRollback),
    ],
  ]);
  let state: GenerationState = {
    revision: 0,
    highestGeneration: 1,
    highestManifestDigest: "d".repeat(64) as Sha256,
    activeGeneration: 1,
    activeManifestDigest: "d".repeat(64) as Sha256,
    consumedRollbackAuthorizationIds: [],
  };
  let accepts = 0;
  const generations: GenerationStore = {
    async get() {
      return state;
    },
    async accept() {
      accepts += 1;
      state = {
        ...state,
        revision: state.revision + 1,
        highestGeneration: 3,
        highestManifestDigest: higherADigest,
        activeGeneration: 3,
        activeManifestDigest: higherADigest,
      };
      return null;
    },
  };
  const candidates = [higherA, higherB, fallback].map((release, index) => ({
    catalogId,
    releaseId: release.manifest.releaseId,
    operationId: fixture.rows[index].id,
  }));
  const result = await createOpenApiRuntime({
    store: {
      ...fixture.store,
      async searchCandidates() {
        return candidates;
      },
      async getManifest(_candidateCatalog, candidateRelease) {
        const signed = signedByRelease.get(candidateRelease);
        if (signed === undefined) throw new Error("manifest unavailable");
        return signed;
      },
    },
    trust: fixture.trust,
    generations,
  }).search({ query: "widgets" });
  expect(accepts).toBe(1);
  expect(state).toMatchObject({
    highestGeneration: 3,
    activeGeneration: 3,
    activeManifestDigest: higherADigest,
    consumedRollbackAuthorizationIds: [],
  });
  expect(result.operations).toHaveLength(1);
  expect(
    await decodeOperationRef(result.operations[0].operation),
  ).toMatchObject({
    releaseId: higherA.manifest.releaseId,
    operationId: fixture.rows[0].id,
    manifestDigest: higherADigest,
  });
  expect(result.warnings).not.toContainEqual(
    expect.objectContaining({ code: "MANIFEST_GENERATION_CONFLICT" }),
  );
});

test("conflicting higher-generation candidates cannot suppress a valid release", async () => {
  const fixture = await searchFixture([
    operation("stable"),
    operation("conflict-a"),
    operation("conflict-b"),
  ]);
  const releases = [
    admitted({ [fixture.rows[0].id]: fixture.rows[0].logicalDigest }),
    admitted(
      { [fixture.rows[1].id]: fixture.rows[1].logicalDigest },
      { releaseId: "release-2a" as ReleaseId, generation: 2 },
    ),
    admitted(
      { [fixture.rows[2].id]: fixture.rows[2].logicalDigest },
      { releaseId: "release-2b" as ReleaseId, generation: 2 },
    ),
  ];
  const signedByRelease = new Map<ReleaseId, ManifestEnvelope>();
  for (const release of releases) {
    signedByRelease.set(
      release.manifest.releaseId,
      await envelope(release.manifest, fixture.privateKey),
    );
  }
  const candidates = releases.map((release, index) => ({
    catalogId,
    releaseId: release.manifest.releaseId,
    operationId: fixture.rows[index].id,
  }));

  for (const orderedCandidates of [candidates, [...candidates].reverse()]) {
    const generations = new MemoryGenerationStore();
    const admittedGenerations: number[] = [];
    const result = await createOpenApiRuntime({
      store: {
        ...fixture.store,
        async searchCandidates() {
          return orderedCandidates;
        },
        async getManifest(_candidateCatalog, candidateRelease) {
          const signed = signedByRelease.get(candidateRelease);
          if (signed === undefined) throw new Error("manifest unavailable");
          return signed;
        },
      },
      trust: fixture.trust,
      generations: {
        get: generations.get.bind(generations),
        async accept(candidateCatalog, issuer, transition) {
          admittedGenerations.push(transition.next.activeGeneration);
          return generations.accept(candidateCatalog, issuer, transition);
        },
      },
    }).search({ query: "widgets" });
    expect(admittedGenerations).toEqual([1]);
    expect(generations.state).toMatchObject({
      highestGeneration: 1,
      activeGeneration: 1,
    });
    expect(result.operations).toHaveLength(1);
    expect(
      (await decodeOperationRef(result.operations[0].operation)).operationId,
    ).toBe("operation:tiny:stable");
  }
});

test("search snapshots final generation state once per catalog and issuer", async () => {
  const fixture = await searchFixture([operation("one"), operation("two")]);
  let reads = 0;
  let state: GenerationState | null = null;
  const generations: GenerationStore = {
    async get() {
      reads += 1;
      if (reads > 2) return null;
      return state;
    },
    async accept(_candidateCatalog, _issuer, transition) {
      if ((state?.revision ?? null) !== transition.expectedRevision)
        return null;
      state = transition.next;
      return state;
    },
  };
  const result = await createOpenApiRuntime({
    store: fixture.store,
    trust: fixture.trust,
    generations,
  }).search({ query: "widgets" });
  expect(result.warnings).toEqual([]);
  expect(result.operations).toHaveLength(2);
  expect(reads).toBe(2);
});

test("a missing candidate row cannot advance persisted generation state", async () => {
  const fixture = await searchFixture([operation("list")]);
  const release2 = admitted(fixture.manifest.manifest.records, {
    releaseId: "release-2" as ReleaseId,
    generation: 2,
  });
  const signed2 = await envelope(release2.manifest, fixture.privateKey);
  const runtime = createOpenApiRuntime({
    store: {
      ...fixture.store,
      async searchCandidates() {
        return [
          {
            catalogId,
            releaseId: release2.manifest.releaseId,
            operationId: fixture.rows[0].id,
          },
        ];
      },
      async getManifest() {
        return signed2;
      },
      async getOperation() {
        return null;
      },
    },
    trust: fixture.trust,
    generations: fixture.generations,
  });
  const result = await runtime.search({ query: "widgets" });
  expect(result.operations).toEqual([]);
  expect(fixture.generations.state).toBeNull();
});

test("a mismatched candidate catalog cannot advance persisted generation state", async () => {
  const fixture = await searchFixture([operation("list")]);
  const foreign = admitted(fixture.manifest.manifest.records, {
    catalogId: "foreign" as CatalogId,
    releaseId: "release-2" as ReleaseId,
    generation: 2,
  });
  const signed = await envelope(foreign.manifest, fixture.privateKey);
  const runtime = createOpenApiRuntime({
    store: {
      ...fixture.store,
      async getManifest() {
        return signed;
      },
    },
    trust: fixture.trust,
    generations: fixture.generations,
  });
  const result = await runtime.search({ query: "widgets" });
  expect(result.operations).toEqual([]);
  expect(fixture.generations.state).toBeNull();
});

test("a higher generation missing a noncandidate operation cannot advance state", async () => {
  const fixture = await searchFixture([
    operation("candidate"),
    operation("noncandidate"),
  ]);
  await fixture.runtime.search({ query: "widgets" });
  const previous = fixture.generations.state;
  const release2 = admitted(fixture.manifest.manifest.records, {
    releaseId: "release-2" as ReleaseId,
    generation: 2,
  });
  const signed2 = await envelope(release2.manifest, fixture.privateKey);
  const result = await createOpenApiRuntime({
    store: {
      ...fixture.store,
      async searchCandidates() {
        return [
          {
            catalogId,
            releaseId: release2.manifest.releaseId,
            operationId: fixture.rows[0].id,
          },
          { catalogId, releaseId, operationId: fixture.rows[0].id },
        ];
      },
      async getManifest(_candidateCatalog, candidateRelease) {
        return candidateRelease === releaseId ? fixture.signed : signed2;
      },
      async getOperation(_candidateCatalog, candidateRelease, id) {
        if (
          candidateRelease === release2.manifest.releaseId &&
          id === fixture.rows[1].id
        )
          return null;
        return fixture.rows.find((row) => row.id === id) ?? null;
      },
    },
    trust: fixture.trust,
    generations: fixture.generations,
  }).search({ query: "widgets" });
  expect(result.operations).toHaveLength(1);
  expect(
    (await decodeOperationRef(result.operations[0].operation)).releaseId,
  ).toBe(releaseId);
  expect(fixture.generations.state).toEqual(previous);
});

test("a higher generation with a tampered noncandidate row cannot advance state", async () => {
  const fixture = await searchFixture([
    operation("candidate"),
    operation("noncandidate"),
  ]);
  await fixture.runtime.search({ query: "widgets" });
  const previous = fixture.generations.state;
  const release2 = admitted(fixture.manifest.manifest.records, {
    releaseId: "release-2" as ReleaseId,
    generation: 2,
  });
  const signed2 = await envelope(release2.manifest, fixture.privateKey);
  const result = await createOpenApiRuntime({
    store: {
      ...fixture.store,
      async searchCandidates() {
        return [
          {
            catalogId,
            releaseId: release2.manifest.releaseId,
            operationId: fixture.rows[0].id,
          },
        ];
      },
      async getManifest() {
        return signed2;
      },
      async getOperation(_candidateCatalog, _candidateRelease, id) {
        const row = fixture.rows.find((candidate) => candidate.id === id);
        if (row === undefined) return null;
        return id === fixture.rows[1].id
          ? { ...row, logicalDigest: digestB }
          : row;
      },
    },
    trust: fixture.trust,
    generations: fixture.generations,
  }).search({ query: "widgets" });
  expect(result.operations).toEqual([]);
  expect(fixture.generations.state).toEqual(previous);
});

test("a higher generation missing a required schema cannot advance state", async () => {
  const schemaId = "schema:tiny:#/components/schemas/Required" as TypedSchemaId;
  const candidate = operation("candidate", { schemaIds: [schemaId] });
  const fixture = await searchFixture([operation("stable")]);
  await fixture.runtime.search({ query: "widgets" });
  const previous = fixture.generations.state;
  const candidateRow = await storedOperation(candidate);
  const schemaRow = await storedSchema(schemaId, { type: "object" });
  const release2 = admitted(
    {
      [candidateRow.id]: candidateRow.logicalDigest,
      [schemaRow.id]: schemaRow.logicalDigest,
    },
    { releaseId: "release-2" as ReleaseId, generation: 2 },
  );
  const signed2 = await envelope(release2.manifest, fixture.privateKey);
  const result = await createOpenApiRuntime({
    store: {
      ...fixture.store,
      async searchCandidates() {
        return [
          {
            catalogId,
            releaseId: release2.manifest.releaseId,
            operationId: candidateRow.id,
          },
        ];
      },
      async getManifest() {
        return signed2;
      },
      async getOperation() {
        return candidateRow;
      },
      async getSchemas() {
        return [];
      },
    },
    trust: fixture.trust,
    generations: fixture.generations,
  }).search({ query: "widgets" });
  expect(result.operations).toEqual([]);
  expect(fixture.generations.state).toEqual(previous);
});

test("a higher generation with a tampered noncandidate schema cannot advance state", async () => {
  const schemaId = "schema:tiny:#/components/schemas/Unused" as TypedSchemaId;
  const fixture = await searchFixture([operation("stable")]);
  await fixture.runtime.search({ query: "widgets" });
  const previous = fixture.generations.state;
  const candidateRow = await storedOperation(operation("candidate"));
  const schemaRow = await storedSchema(schemaId, { type: "string" });
  const release2 = admitted(
    {
      [candidateRow.id]: candidateRow.logicalDigest,
      [schemaRow.id]: schemaRow.logicalDigest,
    },
    { releaseId: "release-2" as ReleaseId, generation: 2 },
  );
  const signed2 = await envelope(release2.manifest, fixture.privateKey);
  const result = await createOpenApiRuntime({
    store: {
      ...fixture.store,
      async searchCandidates() {
        return [
          {
            catalogId,
            releaseId: release2.manifest.releaseId,
            operationId: candidateRow.id,
          },
        ];
      },
      async getManifest() {
        return signed2;
      },
      async getOperation() {
        return candidateRow;
      },
      async getSchemas() {
        return [{ ...schemaRow, logicalDigest: digestB }];
      },
    },
    trust: fixture.trust,
    generations: fixture.generations,
  }).search({ query: "widgets" });
  expect(result.operations).toEqual([]);
  expect(fixture.generations.state).toEqual(previous);
});

test("a higher generation with a dangling schema reference cannot advance state", async () => {
  const root = "schema:tiny:#/components/schemas/Root" as TypedSchemaId;
  const missing = "schema:tiny:#/components/schemas/Missing" as TypedSchemaId;
  const fixture = await searchFixture([operation("stable")]);
  await fixture.runtime.search({ query: "widgets" });
  const previous = fixture.generations.state;
  const candidateRow = await storedOperation(
    operation("candidate", { schemaIds: [root] }),
  );
  const rootRow = await storedSchema(root, { $ref: missing });
  const release2 = admitted(
    {
      [candidateRow.id]: candidateRow.logicalDigest,
      [rootRow.id]: rootRow.logicalDigest,
    },
    { releaseId: "release-2" as ReleaseId, generation: 2 },
  );
  const signed2 = await envelope(release2.manifest, fixture.privateKey);
  const result = await createOpenApiRuntime({
    store: {
      ...fixture.store,
      async searchCandidates() {
        return [
          {
            catalogId,
            releaseId: release2.manifest.releaseId,
            operationId: candidateRow.id,
          },
        ];
      },
      async getManifest() {
        return signed2;
      },
      async getOperation() {
        return candidateRow;
      },
      async getSchemas(_candidateCatalog, _candidateRelease, ids) {
        return ids.includes(root) ? [rootRow] : [];
      },
    },
    trust: fixture.trust,
    generations: fixture.generations,
  }).search({ query: "widgets" });
  expect(result.operations).toEqual([]);
  expect(fixture.generations.state).toEqual(previous);
});

test("complete release verification caps schema batch cardinality under lowered record limits", async () => {
  const fixture = await searchFixture([operation("candidate")]);
  const schemaRows = await Promise.all(
    Array.from({ length: 129 }, (_, index) =>
      storedSchema(
        `schema:tiny:#/components/schemas/S${String(index).padStart(3, "0")}` as TypedSchemaId,
        { type: "string" },
      ),
    ),
  );
  const manifest = admitted(
    Object.fromEntries(
      [...fixture.rows, ...schemaRows].map((row) => [
        row.id,
        row.logicalDigest,
      ]),
    ),
  );
  const signed = await envelope(manifest.manifest, fixture.privateKey);
  const batchSizes: number[] = [];
  const result = await createOpenApiRuntime({
    store: {
      ...fixture.store,
      async getManifest() {
        return signed;
      },
      async getSchemas(_candidateCatalog, _candidateRelease, ids) {
        batchSizes.push(ids.length);
        return schemaRows.filter((row) => ids.includes(row.id));
      },
    },
    trust: fixture.trust,
    generations: fixture.generations,
    limits: { maxRecordBytes: 1024 },
  }).search({ query: "widgets" });
  expect(result.operations).toHaveLength(1);
  expect(batchSizes).toEqual([128, 1]);
});

test("complete release verification loads a shared schema graph only once", async () => {
  const schemaId = "schema:tiny:#/components/schemas/Shared" as TypedSchemaId;
  const schemaUse = {
    name: "q",
    in: "query" as const,
    required: false,
    deprecated: false,
    style: "form" as const,
    explode: true,
    allowReserved: false,
    value: { kind: "schema" as const, schemaId },
  };
  const fixture = await searchFixture([
    operation("one", { parameters: [schemaUse], schemaIds: [schemaId] }),
    operation("two", { parameters: [schemaUse], schemaIds: [schemaId] }),
  ]);
  let schemaReads = 0;
  const result = await createOpenApiRuntime({
    store: {
      ...fixture.store,
      async getSchemas(...args) {
        schemaReads += 1;
        return fixture.store.getSchemas(...args);
      },
    },
    trust: fixture.trust,
    generations: fixture.generations,
  }).search({ query: "widgets" });
  expect(result.warnings).toEqual([]);
  expect(result.operations).toHaveLength(2);
  expect(schemaReads).toBe(1);
});

test("release inventory bytes admit the exact limit and reject limit plus one", async () => {
  const schemaId =
    "schema:tiny:#/components/schemas/Candidate" as TypedSchemaId;
  const fixture = await searchFixture([
    operation("candidate", {
      parameters: [
        {
          name: "q",
          in: "query",
          required: false,
          deprecated: false,
          style: "form",
          explode: true,
          allowReserved: false,
          value: { kind: "schema", schemaId },
        },
      ],
      schemaIds: [schemaId],
    }),
  ]);
  const inventoryBytes = [...fixture.rows, ...fixture.schemaRows].reduce(
    (total, row) =>
      total + encoder.encode(canonicalJson(row.record)).byteLength,
    0,
  );
  const exactGenerations = new MemoryGenerationStore();
  const exact = await createOpenApiRuntime({
    store: fixture.store,
    trust: fixture.trust,
    generations: exactGenerations,
    limits: { maxReleaseInventoryBytes: inventoryBytes },
  }).search({ query: "widgets" });
  expect(exact.warnings).toEqual([]);
  expect(exact.operations).toHaveLength(1);
  expect(exactGenerations.state).not.toBeNull();

  const overGenerations = new MemoryGenerationStore();
  const over = await createOpenApiRuntime({
    store: fixture.store,
    trust: fixture.trust,
    generations: overGenerations,
    limits: { maxReleaseInventoryBytes: inventoryBytes - 1 },
  }).search({ query: "widgets" });
  expect(over.operations).toEqual([]);
  expect(over.warnings).toEqual([
    expect.objectContaining({ code: "RECORD_NOT_ADMITTED" }),
  ]);
  expect(overGenerations.state).toBeNull();
});

test("release inventory bytes share one search-wide budget across releases", async () => {
  const fixture = await searchFixture([operation("candidate")]);
  const catalogs = ["catalog-one", "catalog-two"] as const;
  const releases = ["release-one", "release-two"] as const;
  const signedByCatalog = new Map<CatalogId, ManifestEnvelope>();
  const candidates: CandidateRef[] = [];
  for (const [index, candidateCatalog] of catalogs.entries()) {
    const candidateRelease = releases[index] as ReleaseId;
    const manifest = admitted(fixture.manifest.manifest.records, {
      catalogId: candidateCatalog as CatalogId,
      releaseId: candidateRelease,
    });
    signedByCatalog.set(
      candidateCatalog as CatalogId,
      await envelope(manifest.manifest, fixture.privateKey),
    );
    candidates.push({
      catalogId: candidateCatalog as CatalogId,
      releaseId: candidateRelease,
      operationId: fixture.rows[0].id,
    });
  }
  const oneReleaseBytes = encoder.encode(
    canonicalJson(fixture.rows[0].record),
  ).byteLength;
  const sharedBoundary = oneReleaseBytes * catalogs.length;

  const runAtLimit = async (maxReleaseInventoryBytes: number) => {
    const states = new Map<CatalogId, GenerationState>();
    const generations: GenerationStore = {
      async get(candidateCatalog) {
        return states.get(candidateCatalog) ?? null;
      },
      async accept(candidateCatalog, _issuer, transition) {
        const current = states.get(candidateCatalog) ?? null;
        if ((current?.revision ?? null) !== transition.expectedRevision)
          return null;
        states.set(candidateCatalog, transition.next);
        return transition.next;
      },
    };
    const result = await createOpenApiRuntime({
      store: {
        ...fixture.store,
        async searchCandidates() {
          return candidates;
        },
        async getManifest(candidateCatalog) {
          return signedByCatalog.get(candidateCatalog) ?? null;
        },
      },
      trust: fixture.trust,
      generations,
      limits: { maxReleaseInventoryBytes },
    }).search({ query: "widgets" });
    return { result, states };
  };

  const exact = await runAtLimit(sharedBoundary);
  expect(exact.result.operations).toHaveLength(2);
  expect(exact.states.size).toBe(2);

  const over = await runAtLimit(sharedBoundary - 1);
  expect(over.result.operations).toHaveLength(1);
  expect(over.result.warnings).toContainEqual(
    expect.objectContaining({ code: "RECORD_NOT_ADMITTED" }),
  );
  expect(over.states.has(catalogs[0] as CatalogId)).toBe(true);
  expect(over.states.has(catalogs[1] as CatalogId)).toBe(false);
});

test("CAS retries consume the same search-wide inventory byte budget", async () => {
  const fixture = await searchFixture([operation("candidate")]);
  const release2 = admitted(fixture.manifest.manifest.records, {
    releaseId: "release-2" as ReleaseId,
    generation: 2,
  });
  const signed2 = await envelope(release2.manifest, fixture.privateKey);
  const state: GenerationState = {
    revision: 0,
    highestGeneration: 1,
    highestManifestDigest: digestA,
    activeGeneration: 1,
    activeManifestDigest: digestA,
    consumedRollbackAuthorizationIds: [],
  };
  const attemptedRollbackIds: string[][] = [];
  let accepts = 0;
  const generations: GenerationStore = {
    async get() {
      return state;
    },
    async accept(_catalog, _issuer, transition) {
      accepts += 1;
      attemptedRollbackIds.push([
        ...transition.next.consumedRollbackAuthorizationIds,
      ]);
      return null;
    },
  };
  const inventoryBytes = encoder.encode(
    canonicalJson(fixture.rows[0].record),
  ).byteLength;
  const result = await createOpenApiRuntime({
    store: {
      ...fixture.store,
      async searchCandidates() {
        return [
          {
            catalogId,
            releaseId: release2.manifest.releaseId,
            operationId: fixture.rows[0].id,
          },
        ];
      },
      async getManifest() {
        return signed2;
      },
    },
    trust: fixture.trust,
    generations,
    limits: { maxReleaseInventoryBytes: inventoryBytes * 2 - 1 },
  }).search({ query: "widgets" });

  expect(result.operations).toEqual([]);
  expect(result.warnings).toContainEqual(
    expect.objectContaining({ code: "RECORD_NOT_ADMITTED" }),
  );
  expect(accepts).toBe(1);
  expect(attemptedRollbackIds).toEqual([[]]);
  expect(state).toEqual({
    revision: 0,
    highestGeneration: 1,
    highestManifestDigest: digestA,
    activeGeneration: 1,
    activeManifestDigest: digestA,
    consumedRollbackAuthorizationIds: [],
  });
});

test("a verified higher-generation candidate advances persisted state", async () => {
  const fixture = await searchFixture([operation("list")]);
  await fixture.runtime.search({ query: "widgets" });
  const release2 = admitted(fixture.manifest.manifest.records, {
    releaseId: "release-2" as ReleaseId,
    generation: 2,
  });
  const signed2 = await envelope(release2.manifest, fixture.privateKey);
  const result = await createOpenApiRuntime({
    store: {
      ...fixture.store,
      async searchCandidates() {
        return [
          {
            catalogId,
            releaseId: release2.manifest.releaseId,
            operationId: fixture.rows[0].id,
          },
        ];
      },
      async getManifest() {
        return signed2;
      },
    },
    trust: fixture.trust,
    generations: fixture.generations,
  }).search({ query: "widgets" });
  expect(result.operations).toHaveLength(1);
  expect(fixture.generations.state).toMatchObject({
    highestGeneration: 2,
    activeGeneration: 2,
  });
});

test("search enforces API filters against candidates and verified operations", async () => {
  const foreign = operation("list", {
    id: "operation:other:list",
    api: "other",
  });
  const fixture = await searchFixture([foreign]);
  const result = await fixture.runtime.search({
    query: "widgets",
    api: "tiny",
  });
  expect(result.operations).toEqual([]);
  expect(result.warnings).toEqual([
    { code: "RECORD_DIGEST_MISMATCH", message: "Search candidate rejected" },
  ]);
});

test("search fixes warning text and bounds every model-visible field", async () => {
  const parameters = Array.from({ length: 40 }, (_, index) => ({
    name: `q${String(index).padStart(2, "0")}#heading`,
    in: "query" as const,
    required: false,
    deprecated: false,
    style: "form" as const,
    explode: true,
    allowReserved: false,
    value: {
      kind: "schema" as const,
      schemaId: "schema:tiny:#/components/schemas/Id" as const,
    },
  }));
  const hostile = operation("hostile", {
    summary: `# heading\n\`\`\`secret\`\`\`\u0085\u0600\u2028\u2029\u202e\u2066\ufeff\u{e0001}${"x".repeat(1000)}`,
    parameters,
    schemaIds: ["schema:tiny:#/components/schemas/Id"],
    advisory: {
      authorization: "Bearer sk-secret",
      permissions: Array.from({ length: 100 }, () => "*admin*"),
      scopes: ["read\u0085\u0600\u202e\u2066\ufeff\u{e0001}"],
    },
  });
  const fixture = await searchFixture([hostile]);
  const result = await fixture.runtime.search({ query: "widgets" });
  const serialized = JSON.stringify(result);
  expect(result.operations[0].summary?.length).toBeLessThanOrEqual(600);
  expect(result.operations[0].inputOutline.query as unknown[]).toHaveLength(32);
  expect(serialized).not.toMatch(
    /```|# heading|sk-secret|\*admin\*|\u0085|\u0600|\u2028|\u2029|\u202e|\u2066|\ufeff|\u{e0001}/u,
  );

  const leakingStore: CatalogStore = {
    ...fixture.store,
    async getOperation() {
      throw new OpenApiMcpError("RECORD_DIGEST_MISMATCH", "Bearer sk-secret", {
        details: { path: "/Users/secret/catalog.sqlite" },
      });
    },
  };
  const warningResult = await createOpenApiRuntime({
    store: leakingStore,
    trust: fixture.trust,
    generations: new MemoryGenerationStore(),
  }).search({ query: "widgets" });
  expect(warningResult.warnings).toEqual([
    { code: "RECORD_DIGEST_MISMATCH", message: "Search candidate rejected" },
  ]);
  expect(JSON.stringify(warningResult)).not.toMatch(/sk-secret|Users|sqlite/);
});

test("search enforces the aggregate response byte budget during hydration", async () => {
  const fixture = await searchFixture([
    operation("one", { summary: "x".repeat(300) }),
    operation("two", { summary: "x".repeat(300) }),
    operation("three", { summary: "x".repeat(300) }),
  ]);
  const runtime = createOpenApiRuntime({
    store: fixture.store,
    trust: fixture.trust,
    generations: fixture.generations,
    limits: { maxResponseBytes: 900 },
  });
  const result = await runtime.search({ query: "widgets" });
  expect(
    new TextEncoder().encode(canonicalJson(result)).length,
  ).toBeLessThanOrEqual(900);
  expect(result.operations.length).toBeLessThan(3);
  expect(result.warnings).toContainEqual({
    code: "RESPONSE_LIMIT_EXCEEDED",
    message: "Search response limit reached",
  });
});

test("response sizing ignores candidates outside the ranked return set", async () => {
  const fixture = await searchFixture([
    operation("top"),
    operation("irrelevant", {
      deprecated: true,
      summary: "x".repeat(600),
    }),
  ]);
  const result = await createOpenApiRuntime({
    store: fixture.store,
    trust: fixture.trust,
    generations: fixture.generations,
    limits: { maxResponseBytes: 500 },
  }).search({ query: "widgets", limit: 1 });
  expect(result.operations).toHaveLength(1);
  expect(
    (await decodeOperationRef(result.operations[0].operation)).operationId,
  ).toBe("operation:tiny:top");
  expect(result.warnings).not.toContainEqual({
    code: "RESPONSE_LIMIT_EXCEEDED",
    message: "Search response limit reached",
  });
});

test("search demotes deprecated records and preserves stable candidate order", async () => {
  const { runtime } = await searchFixture([
    operation("zeta"),
    operation("old", { deprecated: true }),
    operation("alpha"),
  ]);
  const result = await runtime.search({ query: "widgets" });
  expect(
    await Promise.all(
      result.operations.map(
        async (item) => (await decodeOperationRef(item.operation)).operationId,
      ),
    ),
  ).toEqual([
    "operation:tiny:zeta",
    "operation:tiny:alpha",
    "operation:tiny:old",
  ]);
});

test("search emits opaque digest-bound refs, bounded display data, and runtime classification", async () => {
  const value = operation("create", {
    method: "POST",
    path: "/widgets/{id}",
    summary: `${"a".repeat(599)}\nsecret`,
    parameters: [
      {
        name: "id",
        in: "path",
        required: true,
        deprecated: false,
        style: "simple",
        explode: false,
        allowReserved: false,
        value: {
          kind: "schema",
          schemaId: "schema:tiny:#/components/schemas/Id",
        },
      },
    ],
    schemaIds: ["schema:tiny:#/components/schemas/Id"],
  });
  const { runtime } = await searchFixture([value]);
  const result = await runtime.search({ query: "widgets" });
  const item = result.operations[0];
  expect(item.operation.startsWith("opref.v1.")).toBe(true);
  expect(await decodeOperationRef(item.operation)).toMatchObject({
    operationId: value.id,
  });
  expect(item.summary?.length).toBe(600);
  expect(item.summary).not.toContain("\n");
  expect(item.inputOutline).toEqual({
    body: [],
    headers: [],
    path: [{ name: "id", required: true }],
    query: [],
  });
  expect(item).toMatchObject({
    safety: "action",
    actionKind: "unknown",
    cardinality: { kind: "unknown" },
  });
  expect(JSON.stringify(item)).not.toContain("https://api.example.test");
});

async function schemaFixture(
  definitions: Readonly<Record<TypedSchemaId, SchemaRecordV4["schema"]>>,
) {
  const rows = await Promise.all(
    Object.entries(definitions).map(([id, schema]) =>
      storedSchema(id as TypedSchemaId, schema),
    ),
  );
  const calls: TypedSchemaId[][] = [];
  const store: CatalogStore = {
    async getManifest() {
      throw new Error("unused");
    },
    async searchCandidates() {
      return [];
    },
    async getOperation() {
      return null;
    },
    async getSchemas(_catalog, _release, ids) {
      calls.push([...ids]);
      return rows.filter((row) => ids.includes(row.id));
    },
  };
  return {
    calls,
    manifest: admitted(
      Object.fromEntries(rows.map((row) => [row.id, row.logicalDigest])),
    ),
    rows,
    store,
  };
}

const rootId = "schema:tiny:#/components/schemas/Root" as const;
const ownerId = "schema:tiny:#/components/schemas/Owner" as const;
const partId = "schema:tiny:#/components/schemas/Part" as const;

test("schema resolution verifies and batches each breadth-first hop", async () => {
  const { calls, manifest, store } = await schemaFixture({
    [rootId]: {
      properties: { owner: { $ref: ownerId }, part: { $ref: partId } },
    },
    [ownerId]: { type: "object" },
    [partId]: { type: "string" },
  });
  const result = await resolveSchemaClosure(store, manifest, rootId);
  expect(calls).toEqual([[rootId], [ownerId, partId]]);
  expect([...result.keys()]).toEqual([rootId, ownerId, partId]);
  expect(Object.isFrozen(result.get(rootId))).toBe(true);
});

test("schema resolution does not advance a same-frontier reference to another hop", async () => {
  const terminalId = "schema:tiny:#/components/schemas/Zeta" as TypedSchemaId;
  const { calls, manifest, store } = await schemaFixture({
    [ownerId]: { $ref: rootId },
    [rootId]: { $ref: terminalId },
    [terminalId]: { type: "object" },
  });
  const result = await resolveSchemaClosure(
    store,
    manifest,
    [ownerId, rootId],
    limits({ maxSchemaRefHops: 1 }),
  );
  expect(calls).toEqual([[ownerId, rootId], [terminalId]]);
  expect([...result.keys()]).toEqual([ownerId, rootId, terminalId]);
});

test("schema resolution accounts same-frontier references only once", async () => {
  const fixture = await schemaFixture({
    [ownerId]: { $ref: rootId },
    [rootId]: { type: "object" },
  });
  const exactClosureBytes = fixture.rows.reduce(
    (total, row) =>
      total + new TextEncoder().encode(canonicalJson(row.record)).length,
    0,
  );
  const result = await resolveSchemaClosure(
    fixture.store,
    fixture.manifest,
    [ownerId, rootId],
    limits({ maxSchemaClosureBytes: exactClosureBytes }),
  );
  expect(fixture.calls.flat()).toEqual([ownerId, rootId]);
  expect([...result.keys()]).toEqual([ownerId, rootId]);
});

test("schema resolution normalizes store throws and rejections", async () => {
  const fixture = await schemaFixture({ [rootId]: true });
  const failures = [
    () => {
      throw new Error("Bearer sk-secret");
    },
    () => Promise.reject(new Error("/Users/secret/catalog.sqlite")),
  ];
  for (const getSchemas of failures) {
    const store = { ...fixture.store, getSchemas } as CatalogStore;
    const error = await resolveSchemaClosure(
      store,
      fixture.manifest,
      rootId,
    ).catch((value) => value);
    expect(error).toEqual(
      new OpenApiMcpError("UPSTREAM_ERROR", "Schema lookup is unavailable", {
        retryable: true,
      }),
    );
    expect(JSON.stringify(error)).not.toMatch(/sk-secret|Users|sqlite/);
  }
});

test("schema resolution terminates cycles without repeat reads", async () => {
  const { calls, manifest, store } = await schemaFixture({
    [rootId]: { $ref: ownerId },
    [ownerId]: { $ref: rootId },
  });
  const result = await resolveSchemaClosure(store, manifest, rootId);
  expect(calls).toEqual([[rootId], [ownerId]]);
  expect([...result.keys()]).toEqual([rootId, ownerId]);
});

test("schema resolution rejects missing and poisoned batches without partial output", async () => {
  const missing = await schemaFixture({ [rootId]: { $ref: ownerId } });
  await expect(
    resolveSchemaClosure(missing.store, missing.manifest, rootId),
  ).rejects.toMatchObject({ code: "RECORD_NOT_ADMITTED" });

  const poisoned = await schemaFixture({ [rootId]: { type: "string" } });
  poisoned.rows[0].record = { id: rootId, schema: { type: "number" } };
  await expect(
    resolveSchemaClosure(poisoned.store, poisoned.manifest, rootId),
  ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
});

async function chain(length: number) {
  const definitions: Record<TypedSchemaId, SchemaRecordV4["schema"]> = {};
  const ids = Array.from(
    { length },
    (_, index) =>
      `schema:tiny:#/components/schemas/Hop${index}` as TypedSchemaId,
  );
  ids.forEach((id, index) => {
    definitions[id] = index + 1 < ids.length ? { $ref: ids[index + 1] } : true;
  });
  return { ...(await schemaFixture(definitions)), ids };
}

test("schema resolution permits hop 16 and rejects crossing into hop 17", async () => {
  const atLimit = await chain(17);
  expect(
    (
      await resolveSchemaClosure(
        atLimit.store,
        atLimit.manifest,
        atLimit.ids[0],
      )
    ).size,
  ).toBe(17);
  const overLimit = await chain(18);
  await expect(
    resolveSchemaClosure(overLimit.store, overLimit.manifest, overLimit.ids[0]),
  ).rejects.toMatchObject({ code: "SCHEMA_RESOLUTION_LIMIT" });
  expect(overLimit.calls).toHaveLength(17);
});

function limits(overrides: Partial<RuntimeLimits>): RuntimeLimits {
  return { ...DEFAULT_RUNTIME_LIMITS, ...overrides };
}

test("schema resolution enforces exact aggregate byte boundary", async () => {
  const fixture = await schemaFixture({ [rootId]: { type: "string" } });
  const bytes = new TextEncoder().encode(
    canonicalJson(fixture.rows[0].record),
  ).length;
  expect(
    (
      await resolveSchemaClosure(
        fixture.store,
        fixture.manifest,
        rootId,
        limits({ maxSchemaClosureBytes: bytes }),
      )
    ).size,
  ).toBe(1);
  await expect(
    resolveSchemaClosure(
      fixture.store,
      fixture.manifest,
      rootId,
      limits({ maxSchemaClosureBytes: bytes - 1 }),
    ),
  ).rejects.toMatchObject({ code: "SCHEMA_RESOLUTION_LIMIT" });
});

test("schema resolution rejects one oversized schema before returning it", async () => {
  const fixture = await schemaFixture({
    [rootId]: { description: "x".repeat(200) },
  });
  await expect(
    resolveSchemaClosure(
      fixture.store,
      fixture.manifest,
      rootId,
      limits({ maxSchemaClosureBytes: 64 }),
    ),
  ).rejects.toMatchObject({ code: "SCHEMA_RESOLUTION_LIMIT" });
});

test("schema resolution snapshots and bounds hostile multi-root arrays", async () => {
  const fixture = await schemaFixture({ [rootId]: true });
  let getterReads = 0;
  const roots = [rootId];
  Object.defineProperty(roots, "0", {
    enumerable: true,
    get() {
      getterReads += 1;
      return rootId;
    },
  });
  await expect(
    resolveSchemaClosure(fixture.store, fixture.manifest, roots),
  ).rejects.toMatchObject({ code: "SCHEMA_RESOLUTION_LIMIT" });
  await expect(
    resolveSchemaClosure(
      fixture.store,
      fixture.manifest,
      new Proxy([rootId], {
        ownKeys: () => {
          throw new Error("secret");
        },
      }),
    ),
  ).rejects.toMatchObject({ code: "SCHEMA_RESOLUTION_LIMIT" });
  expect(getterReads).toBe(0);
  expect(fixture.calls).toEqual([]);
});

test("schema resolution returns an immutable empty closure without store access", async () => {
  const fixture = await schemaFixture({ [rootId]: true });
  const result = await resolveSchemaClosure(
    fixture.store,
    fixture.manifest,
    [],
  );
  expect(result.size).toBe(0);
  expect(Object.isFrozen(result)).toBe(true);
  expect("set" in result).toBe(false);
  expect(fixture.calls).toEqual([]);
});

test("schema resolution normalizes secret-bearing row-array reflection traps", async () => {
  const fixture = await schemaFixture({ [rootId]: true });
  const store: CatalogStore = {
    ...fixture.store,
    async getSchemas() {
      return new Proxy([], {
        getOwnPropertyDescriptor(_target, property) {
          if (property !== "length")
            return Reflect.getOwnPropertyDescriptor(_target, property);
          throw new Error("/Users/secret/catalog.sqlite");
        },
      });
    },
  };
  await expect(
    resolveSchemaClosure(store, fixture.manifest, rootId),
  ).rejects.toEqual(
    new OpenApiMcpError(
      "RECORD_NOT_ADMITTED",
      "Schema lookup result is invalid",
    ),
  );
});

test("schema resolution captures row-array length once", async () => {
  const fixture = await schemaFixture({ [rootId]: true });
  let lengthReads = 0;
  const rows = new Proxy([fixture.rows[0]], {
    get(target, property, receiver) {
      if (property === "length") {
        lengthReads += 1;
        return lengthReads === 1 ? 1 : 2;
      }
      return Reflect.get(target, property, receiver);
    },
  });
  const result = await resolveSchemaClosure(
    {
      ...fixture.store,
      async getSchemas() {
        return rows;
      },
    },
    fixture.manifest,
    rootId,
  );
  expect(result.size).toBe(1);
  expect(lengthReads).toBe(0);
});

test("schema resolution captures root-array length once", async () => {
  const fixture = await schemaFixture({ [rootId]: true });
  let lengthReads = 0;
  const roots = new Proxy([rootId], {
    get(target, property, receiver) {
      if (property === "length") {
        lengthReads += 1;
        return lengthReads === 1
          ? 1
          : DEFAULT_RUNTIME_LIMITS.maxManifestRecords + 1;
      }
      return Reflect.get(target, property, receiver);
    },
  });
  expect(
    (await resolveSchemaClosure(fixture.store, fixture.manifest, roots)).size,
  ).toBe(1);
  expect(lengthReads).toBe(0);
});

test("schema resolution stops wide-frontier reads when one chunk consumes the budget", async () => {
  const childIds = Array.from(
    { length: 20 },
    (_, index) =>
      `schema:tiny:#/components/schemas/Wide${String(index).padStart(2, "0")}` as TypedSchemaId,
  );
  const definitions: Record<TypedSchemaId, SchemaRecordV4["schema"]> = {
    [rootId]: { oneOf: childIds.map((id) => ({ $ref: id })) },
  };
  for (const id of childIds) definitions[id] = { type: "string" };
  const fixture = await schemaFixture(definitions);
  const rootBytes = new TextEncoder().encode(
    canonicalJson(fixture.rows.find((row) => row.id === rootId)?.record),
  ).length;
  const childBytes = new TextEncoder().encode(
    canonicalJson(fixture.rows.find((row) => row.id === childIds[0])?.record),
  ).length;
  await expect(
    resolveSchemaClosure(
      fixture.store,
      fixture.manifest,
      rootId,
      limits({ maxSchemaClosureBytes: rootBytes + childBytes }),
    ),
  ).rejects.toMatchObject({ code: "SCHEMA_RESOLUTION_LIMIT" });
  expect(fixture.calls).toEqual([[rootId], [childIds[0]]]);
});
