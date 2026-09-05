import { expect, test } from "bun:test";
import {
  type AdmittedManifest,
  admitCatalogRelease,
  type CandidateRef,
  type CatalogId,
  type CatalogStore,
  canonicalJson,
  createOpenApiRuntime,
  type GenerationState,
  type GenerationStore,
  type GenerationTransition,
  type ManifestEnvelope,
  type ManifestTrust,
  OpenApiMcpError,
  type OperationRecordV4,
  type ReleaseId,
  type RollbackAuthorization,
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
      encoder.encode(`knitli.openapi-mcp.release-manifest.v5\0${manifestJson}`),
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
    tags: [],
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
      "knitli.openapi-mcp.operation-record.v5",
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
    logicalDigest: await sha256("knitli.openapi-mcp.schema-record.v5", record),
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
      records: records as AdmittedManifest["manifest"]["records"],
      ...overrides,
    },
  };
}

async function fixture(values: readonly OperationRecordV4[]) {
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

test("public admission proves a complete signed release", async () => {
  const f = await fixture([operation("list"), operation("unreferenced")]);
  const result = await admitCatalogRelease(f, catalogId, releaseId);
  expect(result.manifest.records[f.rows[1]?.id]).toBe(f.rows[1]?.logicalDigest);
  expect(f.generations.state?.highestGeneration).toBe(1);
});

for (const fault of ["missing-operation", "corrupt-schema"] as const) {
  test(`${fault} rejects complete inventory without accepting a generation`, async () => {
    const schemaId = "schema:tiny:#/components/schemas/Unused" as TypedSchemaId;
    const f = await fixture([
      operation("list"),
      operation("unreferenced", { schemaIds: [schemaId] }),
    ]);
    let accepts = 0;
    const accept = f.generations.accept.bind(f.generations);
    f.generations.accept = async (...args) => {
      accepts++;
      return accept(...args);
    };
    if (fault === "missing-operation") f.rows.splice(1, 1);
    else
      f.schemaRows.splice(0, 1, {
        ...f.schemaRows[0]!,
        record: { ...f.schemaRows[0]!.record, schema: { type: "number" } },
      });
    const error = await admitCatalogRelease(f, catalogId, releaseId).catch(
      (error) => error,
    );
    expect(accepts).toBe(0);
    expect(error).toBeInstanceOf(OpenApiMcpError);
    expect(error.code).toBe(
      fault === "missing-operation"
        ? "RECORD_NOT_ADMITTED"
        : "RECORD_DIGEST_MISMATCH",
    );
    expect(accepts).toBe(0);
    expect(f.generations.state).toBeNull();
  });
}

for (const fault of ["inventory", "manifest"] as const) {
  test(`changed ${fault} after preflight rejects without acceptance`, async () => {
    const f = await fixture([operation("list"), operation("unreferenced")]);
    const replacement = await envelope(
      { ...f.manifest.manifest, generation: 2 },
      f.privateKey,
    );
    const getManifest = f.store.getManifest;
    let reads = 0;
    f.store.getManifest = async (...args) => {
      reads++;
      if (reads === 2) {
        if (fault === "manifest") return replacement;
        f.rows.splice(1, 1, {
          ...f.rows[1]!,
          record: {
            ...f.rows[1]!.record,
            summary: "corrupted after preflight",
          },
        });
      }
      return getManifest(...args);
    };
    let accepts = 0;
    f.generations.accept = async () => {
      accepts++;
      return null;
    };
    await expect(
      admitCatalogRelease(f, catalogId, releaseId),
    ).rejects.toMatchObject({
      code:
        fault === "manifest"
          ? "MANIFEST_GENERATION_CONFLICT"
          : "RECORD_DIGEST_MISMATCH",
    });
    expect(reads).toBe(2);
    expect(accepts).toBe(0);
    expect(f.generations.state).toBeNull();
  });
}

test("lost CAS retries complete inventory before acceptance", async () => {
  const f = await fixture([operation("list")]);
  let accepts = 0;
  let operationReads = 0;
  const getOperation = f.store.getOperation;
  f.store.getOperation = async (...args) => {
    operationReads++;
    return getOperation(...args);
  };
  const accept = f.generations.accept.bind(f.generations);
  f.generations.accept = async (...args) => {
    accepts++;
    return accepts === 1 ? null : accept(...args);
  };
  await admitCatalogRelease(f, catalogId, releaseId);
  expect(accepts).toBe(2);
  expect(operationReads).toBe(3);
  expect(f.generations.state?.highestGeneration).toBe(1);
});

test("corruption following a lost CAS prevents the retry from accepting", async () => {
  const f = await fixture([operation("list")]);
  let accepts = 0;
  f.generations.accept = async () => {
    accepts++;
    f.rows.splice(0, 1, {
      ...f.rows[0]!,
      record: { ...f.rows[0]!.record, summary: "corrupted during CAS" },
    });
    return null;
  };
  await expect(
    admitCatalogRelease(f, catalogId, releaseId),
  ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
  expect(accepts).toBe(1);
  expect(f.generations.state).toBeNull();
});

test("concurrent higher generation cannot reinterpret admission as rollback", async () => {
  const f = await fixture([operation("list")]);
  let accepts = 0;
  f.generations.accept = async (_catalog, _issuer, transition) => {
    accepts++;
    f.generations.state = {
      ...transition.next,
      highestGeneration: 2,
      highestManifestDigest: digestB,
      activeGeneration: 2,
      activeManifestDigest: digestB,
    };
    return null;
  };
  await expect(
    admitCatalogRelease(f, catalogId, releaseId),
  ).rejects.toMatchObject({ code: "MANIFEST_GENERATION_CONFLICT" });
  expect(accepts).toBe(1);
  expect(f.generations.state?.highestGeneration).toBe(2);
});
