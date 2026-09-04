import { describe, expect, test } from "bun:test";
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import {
  type CatalogStoreFactoryResult,
  type ConformanceTestAdapter,
  RUNTIME_CONFORMANCE_FIXTURE,
  type RuntimeConformanceScenario,
  runRuntimeConformanceSuite,
} from "../src/conformance/index.ts";
import {
  populateOperationsFtsV4,
  RELEASE_SCHEMA_V4,
} from "../src/release/schema-v4.ts";
import type {
  CatalogId,
  OpenApiMcpError,
  ReleaseId,
  TypedOperationId,
  TypedSchemaId,
} from "../src/runtime/index.ts";
import {
  CATALOG_STORE_PUBLIC_MESSAGES,
  DEFAULT_RUNTIME_LIMITS,
} from "../src/runtime/index.ts";
import { MAX_SEARCH_QUERY_BYTES } from "../src/runtime/versions.ts";
import { SqliteCatalogStore } from "../src/sqlite/index.ts";

const catalogId = "catalog" as CatalogId;
const releaseA = "release-a" as ReleaseId;
const releaseB = "release-b" as ReleaseId;
const operationId = "operation:api:get" as TypedOperationId;
const schemaId = "schema:api:#/components/schemas/Item" as TypedSchemaId;
const unsupported = {
  code: "ARTIFACT_FORMAT_UNSUPPORTED",
} satisfies Partial<OpenApiMcpError>;

interface DiskFixture {
  readonly directory: string;
  readonly path: string;
}

function temporaryArtifact(name = "catalog.sqlite"): DiskFixture {
  const directory = mkdtempSync(join(tmpdir(), "openapi-mcp-catalog-"));
  return { directory, path: join(directory, name) };
}

function createV4Catalog(): DiskFixture {
  const artifact = temporaryArtifact();
  const database = new DatabaseSync(artifact.path);
  database.exec(RELEASE_SCHEMA_V4);
  for (const release of [releaseA, releaseB]) {
    const manifestJson = JSON.stringify({
      format: 4,
      contract: 1,
      catalogId,
      releaseId: release,
    });
    database
      .prepare(
        `INSERT INTO release_metadata VALUES
         (?, ?, 4, 1, 1, 'issuer', 'key', 'policy', '[]',
          '2026-01-01T00:00:00.000Z', 'compiler',
          'https://example.invalid/openapi.json', 'rev', ?, ?, ?,
          'Ed25519', 'key', ?)`,
      )
      .run(
        catalogId,
        release,
        "0".repeat(64),
        "1".repeat(64),
        manifestJson,
        `signature-${release}`,
      );
    const operation = JSON.stringify({
      id: operationId,
      api: "api",
      operationId: "get",
      method: "GET",
      path: "/items/{id}",
      origin: "https://example.invalid",
      summary: release,
      deprecated: false,
      parameters: [],
      requestBody: null,
      schemaIds: [schemaId],
      advisory: {},
    });
    database
      .prepare("INSERT INTO operations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(
        catalogId,
        release,
        operationId,
        operation,
        release === releaseA ? "a".repeat(64) : "b".repeat(64),
        "api",
        "get",
        release,
        "/items/{id}",
        "get api item",
      );
    const schema = JSON.stringify({
      id: schemaId,
      schema: { type: "object", title: release },
    });
    database
      .prepare("INSERT INTO schemas VALUES (?, ?, ?, ?, ?)")
      .run(
        catalogId,
        release,
        schemaId,
        schema,
        release === releaseA ? "c".repeat(64) : "d".repeat(64),
      );
  }
  populateOperationsFtsV4(database);
  database.close();
  return artifact;
}

function createConformanceV4Catalog(
  duplicateReleaseMetadata = false,
): DiskFixture {
  const fixture = RUNTIME_CONFORMANCE_FIXTURE;
  const artifact = temporaryArtifact("conformance.sqlite");
  const database = new DatabaseSync(artifact.path);
  const schema = duplicateReleaseMetadata
    ? RELEASE_SCHEMA_V4.replace(
        /,\s*PRIMARY KEY \(catalog_id, release_id\)\s*\) WITHOUT ROWID;/,
        ");",
      )
    : RELEASE_SCHEMA_V4;
  if (duplicateReleaseMetadata && schema === RELEASE_SCHEMA_V4)
    throw new Error("Conformance fixture could not remove metadata uniqueness");
  database.exec(schema);
  if (duplicateReleaseMetadata) database.exec("PRAGMA foreign_keys = OFF;");
  for (const [release, envelope, operation, schemas] of [
    [fixture.releaseA, fixture.envelopeA, fixture.operationA, fixture.schemasA],
    [fixture.releaseB, fixture.envelopeB, fixture.operationB, fixture.schemasB],
  ] as const) {
    const manifest = JSON.parse(envelope.manifestJson);
    const insertMetadata = database.prepare(`INSERT INTO release_metadata (
        catalog_id, release_id, format, contract, generation, issuer, key_id,
        policy_id, allowed_origins_json, compiled_at, compiler_version,
        source_uri, source_revision, source_content_sha256,
        reference_graph_digest, manifest_json, signature_algorithm,
        signature_key_id, signature
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    for (
      let copies =
        duplicateReleaseMetadata && release === fixture.releaseA ? 2 : 1;
      copies > 0;
      copies -= 1
    )
      insertMetadata.run(
        fixture.catalogId,
        release,
        manifest.format,
        manifest.contract,
        manifest.generation,
        manifest.issuer,
        manifest.keyId,
        manifest.policyId,
        JSON.stringify(manifest.allowedOrigins),
        manifest.compiledAt,
        manifest.compilerVersion,
        manifest.source.uri,
        manifest.source.revision,
        manifest.source.contentSha256,
        manifest.source.referenceGraphDigest,
        envelope.manifestJson,
        envelope.signature.algorithm,
        envelope.signature.keyId,
        envelope.signature.signature,
      );
    database
      .prepare(`INSERT INTO operations (
        catalog_id, release_id, record_id, record_json, logical_digest, api,
        operation_id, summary, path, search_text
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(
        fixture.catalogId,
        release,
        operation.id,
        JSON.stringify(operation.record),
        operation.logicalDigest,
        operation.record.api,
        operation.record.operationId,
        operation.record.summary,
        operation.record.path,
        `item ${operation.record.operationId}`,
      );
    const insertSchema = database.prepare(
      "INSERT INTO schemas VALUES (?, ?, ?, ?, ?)",
    );
    for (const schema of schemas) {
      insertSchema.run(
        fixture.catalogId,
        release,
        schema.id,
        JSON.stringify(schema.record),
        schema.logicalDigest,
      );
    }
  }
  populateOperationsFtsV4(database);
  database.close();
  return artifact;
}

function createDriverErrorCatalog(): DiskFixture {
  const artifact = temporaryArtifact("conformance-driver-error.sqlite");
  const database = new DatabaseSync(artifact.path);
  database.exec(`
    CREATE TABLE release_metadata (format INTEGER NOT NULL, contract INTEGER NOT NULL);
    INSERT INTO release_metadata VALUES (4, 1);
  `);
  database.close();
  return artifact;
}

function copiedV3Catalog(): DiskFixture {
  const artifact = temporaryArtifact("v3-copy.sqlite");
  copyFileSync(join(import.meta.dir, "fixtures", "v3.sqlite"), artifact.path);
  return artifact;
}

function expectUnsupported(
  run: () => unknown | Promise<unknown>,
): Promise<void> {
  return expect(Promise.resolve().then(run)).rejects.toMatchObject(unsupported);
}

function openFileDescriptorsFor(path: string): number | undefined {
  try {
    return readdirSync("/proc/self/fd").filter((descriptor) => {
      try {
        return readlinkSync(join("/proc/self/fd", descriptor)) === path;
      } catch {
        return false;
      }
    }).length;
  } catch {
    return undefined;
  }
}

test("v4 on-disk catalog serves manifest, search, operation, and schemas without mutation", async () => {
  const artifact = createV4Catalog();
  const before = readFileSync(artifact.path);
  const store = new SqliteCatalogStore(artifact.path);
  try {
    expect(store.legacyInventoryOnly).toBe(false);
    expect(
      await store.searchCandidates({ query: "item", api: "api", limit: 1 }),
    ).toEqual([{ catalogId, releaseId: releaseA, operationId }]);
    expect(await store.getManifest(catalogId, releaseA)).toEqual({
      manifestJson: JSON.stringify({
        format: 4,
        contract: 1,
        catalogId,
        releaseId: releaseA,
      }),
      signature: {
        algorithm: "Ed25519",
        keyId: "key",
        signature: `signature-${releaseA}`,
      },
    });
    expect(
      (await store.getOperation(catalogId, releaseA, operationId))?.record,
    ).toMatchObject({ id: operationId, summary: releaseA });
    expect(
      (await store.getOperation(catalogId, releaseB, operationId))?.record,
    ).toMatchObject({ id: operationId, summary: releaseB });
    expect(
      await store.getOperation(catalogId, releaseA, "operation:api:missing"),
    ).toBeNull();
    expect(await store.getSchemas(catalogId, releaseA, [schemaId])).toEqual([
      {
        id: schemaId,
        logicalDigest: "c".repeat(64),
        record: {
          id: schemaId,
          schema: { type: "object", title: releaseA },
        },
      },
    ]);
  } finally {
    store.close();
    store.close();
  }
  expect(readFileSync(artifact.path)).toEqual(before);
  rmSync(artifact.directory, { recursive: true, force: true });
});

test("closing a v4 store is idempotent and disables every catalog operation", async () => {
  const artifact = createV4Catalog();
  try {
    const store = new SqliteCatalogStore(artifact.path);
    store.close();
    store.close();
    await expectUnsupported(() => store.getManifest(catalogId, releaseA));
    await expectUnsupported(() =>
      store.searchCandidates({ query: "item", limit: 1 }),
    );
    await expectUnsupported(() =>
      store.getOperation(catalogId, releaseA, operationId),
    );
    await expectUnsupported(() =>
      store.getSchemas(catalogId, releaseA, [schemaId]),
    );
  } finally {
    rmSync(artifact.directory, { recursive: true, force: true });
  }
});

test("constructor resolves partial limits and preserves invalid limit errors before probing", async () => {
  const artifact = createV4Catalog();
  try {
    const store = new SqliteCatalogStore(artifact.path, {
      limits: { maxSearchResults: 1 },
    });
    try {
      await expect(
        store.searchCandidates({ query: "item", api: "api", limit: 1 }),
      ).resolves.toEqual([{ catalogId, releaseId: releaseA, operationId }]);
      await expect(
        store.searchCandidates({ query: "item", api: "api", limit: 2 }),
      ).rejects.toMatchObject({ code: "INPUT_INVALID" });
    } finally {
      store.close();
    }
  } finally {
    rmSync(artifact.directory, { recursive: true, force: true });
  }

  const originalGetBuiltinModule = process.getBuiltinModule;
  let opens = 0;
  class ProbeMustNotOpen {
    constructor() {
      opens += 1;
    }
  }
  process.getBuiltinModule = ((id: string) =>
    id === "bun:sqlite"
      ? { Database: ProbeMustNotOpen }
      : originalGetBuiltinModule?.(id)) as typeof process.getBuiltinModule;
  try {
    for (const [limits, message] of [
      [
        { maxSearchResults: DEFAULT_RUNTIME_LIMITS.maxSearchResults + 1 },
        "Runtime limit maxSearchResults must only lower its default",
      ],
      [
        { unexpected: 1 },
        "Runtime limits overrides must be an exact plain data object",
      ],
      [[], "Runtime limits overrides must be an exact plain data object"],
    ] as const) {
      expect(
        () =>
          new SqliteCatalogStore("unused.sqlite", { limits: limits as never }),
      ).toThrow(new RangeError(message));
    }
    expect(opens).toBe(0);
  } finally {
    process.getBuiltinModule = originalGetBuiltinModule;
  }
});

test("constructor redacts hostile outer limit options before probing", () => {
  const originalGetBuiltinModule = process.getBuiltinModule;
  let opens = 0;
  class ProbeMustNotOpen {
    constructor() {
      opens += 1;
    }
  }
  const secret = "outer-options-limit-secret";
  const getterOptions = Object.defineProperty({}, "limits", {
    enumerable: true,
    get: () => {
      throw new Error(secret);
    },
  });
  const proxyOptions = new Proxy(
    {},
    {
      get: () => {
        throw new Error(secret);
      },
      getOwnPropertyDescriptor: () => {
        throw new Error(secret);
      },
    },
  );
  process.getBuiltinModule = ((id: string) =>
    id === "bun:sqlite"
      ? { Database: ProbeMustNotOpen }
      : originalGetBuiltinModule?.(id)) as typeof process.getBuiltinModule;
  try {
    for (const options of [getterOptions, proxyOptions]) {
      let caught: unknown;
      try {
        new SqliteCatalogStore("unused.sqlite", options as never);
      } catch (error) {
        caught = error;
      }
      expect(opens).toBe(0);
      expect(caught).toEqual(
        new RangeError(
          "Runtime limits overrides must be an exact plain data object",
        ),
      );
      expect((caught as Error).message).not.toContain(secret);
    }
  } finally {
    process.getBuiltinModule = originalGetBuiltinModule;
  }
});

test("v4 ignores hostile legacy identity options without invoking accessors", async () => {
  const artifact = createV4Catalog();
  let accessorReads = 0;
  const hostileIdentity = Object.defineProperty({}, "catalogId", {
    enumerable: true,
    get: () => {
      accessorReads += 1;
      throw new Error("v4-legacy-identity-secret");
    },
  });
  const store = new SqliteCatalogStore(artifact.path, {
    legacyIdentity: hostileIdentity as never,
  });
  try {
    expect(store.legacyInventoryOnly).toBe(false);
    await expect(
      store.searchCandidates({ query: "item", limit: 1 }),
    ).resolves.toHaveLength(1);
    expect(accessorReads).toBe(0);
  } finally {
    store.close();
    rmSync(artifact.directory, { recursive: true, force: true });
  }
});

test("v4 manifest metadata cannot substitute another release envelope", async () => {
  const fixture = RUNTIME_CONFORMANCE_FIXTURE;
  const artifact = createConformanceV4Catalog();
  const database = new DatabaseSync(artifact.path);
  try {
    database
      .prepare(`UPDATE release_metadata
        SET manifest_json = ?, signature_algorithm = ?, signature_key_id = ?, signature = ?
        WHERE catalog_id = ? AND release_id = ?`)
      .run(
        fixture.envelopeB.manifestJson,
        fixture.envelopeB.signature.algorithm,
        fixture.envelopeB.signature.keyId,
        fixture.envelopeB.signature.signature,
        fixture.catalogId,
        fixture.releaseA,
      );
  } finally {
    database.close();
  }
  const store = new SqliteCatalogStore(artifact.path);
  try {
    await expect(
      store.getManifest(fixture.catalogId, fixture.releaseA),
    ).rejects.toMatchObject({
      code: "MANIFEST_INVALID",
      details: {},
      message: CATALOG_STORE_PUBLIC_MESSAGES.manifestIdentityMismatch,
      retryable: false,
    });
  } finally {
    store.close();
    rmSync(artifact.directory, { recursive: true, force: true });
  }
});

test("copied frozen v3 catalog is inventory-only under an explicit legacy identity", async () => {
  const artifact = copiedV3Catalog();
  const before = readFileSync(artifact.path);
  const legacyCatalog = "legacy-catalog" as CatalogId;
  const legacyRelease = "legacy-release" as ReleaseId;
  const store = new SqliteCatalogStore(artifact.path, {
    legacyIdentity: { catalogId: legacyCatalog, releaseId: legacyRelease },
  });
  try {
    expect(store.legacyInventoryOnly).toBe(true);
    expect(
      await store.searchCandidates({ query: "widget", api: "tiny", limit: 2 }),
    ).toEqual([
      {
        catalogId: legacyCatalog,
        releaseId: legacyRelease,
        operationId: "operation:tiny:widgets.widget.DeleteWidget",
      },
      {
        catalogId: legacyCatalog,
        releaseId: legacyRelease,
        operationId: "operation:tiny:widgets.widget.GetWidget",
      },
    ]);
    await expectUnsupported(() =>
      store.getOperation(
        legacyCatalog,
        legacyRelease,
        "operation:tiny:widgets.ListWidgets",
      ),
    );
    await expectUnsupported(() =>
      store.getSchemas(legacyCatalog, legacyRelease, [
        "schema:tiny:#/components/schemas/Widget",
      ]),
    );
    await expectUnsupported(() =>
      store.getManifest(legacyCatalog, legacyRelease),
    );
  } finally {
    store.close();
    store.close();
  }
  expect(readFileSync(artifact.path)).toEqual(before);
  rmSync(artifact.directory, { recursive: true, force: true });
});

test("v3 inventory rejects a cross-API qualified operation returned by FTS", async () => {
  const artifact = copiedV3Catalog();
  const database = new DatabaseSync(artifact.path);
  database
    .prepare("UPDATE operations SET qualified_id = ? WHERE qualified_id = ?")
    .run(
      "foreign:widgets.widget.DeleteWidget",
      "tiny:widgets.widget.DeleteWidget",
    );
  database.close();
  const store = new SqliteCatalogStore(artifact.path, {
    legacyIdentity: {
      catalogId: "legacy-catalog" as CatalogId,
      releaseId: "legacy-release" as ReleaseId,
    },
  });
  try {
    await expect(
      store.searchCandidates({ query: "widget", api: "tiny", limit: 1 }),
    ).rejects.toMatchObject({
      code: "INPUT_INVALID",
      details: {},
      message: "Search expression is invalid",
      retryable: false,
    });
  } finally {
    store.close();
    rmSync(artifact.directory, { recursive: true, force: true });
  }
});

test("v3 inventory search fails closed without explicit legacy identity", async () => {
  const artifact = copiedV3Catalog();
  try {
    const store = new SqliteCatalogStore(artifact.path);
    try {
      expect(store.legacyInventoryOnly).toBe(true);
      await expectUnsupported(() =>
        store.searchCandidates({ query: "widget", limit: 1 }),
      );
    } finally {
      store.close();
    }
  } finally {
    rmSync(artifact.directory, { recursive: true, force: true });
  }
});

test("v3 treats an own undefined legacy identity as omitted", async () => {
  const artifact = copiedV3Catalog();
  const store = new SqliteCatalogStore(artifact.path, {
    legacyIdentity: undefined,
  });
  try {
    expect(store.legacyInventoryOnly).toBe(true);
    await expectUnsupported(() =>
      store.searchCandidates({ query: "widget", limit: 1 }),
    );
  } finally {
    store.close();
    rmSync(artifact.directory, { recursive: true, force: true });
  }
});

test("v3 inventory search classifies malformed caller API filters as input", async () => {
  const artifact = copiedV3Catalog();
  const store = new SqliteCatalogStore(artifact.path, {
    legacyIdentity: {
      catalogId: "legacy-catalog" as CatalogId,
      releaseId: "legacy-release" as ReleaseId,
    },
  });
  try {
    await expect(
      store.searchCandidates({ query: "widget", api: "bad:api", limit: 1 }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
  } finally {
    store.close();
    rmSync(artifact.directory, { recursive: true, force: true });
  }
});

test("v3 inventory enforces the UTF-8 query limit before preparing FTS or encoding huge input", async () => {
  const originalGetBuiltinModule = process.getBuiltinModule;
  const prepared: string[] = [];
  class InstrumentedDatabase {
    prepare(sql: string) {
      prepared.push(sql);
      const rows = sql.includes("sqlite_schema")
        ? [{ name: "meta", type: "table" }]
        : sql.includes("FROM meta")
          ? [{ value: "3" }]
          : [];
      return {
        all() {
          return rows;
        },
        get() {
          return undefined;
        },
        finalize() {},
      };
    }

    close() {}
  }

  process.getBuiltinModule = ((id: string) =>
    id === "bun:sqlite"
      ? { Database: InstrumentedDatabase }
      : originalGetBuiltinModule?.(id)) as typeof process.getBuiltinModule;
  try {
    const store = new SqliteCatalogStore("unused.sqlite", {
      legacyIdentity: { catalogId, releaseId: releaseA },
    });
    try {
      await expect(
        store.searchCandidates({
          query: "x".repeat(MAX_SEARCH_QUERY_BYTES),
          limit: 1,
        }),
      ).resolves.toEqual([]);
      await expect(
        store.searchCandidates({
          query: "é".repeat(MAX_SEARCH_QUERY_BYTES / 2),
          limit: 1,
        }),
      ).resolves.toEqual([]);
      expect(
        prepared.filter((sql) => sql.includes("FROM operations_fts")),
      ).toHaveLength(2);
      await expect(
        store.searchCandidates({
          query: "x".repeat(MAX_SEARCH_QUERY_BYTES + 1),
          limit: 1,
        }),
      ).rejects.toMatchObject({
        code: "INPUT_INVALID",
        details: {},
        message: "Search input is invalid",
        retryable: false,
      });
      expect(
        prepared.filter((sql) => sql.includes("FROM operations_fts")),
      ).toHaveLength(2);
      const NativeTextEncoder = globalThis.TextEncoder;
      let encodes = 0;
      class TrackingTextEncoder extends NativeTextEncoder {
        override encode(input?: string): Uint8Array {
          encodes += 1;
          return super.encode(input);
        }
      }
      globalThis.TextEncoder = TrackingTextEncoder;
      try {
        await expect(
          store.searchCandidates({
            query: "x".repeat(MAX_SEARCH_QUERY_BYTES * 1024),
            limit: 1,
          }),
        ).rejects.toMatchObject({
          code: "INPUT_INVALID",
          details: {},
          message: "Search input is invalid",
          retryable: false,
        });
        expect(encodes).toBe(0);
        expect(
          prepared.filter((sql) => sql.includes("FROM operations_fts")),
        ).toHaveLength(2);
      } finally {
        globalThis.TextEncoder = NativeTextEncoder;
      }
    } finally {
      store.close();
    }
  } finally {
    process.getBuiltinModule = originalGetBuiltinModule;
  }
});

test("v3 inventory snapshots plain data search queries before SQLite access", async () => {
  const artifact = copiedV3Catalog();
  const store = new SqliteCatalogStore(artifact.path, {
    legacyIdentity: {
      catalogId: "legacy-catalog" as CatalogId,
      releaseId: "legacy-release" as ReleaseId,
    },
  });
  let getterReads = 0;
  const accessorQuery = Object.defineProperties(
    {},
    {
      query: {
        enumerable: true,
        get: () => {
          getterReads += 1;
          throw new Error("v3-query-getter-secret");
        },
      },
      limit: { enumerable: true, value: 1 },
    },
  );
  const proxyQuery = new Proxy(
    { query: "widget", limit: 1 },
    {
      get: () => {
        getterReads += 1;
        throw new Error("v3-query-getter-secret");
      },
      getOwnPropertyDescriptor: () => {
        throw new Error("v3-query-proxy-secret");
      },
    },
  );
  try {
    for (const query of [accessorQuery, proxyQuery]) {
      await expect(
        store.searchCandidates(query as never),
      ).rejects.toMatchObject({
        code: "INPUT_INVALID",
        details: {},
        message: "Search input is invalid",
        retryable: false,
      });
    }
    expect(getterReads).toBe(0);
  } finally {
    store.close();
    rmSync(artifact.directory, { recursive: true, force: true });
  }
});

test("v3 inventory snapshots legacy identity before opening or retaining it", async () => {
  const artifact = copiedV3Catalog();
  const identity = {
    catalogId: "legacy-catalog" as CatalogId,
    releaseId: "legacy-release" as ReleaseId,
  };
  const store = new SqliteCatalogStore(artifact.path, {
    legacyIdentity: identity,
  });
  identity.catalogId = "mutated-catalog" as CatalogId;
  identity.releaseId = "mutated-release" as ReleaseId;
  try {
    expect(await store.searchCandidates({ query: "widget", limit: 1 })).toEqual(
      [
        {
          catalogId: "legacy-catalog",
          releaseId: "legacy-release",
          operationId: "operation:tiny:widgets.widget.DeleteWidget",
        },
      ],
    );
  } finally {
    store.close();
  }

  let accessorReads = 0;
  const accessorIdentity = Object.defineProperty({}, "catalogId", {
    enumerable: true,
    get: () => {
      accessorReads += 1;
      throw new Error("legacy-identity-getter-secret");
    },
  });
  expect(
    () =>
      new SqliteCatalogStore(artifact.path, {
        legacyIdentity: accessorIdentity as never,
      }),
  ).toThrow(
    expect.objectContaining({
      code: "ARTIFACT_FORMAT_UNSUPPORTED",
      message: "Catalog identity is invalid",
    }),
  );
  expect(accessorReads).toBe(0);

  let coercions = 0;
  let caught: unknown;
  let nonStringStore: SqliteCatalogStore | undefined;
  try {
    nonStringStore = new SqliteCatalogStore(artifact.path, {
      legacyIdentity: {
        catalogId: {
          toString: () => {
            coercions += 1;
            return "legacy-catalog";
          },
        } as never,
        releaseId: "legacy-release" as ReleaseId,
      },
    });
  } catch (error) {
    caught = error;
  } finally {
    nonStringStore?.close();
  }
  expect(caught).toMatchObject({
    code: "ARTIFACT_FORMAT_UNSUPPORTED",
    message: "Catalog identity is invalid",
  });
  expect(coercions).toBe(0);
  rmSync(artifact.directory, { recursive: true, force: true });
});

test("read-only open refuses a missing artifact without creating it", () => {
  const artifact = temporaryArtifact("missing.sqlite");
  try {
    expect(existsSync(artifact.path)).toBe(false);
    expect(() => new SqliteCatalogStore(artifact.path)).toThrow(
      expect.objectContaining(unsupported),
    );
    expect(existsSync(artifact.path)).toBe(false);
  } finally {
    rmSync(artifact.directory, { recursive: true, force: true });
  }
});

test("artifact-open failures take precedence over hostile legacy identity options", () => {
  const artifact = temporaryArtifact("missing-with-legacy-option.sqlite");
  let accessorReads = 0;
  const hostileIdentity = Object.defineProperty({}, "catalogId", {
    enumerable: true,
    get: () => {
      accessorReads += 1;
      throw new Error("open-precedence-secret");
    },
  });
  try {
    expect(
      () =>
        new SqliteCatalogStore(artifact.path, {
          legacyIdentity: hostileIdentity as never,
        }),
    ).toThrow(
      expect.objectContaining({
        code: "ARTIFACT_FORMAT_UNSUPPORTED",
        message: "Artifact format is unsupported",
      }),
    );
    expect(accessorReads).toBe(0);
  } finally {
    rmSync(artifact.directory, { recursive: true, force: true });
  }
});

test("constructor rejects absent, unsupported, and ambiguous artifact formats", async () => {
  const fixtures: DiskFixture[] = [];
  try {
    const garbage = temporaryArtifact("garbage.sqlite");
    fixtures.push(garbage);
    await Bun.write(garbage.path, "not sqlite");

    const emptyV4 = temporaryArtifact("empty-v4.sqlite");
    fixtures.push(emptyV4);
    const emptyDatabase = new DatabaseSync(emptyV4.path);
    emptyDatabase.exec(
      "CREATE TABLE release_metadata (format INTEGER, contract INTEGER)",
    );
    emptyDatabase.close();

    const unsupportedV4 = temporaryArtifact("unsupported-v4.sqlite");
    fixtures.push(unsupportedV4);
    const unsupportedDatabase = new DatabaseSync(unsupportedV4.path);
    unsupportedDatabase.exec(
      "CREATE TABLE release_metadata (format INTEGER, contract INTEGER)",
    );
    unsupportedDatabase
      .prepare("INSERT INTO release_metadata VALUES (?, ?)")
      .run(5, 1);
    unsupportedDatabase.close();

    const ambiguous = temporaryArtifact("ambiguous.sqlite");
    fixtures.push(ambiguous);
    const ambiguousDatabase = new DatabaseSync(ambiguous.path);
    ambiguousDatabase.exec(
      "CREATE TABLE meta (key TEXT, value TEXT); CREATE TABLE release_metadata (format INTEGER, contract INTEGER)",
    );
    ambiguousDatabase.close();

    for (const artifact of fixtures) {
      expect(() => new SqliteCatalogStore(artifact.path)).toThrow(
        expect.objectContaining(unsupported),
      );
    }
  } finally {
    for (const artifact of fixtures)
      rmSync(artifact.directory, { recursive: true, force: true });
  }
});

test("Bun probe statements finalize before strict close on failure", () => {
  const originalGetBuiltinModule = process.getBuiltinModule;
  const events: string[] = [];
  let finalized = false;
  class InstrumentedDatabase {
    prepare(_sql: string) {
      return {
        all() {
          throw new Error("driver secret");
        },
        get() {
          return undefined;
        },
        finalize() {
          if (finalized) throw new Error("statement finalized twice");
          finalized = true;
          events.push("finalize");
        },
      };
    }

    close(strict?: boolean) {
      if (!finalized) throw new Error("strict close observed a live statement");
      events.push(`close:${String(strict)}`);
    }
  }

  process.getBuiltinModule = ((id: string) =>
    id === "bun:sqlite"
      ? { Database: InstrumentedDatabase }
      : originalGetBuiltinModule(id)) as typeof process.getBuiltinModule;
  try {
    expect(() => new SqliteCatalogStore("unused.sqlite")).toThrow(
      expect.objectContaining(unsupported),
    );
    expect(events).toEqual(["finalize", "close:true"]);
  } finally {
    process.getBuiltinModule = originalGetBuiltinModule;
  }
});

test("Bun bridge statements finalize before strict close on successful v4 search", async () => {
  const originalGetBuiltinModule = process.getBuiltinModule;
  const prepared: Array<{ readonly sql: string; finalizations: number }> = [];
  const events: string[] = [];
  class InstrumentedDatabase {
    prepare(sql: string) {
      const entry = { sql, finalizations: 0 };
      prepared.push(entry);
      const rows = sql.includes("sqlite_schema")
        ? [{ name: "release_metadata", type: "table" }]
        : sql.includes("DISTINCT format")
          ? [{ format: 4, contract: 1 }]
          : [
              {
                catalog_id: catalogId,
                release_id: releaseA,
                record_id: operationId,
              },
            ];
      return {
        all() {
          return rows;
        },
        get() {
          return undefined;
        },
        finalize() {
          entry.finalizations += 1;
          events.push("finalize");
        },
      };
    }

    close(strict?: boolean) {
      if (prepared.some(({ finalizations }) => finalizations !== 1))
        throw new Error("strict close observed a live statement");
      events.push(`close:${String(strict)}`);
    }
  }
  process.getBuiltinModule = ((id: string) =>
    id === "bun:sqlite"
      ? { Database: InstrumentedDatabase }
      : originalGetBuiltinModule?.(id)) as typeof process.getBuiltinModule;
  try {
    const store = new SqliteCatalogStore("unused.sqlite");
    await expect(
      store.searchCandidates({ query: "item", api: "api", limit: 1 }),
    ).resolves.toEqual([{ catalogId, releaseId: releaseA, operationId }]);
    store.close();
    expect(prepared).toHaveLength(3);
    expect(prepared.map(({ finalizations }) => finalizations)).toEqual([
      1, 1, 1,
    ]);
    expect(events).toEqual(["finalize", "finalize", "finalize", "close:true"]);
  } finally {
    process.getBuiltinModule = originalGetBuiltinModule;
  }
});

test("Bun inventory statements finalize before strict close on v3 search", async () => {
  const originalGetBuiltinModule = process.getBuiltinModule;
  const prepared: Array<{ readonly sql: string; finalizations: number }> = [];
  const events: string[] = [];
  class InstrumentedDatabase {
    prepare(sql: string) {
      const entry = { sql, finalizations: 0 };
      prepared.push(entry);
      const rows = sql.includes("sqlite_schema")
        ? [{ name: "meta", type: "table" }]
        : sql.includes("FROM meta")
          ? [{ value: "3" }]
          : [{ qualified_id: "api:widgets.widget.FindWidget" }];
      return {
        all() {
          return rows;
        },
        get() {
          return undefined;
        },
        finalize() {
          entry.finalizations += 1;
          events.push("finalize");
        },
      };
    }

    close(strict?: boolean) {
      if (prepared.some(({ finalizations }) => finalizations !== 1))
        throw new Error("strict close observed a live statement");
      events.push(`close:${String(strict)}`);
    }
  }
  process.getBuiltinModule = ((id: string) =>
    id === "bun:sqlite"
      ? { Database: InstrumentedDatabase }
      : originalGetBuiltinModule?.(id)) as typeof process.getBuiltinModule;
  try {
    const store = new SqliteCatalogStore("unused.sqlite", {
      legacyIdentity: { catalogId, releaseId: releaseA },
    });
    await expect(
      store.searchCandidates({ query: "widget", api: "api", limit: 1 }),
    ).resolves.toEqual([
      {
        catalogId,
        releaseId: releaseA,
        operationId: "operation:api:widgets.widget.FindWidget",
      },
    ]);
    store.close();
    expect(prepared).toHaveLength(3);
    expect(prepared.at(-1)?.sql).toContain("FROM operations_fts");
    expect(prepared.map(({ finalizations }) => finalizations)).toEqual([
      1, 1, 1,
    ]);
    expect(events).toEqual(["finalize", "finalize", "finalize", "close:true"]);
  } finally {
    process.getBuiltinModule = originalGetBuiltinModule;
  }
});

test("uses the Node sqlite fallback when Bun native sqlite is unavailable", () => {
  const artifact = createV4Catalog();
  const originalGetBuiltinModule = process.getBuiltinModule;
  process.getBuiltinModule = ((id: string) =>
    id === "bun:sqlite"
      ? undefined
      : originalGetBuiltinModule?.(id)) as typeof process.getBuiltinModule;
  try {
    const store = new SqliteCatalogStore(artifact.path);
    expect(store.legacyInventoryOnly).toBe(false);
    store.close();
  } finally {
    process.getBuiltinModule = originalGetBuiltinModule;
    rmSync(artifact.directory, { recursive: true, force: true });
  }
});

test("store close releases the artifact after a prepared lookup", async () => {
  const artifact = createV4Catalog();
  let store: SqliteCatalogStore | undefined;
  try {
    const before = openFileDescriptorsFor(artifact.path);
    store = new SqliteCatalogStore(artifact.path);
    await store.getManifest(catalogId, releaseA);
    store.close();
    const after = openFileDescriptorsFor(artifact.path);
    if (before !== undefined && after !== undefined) expect(after).toBe(before);
  } finally {
    store?.close();
    rmSync(artifact.directory, { recursive: true, force: true });
  }
});

test("constructor closes the database when its format probe fails", () => {
  const artifact = temporaryArtifact("bad-probe.sqlite");
  try {
    const database = new DatabaseSync(artifact.path);
    database.exec(
      "CREATE TABLE release_metadata (format INTEGER, contract INTEGER)",
    );
    database.close();
    const before = openFileDescriptorsFor(artifact.path);
    expect(() => new SqliteCatalogStore(artifact.path)).toThrow(
      expect.objectContaining(unsupported),
    );
    const after = openFileDescriptorsFor(artifact.path);
    if (before !== undefined && after !== undefined) expect(after).toBe(before);
  } finally {
    rmSync(artifact.directory, { recursive: true, force: true });
  }
});

const conformanceAdapter: ConformanceTestAdapter = {
  test,
  equal: (actual, expected, message) =>
    expect(actual, message).toEqual(expected),
  deepEqual: (actual, expected, message) =>
    expect(actual, message).toEqual(expected),
  ok: (value, message) => expect(value, message).toBeTruthy(),
  rejects: async (run, code) => {
    await expect(run()).rejects.toMatchObject({ code });
  },
};

function conformanceSqliteFactory(
  scenario?: RuntimeConformanceScenario,
): CatalogStoreFactoryResult {
  const artifact = scenario?.fault.startsWith("driver-")
    ? createDriverErrorCatalog()
    : createConformanceV4Catalog(
        scenario?.fault.startsWith("duplicate-") ?? false,
      );
  const store = new SqliteCatalogStore(artifact.path);
  return {
    fixture: RUNTIME_CONFORMANCE_FIXTURE,
    store,
    dispose: () => {
      store.close();
      rmSync(artifact.directory, { recursive: true, force: true });
    },
  };
}

describe("SQLite shared conformance", () => {
  runRuntimeConformanceSuite(conformanceSqliteFactory, {
    testAdapter: conformanceAdapter,
  });
});
