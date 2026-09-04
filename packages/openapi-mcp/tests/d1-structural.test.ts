import { describe, expect, test } from "bun:test";
import {
  type CatalogStoreFactoryResult,
  type ConformanceTestAdapter,
  RUNTIME_CONFORMANCE_FIXTURE,
  type RuntimeConformanceScenario,
  runRuntimeConformanceSuite,
} from "../src/conformance/index.ts";
import {
  CATALOG_STORE_PUBLIC_MESSAGES,
  createD1CatalogStore,
  type D1CatalogDatabase,
  type D1CatalogPreparedStatement,
  type D1CatalogResult,
  type D1CatalogValue,
  OpenApiMcpError,
} from "../src/runtime/index.ts";
import type {
  CatalogId,
  ReleaseId,
  TypedOperationId,
  TypedSchemaId,
} from "../src/runtime/types.ts";

const catalog = "conformance" as CatalogId;
const release = "release-a" as ReleaseId;
const operationId = "operation:conformance:get-item" as TypedOperationId;
const itemSchema =
  "schema:conformance:#/components/schemas/Item" as TypedSchemaId;
const userSchema =
  "schema:conformance:#/components/schemas/User" as TypedSchemaId;
const encoder = new TextEncoder();

const SQL = Object.freeze({
  manifest: `SELECT
  CASE WHEN typeof(manifest_json) = 'text' AND length(CAST(manifest_json AS BLOB)) <= ? THEN manifest_json ELSE NULL END AS manifest_json,
  length(CAST(manifest_json AS BLOB)) AS manifest_json_bytes,
  CASE WHEN typeof(signature_algorithm) = 'text' AND length(CAST(signature_algorithm AS BLOB)) <= ? THEN signature_algorithm ELSE NULL END AS signature_algorithm,
  length(CAST(signature_algorithm AS BLOB)) AS signature_algorithm_bytes,
  CASE WHEN typeof(signature_key_id) = 'text' AND length(CAST(signature_key_id AS BLOB)) <= ? THEN signature_key_id ELSE NULL END AS signature_key_id,
  length(CAST(signature_key_id AS BLOB)) AS signature_key_id_bytes,
  CASE WHEN typeof(signature) = 'text' AND length(CAST(signature AS BLOB)) <= ? THEN signature ELSE NULL END AS signature,
  length(CAST(signature AS BLOB)) AS signature_bytes
FROM release_metadata
WHERE catalog_id = ? AND release_id = ? AND format = 4 AND contract = 1
LIMIT 2;`,
  search: `SELECT
       CASE WHEN typeof(o.catalog_id) = 'text' AND length(CAST(o.catalog_id AS BLOB)) <= ? THEN o.catalog_id ELSE NULL END AS catalog_id,
       length(CAST(o.catalog_id AS BLOB)) AS catalog_id_bytes,
       CASE WHEN typeof(o.release_id) = 'text' AND length(CAST(o.release_id AS BLOB)) <= ? THEN o.release_id ELSE NULL END AS release_id,
       length(CAST(o.release_id AS BLOB)) AS release_id_bytes,
       CASE WHEN typeof(o.record_id) = 'text' AND length(CAST(o.record_id AS BLOB)) <= ? THEN o.record_id ELSE NULL END AS record_id,
       length(CAST(o.record_id AS BLOB)) AS record_id_bytes
FROM operations_fts
JOIN operations AS o ON o.rowid = operations_fts.rowid
JOIN release_metadata AS r
  ON r.catalog_id = o.catalog_id AND r.release_id = o.release_id
WHERE operations_fts MATCH ?
  AND (? IS NULL OR o.api = ?)
  AND r.format = 4 AND r.contract = 1
ORDER BY bm25(operations_fts),
         o.catalog_id COLLATE BINARY,
         o.release_id COLLATE BINARY,
         o.record_id COLLATE BINARY
LIMIT ?;`,
  operation: `SELECT
       CASE WHEN typeof(o.record_id) = 'text' AND length(CAST(o.record_id AS BLOB)) <= ? THEN o.record_id ELSE NULL END AS record_id,
       length(CAST(o.record_id AS BLOB)) AS record_id_bytes,
       CASE WHEN typeof(o.logical_digest) = 'text' AND length(CAST(o.logical_digest AS BLOB)) <= ? THEN o.logical_digest ELSE NULL END AS logical_digest,
       length(CAST(o.logical_digest AS BLOB)) AS logical_digest_bytes,
       CASE WHEN typeof(o.record_json) = 'text' AND length(CAST(o.record_json AS BLOB)) <= ? THEN o.record_json ELSE NULL END AS record_json,
       length(CAST(o.record_json AS BLOB)) AS record_json_bytes
FROM operations AS o
JOIN release_metadata AS r
  ON r.catalog_id = o.catalog_id AND r.release_id = o.release_id
WHERE o.catalog_id = ? AND o.release_id = ? AND o.record_id = ?
  AND r.format = 4 AND r.contract = 1
LIMIT 2;`,
  schemas: `WITH requested(record_id) AS (
  SELECT DISTINCT value FROM json_each(?) WHERE typeof(value) = 'text'
)
SELECT
       CASE WHEN typeof(s.record_id) = 'text' AND length(CAST(s.record_id AS BLOB)) <= ? THEN s.record_id ELSE NULL END AS record_id,
       length(CAST(s.record_id AS BLOB)) AS record_id_bytes,
       CASE WHEN typeof(s.logical_digest) = 'text' AND length(CAST(s.logical_digest AS BLOB)) <= ? THEN s.logical_digest ELSE NULL END AS logical_digest,
       length(CAST(s.logical_digest AS BLOB)) AS logical_digest_bytes,
       CASE WHEN typeof(s.record_json) = 'text' AND length(CAST(s.record_json AS BLOB)) <= ? THEN s.record_json ELSE NULL END AS record_json,
       length(CAST(s.record_json AS BLOB)) AS record_json_bytes
FROM requested
JOIN schemas AS s ON s.record_id = requested.record_id
JOIN release_metadata AS r
  ON r.catalog_id = s.catalog_id AND r.release_id = s.release_id
WHERE s.catalog_id = ? AND s.release_id = ?
  AND r.format = 4 AND r.contract = 1
ORDER BY s.record_id COLLATE BINARY
LIMIT ?;`,
});

type Sql = (typeof SQL)[keyof typeof SQL];
type Outcome =
  | D1CatalogResult<Record<string, unknown>>
  | Error
  | ((
      bindings: readonly D1CatalogValue[],
    ) => D1CatalogResult<Record<string, unknown>>);

interface Call {
  readonly sql: string;
  bindings?: readonly D1CatalogValue[];
  allCalls: number;
  firstCalls: number;
}

class StrictD1 implements D1CatalogDatabase {
  readonly calls: Call[] = [];
  readonly #outcomes = new Map<Sql, Outcome[]>();
  readonly #handlers = new Map<
    Sql,
    (
      bindings: readonly D1CatalogValue[],
    ) => D1CatalogResult<Record<string, unknown>>
  >();

  enqueue(sql: Sql, rows: readonly unknown[]): void {
    this.enqueueResult(sql, { success: true, results: rows as never });
  }

  enqueueResult(sql: Sql, outcome: Outcome): void {
    const queue = this.#outcomes.get(sql) ?? [];
    queue.push(outcome);
    this.#outcomes.set(sql, queue);
  }

  handle(
    sql: Sql,
    handler: (
      bindings: readonly D1CatalogValue[],
    ) => D1CatalogResult<Record<string, unknown>>,
  ): void {
    this.#handlers.set(sql, handler);
  }

  prepare(sql: string): D1CatalogPreparedStatement {
    if (!(Object.values(SQL) as readonly string[]).includes(sql)) {
      throw new Error(`unknown SQL: ${sql}`);
    }
    const call: Call = { sql, allCalls: 0, firstCalls: 0 };
    this.calls.push(call);
    const statement: D1CatalogPreparedStatement = {
      bind: (...values) => {
        if (call.bindings !== undefined) throw new Error("bound twice");
        call.bindings = [...values];
        return statement;
      },
      all: async <Row extends Record<string, unknown>>() => {
        call.allCalls += 1;
        const outcome =
          this.#outcomes.get(sql as Sql)?.shift() ??
          this.#handlers.get(sql as Sql);
        if (outcome === undefined)
          throw new Error("unconfigured strict D1 call");
        if (outcome instanceof Error) throw outcome;
        return (
          typeof outcome === "function" ? outcome(call.bindings ?? []) : outcome
        ) as D1CatalogResult<Row>;
      },
      first: async () => {
        call.firstCalls += 1;
        throw new Error("first() is forbidden by the structural contract");
      },
    };
    return statement;
  }
}

const manifestRow = (
  manifestJson: string = RUNTIME_CONFORMANCE_FIXTURE.envelopeA.manifestJson,
) => ({
  manifest_json: manifestJson,
  manifest_json_bytes: encoder.encode(manifestJson).byteLength,
  signature_algorithm: "Ed25519",
  signature_algorithm_bytes: 7,
  signature_key_id: "key-1",
  signature_key_id_bytes: 5,
  signature: "signature",
  signature_bytes: 9,
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

function manifestTransport(release: string) {
  const envelope =
    release === RUNTIME_CONFORMANCE_FIXTURE.releaseA
      ? RUNTIME_CONFORMANCE_FIXTURE.envelopeA
      : RUNTIME_CONFORMANCE_FIXTURE.envelopeB;
  return {
    manifest_json: envelope.manifestJson,
    manifest_json_bytes: encoder.encode(envelope.manifestJson).byteLength,
    signature_algorithm: envelope.signature.algorithm,
    signature_algorithm_bytes: 7,
    signature_key_id: envelope.signature.keyId,
    signature_key_id_bytes: encoder.encode(envelope.signature.keyId).byteLength,
    signature: envelope.signature.signature,
    signature_bytes: encoder.encode(envelope.signature.signature).byteLength,
  };
}

function storedTransport(row: {
  readonly id: string;
  readonly logicalDigest: string;
  readonly record: unknown;
}) {
  return {
    record_id: row.id,
    record_id_bytes: encoder.encode(row.id).byteLength,
    logical_digest: row.logicalDigest,
    logical_digest_bytes: encoder.encode(row.logicalDigest).byteLength,
    record_json: JSON.stringify(row.record),
    record_json_bytes: encoder.encode(JSON.stringify(row.record)).byteLength,
  };
}

function candidateTransport(
  catalogId: string,
  releaseId: string,
  recordId: string,
) {
  return {
    catalog_id: catalogId,
    catalog_id_bytes: encoder.encode(catalogId).byteLength,
    release_id: releaseId,
    release_id_bytes: encoder.encode(releaseId).byteLength,
    record_id: recordId,
    record_id_bytes: encoder.encode(recordId).byteLength,
  };
}

function conformanceD1Factory(
  scenario?: RuntimeConformanceScenario,
): CatalogStoreFactoryResult {
  const fixture = RUNTIME_CONFORMANCE_FIXTURE;
  const d1 = new StrictD1();
  const injectedDriverError =
    scenario !== undefined && "injectedDriverError" in scenario
      ? scenario.injectedDriverError
      : undefined;
  const driverFailure = (fault: string) =>
    scenario?.fault === fault && injectedDriverError !== undefined
      ? new Error(injectedDriverError)
      : undefined;
  const candidateDriverFailure = driverFailure("driver-candidates");
  const manifestDriverFailure = driverFailure("driver-manifest");
  const operationDriverFailure = driverFailure("driver-operation");
  const schemasDriverFailure = driverFailure("driver-schemas");
  if (candidateDriverFailure !== undefined)
    d1.enqueueResult(SQL.search, candidateDriverFailure);
  if (manifestDriverFailure !== undefined)
    d1.enqueueResult(SQL.manifest, manifestDriverFailure);
  if (operationDriverFailure !== undefined)
    d1.enqueueResult(SQL.operation, operationDriverFailure);
  if (schemasDriverFailure !== undefined)
    d1.enqueueResult(SQL.schemas, schemasDriverFailure);
  d1.handle(
    SQL.manifest,
    ([
      _manifestLimit,
      _algorithmLimit,
      _keyIdLimit,
      _signatureLimit,
      boundCatalog,
      boundRelease,
    ]) => ({
      success: true,
      results:
        boundCatalog === fixture.catalogId &&
        (boundRelease === fixture.releaseA || boundRelease === fixture.releaseB)
          ? Array.from(
              { length: scenario?.fault === "duplicate-manifest" ? 2 : 1 },
              () => manifestTransport(boundRelease),
            )
          : [],
    }),
  );
  d1.handle(
    SQL.search,
    ([
      _catalogLimit,
      _releaseLimit,
      _recordLimit,
      query,
      boundApi,
      _duplicateApi,
      rawLimit,
    ]) => {
      if (query === '"')
        return { success: false, results: [], error: "malformed FTS" };
      const limit = typeof rawLimit === "number" ? rawLimit : 0;
      const candidates = fixture.expectedCandidates
        .filter(() => boundApi === null || boundApi === fixture.api)
        .slice(0, limit);
      if (scenario?.fault === "duplicate-candidates") {
        const first = candidates[0];
        return {
          success: true,
          results:
            first === undefined || limit < 2
              ? []
              : [
                  candidateTransport(
                    first.catalogId,
                    first.releaseId,
                    first.operationId,
                  ),
                  candidateTransport(
                    first.catalogId,
                    first.releaseId,
                    first.operationId,
                  ),
                ],
        };
      }
      const first = candidates[0];
      if (
        first !== undefined &&
        scenario?.fault === "candidate-malformed-operation-id"
      ) {
        return {
          success: true,
          results: [
            candidateTransport(
              first.catalogId,
              first.releaseId,
              "not-a-typed-record-id",
            ),
          ],
        };
      }
      if (
        first !== undefined &&
        scenario?.fault === "candidate-non-operation-id"
      ) {
        return {
          success: true,
          results: [
            candidateTransport(
              first.catalogId,
              first.releaseId,
              fixture.schemaIds[0] as string,
            ),
          ],
        };
      }
      if (first !== undefined && scenario?.fault === "candidate-cross-api") {
        return {
          success: true,
          results: [
            candidateTransport(
              first.catalogId,
              first.releaseId,
              "operation:other-api:get-item",
            ),
          ],
        };
      }
      return {
        success: true,
        results: candidates.map((candidate) =>
          candidateTransport(
            candidate.catalogId,
            candidate.releaseId,
            candidate.operationId,
          ),
        ),
      };
    },
  );
  d1.handle(
    SQL.operation,
    ([
      _idLimit,
      _digestLimit,
      _recordLimit,
      boundCatalog,
      boundRelease,
      boundOperation,
    ]) => {
      if (
        boundCatalog !== fixture.catalogId ||
        boundOperation !== fixture.operationId
      )
        return { success: true, results: [] };
      const row =
        boundRelease === fixture.releaseA
          ? fixture.operationA
          : boundRelease === fixture.releaseB
            ? fixture.operationB
            : undefined;
      return {
        success: true,
        results: row
          ? Array.from(
              { length: scenario?.fault === "duplicate-operation" ? 2 : 1 },
              () => storedTransport(row),
            )
          : [],
      };
    },
  );
  d1.handle(
    SQL.schemas,
    ([
      rawIds,
      _idLimit,
      _digestLimit,
      _recordLimit,
      boundCatalog,
      boundRelease,
      transportLimit,
    ]) => {
      if (typeof rawIds !== "string" || boundCatalog !== fixture.catalogId)
        return { success: true, results: [] };
      const requested = new Set(JSON.parse(rawIds) as string[]);
      const rows =
        boundRelease === fixture.releaseA
          ? fixture.schemasA
          : boundRelease === fixture.releaseB
            ? fixture.schemasB
            : [];
      return {
        success: true,
        results: rows
          .filter((row) => requested.has(row.id))
          .flatMap((row) =>
            Array.from(
              { length: scenario?.fault === "duplicate-schemas" ? 2 : 1 },
              () => storedTransport(row),
            ),
          )
          .slice(0, Number(transportLimit)),
      };
    },
  );
  return { store: createD1CatalogStore(d1), fixture };
}

describe("structural D1 shared conformance", () => {
  runRuntimeConformanceSuite(conformanceD1Factory, {
    testAdapter: conformanceAdapter,
  });
});

const searchRow = (
  id: string = operationId,
  catalogId: string = catalog,
  releaseId: string = release,
) => candidateTransport(catalogId, releaseId, id);

const operationRecord = (id: string = operationId) => ({
  id,
  api: "conformance",
  operationId: "get-item",
  method: "GET",
  path: "/items/{id}",
  origin: "https://example.invalid",
  summary: null,
  deprecated: false,
  parameters: [],
  requestBody: null,
  schemaIds: [itemSchema],
  advisory: {},
});

const recordRow = (
  id: string,
  record: unknown,
  logicalDigest = "a".repeat(64),
) => {
  const recordJson = JSON.stringify(record);
  return {
    record_id: id,
    record_id_bytes: encoder.encode(id).byteLength,
    logical_digest: logicalDigest,
    logical_digest_bytes: encoder.encode(logicalDigest).byteLength,
    record_json: recordJson,
    record_json_bytes: encoder.encode(recordJson).byteLength,
  };
};

const schemaRow = (id: string) =>
  recordRow(id, { id, schema: { type: "object" } }, "b".repeat(64));

async function capturedError(
  run: () => Promise<unknown>,
): Promise<OpenApiMcpError> {
  try {
    await run();
  } catch (error) {
    expect(error).toBeInstanceOf(OpenApiMcpError);
    return error as OpenApiMcpError;
  }
  throw new Error("expected OpenApiMcpError");
}

async function expectPublicError(
  run: () => Promise<unknown>,
  code: OpenApiMcpError["code"],
  secret?: string,
  expectedMessage?: string,
): Promise<void> {
  const error = await capturedError(run);
  expect(error.code).toBe(code);
  expect(error.details).toEqual({});
  if (secret !== undefined) expect(error.message).not.toContain(secret);
  if (expectedMessage !== undefined)
    expect(error.message).toBe(expectedMessage);
}

describe("structural D1 CatalogStore", () => {
  test("uses exactly the four fixed statements and binds every caller value", async () => {
    const d1 = new StrictD1();
    const store = createD1CatalogStore(d1);
    const maliciousFts = `widget' OR 1=1; DROP TABLE operations; --`;
    d1.enqueue(SQL.manifest, [manifestRow()]);
    d1.enqueue(SQL.search, [searchRow()]);
    d1.enqueue(SQL.operation, [recordRow(operationId, operationRecord())]);
    d1.enqueue(SQL.schemas, [schemaRow(itemSchema)]);

    await store.getManifest(catalog, release);
    await store.searchCandidates({
      query: maliciousFts,
      api: "conformance",
      limit: 7,
    });
    await store.getOperation(catalog, release, operationId);
    await store.getSchemas(catalog, release, [itemSchema]);

    expect(d1.calls).toEqual([
      {
        sql: SQL.manifest,
        bindings: [8 * 1024 * 1024, 7, 128, 256, catalog, release],
        allCalls: 1,
        firstCalls: 0,
      },
      {
        sql: SQL.search,
        bindings: [
          128,
          128,
          651,
          maliciousFts,
          "conformance",
          "conformance",
          7,
        ],
        allCalls: 1,
        firstCalls: 0,
      },
      {
        sql: SQL.operation,
        bindings: [651, 64, 1024 * 1024, catalog, release, operationId],
        allCalls: 1,
        firstCalls: 0,
      },
      {
        sql: SQL.schemas,
        bindings: [
          `["${itemSchema}"]`,
          669,
          64,
          1024 * 1024,
          catalog,
          release,
          2,
        ],
        allCalls: 1,
        firstCalls: 0,
      },
    ]);
    expect(new Set(d1.calls.map(({ sql }) => sql))).toEqual(
      new Set(Object.values(SQL)),
    );
    expect(d1.calls.every(({ sql }) => !sql.includes(maliciousFts))).toBe(true);
  });

  test("validates caller identities before touching D1, including empty schema reads", async () => {
    const invalidCatalog = `bad'; DROP TABLE schemas; --` as CatalogId;
    const invalidRelease = "../release" as ReleaseId;
    const invalidOperation =
      "schema:conformance:#/components/schemas/Item" as unknown as TypedOperationId;
    const invalidSchema =
      "operation:conformance:get-item" as unknown as TypedSchemaId;
    for (const run of [
      (store: ReturnType<typeof createD1CatalogStore>) =>
        store.getManifest(invalidCatalog, release),
      (store: ReturnType<typeof createD1CatalogStore>) =>
        store.getManifest(catalog, invalidRelease),
      (store: ReturnType<typeof createD1CatalogStore>) =>
        store.getOperation(catalog, release, invalidOperation),
      (store: ReturnType<typeof createD1CatalogStore>) =>
        store.getSchemas(catalog, release, [invalidSchema]),
      (store: ReturnType<typeof createD1CatalogStore>) =>
        store.getSchemas(invalidCatalog, release, []),
    ]) {
      const d1 = new StrictD1();
      await expectPublicError(
        () => run(createD1CatalogStore(d1)),
        "INPUT_INVALID",
      );
      expect(d1.calls).toEqual([]);
    }
  });

  test("rejects non-string caller identities before coercion or D1 access", async () => {
    const objectIdentity = { toString: () => "object-identity" };
    for (const identity of [123, null, objectIdentity] as const) {
      const calls = [
        (store: ReturnType<typeof createD1CatalogStore>) =>
          [
            store.getManifest(identity as never, release),
            CATALOG_STORE_PUBLIC_MESSAGES.catalogIdentityInvalid,
          ] as const,
        (store: ReturnType<typeof createD1CatalogStore>) =>
          [
            store.getManifest(catalog, identity as never),
            CATALOG_STORE_PUBLIC_MESSAGES.releaseIdentityInvalid,
          ] as const,
        (store: ReturnType<typeof createD1CatalogStore>) =>
          [
            store.searchCandidates({
              query: "item",
              api: identity as never,
              limit: 1,
            }),
            CATALOG_STORE_PUBLIC_MESSAGES.catalogIdentityInvalid,
          ] as const,
        (store: ReturnType<typeof createD1CatalogStore>) =>
          [
            store.getOperation(catalog, release, identity as never),
            CATALOG_STORE_PUBLIC_MESSAGES.operationIdentityInvalid,
          ] as const,
        (store: ReturnType<typeof createD1CatalogStore>) =>
          [
            store.getOperation(identity as never, release, operationId),
            CATALOG_STORE_PUBLIC_MESSAGES.catalogIdentityInvalid,
          ] as const,
        (store: ReturnType<typeof createD1CatalogStore>) =>
          [
            store.getOperation(catalog, identity as never, operationId),
            CATALOG_STORE_PUBLIC_MESSAGES.releaseIdentityInvalid,
          ] as const,
        (store: ReturnType<typeof createD1CatalogStore>) =>
          [
            store.getSchemas(catalog, release, [identity as never]),
            CATALOG_STORE_PUBLIC_MESSAGES.schemaIdentityInvalid,
          ] as const,
        (store: ReturnType<typeof createD1CatalogStore>) =>
          [
            store.getSchemas(identity as never, release, [itemSchema]),
            CATALOG_STORE_PUBLIC_MESSAGES.catalogIdentityInvalid,
          ] as const,
        (store: ReturnType<typeof createD1CatalogStore>) =>
          [
            store.getSchemas(catalog, identity as never, [itemSchema]),
            CATALOG_STORE_PUBLIC_MESSAGES.releaseIdentityInvalid,
          ] as const,
      ];
      for (const call of calls) {
        const d1 = new StrictD1();
        const [run, message] = call(createD1CatalogStore(d1));
        await expectPublicError(
          () => run,
          "INPUT_INVALID",
          "object-identity",
          message,
        );
        expect(d1.calls).toEqual([]);
      }
    }
  });

  test("returns an empty schema batch without preparing SQL", async () => {
    const d1 = new StrictD1();
    expect(
      await createD1CatalogStore(d1).getSchemas(catalog, release, []),
    ).toEqual([]);
    expect(d1.calls).toEqual([]);
  });

  test("accepts FTS queries at the 4 KiB UTF-8 boundary", async () => {
    for (const query of ["a".repeat(4 * 1024), "\u{1F98D}".repeat(1024)]) {
      const d1 = new StrictD1();
      d1.enqueue(SQL.search, [searchRow()]);
      await expect(
        createD1CatalogStore(d1).searchCandidates({ query, limit: 1 }),
      ).resolves.toEqual([
        { catalogId: catalog, releaseId: release, operationId },
      ]);
      expect(d1.calls).toHaveLength(1);
      expect(d1.calls[0]?.bindings).toEqual([
        128,
        128,
        651,
        query,
        null,
        null,
        1,
      ]);
    }
  });

  test("rejects FTS queries over 4 KiB before preparing D1", async () => {
    for (const query of [
      "a".repeat(4 * 1024 + 1),
      `${"\u{1F98D}".repeat(1024)}a`,
    ]) {
      const d1 = new StrictD1();
      await expectPublicError(
        () => createD1CatalogStore(d1).searchCandidates({ query, limit: 1 }),
        "INPUT_INVALID",
        undefined,
        CATALOG_STORE_PUBLIC_MESSAGES.searchQueryInvalid,
      );
      expect(d1.calls).toEqual([]);
    }
  });

  test("resolves partial limits and rejects a search-limit relaxation", async () => {
    const d1 = new StrictD1();
    d1.enqueue(SQL.search, [searchRow()]);
    await expect(
      createD1CatalogStore(d1, { maxSearchResults: 1 }).searchCandidates({
        query: "item",
        limit: 1,
      }),
    ).resolves.toEqual([
      { catalogId: catalog, releaseId: release, operationId },
    ]);
    expect(() =>
      createD1CatalogStore(new StrictD1(), { maxSearchResults: 51 }),
    ).toThrow(RangeError);
  });

  test("rejects accessor-backed and non-exact search queries before D1 access", async () => {
    let accessorReads = 0;
    const accessorQuery = Object.defineProperties(
      {},
      {
        query: {
          enumerable: true,
          get: () => {
            accessorReads += 1;
            return "item";
          },
        },
        limit: { enumerable: true, value: 1 },
      },
    );
    const proxyQuery = new Proxy(
      { query: "item", limit: 1 },
      {
        getOwnPropertyDescriptor: () => {
          throw new Error("query-proxy-poison");
        },
      },
    );
    const symbolQuery = {
      query: "item",
      limit: 1,
      [Symbol("extra")]: true,
    };
    for (const query of [
      accessorQuery,
      proxyQuery,
      { query: "item", limit: 1, extra: true },
      symbolQuery,
    ]) {
      const d1 = new StrictD1();
      await expectPublicError(
        () => createD1CatalogStore(d1).searchCandidates(query as never),
        "INPUT_INVALID",
        "query-proxy-poison",
        CATALOG_STORE_PUBLIC_MESSAGES.searchQueryInvalid,
      );
      expect(d1.calls).toEqual([]);
    }
    expect(accessorReads).toBe(0);
  });

  test("snapshots only dense exact schema ID arrays before D1 access", async () => {
    let iteratorCalls = 0;
    const customIterable = {
      [Symbol.iterator]: () => {
        iteratorCalls += 1;
        return [itemSchema][Symbol.iterator]();
      },
    };
    const sparse = Array<TypedSchemaId | undefined>(3);
    sparse[0] = itemSchema;
    sparse[2] = userSchema;
    const extra = [itemSchema];
    Object.defineProperty(extra, "extra", { value: true });
    const symbol = [itemSchema];
    Object.defineProperty(symbol, Symbol("extra"), { value: true });
    const proxy = new Proxy([itemSchema], {
      getOwnPropertyDescriptor: () => {
        throw new Error("schema-proxy-poison");
      },
    });
    for (const ids of [customIterable, sparse, extra, symbol, proxy]) {
      const d1 = new StrictD1();
      await expectPublicError(
        () =>
          createD1CatalogStore(d1).getSchemas(catalog, release, ids as never),
        "INPUT_INVALID",
        "schema-proxy-poison",
        CATALOG_STORE_PUBLIC_MESSAGES.schemaRequestInvalid,
      );
      expect(d1.calls).toEqual([]);
    }
    expect(iteratorCalls).toBe(0);
  });

  test("accepts frozen plain query and schema ID snapshots", async () => {
    const d1 = new StrictD1();
    d1.enqueue(SQL.search, [searchRow()]);
    d1.enqueue(SQL.schemas, [schemaRow(itemSchema)]);
    const store = createD1CatalogStore(d1);
    await expect(
      store.searchCandidates(Object.freeze({ query: "item", limit: 1 })),
    ).resolves.toEqual([
      { catalogId: catalog, releaseId: release, operationId },
    ]);
    await expect(
      store.getSchemas(catalog, release, Object.freeze([itemSchema])),
    ).resolves.toHaveLength(1);
  });

  test("rejects candidate overrun before inspecting any row", async () => {
    const d1 = new StrictD1();
    const poison = Object.defineProperty({}, "catalog_id", {
      enumerable: true,
      get: () => {
        throw new Error("hydrated poison");
      },
    });
    d1.enqueue(SQL.search, [poison, poison]);
    await expectPublicError(
      () =>
        createD1CatalogStore(d1).searchCandidates({ query: "item", limit: 1 }),
      "RECORD_DIGEST_MISMATCH",
      "hydrated poison",
    );
  });

  test("rejects duplicate, extra-shaped, wrong-API, and wrong-kind candidates", async () => {
    const cases: readonly unknown[][] = [
      [searchRow(), searchRow()],
      [{ ...searchRow(), extra: "untrusted" }],
      [searchRow("operation:other:get-item")],
      [searchRow(itemSchema)],
    ];
    for (const rows of cases) {
      const d1 = new StrictD1();
      d1.enqueue(SQL.search, rows);
      await expectPublicError(
        () =>
          createD1CatalogStore(d1).searchCandidates({
            query: "item",
            api: "conformance",
            limit: 2,
          }),
        "RECORD_DIGEST_MISMATCH",
      );
    }
  });

  test("normalizes FTS and D1 failures without exposing driver details", async () => {
    const secret = "d1-internal-secret";
    for (const outcome of [
      new Error(secret),
      { success: false, results: [], error: secret },
      { success: true, results: null as never, error: secret },
    ]) {
      const d1 = new StrictD1();
      d1.enqueueResult(SQL.search, outcome);
      await expectPublicError(
        () =>
          createD1CatalogStore(d1).searchCandidates({ query: '"', limit: 1 }),
        "INPUT_INVALID",
        secret,
        CATALOG_STORE_PUBLIC_MESSAGES.searchExpressionInvalid,
      );
    }
  });

  test("copies D1 row data before field reads can trigger Proxy traps", async () => {
    const cases = [
      [
        SQL.manifest,
        manifestRow(),
        (store: ReturnType<typeof createD1CatalogStore>) =>
          store.getManifest(catalog, release),
      ],
      [
        SQL.search,
        searchRow(),
        (store: ReturnType<typeof createD1CatalogStore>) =>
          store.searchCandidates({ query: "item", limit: 1 }),
      ],
      [
        SQL.operation,
        recordRow(operationId, operationRecord()),
        (store: ReturnType<typeof createD1CatalogStore>) =>
          store.getOperation(catalog, release, operationId),
      ],
      [
        SQL.schemas,
        schemaRow(itemSchema),
        (store: ReturnType<typeof createD1CatalogStore>) =>
          store.getSchemas(catalog, release, [itemSchema]),
      ],
    ] as const;
    for (const [sql, row, run] of cases) {
      let getCalls = 0;
      const poison = new Proxy(row, {
        get: () => {
          getCalls += 1;
          throw new Error("row-getter-secret");
        },
      });
      const d1 = new StrictD1();
      d1.enqueue(sql, [poison]);
      await run(createD1CatalogStore(d1));
      expect(getCalls).toBe(0);
    }
  });

  test("rejects short non-TEXT projection sentinels across bounded fields", async () => {
    for (const field of [
      "manifest_json",
      "signature_algorithm",
      "signature_key_id",
      "signature",
    ] as const) {
      const d1 = new StrictD1();
      d1.enqueue(SQL.manifest, [{ ...manifestRow(), [field]: null }]);
      await expectPublicError(
        () => createD1CatalogStore(d1).getManifest(catalog, release),
        "MANIFEST_INVALID",
        undefined,
        CATALOG_STORE_PUBLIC_MESSAGES.manifestTransportRowInvalid,
      );
    }

    for (const field of ["catalog_id", "release_id", "record_id"] as const) {
      const d1 = new StrictD1();
      d1.enqueue(SQL.search, [{ ...searchRow(), [field]: null }]);
      await expectPublicError(
        () =>
          createD1CatalogStore(d1).searchCandidates({
            query: "item",
            limit: 1,
          }),
        "RECORD_DIGEST_MISMATCH",
        undefined,
        CATALOG_STORE_PUBLIC_MESSAGES.recordTransportRowInvalid,
      );
    }

    for (const [sql, run, row] of [
      [
        SQL.operation,
        (store: ReturnType<typeof createD1CatalogStore>) =>
          store.getOperation(catalog, release, operationId),
        recordRow(operationId, operationRecord()),
      ],
      [
        SQL.schemas,
        (store: ReturnType<typeof createD1CatalogStore>) =>
          store.getSchemas(catalog, release, [itemSchema]),
        schemaRow(itemSchema),
      ],
    ] as const) {
      for (const field of [
        "record_id",
        "logical_digest",
        "record_json",
      ] as const) {
        const d1 = new StrictD1();
        d1.enqueue(sql, [{ ...row, [field]: null }]);
        await expectPublicError(
          () => run(createD1CatalogStore(d1)),
          "RECORD_DIGEST_MISMATCH",
          undefined,
          CATALOG_STORE_PUBLIC_MESSAGES.recordTransportRowInvalid,
        );
      }
    }
  });

  test("rejects oversized projected identifiers and digests from byte sentinels", async () => {
    for (const [field, byteField, byteLength, message] of [
      [
        "catalog_id",
        "catalog_id_bytes",
        129,
        CATALOG_STORE_PUBLIC_MESSAGES.storedCatalogIdentifierInvalid,
      ],
      [
        "release_id",
        "release_id_bytes",
        129,
        CATALOG_STORE_PUBLIC_MESSAGES.storedReleaseIdentifierInvalid,
      ],
      [
        "record_id",
        "record_id_bytes",
        652,
        CATALOG_STORE_PUBLIC_MESSAGES.storedOperationIdentifierInvalid,
      ],
    ] as const) {
      const d1 = new StrictD1();
      d1.enqueue(SQL.search, [
        { ...searchRow(), [field]: null, [byteField]: byteLength },
      ]);
      await expectPublicError(
        () =>
          createD1CatalogStore(d1).searchCandidates({
            query: "item",
            limit: 1,
          }),
        "RECORD_DIGEST_MISMATCH",
        undefined,
        message,
      );
    }

    for (const [sql, run, row, overflow] of [
      [
        SQL.operation,
        (store: ReturnType<typeof createD1CatalogStore>) =>
          store.getOperation(catalog, release, operationId),
        recordRow(operationId, operationRecord()),
        {
          record_id: null,
          record_id_bytes: 652,
          message:
            CATALOG_STORE_PUBLIC_MESSAGES.storedOperationIdentifierInvalid,
        },
      ],
      [
        SQL.schemas,
        (store: ReturnType<typeof createD1CatalogStore>) =>
          store.getSchemas(catalog, release, [itemSchema]),
        schemaRow(itemSchema),
        {
          record_id: null,
          record_id_bytes: 670,
          message: CATALOG_STORE_PUBLIC_MESSAGES.storedSchemaIdentifierInvalid,
        },
      ],
      [
        SQL.operation,
        (store: ReturnType<typeof createD1CatalogStore>) =>
          store.getOperation(catalog, release, operationId),
        recordRow(operationId, operationRecord()),
        {
          logical_digest: null,
          logical_digest_bytes: 65,
          message: CATALOG_STORE_PUBLIC_MESSAGES.recordDigestInvalid,
        },
      ],
    ] as const) {
      const { message, ...fields } = overflow;
      const d1 = new StrictD1();
      d1.enqueue(sql, [{ ...row, ...fields }]);
      await expectPublicError(
        () => run(createD1CatalogStore(d1)),
        "RECORD_DIGEST_MISMATCH",
        undefined,
        message,
      );
    }
  });

  test("requires exactly zero or one operation row before hydration", async () => {
    const empty = new StrictD1();
    empty.enqueue(SQL.operation, []);
    expect(
      await createD1CatalogStore(empty).getOperation(
        catalog,
        release,
        operationId,
      ),
    ).toBeNull();

    const poison = Object.defineProperty({}, "record_id", {
      enumerable: true,
      get: () => {
        throw new Error("hydrated poison");
      },
    });
    const duplicate = new StrictD1();
    duplicate.enqueue(SQL.operation, [poison, poison]);
    await expectPublicError(
      () =>
        createD1CatalogStore(duplicate).getOperation(
          catalog,
          release,
          operationId,
        ),
      "RECORD_DIGEST_MISMATCH",
      "hydrated poison",
    );
  });

  test("rejects operation transport shape, identity, kind, and JSON-record mismatch", async () => {
    const cases: readonly unknown[] = [
      { ...recordRow(operationId, operationRecord()), extra: "untrusted" },
      recordRow(
        "operation:conformance:other",
        operationRecord("operation:conformance:other"),
      ),
      recordRow(itemSchema, { id: itemSchema, schema: {} }),
      recordRow(operationId, { id: itemSchema, schema: {} }),
      recordRow(operationId, operationRecord("operation:conformance:other")),
      recordRow(operationId, []),
      {
        ...recordRow(operationId, operationRecord()),
        logical_digest: "NOT-A-DIGEST",
      },
    ];
    for (const row of cases) {
      const d1 = new StrictD1();
      d1.enqueue(SQL.operation, [row]);
      await expectPublicError(
        () =>
          createD1CatalogStore(d1).getOperation(catalog, release, operationId),
        "RECORD_DIGEST_MISMATCH",
      );
    }
  });

  test("bounds schema result cardinality before hydration", async () => {
    const d1 = new StrictD1();
    const poison = Object.defineProperty({}, "record_id", {
      enumerable: true,
      get: () => {
        throw new Error("hydrated poison");
      },
    });
    d1.enqueue(SQL.schemas, [poison, poison]);
    await expectPublicError(
      () => createD1CatalogStore(d1).getSchemas(catalog, release, [itemSchema]),
      "RECORD_DIGEST_MISMATCH",
      "hydrated poison",
    );
  });

  test("caps poisoned D1 schema relations at requested count plus one", async () => {
    const d1 = new StrictD1();
    let transportedRows = 0;
    let boundLimit: D1CatalogValue | undefined;
    d1.handle(
      SQL.schemas,
      ([
        _ids,
        _idLimit,
        _digestLimit,
        _recordLimit,
        _catalog,
        _release,
        transportLimit,
      ]) => {
        boundLimit = transportLimit;
        const poisonedRelation = Array.from({ length: 10_000 }, () =>
          schemaRow(itemSchema),
        );
        const results = poisonedRelation.slice(0, Number(transportLimit));
        transportedRows = results.length;
        return { success: true, results };
      },
    );

    await expectPublicError(
      () =>
        createD1CatalogStore(d1).getSchemas(catalog, release, [
          itemSchema,
          itemSchema,
        ]),
      "RECORD_DIGEST_MISMATCH",
      undefined,
      CATALOG_STORE_PUBLIC_MESSAGES.schemaTransportTooManyRows,
    );
    expect(boundLimit).toBe(2);
    expect(transportedRows).toBe(2);
  });

  test("rejects incomplete schema rows before inspecting row values", async () => {
    let inspections = 0;
    const poison = new Proxy(
      {},
      {
        get: () => {
          inspections += 1;
          throw new Error("short-schema-poison");
        },
        getOwnPropertyDescriptor: () => {
          inspections += 1;
          throw new Error("short-schema-poison");
        },
        getPrototypeOf: () => {
          inspections += 1;
          throw new Error("short-schema-poison");
        },
        ownKeys: () => {
          inspections += 1;
          throw new Error("short-schema-poison");
        },
      },
    );
    const d1 = new StrictD1();
    d1.enqueue(SQL.schemas, [poison]);

    await expectPublicError(
      () =>
        createD1CatalogStore(d1).getSchemas(catalog, release, [
          itemSchema,
          userSchema,
        ]),
      "RECORD_DIGEST_MISMATCH",
      "short-schema-poison",
      CATALOG_STORE_PUBLIC_MESSAGES.schemaRowsIncomplete,
    );
    expect(inspections).toBe(0);
  });

  test("returns complete unique requested schemas in canonical order", async () => {
    const d1 = new StrictD1();
    d1.enqueue(SQL.schemas, [schemaRow(itemSchema), schemaRow(userSchema)]);
    const result = await createD1CatalogStore(d1).getSchemas(catalog, release, [
      userSchema,
      itemSchema,
      itemSchema,
    ]);
    expect(result.map(({ id }) => id)).toEqual([itemSchema, userSchema]);
    expect(d1.calls[0]?.bindings).toEqual([
      `["${itemSchema}","${userSchema}"]`,
      669,
      64,
      1024 * 1024,
      catalog,
      release,
      3,
    ]);
  });

  test("bounds cumulative schema ID bytes before request amplification", async () => {
    const prefix = "schema:c:#/components/schemas/";
    const exactId =
      `${prefix}${"a".repeat(64 - prefix.length)}` as TypedSchemaId;
    const overId =
      `${prefix}${"a".repeat(65 - prefix.length)}` as TypedSchemaId;

    const exact = new StrictD1();
    exact.enqueue(SQL.schemas, [schemaRow(exactId)]);
    await expect(
      createD1CatalogStore(exact, {
        maxSchemaClosureBytes: 64,
      }).getSchemas(catalog, release, [exactId]),
    ).resolves.toHaveLength(1);

    const over = new StrictD1();
    await expectPublicError(
      () =>
        createD1CatalogStore(over, {
          maxSchemaClosureBytes: 64,
        }).getSchemas(catalog, release, [overId]),
      "INPUT_INVALID",
      undefined,
      CATALOG_STORE_PUBLIC_MESSAGES.schemaRequestLimitExceeded,
    );
    expect(over.calls).toEqual([]);
  });

  test("rejects incomplete, duplicate, extra, unordered, wrong-kind, and mismatched schema rows", async () => {
    const cases: readonly unknown[][] = [
      [schemaRow(itemSchema)],
      [schemaRow(itemSchema), schemaRow(itemSchema)],
      [
        schemaRow(itemSchema),
        schemaRow("schema:conformance:#/components/schemas/Other"),
      ],
      [schemaRow(userSchema), schemaRow(itemSchema)],
      [schemaRow(itemSchema), recordRow(operationId, operationRecord())],
      [
        schemaRow(itemSchema),
        recordRow(userSchema, { id: itemSchema, schema: {} }),
      ],
      [{ ...schemaRow(itemSchema), extra: "untrusted" }, schemaRow(userSchema)],
    ];
    for (const rows of cases) {
      const d1 = new StrictD1();
      d1.enqueue(SQL.schemas, rows);
      await expectPublicError(
        () =>
          createD1CatalogStore(d1).getSchemas(catalog, release, [
            itemSchema,
            userSchema,
          ]),
        "RECORD_DIGEST_MISMATCH",
      );
    }
  });

  test("requires exactly one bounded manifest row with exact shape", async () => {
    const cases: readonly unknown[][] = [
      [],
      [manifestRow(), manifestRow()],
      [{ ...manifestRow(), extra: "untrusted" }],
      [{ ...manifestRow(), signature_algorithm: "RS256" }],
      [
        {
          ...manifestRow(),
          manifest_json: "x".repeat(20),
          manifest_json_bytes: 20,
        },
      ],
      [
        {
          ...manifestRow(),
          manifest_json: null,
          manifest_json_bytes: 33,
        },
      ],
    ];
    for (const rows of cases) {
      const d1 = new StrictD1();
      d1.enqueue(SQL.manifest, rows);
      await expectPublicError(
        () =>
          createD1CatalogStore(d1, { maxManifestBytes: 32 }).getManifest(
            catalog,
            release,
          ),
        "MANIFEST_INVALID",
      );
    }
  });

  test("keeps bounded signature metadata outside the manifest byte budget", async () => {
    const manifestJson = RUNTIME_CONFORMANCE_FIXTURE.envelopeA.manifestJson;
    const maxManifestBytes = encoder.encode(manifestJson).byteLength;
    const d1 = new StrictD1();
    d1.enqueue(SQL.manifest, [
      {
        ...manifestRow(manifestJson),
        signature_key_id: "k".repeat(128),
        signature_key_id_bytes: 128,
        signature: "s".repeat(256),
        signature_bytes: 256,
      },
    ]);

    await expect(
      createD1CatalogStore(d1, { maxManifestBytes }).getManifest(
        catalog,
        release,
      ),
    ).resolves.toMatchObject({
      manifestJson,
      signature: {
        algorithm: "Ed25519",
        keyId: "k".repeat(128),
        signature: "s".repeat(256),
      },
    });
  });

  test("rejects each signature metadata field over its independent bound", async () => {
    const cases = [
      {
        signature_algorithm: null,
        signature_algorithm_bytes: 8,
      },
      { signature_key_id: null, signature_key_id_bytes: 129 },
      { signature: null, signature_bytes: 257 },
      { signature_key_id: "bad key", signature_key_id_bytes: 7 },
      { signature: "bad=signature", signature_bytes: 13 },
    ] as const;
    for (const overflow of cases) {
      const d1 = new StrictD1();
      d1.enqueue(SQL.manifest, [{ ...manifestRow(), ...overflow }]);
      await expectPublicError(
        () => createD1CatalogStore(d1).getManifest(catalog, release),
        "MANIFEST_INVALID",
        undefined,
        CATALOG_STORE_PUBLIC_MESSAGES.manifestSignatureMetadataInvalid,
      );
    }
  });

  test("rejects oversized manifest transport without returning hostile text", async () => {
    const d1 = new StrictD1();
    let transportedBytes = -1;
    d1.handle(
      SQL.manifest,
      ([manifestLimit, _algorithmLimit, _keyLimit, _signatureLimit]) => {
        const hostileBytes = 16 * 1024 * 1024;
        const transported = hostileBytes <= Number(manifestLimit) ? "x" : null;
        transportedBytes = transported === null ? 0 : 1;
        return {
          success: true,
          results: [
            {
              ...manifestRow(),
              manifest_json: transported,
              manifest_json_bytes: hostileBytes,
            },
          ],
        };
      },
    );

    await expectPublicError(
      () => createD1CatalogStore(d1).getManifest(catalog, release),
      "MANIFEST_INVALID",
      undefined,
      CATALOG_STORE_PUBLIC_MESSAGES.manifestTransportLimitExceeded,
    );
    expect(transportedBytes).toBe(0);
  });

  test("accepts exact record bytes and rejects one-over transport", async () => {
    const record = operationRecord();
    const recordJson = JSON.stringify(record);
    const maxRecordBytes = encoder.encode(recordJson).byteLength;
    const exact = new StrictD1();
    exact.enqueue(SQL.operation, [recordRow(operationId, record)]);
    await expect(
      createD1CatalogStore(exact, { maxRecordBytes }).getOperation(
        catalog,
        release,
        operationId,
      ),
    ).resolves.toMatchObject({ id: operationId, record });

    const over = new StrictD1();
    over.enqueue(SQL.operation, [
      {
        ...recordRow(operationId, record),
        record_json: null,
        record_json_bytes: maxRecordBytes + 1,
      },
    ]);
    await expectPublicError(
      () =>
        createD1CatalogStore(over, { maxRecordBytes }).getOperation(
          catalog,
          release,
          operationId,
        ),
      "RECORD_DIGEST_MISMATCH",
      undefined,
      CATALOG_STORE_PUBLIC_MESSAGES.recordJsonInvalid,
    );
  });

  test("does not return huge operation or schema JSON through D1", async () => {
    for (const [sql, run, id] of [
      [
        SQL.operation,
        (store: ReturnType<typeof createD1CatalogStore>) =>
          store.getOperation(catalog, release, operationId),
        operationId,
      ],
      [
        SQL.schemas,
        (store: ReturnType<typeof createD1CatalogStore>) =>
          store.getSchemas(catalog, release, [itemSchema]),
        itemSchema,
      ],
    ] as const) {
      const d1 = new StrictD1();
      let transportedBytes = -1;
      d1.handle(sql, (bindings) => {
        const recordLimit = Number(bindings[sql === SQL.operation ? 2 : 3]);
        const hostileBytes = 16 * 1024 * 1024;
        const transported = hostileBytes <= recordLimit ? "x" : null;
        transportedBytes = transported === null ? 0 : 1;
        return {
          success: true,
          results: [
            {
              record_id: id,
              record_id_bytes: encoder.encode(id).byteLength,
              logical_digest: "a".repeat(64),
              logical_digest_bytes: 64,
              record_json: transported,
              record_json_bytes: hostileBytes,
            },
          ],
        };
      });

      await expectPublicError(
        () => run(createD1CatalogStore(d1)),
        "RECORD_DIGEST_MISMATCH",
        undefined,
        CATALOG_STORE_PUBLIC_MESSAGES.recordJsonInvalid,
      );
      expect(transportedBytes).toBe(0);
    }
  });

  test("rejects manifests whose signed identities differ from the request", async () => {
    const crossCatalogManifest = JSON.stringify({
      ...JSON.parse(RUNTIME_CONFORMANCE_FIXTURE.envelopeA.manifestJson),
      catalogId: "other-catalog",
    });
    for (const manifestJson of [
      RUNTIME_CONFORMANCE_FIXTURE.envelopeB.manifestJson,
      crossCatalogManifest,
    ]) {
      const d1 = new StrictD1();
      d1.enqueue(SQL.manifest, [manifestRow(manifestJson)]);
      await expectPublicError(
        () => createD1CatalogStore(d1).getManifest(catalog, release),
        "MANIFEST_INVALID",
        undefined,
        CATALOG_STORE_PUBLIC_MESSAGES.manifestIdentityMismatch,
      );
    }
  });

  test("normalizes manifest and record driver failures with stable scrubbed errors", async () => {
    const secret = "driver-secret";
    for (const [sql, run, code, message] of [
      [
        SQL.manifest,
        (store: ReturnType<typeof createD1CatalogStore>) =>
          store.getManifest(catalog, release),
        "MANIFEST_INVALID",
        CATALOG_STORE_PUBLIC_MESSAGES.manifestTransportUnavailable,
      ],
      [
        SQL.operation,
        (store: ReturnType<typeof createD1CatalogStore>) =>
          store.getOperation(catalog, release, operationId),
        "RECORD_DIGEST_MISMATCH",
        CATALOG_STORE_PUBLIC_MESSAGES.recordTransportUnavailable,
      ],
      [
        SQL.schemas,
        (store: ReturnType<typeof createD1CatalogStore>) =>
          store.getSchemas(catalog, release, [itemSchema]),
        "RECORD_DIGEST_MISMATCH",
        CATALOG_STORE_PUBLIC_MESSAGES.recordTransportUnavailable,
      ],
    ] as const) {
      for (const outcome of [
        new Error(secret),
        { success: false, results: [], error: secret },
      ]) {
        const d1 = new StrictD1();
        d1.enqueueResult(sql, outcome);
        await expectPublicError(
          () => run(createD1CatalogStore(d1)),
          code,
          secret,
          message,
        );
      }
    }
  });
});
