import { DatabaseSync } from "node:sqlite";
import {
  type CatalogId,
  type CatalogStore,
  createD1CatalogStore,
  type D1CatalogDatabase,
  type D1CatalogPreparedStatement,
  type D1CatalogResult,
  type D1CatalogValue,
  type ManifestEnvelope,
  OpenApiMcpError,
  type OperationRecordV4,
  parseTypedRecordId,
  type ReleaseId,
  type RuntimeLimits,
  resolveRuntimeLimits,
  type SchemaRecordV4,
  type SearchQuery,
  type StoredRecord,
  type TypedOperationId,
  type TypedSchemaId,
} from "../runtime/index.ts";

const SCHEMA_PROBE = `SELECT name AS name, type AS type
FROM sqlite_schema
WHERE name IN ('meta', 'release_metadata')
ORDER BY name COLLATE BINARY;`;
const V3_VERSION_PROBE =
  "SELECT value AS value FROM meta WHERE key = ? LIMIT 2;";
const V4_VERSION_PROBE = `SELECT DISTINCT format AS format, contract AS contract
FROM release_metadata
ORDER BY format, contract
LIMIT 2;`;
const V3_SEARCH_SQL = `SELECT o.qualified_id AS qualified_id
FROM operations_fts
JOIN operations AS o ON o.rowid = operations_fts.rowid
WHERE operations_fts MATCH ?
  AND (? IS NULL OR o.api = ?)
ORDER BY bm25(operations_fts), o.qualified_id COLLATE BINARY
LIMIT ?;`;

export interface LegacyV3CatalogIdentity {
  readonly catalogId: CatalogId;
  readonly releaseId: ReleaseId;
}
export interface SqliteCatalogStoreOptions {
  readonly limits?: Partial<RuntimeLimits>;
  readonly legacyIdentity?: LegacyV3CatalogIdentity;
}
function unsupported(message: string): OpenApiMcpError {
  return new OpenApiMcpError("ARTIFACT_FORMAT_UNSUPPORTED", message);
}
function segment(value: unknown): string {
  try {
    if (typeof value !== "string") throw new Error();
    parseTypedRecordId(`operation:${value}:x`);
    return value;
  } catch {
    throw unsupported("Catalog identity is invalid");
  }
}

function snapshotLegacyIdentity(
  options: SqliteCatalogStoreOptions,
): LegacyV3CatalogIdentity | undefined {
  try {
    const legacyIdentity = Object.getOwnPropertyDescriptor(
      options,
      "legacyIdentity",
    );
    if (legacyIdentity === undefined) return undefined;
    if (!legacyIdentity.enumerable || !("value" in legacyIdentity))
      throw new Error();
    if (legacyIdentity.value === undefined) return undefined;
    const value = legacyIdentity.value;
    if (typeof value !== "object" || value === null || Array.isArray(value))
      throw new Error();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== null && prototype !== Object.prototype) throw new Error();
    if (Object.getOwnPropertySymbols(value).length !== 0) throw new Error();
    const keys = Object.getOwnPropertyNames(value).sort();
    if (keys.length !== 2 || keys[0] !== "catalogId" || keys[1] !== "releaseId")
      throw new Error();
    const catalogId = Object.getOwnPropertyDescriptor(value, "catalogId");
    const releaseId = Object.getOwnPropertyDescriptor(value, "releaseId");
    if (
      !catalogId?.enumerable ||
      !("value" in catalogId) ||
      !releaseId?.enumerable ||
      !("value" in releaseId)
    )
      throw new Error();
    return Object.freeze({
      catalogId: segment(catalogId.value) as CatalogId,
      releaseId: segment(releaseId.value) as ReleaseId,
    });
  } catch (error) {
    if (error instanceof OpenApiMcpError) throw error;
    throw unsupported("Catalog identity is invalid");
  }
}

function snapshotLegacySearchQuery(
  value: unknown,
  limits: RuntimeLimits,
): {
  readonly query: string;
  readonly api: string | null;
  readonly limit: number;
} {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value))
      throw new Error();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== null && prototype !== Object.prototype) throw new Error();
    if (Object.getOwnPropertySymbols(value).length !== 0) throw new Error();
    const api = Object.getOwnPropertyDescriptor(value, "api");
    const expected =
      api === undefined ? ["limit", "query"] : ["api", "limit", "query"];
    const keys = Object.getOwnPropertyNames(value).sort();
    if (
      keys.length !== expected.length ||
      keys.some((key, index) => key !== expected[index])
    )
      throw new Error();
    const query = Object.getOwnPropertyDescriptor(value, "query");
    const limit = Object.getOwnPropertyDescriptor(value, "limit");
    if (
      !query?.enumerable ||
      !("value" in query) ||
      !limit?.enumerable ||
      !("value" in limit) ||
      (api !== undefined && (!api.enumerable || !("value" in api)))
    )
      throw new Error();
    if (
      typeof query.value !== "string" ||
      query.value.length === 0 ||
      !Number.isSafeInteger(limit.value) ||
      limit.value < 1 ||
      limit.value > limits.maxSearchResults
    )
      throw new OpenApiMcpError("INPUT_INVALID", "Search input is invalid");
    let apiValue: string | null = null;
    if (api !== undefined && api.value !== undefined) {
      searchApi(api.value);
      apiValue = api.value as string;
    }
    return {
      query: query.value,
      api: apiValue,
      limit: limit.value,
    };
  } catch (error) {
    if (error instanceof OpenApiMcpError) throw error;
    throw new OpenApiMcpError("INPUT_INVALID", "Search input is invalid");
  }
}
function searchApi(value: unknown): void {
  try {
    if (typeof value !== "string") throw new Error();
    parseTypedRecordId(`operation:${value}:x`);
  } catch {
    throw new OpenApiMcpError("INPUT_INVALID", "Search API is invalid");
  }
}
function exactly(rows: unknown[], name: string): boolean {
  return (
    rows.length === 1 &&
    typeof rows[0] === "object" &&
    rows[0] !== null &&
    (rows[0] as Record<string, unknown>).name === name &&
    (rows[0] as Record<string, unknown>).type === "table"
  );
}

function isV4(rows: unknown[]): boolean {
  return (
    rows.length === 1 &&
    typeof rows[0] === "object" &&
    rows[0] !== null &&
    (rows[0] as Record<string, unknown>).format === 4 &&
    (rows[0] as Record<string, unknown>).contract === 1
  );
}

function forceCloseDatabase(database: DatabaseSync): void {
  const close = database.close as unknown as (
    this: DatabaseSync,
    force?: boolean,
  ) => void;
  close.call(database, true);
}

function bridge(database: DatabaseSync): D1CatalogDatabase {
  return {
    prepare(sql: string): D1CatalogPreparedStatement {
      const statement = database.prepare(sql);
      let values: readonly D1CatalogValue[] = [];
      return {
        bind(...next: readonly D1CatalogValue[]): D1CatalogPreparedStatement {
          values = next;
          return this;
        },
        async all<Row extends Record<string, unknown>>(): Promise<
          D1CatalogResult<Row>
        > {
          return { success: true, results: statement.all(...values) as Row[] };
        },
        async first<
          Row extends Record<string, unknown>,
        >(): Promise<Row | null> {
          return (statement.get(...values) as Row | undefined) ?? null;
        },
      };
    },
  };
}

/** Read-only v4 store with an explicit inventory-only v3 migration mode. */
export class SqliteCatalogStore implements CatalogStore {
  readonly legacyInventoryOnly: boolean;
  #database: DatabaseSync | undefined;
  #v4: CatalogStore | undefined;
  #legacyIdentity: LegacyV3CatalogIdentity | undefined;
  #limits: RuntimeLimits;

  constructor(path: string, options: SqliteCatalogStoreOptions = {}) {
    let database: DatabaseSync | undefined;
    try {
      this.#limits = resolveRuntimeLimits(options.limits);
      database = new DatabaseSync(path, { readOnly: true });
      const tables = database.prepare(SCHEMA_PROBE).all() as unknown[];
      if (exactly(tables, "release_metadata")) {
        const versions = database.prepare(V4_VERSION_PROBE).all() as unknown[];
        if (!isV4(versions)) throw unsupported("Artifact format unsupported");
        this.legacyInventoryOnly = false;
        this.#v4 = createD1CatalogStore(bridge(database), this.#limits);
      } else if (exactly(tables, "meta")) {
        const versions = database
          .prepare(V3_VERSION_PROBE)
          .all("format_version") as unknown[];
        if (
          versions.length !== 1 ||
          typeof versions[0] !== "object" ||
          versions[0] === null ||
          (versions[0] as Record<string, unknown>).value !== "3"
        )
          throw unsupported("Artifact format is unsupported");
        this.#legacyIdentity = snapshotLegacyIdentity(options);
        this.legacyInventoryOnly = true;
      } else throw unsupported("Artifact format is unsupported");
      this.#database = database;
    } catch (error) {
      if (database !== undefined) forceCloseDatabase(database);
      if (error instanceof OpenApiMcpError) throw error;
      throw unsupported("Artifact format is unsupported");
    }
  }
  close(): void {
    if (this.#database !== undefined) forceCloseDatabase(this.#database);
    this.#database = undefined;
  }
  #v4Store(): CatalogStore {
    if (!this.#database) throw unsupported("Catalog store is closed");
    if (!this.#v4) throw unsupported("v3 artifacts are inventory-only");
    return this.#v4;
  }
  async getManifest(
    catalog: CatalogId,
    release: ReleaseId,
  ): Promise<ManifestEnvelope> {
    return await this.#v4Store().getManifest(catalog, release);
  }
  async searchCandidates(query: SearchQuery) {
    if (!this.legacyInventoryOnly)
      return this.#v4Store().searchCandidates(query);
    if (!this.#database) throw unsupported("Catalog store is closed");
    const legacyIdentity = this.#legacyIdentity;
    if (!legacyIdentity)
      throw unsupported("v3 inventory requires an explicit catalog identity");
    const snapshot = snapshotLegacySearchQuery(query, this.#limits);
    try {
      const rows = this.#database
        .prepare(V3_SEARCH_SQL)
        .all(
          snapshot.query,
          snapshot.api,
          snapshot.api,
          snapshot.limit,
        ) as unknown[];
      if (rows.length > snapshot.limit) throw new Error();
      const seen = new Set<string>();
      return rows.map((row) => {
        const qualified =
          typeof row === "object" && row !== null
            ? (row as Record<string, unknown>).qualified_id
            : undefined;
        if (typeof qualified !== "string") throw new Error();
        const parsed = parseTypedRecordId(`operation:${qualified}`);
        if (!parsed.startsWith("operation:") || seen.has(parsed))
          throw new Error();
        seen.add(parsed);
        return {
          catalogId: legacyIdentity.catalogId,
          releaseId: legacyIdentity.releaseId,
          operationId: parsed as TypedOperationId,
        };
      });
    } catch (error) {
      if (error instanceof OpenApiMcpError) throw error;
      throw new OpenApiMcpError(
        "INPUT_INVALID",
        "Search expression is invalid",
      );
    }
  }
  async getOperation(
    catalog: CatalogId,
    release: ReleaseId,
    id: TypedOperationId,
  ): Promise<StoredRecord<OperationRecordV4> | null> {
    return await this.#v4Store().getOperation(catalog, release, id);
  }
  async getSchemas(
    catalog: CatalogId,
    release: ReleaseId,
    ids: readonly TypedSchemaId[],
  ): Promise<readonly StoredRecord<SchemaRecordV4>[]> {
    return await this.#v4Store().getSchemas(catalog, release, ids);
  }
}
