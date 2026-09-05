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
import { MAX_SEARCH_QUERY_BYTES } from "../runtime/versions.ts";

const SCHEMA_PROBE = `SELECT CASE
  WHEN typeof(name) = 'text' AND name IN ('meta', 'release_metadata') THEN name
  ELSE NULL
END AS name,
CASE
  WHEN typeof(type) = 'text' AND type = 'table' THEN type
  ELSE NULL
END AS type
FROM sqlite_schema
WHERE name IN ('meta', 'release_metadata')
ORDER BY name COLLATE BINARY
LIMIT 3;`;
const V3_VERSION_PROBE = `SELECT CASE
  WHEN typeof(value) = 'text' AND length(CAST(value AS BLOB)) <= 1 THEN value
  ELSE NULL
END AS value
FROM meta
WHERE key = ?
LIMIT 2;`;
const V4_VERSION_PROBE = `SELECT DISTINCT
CASE
  WHEN typeof(format) = 'integer' AND length(CAST(format AS BLOB)) <= 1 THEN format
  ELSE NULL
END AS format,
CASE
  WHEN typeof(contract) = 'integer' AND length(CAST(contract AS BLOB)) <= 1 THEN contract
  ELSE NULL
END AS contract
FROM release_metadata
ORDER BY format, contract
LIMIT 3;`;
const V3_SEARCH_SQL = `SELECT CASE
  WHEN typeof(o.qualified_id) = 'text'
    AND length(CAST(o.qualified_id AS BLOB)) <= ?
  THEN o.qualified_id
  ELSE NULL
END AS qualified_id
FROM operations_fts
JOIN operations AS o ON o.rowid = operations_fts.rowid
WHERE operations_fts MATCH ?
  AND (? IS NULL OR o.api = ?)
ORDER BY bm25(operations_fts), o.qualified_id COLLATE BINARY
LIMIT ?;`;
const legacyQualifiedIdBytes = 641;

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
    const queryValue = query.value;
    if (
      typeof queryValue !== "string" ||
      queryValue.length > MAX_SEARCH_QUERY_BYTES ||
      new TextEncoder().encode(queryValue).byteLength >
        MAX_SEARCH_QUERY_BYTES ||
      queryValue.length === 0 ||
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
      query: queryValue,
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

function snapshotSqliteRuntimeLimits(
  options: SqliteCatalogStoreOptions,
): RuntimeLimits {
  let overrides: Partial<RuntimeLimits> | undefined;
  try {
    if (
      typeof options !== "object" ||
      options === null ||
      Array.isArray(options)
    )
      throw new Error();
    const limits = Object.getOwnPropertyDescriptor(options, "limits");
    if (limits !== undefined) {
      if (!limits.enumerable || !("value" in limits)) throw new Error();
      overrides = limits.value as Partial<RuntimeLimits> | undefined;
    }
  } catch {
    throw new RangeError(
      "Runtime limits overrides must be an exact plain data object",
    );
  }
  return resolveRuntimeLimits(overrides);
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

function isExecutableArtifact(rows: unknown[]): boolean {
  return (
    rows.length > 0 &&
    rows.length <= 2 &&
    rows.every(
      (row) =>
        typeof row === "object" &&
        row !== null &&
        ((row as Record<string, unknown>).format === 4 ||
          (row as Record<string, unknown>).format === 5) &&
        (row as Record<string, unknown>).contract === 1,
    )
  );
}

interface SqliteStatement {
  all(...values: readonly unknown[]): unknown[];
  get(...values: readonly unknown[]): unknown;
  finalize?: () => void;
}

interface SqliteDatabase {
  prepare(sql: string): SqliteStatement;
  close(strict?: boolean): void;
}

interface BunSqliteModule {
  Database: new (path: string, options: { readonly: true }) => SqliteDatabase;
}

function bunSqlite(): BunSqliteModule | undefined {
  return process.getBuiltinModule?.("bun:sqlite") as
    | BunSqliteModule
    | undefined;
}

function openReadOnlyDatabase(path: string): SqliteDatabase {
  const module = bunSqlite();
  if (module !== undefined)
    return new module.Database(path, { readonly: true });
  return new DatabaseSync(path, { readOnly: true });
}

function all(
  database: SqliteDatabase,
  sql: string,
  values: readonly unknown[] = [],
): unknown[] {
  const statement = database.prepare(sql);
  try {
    return statement.all(...values);
  } finally {
    statement.finalize?.();
  }
}

function first(
  database: SqliteDatabase,
  sql: string,
  values: readonly unknown[],
): unknown {
  const statement = database.prepare(sql);
  try {
    return statement.get(...values);
  } finally {
    statement.finalize?.();
  }
}

function closeDatabase(database: SqliteDatabase): void {
  database.close(true);
}

function bridge(database: SqliteDatabase): D1CatalogDatabase {
  return {
    prepare(sql: string): D1CatalogPreparedStatement {
      let values: readonly D1CatalogValue[] = [];
      return {
        bind(...next: readonly D1CatalogValue[]): D1CatalogPreparedStatement {
          values = next;
          return this;
        },
        async all<Row extends Record<string, unknown>>(): Promise<
          D1CatalogResult<Row>
        > {
          return {
            success: true,
            results: all(database, sql, values) as Row[],
          };
        },
        async first<
          Row extends Record<string, unknown>,
        >(): Promise<Row | null> {
          return (first(database, sql, values) as Row | undefined) ?? null;
        },
      };
    },
  };
}

/** Read-only v4/v5 store with an explicit inventory-only v3 migration mode. */
export class SqliteCatalogStore implements CatalogStore {
  readonly legacyInventoryOnly: boolean;
  #database: SqliteDatabase | undefined;
  #v4: CatalogStore | undefined;
  #legacyIdentity: LegacyV3CatalogIdentity | undefined;
  #limits: RuntimeLimits;

  constructor(path: string, options: SqliteCatalogStoreOptions = {}) {
    this.#limits = snapshotSqliteRuntimeLimits(options);
    let database: SqliteDatabase | undefined;
    try {
      database = openReadOnlyDatabase(path);
      const tables = all(database, SCHEMA_PROBE);
      if (exactly(tables, "release_metadata")) {
        const versions = all(database, V4_VERSION_PROBE);
        if (!isExecutableArtifact(versions))
          throw unsupported("Artifact format unsupported");
        this.legacyInventoryOnly = false;
        this.#v4 = createD1CatalogStore(bridge(database), this.#limits);
      } else if (exactly(tables, "meta")) {
        const versions = all(database, V3_VERSION_PROBE, ["format_version"]);
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
      if (database !== undefined) closeDatabase(database);
      if (error instanceof OpenApiMcpError) throw error;
      throw unsupported("Artifact format is unsupported");
    }
  }
  close(): void {
    if (this.#database !== undefined) closeDatabase(this.#database);
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
      const rows = all(this.#database, V3_SEARCH_SQL, [
        legacyQualifiedIdBytes,
        snapshot.query,
        snapshot.api,
        snapshot.api,
        snapshot.limit,
      ]);
      if (rows.length > snapshot.limit) throw new Error();
      const seen = new Set<string>();
      return rows.map((row) => {
        const qualified =
          typeof row === "object" && row !== null
            ? (row as Record<string, unknown>).qualified_id
            : undefined;
        if (typeof qualified !== "string") throw new Error();
        if (snapshot.api !== null && !qualified.startsWith(`${snapshot.api}:`))
          throw new Error();
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
