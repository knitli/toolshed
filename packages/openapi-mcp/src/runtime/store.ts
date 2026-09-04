import { OpenApiMcpError } from "./errors.ts";
import { parseTypedRecordId } from "./references.ts";
import { canonicalJson, parseJsonStrict } from "./strict-json.ts";
import type {
  CandidateRef,
  CatalogId,
  CatalogStore,
  ManifestEnvelope,
  OperationRecordV4,
  ReleaseId,
  SchemaRecordV4,
  SearchQuery,
  StoredRecord,
  TypedOperationId,
  TypedSchemaId,
} from "./types.ts";
import {
  MAX_SEARCH_QUERY_BYTES,
  type RuntimeLimits,
  resolveRuntimeLimits,
} from "./versions.ts";

const GET_MANIFEST_SQL = `SELECT manifest_json, signature_algorithm, signature_key_id, signature
FROM release_metadata
WHERE catalog_id = ? AND release_id = ? AND format = 4 AND contract = 1
LIMIT 2;`;

const SEARCH_CANDIDATES_SQL = `SELECT o.catalog_id AS catalog_id, o.release_id AS release_id,
       o.record_id AS record_id
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
LIMIT ?;`;

const GET_OPERATION_SQL = `SELECT o.record_id AS record_id, o.logical_digest AS logical_digest,
       o.record_json AS record_json
FROM operations AS o
JOIN release_metadata AS r
  ON r.catalog_id = o.catalog_id AND r.release_id = o.release_id
WHERE o.catalog_id = ? AND o.release_id = ? AND o.record_id = ?
  AND r.format = 4 AND r.contract = 1
LIMIT 2;`;

const GET_SCHEMAS_SQL = `WITH requested(record_id) AS (
  SELECT DISTINCT value FROM json_each(?) WHERE typeof(value) = 'text'
)
SELECT s.record_id AS record_id, s.logical_digest AS logical_digest,
       s.record_json AS record_json
FROM requested
JOIN schemas AS s ON s.record_id = requested.record_id
JOIN release_metadata AS r
  ON r.catalog_id = s.catalog_id AND r.release_id = s.release_id
WHERE s.catalog_id = ? AND s.release_id = ?
  AND r.format = 4 AND r.contract = 1
ORDER BY s.record_id COLLATE BINARY;`;

type Row = Record<string, unknown>;
type RowFailure = "MANIFEST_INVALID" | "RECORD_DIGEST_MISMATCH";
const digestPattern = /^[0-9a-f]{64}$/;

/** Stable, redacted public errors required of every CatalogStore adapter. */
export const CATALOG_STORE_PUBLIC_MESSAGES = Object.freeze({
  catalogIdentityInvalid: "Catalog identity is invalid",
  releaseIdentityInvalid: "Release identity is invalid",
  operationIdentityInvalid: "Operation identity is invalid",
  schemaIdentityInvalid: "Schema identity is invalid",
  storedCatalogIdentifierInvalid: "Stored catalog identifier is invalid",
  storedReleaseIdentifierInvalid: "Stored release identifier is invalid",
  storedOperationIdentifierInvalid: "Stored operation identifier is invalid",
  storedSchemaIdentifierInvalid: "Stored schema identifier is invalid",
  searchQueryInvalid: "Search query is invalid",
  searchLimitInvalid: "Search limit is invalid",
  searchExpressionInvalid: "Search expression is invalid",
  searchTransportTooManyRows: "Search transport returned too many rows",
  searchTransportOutsideRequestedApi:
    "Search transport returned an operation outside the requested API",
  searchTransportDuplicateRows: "Search transport returned duplicate rows",
  manifestTransportUnavailable: "Manifest transport is unavailable",
  manifestTransportAbsentOrAmbiguous:
    "Manifest transport row is absent or ambiguous",
  manifestTransportRowInvalid: "Manifest transport row is invalid",
  manifestTransportLimitExceeded: "Manifest transport row exceeds its limit",
  manifestSignatureMetadataInvalid: "Manifest signature metadata is invalid",
  manifestIdentityMismatch: "Manifest identity does not match request",
  recordTransportUnavailable: "Stored record transport is unavailable",
  recordTransportRowInvalid: "Stored record row is invalid",
  recordDigestInvalid: "Stored record digest is invalid",
  recordJsonInvalid: "Stored record JSON is invalid",
  operationRowAmbiguous: "Stored operation row is ambiguous",
  operationIdentifierMismatch:
    "Stored operation identifier does not match request",
  schemaRequestLimitExceeded: "Schema request exceeds its limit",
  schemaRequestInvalid: "Schema request is invalid",
  schemaTransportTooManyRows: "Stored schema transport returned too many rows",
  schemaRowsInvalid: "Stored schema rows are invalid",
  schemaRowsIncomplete: "Stored schema rows are incomplete",
});

export type D1CatalogValue = string | number | null;
export interface D1CatalogResult<RowType> {
  readonly success: boolean;
  readonly results: readonly RowType[];
  readonly error?: string;
}
export interface D1CatalogPreparedStatement {
  bind(...values: readonly D1CatalogValue[]): D1CatalogPreparedStatement;
  all<RowType extends Record<string, unknown>>(): Promise<
    D1CatalogResult<RowType>
  >;
  first<RowType extends Record<string, unknown>>(): Promise<RowType | null>;
}
export interface D1CatalogDatabase {
  prepare(sql: string): D1CatalogPreparedStatement;
}

function failure(code: RowFailure, message: string): OpenApiMcpError {
  return new OpenApiMcpError(code, message);
}

function input(message: string): OpenApiMcpError {
  return new OpenApiMcpError("INPUT_INVALID", message);
}

function plainRow(
  value: unknown,
  expected: readonly string[],
  code: RowFailure,
): Row {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value))
      throw new Error();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== null && prototype !== Object.prototype) throw new Error();
    if (Object.getOwnPropertySymbols(value).length !== 0) throw new Error();
    const keys = Object.getOwnPropertyNames(value).sort();
    const sortedExpected = [...expected].sort();
    if (
      keys.length !== sortedExpected.length ||
      keys.some((key, index) => key !== sortedExpected[index])
    )
      throw new Error();
    const snapshot = Object.create(null) as Row;
    for (const key of expected) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !("value" in descriptor))
        throw new Error();
      snapshot[key] = descriptor.value;
    }
    return snapshot;
  } catch {
    throw failure(
      code,
      code === "MANIFEST_INVALID"
        ? CATALOG_STORE_PUBLIC_MESSAGES.manifestTransportRowInvalid
        : CATALOG_STORE_PUBLIC_MESSAGES.recordTransportRowInvalid,
    );
  }
}

function stringField(row: Row, key: string, code: RowFailure): string {
  const value = row[key];
  if (typeof value !== "string")
    throw failure(
      code,
      code === "MANIFEST_INVALID"
        ? CATALOG_STORE_PUBLIC_MESSAGES.manifestTransportRowInvalid
        : CATALOG_STORE_PUBLIC_MESSAGES.recordTransportRowInvalid,
    );
  return value;
}

function catalogId(value: unknown): CatalogId {
  try {
    if (typeof value !== "string") throw new Error();
    return parseTypedRecordId(`operation:${value}:x`).slice(
      "operation:".length,
      -2,
    ) as CatalogId;
  } catch {
    throw input(CATALOG_STORE_PUBLIC_MESSAGES.catalogIdentityInvalid);
  }
}

function releaseId(value: unknown): ReleaseId {
  try {
    if (typeof value !== "string") throw new Error();
    return parseTypedRecordId(`operation:${value}:x`).slice(
      "operation:".length,
      -2,
    ) as ReleaseId;
  } catch {
    throw input(CATALOG_STORE_PUBLIC_MESSAGES.releaseIdentityInvalid);
  }
}

function storedCatalogId(value: string): CatalogId {
  try {
    return parseTypedRecordId(`operation:${value}:x`).slice(
      "operation:".length,
      -2,
    ) as CatalogId;
  } catch {
    throw failure(
      "RECORD_DIGEST_MISMATCH",
      CATALOG_STORE_PUBLIC_MESSAGES.storedCatalogIdentifierInvalid,
    );
  }
}

function storedReleaseId(value: string): ReleaseId {
  try {
    return parseTypedRecordId(`operation:${value}:x`).slice(
      "operation:".length,
      -2,
    ) as ReleaseId;
  } catch {
    throw failure(
      "RECORD_DIGEST_MISMATCH",
      CATALOG_STORE_PUBLIC_MESSAGES.storedReleaseIdentifierInvalid,
    );
  }
}

function operationId(value: string, code: RowFailure): TypedOperationId {
  try {
    const parsed = parseTypedRecordId(value);
    if (!parsed.startsWith("operation:")) throw new Error();
    return parsed as TypedOperationId;
  } catch {
    throw failure(
      code,
      CATALOG_STORE_PUBLIC_MESSAGES.storedOperationIdentifierInvalid,
    );
  }
}

function requestedOperationId(value: unknown): TypedOperationId {
  try {
    if (typeof value !== "string") throw new Error();
    const parsed = parseTypedRecordId(value);
    if (!parsed.startsWith("operation:")) throw new Error();
    return parsed as TypedOperationId;
  } catch {
    throw input(CATALOG_STORE_PUBLIC_MESSAGES.operationIdentityInvalid);
  }
}

function schemaId(value: string, code: RowFailure): TypedSchemaId {
  try {
    const parsed = parseTypedRecordId(value);
    if (!parsed.startsWith("schema:")) throw new Error();
    return parsed as TypedSchemaId;
  } catch {
    throw failure(
      code,
      CATALOG_STORE_PUBLIC_MESSAGES.storedSchemaIdentifierInvalid,
    );
  }
}

function requestedSchemaId(value: unknown): TypedSchemaId {
  try {
    if (typeof value !== "string") throw new Error();
    const parsed = parseTypedRecordId(value);
    if (!parsed.startsWith("schema:")) throw new Error();
    return parsed as TypedSchemaId;
  } catch {
    throw input(CATALOG_STORE_PUBLIC_MESSAGES.schemaIdentityInvalid);
  }
}

function requireManifestIdentity(
  manifestJson: string,
  catalog: CatalogId,
  release: ReleaseId,
  limits: RuntimeLimits,
): void {
  try {
    const manifest = parseJsonStrict(manifestJson, {
      maxBytes: limits.maxManifestBytes,
      maxDepth: limits.maxJsonDepth,
      maxKeys: limits.maxManifestRecords + 32,
    });
    if (
      typeof manifest !== "object" ||
      manifest === null ||
      Array.isArray(manifest)
    )
      throw new Error();
    const manifestCatalog = Object.getOwnPropertyDescriptor(
      manifest,
      "catalogId",
    );
    const manifestRelease = Object.getOwnPropertyDescriptor(
      manifest,
      "releaseId",
    );
    if (
      !manifestCatalog?.enumerable ||
      !("value" in manifestCatalog) ||
      manifestCatalog.value !== catalog ||
      !manifestRelease?.enumerable ||
      !("value" in manifestRelease) ||
      manifestRelease.value !== release
    )
      throw new Error();
  } catch {
    throw failure(
      "MANIFEST_INVALID",
      CATALOG_STORE_PUBLIC_MESSAGES.manifestIdentityMismatch,
    );
  }
}

function decodeManifest(
  rows: readonly unknown[],
  catalog: CatalogId,
  release: ReleaseId,
  limits: RuntimeLimits,
): ManifestEnvelope {
  if (rows.length !== 1)
    throw failure(
      "MANIFEST_INVALID",
      CATALOG_STORE_PUBLIC_MESSAGES.manifestTransportAbsentOrAmbiguous,
    );
  const row = plainRow(
    rows[0],
    ["manifest_json", "signature_algorithm", "signature_key_id", "signature"],
    "MANIFEST_INVALID",
  );
  const manifestJson = stringField(row, "manifest_json", "MANIFEST_INVALID");
  if (
    new TextEncoder().encode(manifestJson).byteLength > limits.maxManifestBytes
  )
    throw failure(
      "MANIFEST_INVALID",
      CATALOG_STORE_PUBLIC_MESSAGES.manifestTransportLimitExceeded,
    );
  const algorithm = stringField(row, "signature_algorithm", "MANIFEST_INVALID");
  const keyId = stringField(row, "signature_key_id", "MANIFEST_INVALID");
  const signature = stringField(row, "signature", "MANIFEST_INVALID");
  if (
    new TextEncoder().encode(
      `${manifestJson}\0${algorithm}\0${keyId}\0${signature}`,
    ).byteLength > limits.maxManifestBytes
  )
    throw failure(
      "MANIFEST_INVALID",
      CATALOG_STORE_PUBLIC_MESSAGES.manifestTransportLimitExceeded,
    );
  if (algorithm !== "Ed25519")
    throw failure(
      "MANIFEST_INVALID",
      CATALOG_STORE_PUBLIC_MESSAGES.manifestSignatureMetadataInvalid,
    );
  requireManifestIdentity(manifestJson, catalog, release, limits);
  return { manifestJson, signature: { algorithm, keyId, signature } };
}

function decodeRecord(
  rowValue: unknown,
  kind: "operation" | "schema",
  limits: RuntimeLimits,
): StoredRecord<OperationRecordV4 | SchemaRecordV4> {
  const row = plainRow(
    rowValue,
    ["record_id", "logical_digest", "record_json"],
    "RECORD_DIGEST_MISMATCH",
  );
  const idValue = stringField(row, "record_id", "RECORD_DIGEST_MISMATCH");
  const id =
    kind === "operation"
      ? operationId(idValue, "RECORD_DIGEST_MISMATCH")
      : schemaId(idValue, "RECORD_DIGEST_MISMATCH");
  const logicalDigest = stringField(
    row,
    "logical_digest",
    "RECORD_DIGEST_MISMATCH",
  );
  if (!digestPattern.test(logicalDigest))
    throw failure(
      "RECORD_DIGEST_MISMATCH",
      CATALOG_STORE_PUBLIC_MESSAGES.recordDigestInvalid,
    );
  const recordJson = stringField(row, "record_json", "RECORD_DIGEST_MISMATCH");
  try {
    const record = parseJsonStrict(recordJson, {
      maxBytes: limits.maxRecordBytes,
      maxDepth: limits.maxJsonDepth,
      maxKeys: limits.maxManifestRecords,
    });
    if (typeof record !== "object" || record === null || Array.isArray(record))
      throw new Error();
    const recordId = Object.getOwnPropertyDescriptor(record, "id");
    if (
      !recordId?.enumerable ||
      !("value" in recordId) ||
      typeof recordId.value !== "string" ||
      recordId.value !== id
    )
      throw new Error();
    if (kind === "operation")
      operationId(recordId.value, "RECORD_DIGEST_MISMATCH");
    else schemaId(recordId.value, "RECORD_DIGEST_MISMATCH");
    return {
      id,
      logicalDigest: logicalDigest as StoredRecord<
        OperationRecordV4 | SchemaRecordV4
      >["logicalDigest"],
      record: record as unknown as OperationRecordV4 | SchemaRecordV4,
    };
  } catch {
    throw failure(
      "RECORD_DIGEST_MISMATCH",
      CATALOG_STORE_PUBLIC_MESSAGES.recordJsonInvalid,
    );
  }
}

function snapshotSearchQuery(
  value: unknown,
  limits: RuntimeLimits,
): {
  readonly query: string;
  readonly api: CatalogId | null;
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
    const names = Object.getOwnPropertyNames(value).sort();
    if (
      names.length !== expected.length ||
      names.some((key, index) => key !== expected[index])
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
    if (typeof query.value !== "string" || query.value.length === 0)
      throw input(CATALOG_STORE_PUBLIC_MESSAGES.searchQueryInvalid);
    if (
      query.value.length > MAX_SEARCH_QUERY_BYTES ||
      new TextEncoder().encode(query.value).byteLength > MAX_SEARCH_QUERY_BYTES
    )
      throw input(CATALOG_STORE_PUBLIC_MESSAGES.searchQueryInvalid);
    if (
      !Number.isSafeInteger(limit.value) ||
      limit.value < 1 ||
      limit.value > limits.maxSearchResults
    )
      throw input(CATALOG_STORE_PUBLIC_MESSAGES.searchLimitInvalid);
    return {
      query: query.value,
      api:
        api === undefined || api.value === undefined
          ? null
          : catalogId(api.value),
      limit: limit.value,
    };
  } catch (error) {
    if (error instanceof OpenApiMcpError) throw error;
    throw input(CATALOG_STORE_PUBLIC_MESSAGES.searchQueryInvalid);
  }
}

function snapshotSchemaIds(
  value: unknown,
  limits: RuntimeLimits,
): readonly TypedSchemaId[] {
  try {
    if (
      !Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Array.prototype
    )
      throw new Error();
    if (Object.getOwnPropertySymbols(value).length !== 0) throw new Error();
    const length = Object.getOwnPropertyDescriptor(value, "length");
    if (
      length === undefined ||
      !("value" in length) ||
      !Number.isSafeInteger(length.value) ||
      length.value < 0
    )
      throw new Error();
    if (length.value > limits.maxManifestRecords)
      throw input(CATALOG_STORE_PUBLIC_MESSAGES.schemaRequestLimitExceeded);
    const names = Object.getOwnPropertyNames(value);
    if (names.length !== length.value + 1 || !names.includes("length"))
      throw new Error();
    const ids: TypedSchemaId[] = [];
    for (let index = 0; index < length.value; index += 1) {
      const id = Object.getOwnPropertyDescriptor(value, String(index));
      if (!id?.enumerable || !("value" in id)) throw new Error();
      ids.push(requestedSchemaId(id.value));
    }
    return ids;
  } catch (error) {
    if (error instanceof OpenApiMcpError) throw error;
    throw input(CATALOG_STORE_PUBLIC_MESSAGES.schemaRequestInvalid);
  }
}

async function d1All(
  database: D1CatalogDatabase,
  sql: string,
  values: readonly D1CatalogValue[],
  errorCode: RowFailure | "INPUT_INVALID",
): Promise<readonly unknown[]> {
  try {
    const result = await database
      .prepare(sql)
      .bind(...values)
      .all<Row>();
    if (!result.success || !Array.isArray(result.results)) {
      if (errorCode === "INPUT_INVALID")
        throw input(CATALOG_STORE_PUBLIC_MESSAGES.searchExpressionInvalid);
      throw failure(
        errorCode,
        errorCode === "MANIFEST_INVALID"
          ? CATALOG_STORE_PUBLIC_MESSAGES.manifestTransportUnavailable
          : CATALOG_STORE_PUBLIC_MESSAGES.recordTransportUnavailable,
      );
    }
    return [...result.results];
  } catch (error) {
    if (error instanceof OpenApiMcpError) throw error;
    if (errorCode === "INPUT_INVALID")
      throw input(CATALOG_STORE_PUBLIC_MESSAGES.searchExpressionInvalid);
    throw failure(
      errorCode,
      errorCode === "MANIFEST_INVALID"
        ? CATALOG_STORE_PUBLIC_MESSAGES.manifestTransportUnavailable
        : CATALOG_STORE_PUBLIC_MESSAGES.recordTransportUnavailable,
    );
  }
}

class D1CatalogStore implements CatalogStore {
  constructor(
    private readonly database: D1CatalogDatabase,
    private readonly limits: RuntimeLimits,
  ) {}

  async getManifest(
    catalog: CatalogId,
    release: ReleaseId,
  ): Promise<ManifestEnvelope> {
    const catalogIdValue = catalogId(catalog);
    const releaseIdValue = releaseId(release);
    return decodeManifest(
      await d1All(
        this.database,
        GET_MANIFEST_SQL,
        [catalogIdValue, releaseIdValue],
        "MANIFEST_INVALID",
      ),
      catalogIdValue,
      releaseIdValue,
      this.limits,
    );
  }

  async searchCandidates(query: SearchQuery): Promise<readonly CandidateRef[]> {
    const snapshot = snapshotSearchQuery(query, this.limits);
    const rows = await d1All(
      this.database,
      SEARCH_CANDIDATES_SQL,
      [snapshot.query, snapshot.api, snapshot.api, snapshot.limit],
      "INPUT_INVALID",
    );
    if (rows.length > snapshot.limit)
      throw failure(
        "RECORD_DIGEST_MISMATCH",
        CATALOG_STORE_PUBLIC_MESSAGES.searchTransportTooManyRows,
      );
    const seen = new Set<string>();
    return rows.map((value) => {
      const row = plainRow(
        value,
        ["catalog_id", "release_id", "record_id"],
        "RECORD_DIGEST_MISMATCH",
      );
      const catalogIdValue = storedCatalogId(
        stringField(row, "catalog_id", "RECORD_DIGEST_MISMATCH"),
      );
      const releaseIdValue = storedReleaseId(
        stringField(row, "release_id", "RECORD_DIGEST_MISMATCH"),
      );
      const operationIdValue = operationId(
        stringField(row, "record_id", "RECORD_DIGEST_MISMATCH"),
        "RECORD_DIGEST_MISMATCH",
      );
      if (
        snapshot.api !== null &&
        !operationIdValue.startsWith(`operation:${snapshot.api}:`)
      )
        throw failure(
          "RECORD_DIGEST_MISMATCH",
          CATALOG_STORE_PUBLIC_MESSAGES.searchTransportOutsideRequestedApi,
        );
      const key = `${catalogIdValue}\u0000${releaseIdValue}\u0000${operationIdValue}`;
      if (seen.has(key))
        throw failure(
          "RECORD_DIGEST_MISMATCH",
          CATALOG_STORE_PUBLIC_MESSAGES.searchTransportDuplicateRows,
        );
      seen.add(key);
      return {
        catalogId: catalogIdValue,
        releaseId: releaseIdValue,
        operationId: operationIdValue,
      };
    });
  }

  async getOperation(
    catalog: CatalogId,
    release: ReleaseId,
    id: TypedOperationId,
  ): Promise<StoredRecord<OperationRecordV4> | null> {
    const requested = requestedOperationId(id);
    const rows = await d1All(
      this.database,
      GET_OPERATION_SQL,
      [catalogId(catalog), releaseId(release), requested],
      "RECORD_DIGEST_MISMATCH",
    );
    if (rows.length === 0) return null;
    if (rows.length !== 1)
      throw failure(
        "RECORD_DIGEST_MISMATCH",
        CATALOG_STORE_PUBLIC_MESSAGES.operationRowAmbiguous,
      );
    const row = decodeRecord(rows[0], "operation", this.limits);
    if (row.id !== requested)
      throw failure(
        "RECORD_DIGEST_MISMATCH",
        CATALOG_STORE_PUBLIC_MESSAGES.operationIdentifierMismatch,
      );
    return row as StoredRecord<OperationRecordV4>;
  }

  async getSchemas(
    catalog: CatalogId,
    release: ReleaseId,
    ids: readonly TypedSchemaId[],
  ): Promise<readonly StoredRecord<SchemaRecordV4>[]> {
    const catalogIdValue = catalogId(catalog);
    const releaseIdValue = releaseId(release);
    const schemaIds = snapshotSchemaIds(ids, this.limits);
    if (schemaIds.length === 0) return [];
    const requested = new Set<string>();
    for (const id of schemaIds) requested.add(id);
    const requestedIds = [...requested].sort();
    const requestJson = canonicalJson(requestedIds);
    const rows = await d1All(
      this.database,
      GET_SCHEMAS_SQL,
      [requestJson, catalogIdValue, releaseIdValue],
      "RECORD_DIGEST_MISMATCH",
    );
    if (rows.length > requested.size)
      throw failure(
        "RECORD_DIGEST_MISMATCH",
        CATALOG_STORE_PUBLIC_MESSAGES.schemaTransportTooManyRows,
      );
    if (rows.length < requested.size)
      throw failure(
        "RECORD_DIGEST_MISMATCH",
        CATALOG_STORE_PUBLIC_MESSAGES.schemaRowsIncomplete,
      );
    const records: StoredRecord<SchemaRecordV4>[] = [];
    let previous = "";
    for (const value of rows) {
      const row = decodeRecord(value, "schema", this.limits);
      if (!requested.has(row.id) || row.id <= previous)
        throw failure(
          "RECORD_DIGEST_MISMATCH",
          CATALOG_STORE_PUBLIC_MESSAGES.schemaRowsInvalid,
        );
      previous = row.id;
      records.push(row as StoredRecord<SchemaRecordV4>);
    }
    return records;
  }
}

/** Construct the Worker-safe D1 implementation using only fixed SQL statements. */
export function createD1CatalogStore(
  binding: D1CatalogDatabase,
  limits?: Partial<RuntimeLimits>,
): CatalogStore {
  return new D1CatalogStore(binding, resolveRuntimeLimits(limits));
}
