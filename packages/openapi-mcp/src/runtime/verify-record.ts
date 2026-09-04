import { sha256 } from "./digest.ts";
import { OpenApiMcpError } from "./errors.ts";
import type { AdmittedManifest } from "./manifest.ts";
import { parseTypedRecordId } from "./references.ts";
import { canonicalJsonBounded, parseJsonStrict } from "./strict-json.ts";
import type {
  JsonObject,
  OperationRecordV4,
  SchemaRecordV4,
  StoredRecord,
  TypedRecordId,
} from "./types.ts";
import { DEFAULT_RUNTIME_LIMITS, type RuntimeLimits } from "./versions.ts";

const operationKeys = [
  "advisory",
  "api",
  "deprecated",
  "id",
  "method",
  "operationId",
  "origin",
  "parameters",
  "path",
  "requestBody",
  "schemaIds",
  "summary",
];
const schemaKeys = ["id", "schema"];
const wrapperKeys = ["id", "logicalDigest", "record"];
const digestPattern = /^[0-9a-f]{64}$/;

function mismatch(message: string): OpenApiMcpError {
  return new OpenApiMcpError("RECORD_DIGEST_MISMATCH", message);
}

function exactObject(
  value: unknown,
  keys: readonly string[],
  label: string,
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw mismatch(`${label} is not an object`);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype)
    throw mismatch(`${label} prototype is invalid`);
  const actual = Reflect.ownKeys(value);
  if (actual.some((key) => typeof key !== "string"))
    throw mismatch(`${label} has a symbol property`);
  const sorted = (actual as string[]).sort();
  const expected = [...keys].sort();
  if (
    sorted.length !== expected.length ||
    sorted.some((key, index) => key !== expected[index])
  )
    throw mismatch(`${label} shape is invalid`);
  for (const key of sorted) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable
    )
      throw mismatch(`${label} properties must be own data`);
  }
  return value as Record<string, unknown>;
}

interface ExtractedStoredRecord {
  id: unknown;
  logicalDigest: unknown;
  record: unknown;
}

function extractStoredRecord(value: unknown): ExtractedStoredRecord {
  try {
    const object = exactObject(value, wrapperKeys, "stored row");
    const id = Object.getOwnPropertyDescriptor(object, "id");
    const logicalDigest = Object.getOwnPropertyDescriptor(
      object,
      "logicalDigest",
    );
    const record = Object.getOwnPropertyDescriptor(object, "record");
    if (
      id === undefined ||
      !("value" in id) ||
      logicalDigest === undefined ||
      !("value" in logicalDigest) ||
      record === undefined ||
      !("value" in record)
    )
      throw mismatch("Stored row properties must be own data");
    return {
      id: id.value,
      logicalDigest: logicalDigest.value,
      record: record.value,
    };
  } catch (error) {
    if (
      error instanceof OpenApiMcpError &&
      error.code === "RECORD_DIGEST_MISMATCH"
    )
      throw error;
    throw mismatch("Stored row wrapper cannot be inspected");
  }
}

function validateRecord(
  record: unknown,
  wrapperId: unknown,
): OperationRecordV4 | SchemaRecordV4 {
  let id: TypedRecordId;
  try {
    if (typeof wrapperId !== "string") throw new Error();
    id = parseTypedRecordId(wrapperId);
  } catch {
    throw mismatch("Stored row ID is malformed");
  }
  const object = exactObject(
    record,
    id.startsWith("operation:") ? operationKeys : schemaKeys,
    "logical record",
  );
  if (object.id !== id)
    throw mismatch("Stored row and logical record IDs disagree");
  if (id.startsWith("operation:")) {
    if (
      typeof object.api !== "string" ||
      typeof object.operationId !== "string" ||
      ![
        "GET",
        "HEAD",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "TRACE",
      ].includes(object.method as string) ||
      typeof object.path !== "string" ||
      typeof object.origin !== "string" ||
      !(object.summary === null || typeof object.summary === "string") ||
      typeof object.deprecated !== "boolean" ||
      !Array.isArray(object.parameters) ||
      !(
        object.requestBody === null ||
        (typeof object.requestBody === "object" &&
          !Array.isArray(object.requestBody))
      ) ||
      !Array.isArray(object.schemaIds) ||
      !(
        typeof object.advisory === "object" &&
        object.advisory !== null &&
        !Array.isArray(object.advisory)
      )
    )
      throw mismatch("Operation record fields are invalid");
    if (`operation:${object.api}:${object.operationId}` !== id) {
      throw mismatch(
        "Operation record ID does not match its API and operation ID",
      );
    }
    for (const schemaId of object.schemaIds) {
      try {
        if (
          typeof schemaId !== "string" ||
          !parseTypedRecordId(schemaId).startsWith("schema:")
        )
          throw new Error();
      } catch {
        throw mismatch("Operation schema ID is invalid");
      }
    }
  } else if (
    !(
      typeof object.schema === "object" &&
      object.schema !== null &&
      !Array.isArray(object.schema)
    )
  ) {
    throw mismatch("Schema record is invalid");
  }
  return object as unknown as OperationRecordV4 | SchemaRecordV4;
}

function detached(record: unknown, limits: RuntimeLimits): unknown {
  let json: string;
  try {
    json = canonicalJsonBounded(record as unknown as JsonObject, {
      maxBytes: limits.maxRecordBytes,
      maxDepth: limits.maxJsonDepth,
      maxNodes: Math.max(1, limits.maxRecordBytes),
    });
  } catch {
    throw mismatch("Logical record cannot be bounded and canonicalized");
  }
  return parseJsonStrict(json, {
    maxBytes: limits.maxRecordBytes,
    maxDepth: limits.maxJsonDepth,
    maxKeys: limits.maxManifestRecords,
  });
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value))
    return value;
  for (const key of Reflect.ownKeys(value))
    deepFreeze((value as Record<PropertyKey, unknown>)[key]);
  return Object.freeze(value);
}

/** Reconstruct, hash, admit, detach, and freeze one untrusted store row. */
export async function verifyStoredRecord<
  T extends OperationRecordV4 | SchemaRecordV4,
>(
  admitted: AdmittedManifest,
  rowValue: StoredRecord<T>,
  limitOverrides: RuntimeLimits = DEFAULT_RUNTIME_LIMITS,
): Promise<Readonly<T>> {
  const limits = {
    ...DEFAULT_RUNTIME_LIMITS,
    ...limitOverrides,
  } as RuntimeLimits;
  const row = extractStoredRecord(rowValue);
  let wrapperId: TypedRecordId;
  try {
    if (typeof row.id !== "string") throw new Error();
    wrapperId = parseTypedRecordId(row.id);
  } catch {
    throw mismatch("Stored row ID is malformed");
  }
  if (!Object.hasOwn(admitted.manifest.records, wrapperId)) {
    throw new OpenApiMcpError(
      "RECORD_NOT_ADMITTED",
      "Logical record is absent from the admitted manifest",
    );
  }
  if (
    typeof row.logicalDigest !== "string" ||
    !digestPattern.test(row.logicalDigest)
  )
    throw mismatch("Stored row digest is invalid");
  let copy: T;
  try {
    copy = validateRecord(detached(row.record, limits), wrapperId) as T;
  } catch (error) {
    if (
      error instanceof OpenApiMcpError &&
      error.code === "RECORD_DIGEST_MISMATCH"
    )
      throw error;
    throw mismatch("Logical record cannot be canonicalized");
  }
  const domain = copy.id.startsWith("operation:")
    ? "knitli.openapi-mcp.operation-record.v4"
    : "knitli.openapi-mcp.schema-record.v4";
  const digest = await sha256(domain, copy as unknown as JsonObject);
  if (digest !== row.logicalDigest)
    throw mismatch("Stored logical digest does not match the row");
  if (admitted.manifest.records[copy.id] !== digest) {
    throw mismatch(
      "Logical record digest does not match the admitted manifest",
    );
  }
  if (copy.id.startsWith("operation:")) {
    const operation = copy as OperationRecordV4;
    let origin: URL;
    try {
      origin = new URL(operation.origin);
    } catch {
      throw mismatch("Operation origin is invalid");
    }
    if (
      origin.protocol !== "https:" ||
      origin.username !== "" ||
      origin.password !== "" ||
      origin.pathname !== "/" ||
      origin.search !== "" ||
      origin.hash !== "" ||
      origin.origin !== operation.origin ||
      !admitted.manifest.allowedOrigins.includes(operation.origin)
    )
      throw mismatch("Operation origin is not admitted by the manifest");
  }
  return deepFreeze(copy);
}
