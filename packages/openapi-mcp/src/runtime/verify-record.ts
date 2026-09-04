import { sha256 } from "./digest.ts";
import { OpenApiMcpError } from "./errors.ts";
import type { AdmittedManifest } from "./manifest.ts";
import { parseTypedRecordId } from "./references.ts";
import { schemaChildKind } from "./schema-keywords.ts";
import { canonicalJsonBounded, parseJsonStrict } from "./strict-json.ts";
import type {
  JsonObject,
  OperationRecordV4,
  SchemaRecordV4,
  StoredRecord,
  TypedRecordId,
} from "./types.ts";
import { type RuntimeLimits, resolveRuntimeLimits } from "./versions.ts";

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
const parameterKeys = [
  "allowReserved",
  "deprecated",
  "explode",
  "in",
  "name",
  "required",
  "style",
  "value",
];
const schemaUseSchemaKeys = ["kind", "schemaId"];
const schemaUseContentKeys = ["kind", "mediaType", "schemaId"];
const requestBodyKeys = ["content", "required"];
const requestBodyMediaKeys = ["encoding", "mediaType", "schemaId"];
const encodingKeys = [
  "allowReserved",
  "contentType",
  "explode",
  "headers",
  "property",
  "style",
];
const encodingHeaderKeys = ["name", "required", "value"];
const digestPattern = /^[0-9a-f]{64}$/;
const mediaTypePattern = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/;
const headerPattern = /^[a-z0-9!#$%&'*+.^_`|~-]+$/;
const locations = ["path", "query", "header", "cookie"];
const styles = [
  "matrix",
  "label",
  "form",
  "simple",
  "spaceDelimited",
  "pipeDelimited",
  "deepObject",
];

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

function schemaId(value: unknown, label: string): string {
  try {
    if (
      typeof value !== "string" ||
      !parseTypedRecordId(value).startsWith("schema:")
    )
      throw new Error();
    return value;
  } catch {
    throw mismatch(`${label} is not a typed schema ID`);
  }
}

function sortedUnique(values: readonly string[], label: string): void {
  for (let index = 1; index < values.length; index += 1) {
    if (values[index - 1] >= values[index])
      throw mismatch(`${label} must be sorted and unique`);
  }
}

function validateSchemaUse(value: unknown, label: string): string {
  const candidate = exactObject(
    value,
    (value as { kind?: unknown })?.kind === "content"
      ? schemaUseContentKeys
      : schemaUseSchemaKeys,
    label,
  );
  if (candidate.kind !== "schema" && candidate.kind !== "content")
    throw mismatch(`${label} discriminant is invalid`);
  if (
    candidate.kind === "content" &&
    (typeof candidate.mediaType !== "string" ||
      !mediaTypePattern.test(candidate.mediaType))
  ) {
    throw mismatch(`${label} media type is invalid`);
  }
  return schemaId(candidate.schemaId, `${label} schema ID`);
}

interface ValidatedParameters {
  readonly schemaIds: string[];
  readonly pathNames: string[];
}

function validateParameters(value: unknown): ValidatedParameters {
  if (!Array.isArray(value)) throw mismatch("Operation parameters are invalid");
  const schemaIds: string[] = [];
  const pathNames: string[] = [];
  let previousLocation = -1;
  let previousName = "";
  for (const [index, raw] of value.entries()) {
    const parameter = exactObject(raw, parameterKeys, `parameter ${index}`);
    if (
      typeof parameter.name !== "string" ||
      parameter.name.length === 0 ||
      typeof parameter.in !== "string" ||
      !locations.includes(parameter.in) ||
      typeof parameter.required !== "boolean" ||
      typeof parameter.deprecated !== "boolean" ||
      typeof parameter.style !== "string" ||
      !styles.includes(parameter.style) ||
      typeof parameter.explode !== "boolean" ||
      typeof parameter.allowReserved !== "boolean"
    )
      throw mismatch(`parameter ${index} fields are invalid`);
    if (parameter.in === "path" && parameter.required !== true)
      throw mismatch("Path parameters must be required");
    if (parameter.in === "path") pathNames.push(parameter.name);
    const location = locations.indexOf(parameter.in);
    if (
      location < previousLocation ||
      (location === previousLocation && parameter.name <= previousName)
    )
      throw mismatch("Operation parameters must be sorted and unique");
    previousLocation = location;
    previousName = parameter.name;
    schemaIds.push(
      validateSchemaUse(parameter.value, `parameter ${index} value`),
    );
  }
  return { schemaIds, pathNames };
}

export function parseOperationPathTemplateV4(path: string): readonly string[] {
  if (
    !path.startsWith("/") ||
    path.startsWith("//") ||
    !/^[\x21-\x7e]+$/.test(path) ||
    path.includes("\\") ||
    path.includes("?") ||
    path.includes("#")
  )
    throw new Error("operation path must be a root-relative request target");
  const matches = [...path.matchAll(/\{([^{}]+)\}/g)];
  const withoutValidTemplates = path.replace(/\{([^{}]+)\}/g, "");
  if (
    withoutValidTemplates.includes("{") ||
    withoutValidTemplates.includes("}")
  ) {
    throw new Error("operation path template is malformed");
  }
  const variables = matches.map((match) => match[1] as string);
  if (new Set(variables).size !== variables.length) {
    throw new Error("operation path template variables must be unique");
  }
  const comparablePath = path.replace(/\{([^{}]+)\}/g, "openapi-template");
  const normalized = new URL(comparablePath, "https://openapi.invalid");
  if (
    normalized.origin !== "https://openapi.invalid" ||
    normalized.pathname !== comparablePath ||
    normalized.search !== "" ||
    normalized.hash !== ""
  )
    throw new Error("operation path must be normalized");
  return variables;
}

function validatePathTemplate(
  path: string,
  pathNames: readonly string[],
): void {
  let variables: readonly string[];
  try {
    variables = parseOperationPathTemplateV4(path);
  } catch {
    throw mismatch("Operation path template is invalid");
  }
  const sortedVariables = [...variables].sort();
  const sortedPathNames = [...pathNames].sort();
  if (
    sortedVariables.length !== sortedPathNames.length ||
    sortedVariables.some((name, index) => name !== sortedPathNames[index])
  ) {
    throw mismatch(
      "Operation path parameters must exactly match path-template variables",
    );
  }
}

function validateRequestBody(value: unknown): string[] {
  if (value === null) return [];
  const body = exactObject(value, requestBodyKeys, "request body");
  if (
    typeof body.required !== "boolean" ||
    !Array.isArray(body.content) ||
    body.content.length === 0
  )
    throw mismatch("Request body fields are invalid");
  const schemaIds: string[] = [];
  let previousMedia = "";
  for (const [mediaIndex, rawMedia] of body.content.entries()) {
    const media = exactObject(
      rawMedia,
      requestBodyMediaKeys,
      `request body media ${mediaIndex}`,
    );
    if (
      typeof media.mediaType !== "string" ||
      !mediaTypePattern.test(media.mediaType) ||
      media.mediaType <= previousMedia ||
      !Array.isArray(media.encoding)
    ) {
      throw mismatch("Request body media entries are invalid or unsorted");
    }
    previousMedia = media.mediaType;
    schemaIds.push(schemaId(media.schemaId, "request body schema ID"));
    let previousProperty = "";
    for (const [encodingIndex, rawEncoding] of media.encoding.entries()) {
      const encoding = exactObject(
        rawEncoding,
        encodingKeys,
        `encoding ${encodingIndex}`,
      );
      if (
        typeof encoding.property !== "string" ||
        encoding.property.length === 0 ||
        encoding.property <= previousProperty ||
        !(
          encoding.contentType === null ||
          (typeof encoding.contentType === "string" &&
            mediaTypePattern.test(encoding.contentType))
        ) ||
        !(
          encoding.style === null ||
          (typeof encoding.style === "string" &&
            styles.includes(encoding.style))
        ) ||
        !(encoding.explode === null || typeof encoding.explode === "boolean") ||
        typeof encoding.allowReserved !== "boolean" ||
        !Array.isArray(encoding.headers)
      )
        throw mismatch("Request body encoding fields are invalid or unsorted");
      previousProperty = encoding.property;
      let previousHeader = "";
      for (const [headerIndex, rawHeader] of encoding.headers.entries()) {
        const header = exactObject(
          rawHeader,
          encodingHeaderKeys,
          `encoding header ${headerIndex}`,
        );
        if (
          typeof header.name !== "string" ||
          !headerPattern.test(header.name) ||
          header.name <= previousHeader ||
          typeof header.required !== "boolean"
        ) {
          throw mismatch("Encoding headers are invalid or unsorted");
        }
        previousHeader = header.name;
        schemaIds.push(
          validateSchemaUse(
            header.value,
            `encoding header ${headerIndex} value`,
          ),
        );
      }
    }
  }
  return schemaIds;
}

function validateSchemaReferences(value: unknown): void {
  if (typeof value === "boolean") return;
  const stack: Array<{ readonly label: string; readonly value: unknown }> = [
    { label: "schema", value },
  ];
  const pushSubschema = (child: unknown, label: string): void => {
    if (typeof child === "boolean") return;
    if (typeof child !== "object" || child === null || Array.isArray(child))
      throw mismatch(`${label} must be a boolean or object schema`);
    stack.push({ label, value: child });
  };
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) continue;
    if (
      typeof current.value !== "object" ||
      current.value === null ||
      Array.isArray(current.value)
    )
      throw mismatch(`${current.label} must be an object schema`);
    for (const [key, child] of Object.entries(current.value)) {
      if (
        ["$dynamicRef", "$recursiveRef", "$anchor", "$dynamicAnchor"].includes(
          key,
        )
      )
        throw mismatch(`${key} is unsupported in a schema record`);
      if (key === "$ref") schemaId(child, "schema $ref");
      else if (schemaChildKind(key) === "single")
        pushSubschema(child, `schema ${key}`);
      else if (schemaChildKind(key) === "array") {
        if (!Array.isArray(child))
          throw mismatch(`schema ${key} must be an array`);
        child.forEach((entry, index) => {
          pushSubschema(entry, `schema ${key}[${index}]`);
        });
      } else if (schemaChildKind(key) === "map") {
        if (typeof child !== "object" || child === null || Array.isArray(child))
          throw mismatch(`schema ${key} must be an object`);
        for (const [name, entry] of Object.entries(child))
          pushSubschema(entry, `schema ${key}.${name}`);
      }
    }
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
    const parameters = validateParameters(object.parameters);
    validatePathTemplate(object.path, parameters.pathNames);
    const directSchemaIds = [
      ...parameters.schemaIds,
      ...validateRequestBody(object.requestBody),
    ].sort();
    const declaredSchemaIds = object.schemaIds.map((value) =>
      schemaId(value, "Operation schema ID"),
    );
    sortedUnique(declaredSchemaIds, "Operation schema IDs");
    const expectedSchemaIds = [...new Set(directSchemaIds)].sort();
    if (
      declaredSchemaIds.length !== expectedSchemaIds.length ||
      declaredSchemaIds.some(
        (value, index) => value !== expectedSchemaIds[index],
      )
    ) {
      throw mismatch("Operation schema IDs do not equal direct schema uses");
    }
  } else if (
    typeof object.schema !== "boolean" &&
    (typeof object.schema !== "object" ||
      object.schema === null ||
      Array.isArray(object.schema))
  ) {
    throw mismatch("Schema record is invalid");
  } else {
    validateSchemaReferences(object.schema);
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
  limitOverrides?: Partial<RuntimeLimits>,
): Promise<Readonly<T>> {
  const limits = resolveRuntimeLimits(limitOverrides);
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
