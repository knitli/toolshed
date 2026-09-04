import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { mkdir, mkdtemp, open } from "node:fs/promises";
import { extname, join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { OpenApiDoc } from "../load.ts";
import { resolveLocalPointer, splitWords } from "../operations.ts";
import {
  buildPermissionIndex,
  lookupPermissions,
  type PermissionIndex,
  type PermissionsDataset,
} from "../permissions.ts";
import { sha256 } from "../runtime/digest.ts";
import { admitManifest } from "../runtime/manifest.ts";
import { parseTypedRecordId } from "../runtime/references.ts";
import {
  canonicalJson,
  canonicalJsonBounded,
  parseJsonStrict,
} from "../runtime/strict-json.ts";
import type {
  CanonicalMediaTypeV4,
  CatalogId,
  EncodingHeaderV4,
  GenerationState,
  GenerationStore,
  HttpMethod,
  JsonObject,
  JsonValue,
  MediaEncodingV4,
  OperationRecordV4,
  ParameterLocationV4,
  ParameterRecordV4,
  ParameterStyleV4,
  ReleaseId,
  RequestBodyMediaV4,
  RequestBodyRecordV4,
  SchemaRecordV4,
  SchemaUseV4,
  Sha256,
  StoredRecord,
  TypedOperationId,
  TypedRecordId,
  TypedSchemaId,
} from "../runtime/types.ts";
import {
  parseOperationPathTemplateV4,
  verifyStoredRecord,
} from "../runtime/verify-record.ts";
import { DEFAULT_RUNTIME_LIMITS } from "../runtime/versions.ts";
import { classifySafety, riskFor } from "../safety.ts";
import { deriveReleasePublicKeyV4 } from "../sign.ts";
import {
  type CompilerLimits,
  DEFAULT_COMPILER_LIMITS,
  parseSpecBytesV4,
  readFileBoundedV4,
} from "./load-v4.ts";
import {
  buildManifestEnvelopeV4,
  buildReleaseManifestV4,
} from "./manifest-builder.ts";
import {
  type CompiledRelease,
  type CompiledReleaseOwnership,
  type CompiledReleasePaths,
  capturePathIdentity,
  cleanupOwnedStage,
  type PathIdentity,
  pathIdentityFromStats,
  registerCompiledRelease,
  samePathIdentity,
} from "./publish.ts";
import {
  normalizeHttpsUri,
  ReferenceGraphV4,
  type ReferenceResolver,
  referenceGraphDigest,
  sourceUriFromLabel,
} from "./reference-map.ts";
import { createReleaseSchemaV4, populateOperationsFtsV4 } from "./schema-v4.ts";

const COMPILER_VERSION = "0.1.0";
const HTTP_METHODS = [
  "get",
  "head",
  "post",
  "put",
  "patch",
  "delete",
  "options",
  "trace",
] as const;
const PARAMETER_LOCATIONS: ParameterLocationV4[] = [
  "path",
  "query",
  "header",
  "cookie",
];
const PARAMETER_STYLES: ParameterStyleV4[] = [
  "matrix",
  "label",
  "form",
  "simple",
  "spaceDelimited",
  "pipeDelimited",
  "deepObject",
];
const reservedComponentPrefix = "__openapi_mcp_v4_";

type Provenance =
  | { readonly sourceUri: string; readonly sourceLabel?: never }
  | { readonly sourceLabel: string; readonly sourceUri?: never };

export type CompileReleaseOptions = Provenance & {
  readonly specPath: string;
  readonly sourceRevision: string;
  readonly catalogId: string;
  readonly releaseId: string;
  readonly generation: number;
  readonly issuer: string;
  readonly keyId: string;
  readonly policyId: string;
  readonly allowedOrigins: readonly string[];
  readonly outDir: string;
  readonly privateKeyPem: string;
  readonly permissionsPath?: string;
  readonly referenceRoot?: string;
  readonly referenceMapPath?: string;
  readonly referenceResolver?: ReferenceResolver;
  readonly limits?: CompilerLimits;
};

export type ConstructionCheckpoint =
  | "before-sqlite-created"
  | "before-signature-created"
  | "before-manifest-created"
  | "after-sqlite-opened"
  | "after-sqlite-emitted"
  | "before-sqlite-snapshot-read"
  | "after-signature-opened"
  | "after-manifest-opened";

type ConstructionHook = (
  checkpoint: ConstructionCheckpoint,
  paths: CompiledReleasePaths,
) => void | Promise<void>;

interface AddressedValue {
  documentUri: string;
  pointer: string;
  document: Record<string, unknown>;
  value: unknown;
}

function encodePointerToken(value: string): string {
  return value.replace(/~/g, "~0").replace(/\//g, "~1");
}

function exactObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function canonicalMediaType(value: string): CanonicalMediaTypeV4 {
  const normalized = value.toLowerCase();
  if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(normalized)) {
    throw new Error(
      `media type "${value}" is not a type/subtype without parameters`,
    );
  }
  return normalized as CanonicalMediaTypeV4;
}

function canonicalOrigin(value: unknown): string {
  if (typeof value !== "string")
    throw new Error("document declares no servers[0].url");
  const url = new URL(value);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  )
    throw new Error("operation server must be credential-free HTTPS");
  if (url.pathname !== "/")
    throw new Error("operation server must be an exact HTTPS origin");
  return url.origin;
}

function checkedRecordJson(record: JsonValue, limits: CompilerLimits): string {
  try {
    return canonicalJsonBounded(record, {
      maxBytes: limits.maxRecordBytes,
      maxDepth: limits.maxJsonDepth,
      maxNodes: limits.maxDocumentNodes,
    });
  } catch (error) {
    throw new Error(
      "logical record exceeds record limit or cannot be canonicalized",
      { cause: error },
    );
  }
}

function stableSort<T>(values: T[], key: (value: T) => string): T[] {
  return values.sort((left, right) =>
    key(left) < key(right) ? -1 : key(left) > key(right) ? 1 : 0,
  );
}

class SchemaMaterializer {
  readonly records = new Map<TypedSchemaId, SchemaRecordV4>();
  readonly #addresses = new Map<TypedSchemaId, string>();

  constructor(
    readonly api: string,
    readonly sourceUri: string,
    readonly rootDocument: Record<string, unknown>,
    readonly graph: ReferenceGraphV4,
    readonly limits: CompilerLimits,
  ) {}

  async resolveReference(
    rawRef: string,
    from: AddressedValue,
    depth: number,
  ): Promise<AddressedValue> {
    if (Buffer.byteLength(rawRef) > this.limits.maxRefLength)
      throw new Error("reference exceeds ref length limit");
    if (depth > this.limits.maxJsonDepth)
      throw new Error("reference depth exceeds limit");
    const hash = rawRef.indexOf("#");
    const documentPart = hash < 0 ? rawRef : rawRef.slice(0, hash);
    const pointer = hash < 0 ? "#" : `#${rawRef.slice(hash + 1)}`;
    if (documentPart === "") {
      return {
        documentUri: from.documentUri,
        pointer,
        document: from.document,
        value: resolveLocalPointer(from.document, pointer),
      };
    }
    const external = await this.graph.resolve(rawRef, from.documentUri, depth);
    return {
      documentUri: external.uri,
      pointer: external.pointer,
      document: external.document,
      value: resolveLocalPointer(external.document, external.pointer),
    };
  }

  #rootComponentName(address: AddressedValue): string | null {
    if (address.documentUri !== this.sourceUri) return null;
    const prefix = "#/components/schemas/";
    if (!address.pointer.startsWith(prefix)) return null;
    const tail = address.pointer.slice(prefix.length);
    if (tail.includes("/")) return null;
    return tail.replace(/~1/g, "/").replace(/~0/g, "~");
  }

  async #idFor(
    address: AddressedValue,
    authoredName?: string,
  ): Promise<TypedSchemaId> {
    const componentName = authoredName ?? this.#rootComponentName(address);
    if (componentName !== null && componentName !== undefined) {
      if (componentName.startsWith(reservedComponentPrefix))
        throw new Error(
          "authored schema component uses the reserved v4 namespace",
        );
      const id = `schema:${this.api}:#/components/schemas/${encodePointerToken(componentName)}`;
      const parsed = parseTypedRecordId(id);
      if (!parsed.startsWith("schema:"))
        throw new Error("schema identifier is invalid");
      return parsed as TypedSchemaId;
    }
    const digest = await sha256(
      "knitli.openapi-mcp.schema-materialization-id.v1",
      {
        api: this.api,
        documentUri: address.documentUri,
        pointer: address.pointer,
      },
    );
    return `schema:${this.api}:#/components/schemas/${reservedComponentPrefix}${digest}` as TypedSchemaId;
  }

  async materialize(
    address: AddressedValue,
    authoredName?: string,
    referenceDepth = 0,
  ): Promise<TypedSchemaId> {
    const id = await this.#idFor(address, authoredName);
    const identity = `${address.documentUri}\0${address.pointer}`;
    const prior = this.#addresses.get(id);
    if (prior && prior !== identity)
      throw new Error("synthetic schema identifier collision");
    if (this.records.has(id)) return id;
    if (this.records.size >= this.limits.maxSchemas)
      throw new Error("Schemas exceed maxSchemas limit");
    this.#addresses.set(id, identity);
    this.records.set(id, { id, schema: Object.create(null) as JsonObject });
    const schema = await this.#rewriteSchema(
      address.value,
      address,
      0,
      referenceDepth,
    );
    const record: SchemaRecordV4 = { id, schema };
    checkedRecordJson(record as unknown as JsonValue, this.limits);
    this.records.set(id, record);
    return id;
  }

  async materializeUse(address: AddressedValue): Promise<TypedSchemaId> {
    const object = exactObject(address.value, "schema use");
    if (Object.keys(object).length === 1 && typeof object.$ref === "string") {
      return this.materialize(
        await this.resolveReference(object.$ref, address, 1),
        undefined,
        1,
      );
    }
    return this.materialize(address);
  }

  async #rewriteSchema(
    value: unknown,
    address: AddressedValue,
    depth: number,
    referenceDepth: number,
  ): Promise<JsonObject> {
    if (depth > this.limits.maxJsonDepth)
      throw new Error("schema depth exceeds limit");
    const object = exactObject(value, "schema");
    for (const keyword of [
      "$dynamicRef",
      "$recursiveRef",
      "$anchor",
      "$dynamicAnchor",
    ]) {
      if (Object.hasOwn(object, keyword))
        throw new Error(`${keyword} is unsupported`);
    }
    const properties = object.properties;
    if (
      properties &&
      Object.keys(exactObject(properties, "schema properties")).length >
        this.limits.maxPropertiesPerSchema
    ) {
      throw new Error("Properties exceed maxPropertiesPerSchema limit");
    }
    const output = Object.create(null) as JsonObject;
    for (const [key, child] of Object.entries(object)) {
      if (key === "$ref") {
        if (typeof child !== "string")
          throw new Error("schema $ref must be a string");
        const target = await this.resolveReference(
          child,
          address,
          referenceDepth + 1,
        );
        output.$ref = await this.materialize(
          target,
          undefined,
          referenceDepth + 1,
        );
        continue;
      }
      output[key] = await this.#rewriteJson(
        child,
        {
          ...address,
          pointer: `${address.pointer}/${encodePointerToken(key)}`,
          value: child,
        },
        depth + 1,
        referenceDepth,
      );
    }
    return output;
  }

  async #rewriteJson(
    value: unknown,
    address: AddressedValue,
    depth: number,
    referenceDepth: number,
  ): Promise<JsonValue> {
    if (depth > this.limits.maxJsonDepth)
      throw new Error("schema depth exceeds limit");
    if (
      value === null ||
      typeof value === "string" ||
      typeof value === "boolean" ||
      typeof value === "number"
    )
      return value;
    if (Array.isArray(value)) {
      return Promise.all(
        value.map((entry, index) =>
          this.#rewriteJson(
            entry,
            {
              ...address,
              pointer: `${address.pointer}/${index}`,
              value: entry,
            },
            depth + 1,
            referenceDepth,
          ),
        ),
      );
    }
    return this.#rewriteSchema(value, address, depth, referenceDepth);
  }
}

async function resolveObject(
  value: unknown,
  address: AddressedValue,
  materializer: SchemaMaterializer,
  depth = 0,
): Promise<{ object: Record<string, unknown>; address: AddressedValue }> {
  let object = exactObject(value, "OpenAPI object");
  let current = address;
  const seen = new Set<string>();
  while (typeof object.$ref === "string") {
    const target = await materializer.resolveReference(
      object.$ref,
      current,
      depth + 1,
    );
    const identity = `${target.documentUri}\0${target.pointer}`;
    if (seen.has(identity))
      throw new Error("object reference cycle is unsupported");
    seen.add(identity);
    current = target;
    object = exactObject(target.value, "referenced OpenAPI object");
    depth += 1;
    if (depth > materializer.limits.maxJsonDepth)
      throw new Error("reference depth exceeds limit");
  }
  return { object, address: current };
}

async function schemaUse(
  owner: Record<string, unknown>,
  address: AddressedValue,
  materializer: SchemaMaterializer,
): Promise<SchemaUseV4> {
  const hasSchema = Object.hasOwn(owner, "schema");
  const hasContent = Object.hasOwn(owner, "content");
  if (hasSchema === hasContent)
    throw new Error(
      "parameter/header must declare exactly one of schema or content",
    );
  if (hasSchema) {
    const schemaAddress = {
      ...address,
      pointer: `${address.pointer}/schema`,
      value: owner.schema,
    };
    return {
      kind: "schema",
      schemaId: await materializer.materializeUse(schemaAddress),
    };
  }
  const entries = Object.entries(
    exactObject(owner.content, "parameter content"),
  );
  if (entries.length !== 1)
    throw new Error("parameter content must contain exactly one media type");
  const [rawMediaType, media] = entries[0];
  const mediaObject = exactObject(media, "parameter media type");
  if (!Object.hasOwn(mediaObject, "schema"))
    throw new Error("parameter content is missing a schema");
  return {
    kind: "content",
    mediaType: canonicalMediaType(rawMediaType),
    schemaId: await materializer.materializeUse({
      ...address,
      pointer: `${address.pointer}/content/${encodePointerToken(rawMediaType)}/schema`,
      value: mediaObject.schema,
    }),
  };
}

function defaultStyle(location: ParameterLocationV4): ParameterStyleV4 {
  return location === "path" || location === "header" ? "simple" : "form";
}

async function normalizeParameter(
  raw: unknown,
  address: AddressedValue,
  materializer: SchemaMaterializer,
): Promise<ParameterRecordV4> {
  const resolved = await resolveObject(raw, address, materializer);
  const object = resolved.object;
  if (
    typeof object.name !== "string" ||
    !PARAMETER_LOCATIONS.includes(object.in as ParameterLocationV4)
  )
    throw new Error("parameter name or location is invalid");
  const location = object.in as ParameterLocationV4;
  const style =
    object.style === undefined ? defaultStyle(location) : object.style;
  if (!PARAMETER_STYLES.includes(style as ParameterStyleV4))
    throw new Error("parameter style is invalid");
  const allowedStyles: Record<
    ParameterLocationV4,
    readonly ParameterStyleV4[]
  > = {
    path: ["matrix", "label", "simple"],
    query: ["form", "spaceDelimited", "pipeDelimited", "deepObject"],
    header: ["simple"],
    cookie: ["form"],
  };
  if (!allowedStyles[location].includes(style as ParameterStyleV4))
    throw new Error("parameter style is invalid for its location");
  const explode =
    object.explode === undefined ? style === "form" : object.explode;
  if (typeof explode !== "boolean")
    throw new Error("parameter explode is invalid");
  if (location === "path" && object.required !== true)
    throw new Error("path parameters must be required");
  if (location !== "query" && object.allowReserved === true)
    throw new Error("allowReserved is valid only for query parameters");
  return {
    name: object.name,
    in: location,
    required: object.required === true,
    deprecated: object.deprecated === true,
    style: style as ParameterStyleV4,
    explode,
    allowReserved: object.allowReserved === true,
    value: await schemaUse(object, resolved.address, materializer),
  };
}

async function normalizeParameters(
  path: string,
  pathItem: Record<string, unknown>,
  operation: Record<string, unknown>,
  baseAddress: AddressedValue,
  materializer: SchemaMaterializer,
  operationPointer: string,
): Promise<ParameterRecordV4[]> {
  const merged = new Map<string, ParameterRecordV4>();
  for (const [scope, rawList] of [
    ["path", pathItem.parameters],
    ["operation", operation.parameters],
  ] as const) {
    if (rawList === undefined) continue;
    if (!Array.isArray(rawList))
      throw new Error(`${scope} parameters must be an array`);
    if (rawList.length > materializer.limits.maxParametersPerOperation)
      throw new Error("Parameters exceed maxParametersPerOperation limit");
    const local = new Set<string>();
    for (let index = 0; index < rawList.length; index += 1) {
      const parameter = await normalizeParameter(
        rawList[index],
        {
          ...baseAddress,
          pointer: `${scope === "path" ? baseAddress.pointer : operationPointer}/parameters/${index}`,
          value: rawList[index],
        },
        materializer,
      );
      const key = `${parameter.in}\0${parameter.name}`;
      if (local.has(key))
        throw new Error("duplicate parameter after normalization");
      local.add(key);
      merged.set(key, parameter);
    }
  }
  const variables = new Set(parseOperationPathTemplateV4(path));
  if (merged.size > materializer.limits.maxParametersPerOperation)
    throw new Error("Parameters exceed maxParametersPerOperation limit");
  const pathParameters = [...merged.values()].filter(
    (parameter) => parameter.in === "path",
  );
  if (
    pathParameters.some((parameter) => !variables.has(parameter.name)) ||
    pathParameters.length !== variables.size
  ) {
    throw new Error(
      "path parameters must exactly match path-template variables",
    );
  }
  return [...merged.values()].sort((left, right) => {
    const location =
      PARAMETER_LOCATIONS.indexOf(left.in) -
      PARAMETER_LOCATIONS.indexOf(right.in);
    return (
      location || (left.name < right.name ? -1 : left.name > right.name ? 1 : 0)
    );
  });
}

async function normalizeEncodingHeaders(
  headers: unknown,
  address: AddressedValue,
  materializer: SchemaMaterializer,
): Promise<EncodingHeaderV4[]> {
  if (headers === undefined) return [];
  const output: EncodingHeaderV4[] = [];
  const seen = new Set<string>();
  for (const [rawName, rawHeader] of Object.entries(
    exactObject(headers, "encoding headers"),
  )) {
    const name = rawName.toLowerCase();
    if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(name) || seen.has(name))
      throw new Error("encoding header name is invalid or duplicated");
    seen.add(name);
    const headerAddress = {
      ...address,
      pointer: `${address.pointer}/${encodePointerToken(rawName)}`,
      value: rawHeader,
    };
    const resolved = await resolveObject(
      rawHeader,
      headerAddress,
      materializer,
    );
    output.push({
      name,
      required: resolved.object.required === true,
      value: await schemaUse(resolved.object, resolved.address, materializer),
    });
  }
  return stableSort(output, (header) => header.name);
}

async function normalizeRequestBody(
  raw: unknown,
  address: AddressedValue,
  materializer: SchemaMaterializer,
): Promise<RequestBodyRecordV4 | null> {
  if (raw === undefined) return null;
  const resolved = await resolveObject(raw, address, materializer);
  const alternatives = Object.entries(
    exactObject(resolved.object.content, "request body content"),
  );
  if (alternatives.length === 0)
    throw new Error("request body content must be nonempty");
  const seen = new Set<string>();
  const content: RequestBodyMediaV4[] = [];
  for (const [rawMediaType, rawMedia] of alternatives) {
    const mediaType = canonicalMediaType(rawMediaType);
    if (seen.has(mediaType))
      throw new Error("duplicate normalized request-body media type");
    seen.add(mediaType);
    const media = exactObject(rawMedia, "request body media entry");
    if (!Object.hasOwn(media, "schema"))
      throw new Error("request body media entry is missing a schema");
    const mediaAddress: AddressedValue = {
      ...resolved.address,
      pointer: `${resolved.address.pointer}/content/${encodePointerToken(rawMediaType)}`,
      value: media,
    };
    const schemaId = await materializer.materializeUse({
      ...mediaAddress,
      pointer: `${mediaAddress.pointer}/schema`,
      value: media.schema,
    });
    let encodingProperties: Record<string, unknown> | null = null;
    if (media.encoding !== undefined) {
      let schemaAddress: AddressedValue = {
        ...mediaAddress,
        pointer: `${mediaAddress.pointer}/schema`,
        value: media.schema,
      };
      let schemaObject = exactObject(
        schemaAddress.value,
        "request body root schema",
      );
      const visited = new Set<string>();
      while (typeof schemaObject.$ref === "string") {
        schemaAddress = await materializer.resolveReference(
          schemaObject.$ref,
          schemaAddress,
          visited.size + 1,
        );
        const identity = `${schemaAddress.documentUri}\0${schemaAddress.pointer}`;
        if (visited.has(identity))
          throw new Error(
            "request body root schema reference cycle is unsupported for encoding",
          );
        visited.add(identity);
        schemaObject = exactObject(
          schemaAddress.value,
          "request body root schema",
        );
      }
      if (
        schemaObject.type !== "object" ||
        typeof schemaObject.properties !== "object" ||
        schemaObject.properties === null ||
        Array.isArray(schemaObject.properties)
      ) {
        throw new Error(
          "request body encoding requires a resolved root object schema",
        );
      }
      encodingProperties = schemaObject.properties as Record<string, unknown>;
    }
    const encodings: MediaEncodingV4[] = [];
    if (media.encoding !== undefined) {
      if (
        mediaType !== "multipart/form-data" &&
        mediaType !== "application/x-www-form-urlencoded"
      )
        throw new Error("encoding is unsupported for this media type");
      for (const [property, rawEncoding] of Object.entries(
        exactObject(media.encoding, "request body encoding"),
      )) {
        if (!encodingProperties || !Object.hasOwn(encodingProperties, property))
          throw new Error(
            "encoding property is not an immediate root schema property",
          );
        const encoding = exactObject(rawEncoding, "encoding entry");
        const style = encoding.style === undefined ? null : encoding.style;
        if (
          style !== null &&
          !PARAMETER_STYLES.includes(style as ParameterStyleV4)
        )
          throw new Error("encoding style is invalid");
        const explode =
          encoding.explode === undefined ? null : encoding.explode;
        if (explode !== null && typeof explode !== "boolean")
          throw new Error("encoding explode is invalid");
        encodings.push({
          property,
          contentType:
            encoding.contentType === undefined
              ? null
              : canonicalMediaType(String(encoding.contentType)),
          style: style as ParameterStyleV4 | null,
          explode,
          allowReserved: encoding.allowReserved === true,
          headers: await normalizeEncodingHeaders(
            encoding.headers,
            {
              ...mediaAddress,
              pointer: `${mediaAddress.pointer}/encoding/${encodePointerToken(property)}/headers`,
              value: encoding.headers,
            },
            materializer,
          ),
        });
      }
    }
    content.push({
      mediaType,
      schemaId,
      encoding: stableSort(encodings, (entry) => entry.property),
    });
  }
  return {
    required: resolved.object.required === true,
    content: stableSort(content, (entry) => entry.mediaType),
  };
}

async function extractLogicalRecords(
  document: OpenApiDoc,
  sourceUri: string,
  graph: ReferenceGraphV4,
  api: string,
  allowedOrigins: readonly string[],
  limits: CompilerLimits,
  permissionIndex?: PermissionIndex,
): Promise<{ operations: OperationRecordV4[]; schemas: SchemaRecordV4[] }> {
  const root = document as unknown as Record<string, unknown>;
  const materializer = new SchemaMaterializer(
    api,
    sourceUri,
    root,
    graph,
    limits,
  );
  const componentSchemas = exactObject(
    document.components?.schemas ?? Object.create(null),
    "component schemas",
  );
  if (Object.keys(componentSchemas).length > limits.maxSchemas)
    throw new Error("Schemas exceed maxSchemas limit");
  for (const [name, schema] of Object.entries(componentSchemas)) {
    await materializer.materialize(
      {
        documentUri: sourceUri,
        pointer: `#/components/schemas/${encodePointerToken(name)}`,
        document: root,
        value: schema,
      },
      name,
    );
  }

  const paths = Object.entries(document.paths);
  if (paths.length > limits.maxPaths)
    throw new Error("Paths exceed maxPaths limit");
  const operations: OperationRecordV4[] = [];
  const seen = new Set<string>();
  const documentOrigin = canonicalOrigin(document.servers?.[0]?.url);
  if (!allowedOrigins.includes(documentOrigin))
    throw new Error("document origin is absent from allowedOrigins");
  for (const [path, rawPathItem] of paths) {
    const resolvedPathItem = await resolveObject(
      rawPathItem,
      {
        documentUri: sourceUri,
        document: root,
        pointer: `#/paths/${encodePointerToken(path)}`,
        value: rawPathItem,
      },
      materializer,
    );
    const pathItem = resolvedPathItem.object;
    if (pathItem.servers !== undefined)
      throw new Error(`${path}: path-item server override is unsupported`);
    for (const method of HTTP_METHODS) {
      if (!Object.hasOwn(pathItem, method)) continue;
      if (operations.length >= limits.maxOperations)
        throw new Error("Operations exceed maxOperations limit");
      const operation = exactObject(pathItem[method], "operation");
      if (operation.servers !== undefined)
        throw new Error(
          `${method.toUpperCase()} ${path}: operation server override is unsupported`,
        );
      if (typeof operation.operationId !== "string")
        throw new Error(
          `${method.toUpperCase()} ${path}: operationId is invalid`,
        );
      const id = `operation:${api}:${operation.operationId}`;
      const parsed = parseTypedRecordId(id);
      if (!parsed.startsWith("operation:"))
        throw new Error("operation identifier is invalid");
      if (seen.has(id)) throw new Error("duplicate operationId");
      seen.add(id);
      const baseAddress = resolvedPathItem.address;
      const operationPointer = `${baseAddress.pointer}/${method}`;
      const parameters = await normalizeParameters(
        path,
        pathItem,
        operation,
        baseAddress,
        materializer,
        operationPointer,
      );
      const requestBody = await normalizeRequestBody(
        operation.requestBody,
        {
          ...baseAddress,
          pointer: `${baseAddress.pointer}/${method}/requestBody`,
          value: operation.requestBody,
        },
        materializer,
      );
      const schemaIds = new Set<TypedSchemaId>();
      for (const parameter of parameters)
        schemaIds.add(parameter.value.schemaId);
      for (const media of requestBody?.content ?? []) {
        schemaIds.add(media.schemaId);
        for (const encoding of media.encoding)
          for (const header of encoding.headers)
            schemaIds.add(header.value.schemaId);
      }
      const safety = classifySafety(
        method.toUpperCase(),
        path,
        operation.operationId,
        api,
      );
      const permission = permissionIndex
        ? lookupPermissions(permissionIndex, path, method)
        : null;
      const record: OperationRecordV4 = {
        id: parsed as TypedOperationId,
        api,
        operationId: operation.operationId,
        method: method.toUpperCase() as HttpMethod,
        path,
        origin: documentOrigin,
        summary:
          typeof operation.summary === "string"
            ? operation.summary.slice(0, 600)
            : typeof operation.description === "string"
              ? operation.description.slice(0, 600)
              : null,
        deprecated: operation.deprecated === true,
        parameters,
        requestBody,
        schemaIds: [...schemaIds].sort(),
        advisory: {
          safety,
          risk: riskFor(safety, permission?.privilegeLevel ?? null, path),
          pageable: operation["x-ms-pageable"] !== undefined,
          operationType:
            typeof operation["x-ms-docs-operation-type"] === "string"
              ? operation["x-ms-docs-operation-type"]
              : null,
          permissions: permission?.permissions ?? null,
          permConfidence: permission?.confidence ?? null,
          privilegeLevel: permission?.privilegeLevel ?? null,
        },
      };
      checkedRecordJson(record as unknown as JsonValue, limits);
      operations.push(record);
    }
  }
  return { operations, schemas: [...materializer.records.values()] };
}

class EphemeralGenerationStore implements GenerationStore {
  readonly #states = new Map<string, GenerationState>();
  async get(
    catalogId: CatalogId,
    issuer: string,
  ): Promise<GenerationState | null> {
    const value = this.#states.get(`${catalogId}\0${issuer}`);
    return value ? structuredClone(value) : null;
  }
  async accept(
    catalogId: CatalogId,
    issuer: string,
    transition: { expectedRevision: number | null; next: GenerationState },
  ): Promise<GenerationState | null> {
    const key = `${catalogId}\0${issuer}`;
    const current = this.#states.get(key);
    if ((current?.revision ?? null) !== transition.expectedRevision)
      return null;
    const next = structuredClone(transition.next);
    this.#states.set(key, next);
    return structuredClone(next);
  }
}

async function requireStageDirectory(
  path: string,
  identity: PathIdentity,
): Promise<void> {
  const current = await capturePathIdentity(path, "directory").catch(
    () => null,
  );
  if (!current || !samePathIdentity(current, identity))
    throw new Error("compiler stage directory identity was lost");
}

async function requireStageFile(
  path: string,
  identity: PathIdentity,
): Promise<void> {
  const current = await capturePathIdentity(path, "file").catch(() => null);
  if (!current || !samePathIdentity(current, identity))
    throw new Error("compiler stage file identity was lost");
}

/**
 * Portable Node/Bun has no openat-style API. The compiler therefore assumes
 * no hostile same-UID parent-namespace mutation before O_EXCL creates a leaf.
 * Pre/post parent checks limit that residual to an empty entry: bytes are
 * written only after the pinned handle and its pathname identity both match.
 */
async function createOwnedStageFile(
  path: string,
  directory: string,
  directoryIdentity: PathIdentity,
  contents: string | Uint8Array,
  recordIdentity: (identity: PathIdentity) => void,
  afterOpen: () => void | Promise<void> = () => {},
): Promise<void> {
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0)
    throw new Error("compiler staging requires O_NOFOLLOW support");
  await requireStageDirectory(directory, directoryIdentity);
  const handle = await open(
    path,
    constants.O_CREAT |
      constants.O_EXCL |
      constants.O_WRONLY |
      constants.O_NOFOLLOW,
    0o600,
  );
  try {
    const metadata = await handle.stat({ bigint: true });
    if (!metadata.isFile() || metadata.nlink !== 1n)
      throw new Error("compiler-created stage file is unsafe");
    const identity = pathIdentityFromStats(metadata);
    recordIdentity(identity);
    await afterOpen();
    await requireStageDirectory(directory, directoryIdentity);
    await requireStageFile(path, identity);
    await handle.writeFile(contents);
    await handle.sync();
    const after = await handle.stat({ bigint: true });
    if (
      !after.isFile() ||
      after.nlink !== 1n ||
      !samePathIdentity(pathIdentityFromStats(after), identity)
    )
      throw new Error("compiler stage file identity was lost");
    await requireStageDirectory(directory, directoryIdentity);
    await requireStageFile(path, identity);
  } finally {
    await handle.close();
  }
}

async function readOwnedStageFileSnapshot(
  path: string,
  directory: string,
  directoryIdentity: PathIdentity,
  fileIdentity: PathIdentity,
  maxBytes: number,
  beforeRead: () => void | Promise<void> = () => {},
): Promise<Uint8Array> {
  await requireStageDirectory(directory, directoryIdentity);
  await requireStageFile(path, fileIdentity);
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile() ||
      before.nlink !== 1n ||
      !samePathIdentity(pathIdentityFromStats(before), fileIdentity) ||
      before.size > BigInt(maxBytes)
    )
      throw new Error("emitted SQLite identity or size is invalid");
    await requireStageDirectory(directory, directoryIdentity);
    await requireStageFile(path, fileIdentity);
    await beforeRead();
    const expectedBytes = Number(before.size);
    const bytes = new Uint8Array(expectedBytes);
    let offset = 0;
    while (offset < expectedBytes) {
      const { bytesRead } = await handle.read(
        bytes,
        offset,
        Math.min(64 * 1024, expectedBytes - offset),
        null,
      );
      if (bytesRead === 0)
        throw new Error("emitted SQLite ended before its captured size");
      offset += bytesRead;
    }
    const growthProbe = new Uint8Array(1);
    const { bytesRead: extraBytes } = await handle.read(
      growthProbe,
      0,
      1,
      null,
    );
    if (extraBytes !== 0)
      throw new Error("emitted SQLite grew beyond its captured size");
    const after = await handle.stat({ bigint: true });
    if (
      !after.isFile() ||
      after.nlink !== 1n ||
      !samePathIdentity(pathIdentityFromStats(after), fileIdentity) ||
      after.size !== before.size ||
      BigInt(bytes.byteLength) !== after.size
    )
      throw new Error("emitted SQLite identity or size changed during reread");
    await requireStageDirectory(directory, directoryIdentity);
    await requireStageFile(path, fileIdentity);
    return bytes;
  } finally {
    await handle.close();
  }
}

async function syncOwnedStageDirectory(
  path: string,
  identity: PathIdentity,
): Promise<void> {
  await requireStageDirectory(path, identity);
  const handle = await open(
    path,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    const metadata = await handle.stat({ bigint: true });
    if (
      !metadata.isDirectory() ||
      !samePathIdentity(pathIdentityFromStats(metadata), identity)
    )
      throw new Error("compiler stage directory identity was lost");
    await handle.sync();
    await requireStageDirectory(path, identity);
  } finally {
    await handle.close();
  }
}

function sourceIdentity(options: CompileReleaseOptions): string {
  const hasUri = typeof options.sourceUri === "string";
  const hasLabel = typeof options.sourceLabel === "string";
  if (hasUri === hasLabel)
    throw new Error("exactly one source URI or source label is required");
  return hasUri
    ? normalizeHttpsUri(options.sourceUri as string)
    : sourceUriFromLabel(options.sourceLabel as string);
}

function assertIdentifiers(options: CompileReleaseOptions): {
  catalogId: CatalogId;
  releaseId: ReleaseId;
} {
  const operationProbe = parseTypedRecordId(
    `operation:${options.catalogId}:probe`,
  );
  if (!operationProbe.startsWith("operation:"))
    throw new Error("catalog ID is invalid");
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(options.releaseId) ||
    options.releaseId === "." ||
    options.releaseId === ".."
  )
    throw new Error("release ID is invalid");
  return {
    catalogId: options.catalogId as CatalogId,
    releaseId: options.releaseId as ReleaseId,
  };
}

export async function compileReleaseWithCheckpoint(
  options: CompileReleaseOptions,
  checkpoint: ConstructionHook = () => {},
): Promise<CompiledRelease> {
  const sourceUri = sourceIdentity(options);
  const ids = assertIdentifiers(options);
  const limits = options.limits ?? DEFAULT_COMPILER_LIMITS;
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(options.sourceRevision) ||
    options.sourceRevision === "." ||
    options.sourceRevision === ".."
  ) {
    throw new Error("source revision is invalid");
  }
  let stage: string | undefined;
  let stagePaths: CompiledReleasePaths | undefined;
  let constructionDatabase: DatabaseSync | undefined;
  const stageOwnership: {
    -readonly [Kind in keyof CompiledReleaseOwnership]?: CompiledReleaseOwnership[Kind];
  } = {};
  try {
    const rootBytes = await readFileBoundedV4(
      options.specPath,
      limits.maxSourceBytes,
      "source document",
    ).catch((error) => {
      if (
        error instanceof Error &&
        error.message.includes("exceeds byte limit")
      )
        throw new Error("aggregate source bytes exceed limit");
      throw new Error("source document could not be read");
    });
    const extension = extname(options.specPath).toLowerCase();
    const sourceMediaType =
      extension === ".json"
        ? "json"
        : extension === ".yaml" || extension === ".yml"
          ? "yaml"
          : null;
    if (sourceMediaType === null) {
      throw new Error("unsupported OpenAPI media type file extension");
    }
    const document = parseSpecBytesV4(rootBytes, sourceMediaType, limits);
    const graph = await ReferenceGraphV4.create({
      sourceUri,
      mapPath: options.referenceMapPath,
      referenceRoot: options.referenceRoot,
      resolver: options.referenceResolver,
      limits,
      rootBytes: rootBytes.byteLength,
    });
    let permissionIndex: PermissionIndex | undefined;
    if (options.permissionsPath) {
      let permissionsBytes: Uint8Array;
      try {
        permissionsBytes = await readFileBoundedV4(
          options.permissionsPath,
          limits.maxSourceBytes,
          "permissions dataset",
        );
      } catch (error) {
        if (
          error instanceof Error &&
          error.message === "permissions dataset exceeds byte limit"
        )
          throw error;
        throw new Error("permissions dataset could not be read");
      }
      let permissionsText: string;
      try {
        permissionsText = new TextDecoder("utf-8", { fatal: true }).decode(
          permissionsBytes,
        );
      } catch {
        throw new Error("permissions dataset is not valid UTF-8");
      }
      const dataset = parseJsonStrict(permissionsText, {
        maxBytes: limits.maxSourceBytes,
        maxDepth: limits.maxJsonDepth,
        maxKeys: limits.maxDocumentKeys,
      }) as unknown as PermissionsDataset;
      permissionIndex = buildPermissionIndex(dataset);
    }
    const records = await extractLogicalRecords(
      document,
      sourceUri,
      graph,
      options.catalogId,
      options.allowedOrigins,
      limits,
      permissionIndex,
    );
    const sourceContentSha256 = createHash("sha256")
      .update(rootBytes)
      .digest("hex") as Sha256;
    const graphDigest = await referenceGraphDigest(graph.map);

    await mkdir(options.outDir, { recursive: true });
    const outDir = resolve(options.outDir);
    stage = await mkdtemp(join(outDir, ".openapi-mcp-v4-"));
    stageOwnership.directory = await capturePathIdentity(stage, "directory");
    const paths = {
      directory: stage,
      sqlite: join(stage, `${options.releaseId}.sqlite`),
      signature: join(stage, `${options.releaseId}.manifest.sig`),
      manifest: join(stage, `${options.releaseId}.manifest.json`),
    } as const;
    stagePaths = paths;
    const compiledAt = new Date().toISOString();
    await checkpoint("before-sqlite-created", paths);
    await requireStageDirectory(
      paths.directory,
      stageOwnership.directory as PathIdentity,
    );
    const database = new DatabaseSync(":memory:");
    constructionDatabase = database;
    try {
      database.exec("BEGIN IMMEDIATE");
      createReleaseSchemaV4(database);
      database
        .prepare(`INSERT INTO release_metadata (
        catalog_id, release_id, format, contract, generation, issuer, key_id,
        policy_id, allowed_origins_json, compiled_at, compiler_version,
        source_uri, source_revision, source_content_sha256,
        reference_graph_digest, manifest_json, signature_algorithm,
        signature_key_id, signature
      ) VALUES (?, ?, 4, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', 'Ed25519', ?, '')`)
        .run(
          ids.catalogId,
          ids.releaseId,
          options.generation,
          options.issuer,
          options.keyId,
          options.policyId,
          canonicalJson([...options.allowedOrigins].sort()),
          compiledAt,
          COMPILER_VERSION,
          sourceUri,
          options.sourceRevision,
          sourceContentSha256,
          graphDigest,
          options.keyId,
        );
      const insertOperation = database.prepare(`INSERT INTO operations (
        catalog_id, release_id, record_id, record_json, logical_digest,
        api, operation_id, summary, path, search_text
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
      for (const record of records.operations) {
        const json = checkedRecordJson(record as unknown as JsonValue, limits);
        const digest = await sha256(
          "knitli.openapi-mcp.operation-record.v4",
          record as unknown as JsonObject,
        );
        insertOperation.run(
          ids.catalogId,
          ids.releaseId,
          record.id,
          json,
          digest,
          record.api,
          record.operationId,
          record.summary,
          record.path,
          `${splitWords(record.operationId)} ${splitWords(record.path)}`,
        );
      }
      const insertSchema = database.prepare(`INSERT INTO schemas (
        catalog_id, release_id, record_id, record_json, logical_digest
      ) VALUES (?, ?, ?, ?, ?)`);
      for (const record of records.schemas) {
        const json = checkedRecordJson(record as unknown as JsonValue, limits);
        const digest = await sha256(
          "knitli.openapi-mcp.schema-record.v4",
          record as unknown as JsonObject,
        );
        insertSchema.run(ids.catalogId, ids.releaseId, record.id, json, digest);
      }
      populateOperationsFtsV4(database);
      database.exec("COMMIT");
    } catch (error) {
      try {
        database.exec("ROLLBACK");
      } catch {}
      throw error;
    }

    const reread = database;
    let rows: Array<{
      record_id: string;
      record_json: string;
      logical_digest: string;
    }>;
    rows = reread
      .prepare(
        "SELECT record_id, record_json, logical_digest FROM operations UNION ALL SELECT record_id, record_json, logical_digest FROM schemas ORDER BY record_id",
      )
      .all() as typeof rows;
    const manifestRecords = Object.create(null) as Record<
      TypedRecordId,
      Sha256
    >;
    for (const row of rows) {
      const id = parseTypedRecordId(row.record_id);
      const record = parseJsonStrict(row.record_json, {
        maxBytes: limits.maxRecordBytes,
        maxDepth: limits.maxJsonDepth,
        maxKeys: limits.maxDocumentKeys,
      }) as unknown as OperationRecordV4 | SchemaRecordV4;
      const domain = id.startsWith("operation:")
        ? "knitli.openapi-mcp.operation-record.v4"
        : "knitli.openapi-mcp.schema-record.v4";
      const digest = await sha256(domain, record as unknown as JsonObject);
      if (digest !== row.logical_digest)
        throw new Error("reread logical record digest mismatch");
      manifestRecords[id] = digest;
    }
    const manifest = buildReleaseManifestV4({
      ...ids,
      generation: options.generation,
      issuer: options.issuer,
      keyId: options.keyId,
      policyId: options.policyId,
      allowedOrigins: options.allowedOrigins,
      compiledAt,
      compilerVersion: COMPILER_VERSION,
      sourceUri,
      sourceRevision: options.sourceRevision,
      sourceContentSha256,
      referenceGraphDigest: graphDigest,
      records: manifestRecords,
    });
    const envelope = buildManifestEnvelopeV4(manifest, options.privateKeyPem);
    const update = database;
    update
      .prepare(
        `UPDATE release_metadata SET manifest_json = ?, signature_algorithm = ?, signature_key_id = ?, signature = ? WHERE catalog_id = ? AND release_id = ?`,
      )
      .run(
        envelope.manifestJson,
        envelope.signature.algorithm,
        envelope.signature.keyId,
        envelope.signature.signature,
        ids.catalogId,
        ids.releaseId,
      );
    const metadataDatabase = database;
    const metadata = metadataDatabase
      .prepare(
        "SELECT * FROM release_metadata WHERE catalog_id = ? AND release_id = ?",
      )
      .get(ids.catalogId, ids.releaseId) as Record<string, unknown> | undefined;
    if (!metadata)
      throw new Error("release metadata is absent after construction");
    const expectedMetadata: Record<string, unknown> = {
      catalog_id: manifest.catalogId,
      release_id: manifest.releaseId,
      format: manifest.format,
      contract: manifest.contract,
      generation: manifest.generation,
      issuer: manifest.issuer,
      key_id: manifest.keyId,
      policy_id: manifest.policyId,
      allowed_origins_json: canonicalJson([
        ...manifest.allowedOrigins,
      ] as JsonValue),
      compiled_at: manifest.compiledAt,
      compiler_version: manifest.compilerVersion,
      source_uri: manifest.source.uri,
      source_revision: manifest.source.revision,
      source_content_sha256: manifest.source.contentSha256,
      reference_graph_digest: manifest.source.referenceGraphDigest,
      manifest_json: envelope.manifestJson,
      signature_algorithm: envelope.signature.algorithm,
      signature_key_id: envelope.signature.keyId,
      signature: envelope.signature.signature,
    };
    for (const [key, expected] of Object.entries(expectedMetadata)) {
      if (metadata[key] !== expected)
        throw new Error(
          `release metadata field ${key} disagrees with the canonical manifest`,
        );
    }
    const sqliteBytes = database.serialize();
    database.close();
    constructionDatabase = undefined;
    const signatureBytes = canonicalJson(
      envelope.signature as unknown as JsonValue,
    );
    await createOwnedStageFile(
      paths.sqlite,
      paths.directory,
      stageOwnership.directory as PathIdentity,
      sqliteBytes,
      (identity) => {
        stageOwnership.sqlite = identity;
      },
      () => checkpoint("after-sqlite-opened", paths),
    );
    await checkpoint("after-sqlite-emitted", paths);
    const emittedBytes = await readOwnedStageFileSnapshot(
      paths.sqlite,
      paths.directory,
      stageOwnership.directory as PathIdentity,
      stageOwnership.sqlite as PathIdentity,
      sqliteBytes.byteLength,
      () => checkpoint("before-sqlite-snapshot-read", paths),
    ).catch(() => {
      throw new Error("emitted SQLite could not be reopened safely");
    });
    const emittedDatabase = new DatabaseSync(":memory:");
    const emittedStoredRows: StoredRecord<
      OperationRecordV4 | SchemaRecordV4
    >[] = [];
    try {
      emittedDatabase.deserialize(emittedBytes);
      emittedDatabase.exec("PRAGMA query_only = ON");
      const emittedRows = emittedDatabase
        .prepare(
          "SELECT record_id, record_json, logical_digest FROM operations UNION ALL SELECT record_id, record_json, logical_digest FROM schemas ORDER BY record_id",
        )
        .all() as Array<{
        record_id: string;
        record_json: string;
        logical_digest: string;
      }>;
      const emittedManifestRecords = Object.create(null) as Record<
        TypedRecordId,
        Sha256
      >;
      for (const row of emittedRows) {
        const id = parseTypedRecordId(row.record_id);
        let record: OperationRecordV4 | SchemaRecordV4;
        try {
          record = parseJsonStrict(row.record_json, {
            maxBytes: limits.maxRecordBytes,
            maxDepth: limits.maxJsonDepth,
            maxKeys: limits.maxDocumentKeys,
          }) as unknown as OperationRecordV4 | SchemaRecordV4;
        } catch {
          throw new Error("reread emitted record_json is invalid");
        }
        const domain = id.startsWith("operation:")
          ? "knitli.openapi-mcp.operation-record.v4"
          : "knitli.openapi-mcp.schema-record.v4";
        const digest = await sha256(domain, record as unknown as JsonObject);
        if (digest !== row.logical_digest)
          throw new Error("reread emitted record digest mismatch");
        emittedManifestRecords[id] = digest;
        emittedStoredRows.push({ id, logicalDigest: digest, record });
      }
      if (
        canonicalJson(emittedManifestRecords as unknown as JsonValue) !==
        canonicalJson(manifest.records as unknown as JsonValue)
      )
        throw new Error("reread emitted manifest record map mismatch");
      const emittedMetadata = emittedDatabase
        .prepare(
          "SELECT * FROM release_metadata WHERE catalog_id = ? AND release_id = ?",
        )
        .get(ids.catalogId, ids.releaseId) as
        | Record<string, unknown>
        | undefined;
      if (!emittedMetadata)
        throw new Error("reread emitted release metadata is absent");
      for (const [key, expected] of Object.entries(expectedMetadata)) {
        if (emittedMetadata[key] !== expected)
          throw new Error(
            `reread emitted release metadata field ${key} disagrees with the canonical manifest`,
          );
      }
    } finally {
      emittedDatabase.close();
    }
    await checkpoint("before-signature-created", paths);
    await createOwnedStageFile(
      paths.signature,
      paths.directory,
      stageOwnership.directory as PathIdentity,
      signatureBytes,
      (identity) => {
        stageOwnership.signature = identity;
      },
      () => checkpoint("after-signature-opened", paths),
    );
    await checkpoint("before-manifest-created", paths);
    await createOwnedStageFile(
      paths.manifest,
      paths.directory,
      stageOwnership.directory as PathIdentity,
      envelope.manifestJson,
      (identity) => {
        stageOwnership.manifest = identity;
      },
      () => checkpoint("after-manifest-opened", paths),
    );
    await syncOwnedStageDirectory(
      paths.directory,
      stageOwnership.directory as PathIdentity,
    );

    const admitted = await admitManifest(
      envelope,
      {
        releaseKeys: [
          {
            issuer: options.issuer,
            keyId: options.keyId,
            publicKey: deriveReleasePublicKeyV4(options.privateKeyPem),
          },
        ],
        rollbackKeys: [],
      },
      new EphemeralGenerationStore(),
      DEFAULT_RUNTIME_LIMITS,
    );
    if (
      canonicalJson(admitted.manifest as unknown as JsonValue) !==
      envelope.manifestJson
    )
      throw new Error("self-admitted manifest is not byte-identical");
    for (const row of emittedStoredRows)
      await verifyStoredRecord(admitted, row as never);

    const compiled: CompiledRelease = Object.freeze({
      manifest: admitted.manifest,
      envelope: Object.freeze({
        manifestJson: envelope.manifestJson,
        signature: Object.freeze({ ...envelope.signature }),
      }),
      paths: Object.freeze({ ...paths }),
    });
    const stageDigests = {
      sqlite: createHash("sha256").update(emittedBytes).digest("hex"),
      signature: createHash("sha256").update(signatureBytes).digest("hex"),
      manifest: createHash("sha256")
        .update(envelope.manifestJson)
        .digest("hex"),
    };
    const stageSizes = {
      sqlite: emittedBytes.byteLength,
      signature: Buffer.byteLength(signatureBytes),
      manifest: Buffer.byteLength(envelope.manifestJson),
    };
    return registerCompiledRelease(
      compiled,
      outDir,
      stageDigests,
      stageSizes,
      stageOwnership as CompiledReleaseOwnership,
    );
  } catch (error) {
    try {
      constructionDatabase?.close();
    } catch {}
    if (stagePaths) await cleanupOwnedStage(stagePaths, stageOwnership);
    throw error;
  }
}

export async function compileRelease(
  options: CompileReleaseOptions,
): Promise<CompiledRelease> {
  return compileReleaseWithCheckpoint(options);
}
