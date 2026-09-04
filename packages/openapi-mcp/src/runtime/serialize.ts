import { OpenApiMcpError } from "./errors.ts";
import {
  canonicalJson,
  canonicalJsonBounded,
  parseJsonStrict,
} from "./strict-json.ts";
import type {
  CredentialSlot,
  JsonObject,
  JsonSchemaV4,
  JsonValue,
  OpenApiArguments,
  OpenApiValue,
  OperationRecordV4,
  ParameterRecordV4,
  SchemaRecordV4,
  SerializeArgumentsOptions,
  TypedSchemaId,
} from "./types.ts";
import {
  DEFAULT_RUNTIME_LIMITS,
  type RuntimeLimits,
  resolveRuntimeLimits,
} from "./versions.ts";

export interface SerializedArguments {
  readonly normalizedArguments: JsonObject;
  readonly relativeUrl: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array | null;
}

const forbiddenObjectKeys = new Set(["__proto__", "constructor", "prototype"]);
const forbiddenHeaderNames = new Set([
  "accept",
  "authorization",
  "cf-access-authenticated-user-email",
  "cf-access-client-id",
  "cf-access-client-secret",
  "cf-connecting-ip",
  "cf-connecting-ipv6",
  "cf-pseudo-ipv4",
  "cloudfront-viewer-address",
  "connection",
  "content-length",
  "content-type",
  "cookie",
  "fastly-client-ip",
  "fly-client-ip",
  "forwarded",
  "host",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "sec-fetch-dest",
  "sec-fetch-mode",
  "sec-fetch-site",
  "sec-fetch-user",
  "set-cookie",
  "te",
  "trailer",
  "transfer-encoding",
  "true-client-ip",
  "upgrade",
  "via",
  "www-authenticate",
  "x-api-key",
  "x-amz-security-token",
  "x-appengine-user-ip",
  "x-auth-request-user",
  "x-auth-token",
  "x-azure-clientip",
  "x-aws-principal",
  "x-client-id",
  "x-client-ip",
  "x-client-secret",
  "x-cluster-client-ip",
  "x-envoy-external-address",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-port",
  "x-forwarded-proto",
  "x-forwarded-server",
  "x-goog-authenticated-user-email",
  "x-ms-client-principal",
  "x-original-forwarded-for",
  "x-provider-id",
  "x-real-ip",
]);
const maximumCredentialSlots = 64;
const maximumCredentialSlotNameBytes = 256;
const maximumSerializerOptionsBytes = 32 * 1024;
// Finite IEEE-754 values stringify within exponents -324 through 308.
const maximumFiniteDecimalExponent = 400;
const supportedSchemaKeys = new Set([
  "$anchor",
  "$comment",
  "$defs",
  "$id",
  "$ref",
  "$schema",
  "additionalProperties",
  "allOf",
  "anyOf",
  "const",
  "default",
  "deprecated",
  "description",
  "discriminator",
  "enum",
  "example",
  "examples",
  "exclusiveMaximum",
  "exclusiveMinimum",
  "format",
  "items",
  "maxItems",
  "maxLength",
  "maxProperties",
  "maximum",
  "minItems",
  "minLength",
  "minProperties",
  "minimum",
  "multipleOf",
  "nullable",
  "oneOf",
  "properties",
  "readOnly",
  "required",
  "title",
  "type",
  "uniqueItems",
  "writeOnly",
  "xml",
]);

function invalid(message = "OpenAPI arguments are invalid"): OpenApiMcpError {
  return new OpenApiMcpError("INPUT_INVALID", message);
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function ownValue(object: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  return descriptor !== undefined && "value" in descriptor
    ? descriptor.value
    : undefined;
}

function hasAsciiControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function snapshotArguments(
  value: unknown,
  limits: RuntimeLimits,
): OpenApiArguments & JsonObject {
  try {
    const json = canonicalJsonBounded(value as JsonValue, {
      maxBytes: limits.maxArgumentsBytes,
      maxDepth: limits.maxJsonDepth,
      maxNodes: Math.max(1, limits.maxArgumentsBytes),
    });
    const detached = parseJsonStrict(json, {
      maxBytes: limits.maxArgumentsBytes,
      maxDepth: limits.maxJsonDepth,
      maxKeys: limits.maxArgumentsBytes,
    });
    if (!isObject(detached)) throw new Error();
    const allowed = new Set(["body", "headers", "path", "query"]);
    if (Object.keys(detached).some((key) => !allowed.has(key)))
      throw new Error();
    for (const section of ["path", "query", "headers"] as const) {
      if (Object.hasOwn(detached, section) && !isObject(detached[section]))
        throw new Error();
    }
    const path = detached.path;
    if (
      isObject(path) &&
      Object.values(path).some(
        (entry) =>
          typeof entry !== "string" &&
          typeof entry !== "number" &&
          typeof entry !== "boolean",
      )
    )
      throw new Error();
    const headers = detached.headers;
    if (
      isObject(headers) &&
      Object.values(headers).some((entry) => typeof entry !== "string")
    )
      throw new Error();
    return detached as OpenApiArguments & JsonObject;
  } catch {
    throw invalid();
  }
}

function schemaFailure(): never {
  throw invalid("OpenAPI argument does not satisfy its declared schema");
}

function canonicalEqual(left: JsonValue, right: JsonValue): boolean {
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
}

function schemaArray(value: unknown): readonly JsonSchemaV4[] {
  if (!Array.isArray(value) || value.length === 0) schemaFailure();
  return value as readonly JsonSchemaV4[];
}

function finiteKeyword(schema: JsonObject, key: string): number | undefined {
  if (!Object.hasOwn(schema, key)) return undefined;
  const value = schema[key];
  if (typeof value !== "number" || !Number.isFinite(value)) schemaFailure();
  return value;
}

interface FiniteDecimal {
  readonly coefficient: bigint;
  readonly exponent: number;
}

function finiteDecimal(value: number): FiniteDecimal {
  const match = /^(-?)(\d+)(?:\.(\d+))?(?:e([+-]?\d+))?$/.exec(
    value.toString(),
  );
  if (match === null) schemaFailure();
  const fraction = match[3] ?? "";
  const coefficient = BigInt(`${match[1] ?? ""}${match[2]}${fraction}`);
  const exponent = Number(match[4] ?? "0") - fraction.length;
  if (
    !Number.isSafeInteger(exponent) ||
    Math.abs(exponent) > maximumFiniteDecimalExponent
  )
    schemaFailure();
  return { coefficient, exponent };
}

function isExactDecimalMultiple(value: number, multiple: number): boolean {
  const candidate = finiteDecimal(value);
  const divisor = finiteDecimal(multiple);
  const exponentDifference = candidate.exponent - divisor.exponent;
  if (exponentDifference >= 0) {
    return (
      (candidate.coefficient * 10n ** BigInt(exponentDifference)) %
        divisor.coefficient ===
      0n
    );
  }
  return (
    candidate.coefficient %
      (divisor.coefficient * 10n ** BigInt(-exponentDifference)) ===
    0n
  );
}

function nonNegativeIntegerKeyword(
  schema: JsonObject,
  key: string,
): number | undefined {
  const value = finiteKeyword(schema, key);
  if (value !== undefined && (!Number.isSafeInteger(value) || value < 0))
    schemaFailure();
  return value;
}

function jsonType(value: JsonValue): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (typeof value === "object") return "object";
  if (typeof value === "number" && Number.isInteger(value)) return "integer";
  return typeof value;
}

interface ValidationContext {
  readonly activeReferences: Map<TypedSchemaId, Set<JsonValue>>;
  readonly maxDepth: number;
  remainingWork: number;
  exhausted: boolean;
}

function validationContext(limits: RuntimeLimits): ValidationContext {
  return {
    activeReferences: new Map(),
    maxDepth: limits.maxJsonDepth,
    remainingWork: Math.max(
      1,
      Math.min(limits.maxArgumentsBytes, limits.maxSchemaClosureBytes),
    ),
    exhausted: false,
  };
}

function consumeValidationWork(context: ValidationContext, amount = 1): void {
  if (amount > context.remainingWork) {
    context.exhausted = true;
    schemaFailure();
  }
  context.remainingWork -= amount;
}

function canonicalEnumMatch(
  entries: readonly JsonValue[],
  value: JsonValue,
  context: ValidationContext,
): boolean {
  let candidate: string;
  try {
    candidate = canonicalJson(value);
  } catch {
    schemaFailure();
  }
  const encoder = new TextEncoder();
  const candidateBytes = encoder.encode(candidate).length;
  consumeValidationWork(context, candidateBytes);
  for (const entry of entries) {
    consumeValidationWork(context);
    let member: string;
    try {
      member = canonicalJson(entry);
    } catch {
      schemaFailure();
    }
    consumeValidationWork(
      context,
      candidateBytes + encoder.encode(member).length,
    );
    if (member === candidate) return true;
  }
  return false;
}

function validates(
  schema: JsonSchemaV4,
  value: JsonValue,
  closure: ReadonlyMap<TypedSchemaId, Readonly<SchemaRecordV4>>,
  depth: number,
  context: ValidationContext,
): boolean {
  try {
    validateSchema(schema, value, closure, depth, context);
    return true;
  } catch (error) {
    if (context.exhausted) throw error;
    if (error instanceof OpenApiMcpError && error.code === "INPUT_INVALID")
      return false;
    throw error;
  }
}

function validateDiscriminator(
  schema: JsonObject,
  branches: readonly JsonSchemaV4[],
  value: JsonValue,
): number | null {
  if (!Object.hasOwn(schema, "discriminator")) return null;
  const discriminator = schema.discriminator;
  if (!isObject(discriminator) || !isObject(value)) schemaFailure();
  const propertyName = discriminator.propertyName;
  if (typeof propertyName !== "string" || propertyName.length === 0)
    schemaFailure();
  const selectedValue = value[propertyName];
  if (typeof selectedValue !== "string") schemaFailure();
  const mapping = discriminator.mapping;
  if (!isObject(mapping)) schemaFailure();
  const target = mapping[selectedValue];
  if (typeof target !== "string") schemaFailure();
  const selected = branches
    .map((branch, index) =>
      isObject(branch) && branch.$ref === target ? index : -1,
    )
    .filter((index) => index >= 0);
  if (selected.length !== 1) schemaFailure();
  return selected[0];
}

function validateReference(
  id: TypedSchemaId,
  schema: JsonSchemaV4,
  value: JsonValue,
  closure: ReadonlyMap<TypedSchemaId, Readonly<SchemaRecordV4>>,
  depth: number,
  context: ValidationContext,
): void {
  const activeValues = context.activeReferences.get(id) ?? new Set();
  if (activeValues.has(value)) schemaFailure();
  activeValues.add(value);
  context.activeReferences.set(id, activeValues);
  try {
    validateSchema(schema, value, closure, depth, context);
  } finally {
    activeValues.delete(value);
    if (activeValues.size === 0) context.activeReferences.delete(id);
  }
}

function validateSchema(
  schema: JsonSchemaV4,
  value: JsonValue,
  closure: ReadonlyMap<TypedSchemaId, Readonly<SchemaRecordV4>>,
  depth: number,
  context: ValidationContext,
): void {
  consumeValidationWork(context);
  if (depth > context.maxDepth) schemaFailure();
  if (schema === true) return;
  if (schema === false || !isObject(schema)) schemaFailure();
  for (const key of Object.keys(schema)) {
    if (!supportedSchemaKeys.has(key)) schemaFailure();
  }

  if (Object.hasOwn(schema, "$ref")) {
    if (typeof schema.$ref !== "string") schemaFailure();
    const id = schema.$ref as TypedSchemaId;
    const referenced = closure.get(id);
    if (referenced === undefined) schemaFailure();
    validateReference(
      id,
      referenced.schema,
      value,
      closure,
      depth + 1,
      context,
    );
  }

  if (Object.hasOwn(schema, "allOf")) {
    for (const branch of schemaArray(schema.allOf))
      validateSchema(branch, value, closure, depth + 1, context);
  }
  if (Object.hasOwn(schema, "anyOf")) {
    const matches = schemaArray(schema.anyOf).filter((branch) =>
      validates(branch, value, closure, depth + 1, context),
    );
    if (matches.length === 0) schemaFailure();
  }
  if (Object.hasOwn(schema, "oneOf")) {
    const branches = schemaArray(schema.oneOf);
    const selected = validateDiscriminator(schema, branches, value);
    const matches = branches
      .map((branch, index) =>
        validates(branch, value, closure, depth + 1, context) ? index : -1,
      )
      .filter((index) => index >= 0);
    if (matches.length !== 1 || (selected !== null && matches[0] !== selected))
      schemaFailure();
  } else if (Object.hasOwn(schema, "discriminator")) {
    schemaFailure();
  }

  if (Object.hasOwn(schema, "nullable")) {
    if (typeof schema.nullable !== "boolean") schemaFailure();
    if (value === null && schema.nullable) return;
  }
  if (Object.hasOwn(schema, "type")) {
    const rawTypes = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (
      rawTypes.length === 0 ||
      rawTypes.some(
        (entry) =>
          typeof entry !== "string" ||
          ![
            "array",
            "boolean",
            "integer",
            "null",
            "number",
            "object",
            "string",
          ].includes(entry),
      )
    )
      schemaFailure();
    const actual = jsonType(value);
    if (
      !rawTypes.includes(actual) &&
      !(actual === "integer" && rawTypes.includes("number"))
    )
      schemaFailure();
  }
  if (
    Object.hasOwn(schema, "enum") &&
    (!Array.isArray(schema.enum) ||
      !canonicalEnumMatch(schema.enum, value, context))
  )
    schemaFailure();
  if (Object.hasOwn(schema, "const") && !canonicalEqual(schema.const, value))
    schemaFailure();

  if (typeof value === "string") {
    const length = [...value].length;
    const minimum = nonNegativeIntegerKeyword(schema, "minLength");
    const maximum = nonNegativeIntegerKeyword(schema, "maxLength");
    if (minimum !== undefined && length < minimum) schemaFailure();
    if (maximum !== undefined && length > maximum) schemaFailure();
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) schemaFailure();
    const minimum = finiteKeyword(schema, "minimum");
    const maximum = finiteKeyword(schema, "maximum");
    if (minimum !== undefined && value < minimum) schemaFailure();
    if (maximum !== undefined && value > maximum) schemaFailure();
    const exclusiveMinimum = schema.exclusiveMinimum;
    if (
      typeof exclusiveMinimum === "number" &&
      (!Number.isFinite(exclusiveMinimum) || value <= exclusiveMinimum)
    )
      schemaFailure();
    if (exclusiveMinimum === true && minimum !== undefined && value <= minimum)
      schemaFailure();
    if (
      exclusiveMinimum !== undefined &&
      typeof exclusiveMinimum !== "number" &&
      typeof exclusiveMinimum !== "boolean"
    )
      schemaFailure();
    const exclusiveMaximum = schema.exclusiveMaximum;
    if (
      typeof exclusiveMaximum === "number" &&
      (!Number.isFinite(exclusiveMaximum) || value >= exclusiveMaximum)
    )
      schemaFailure();
    if (exclusiveMaximum === true && maximum !== undefined && value >= maximum)
      schemaFailure();
    if (
      exclusiveMaximum !== undefined &&
      typeof exclusiveMaximum !== "number" &&
      typeof exclusiveMaximum !== "boolean"
    )
      schemaFailure();
    const multiple = finiteKeyword(schema, "multipleOf");
    if (multiple !== undefined) {
      if (multiple <= 0) schemaFailure();
      if (!isExactDecimalMultiple(value, multiple)) schemaFailure();
    }
  }

  if (Array.isArray(value)) {
    const minimum = nonNegativeIntegerKeyword(schema, "minItems");
    const maximum = nonNegativeIntegerKeyword(schema, "maxItems");
    if (minimum !== undefined && value.length < minimum) schemaFailure();
    if (maximum !== undefined && value.length > maximum) schemaFailure();
    if (Object.hasOwn(schema, "uniqueItems")) {
      if (typeof schema.uniqueItems !== "boolean") schemaFailure();
      if (schema.uniqueItems) {
        const values = new Set(value.map((entry) => canonicalJson(entry)));
        if (values.size !== value.length) schemaFailure();
      }
    }
    if (Object.hasOwn(schema, "items")) {
      const items = schema.items;
      if (typeof items !== "boolean" && !isObject(items)) schemaFailure();
      for (const entry of value)
        validateSchema(
          items as JsonSchemaV4,
          entry,
          closure,
          depth + 1,
          context,
        );
    }
  }

  if (isObject(value)) {
    const keys = Object.keys(value);
    const minimum = nonNegativeIntegerKeyword(schema, "minProperties");
    const maximum = nonNegativeIntegerKeyword(schema, "maxProperties");
    if (minimum !== undefined && keys.length < minimum) schemaFailure();
    if (maximum !== undefined && keys.length > maximum) schemaFailure();
    const properties = Object.hasOwn(schema, "properties")
      ? schema.properties
      : undefined;
    if (properties !== undefined && !isObject(properties)) schemaFailure();
    if (Object.hasOwn(schema, "required")) {
      if (
        !Array.isArray(schema.required) ||
        schema.required.some((key) => typeof key !== "string")
      )
        schemaFailure();
      for (const key of schema.required as string[]) {
        if (!Object.hasOwn(value, key)) schemaFailure();
      }
    }
    for (const key of keys) {
      if (forbiddenObjectKeys.has(key)) schemaFailure();
      if (isObject(properties) && Object.hasOwn(properties, key)) {
        validateSchema(
          properties[key] as JsonSchemaV4,
          value[key],
          closure,
          depth + 1,
          context,
        );
        continue;
      }
      const additional = schema.additionalProperties;
      if (additional === false) schemaFailure();
      if (additional !== undefined && additional !== true) {
        if (!isObject(additional)) schemaFailure();
        validateSchema(additional, value[key], closure, depth + 1, context);
      }
    }
  }
}

function encode(value: OpenApiValue): string {
  const text =
    typeof value === "string" ? value : value === null ? "null" : String(value);
  return encodeURIComponent(text).replace(
    /[!'()*]/g,
    (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

function scalar(value: OpenApiValue): boolean {
  return (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  );
}

function flatObject(value: OpenApiValue): readonly [string, OpenApiValue][] {
  if (!isObject(value)) schemaFailure();
  const entries = Object.entries(value).sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
  if (entries.some(([, entry]) => !scalar(entry))) schemaFailure();
  return entries;
}

function arrayScalars(value: OpenApiValue): readonly OpenApiValue[] {
  if (!Array.isArray(value) || value.some((entry) => !scalar(entry)))
    schemaFailure();
  return value;
}

function pathValue(parameter: ParameterRecordV4, value: OpenApiValue): string {
  // OpenApiArguments intentionally permits scalar path values only.
  if (!scalar(value) || value === null) schemaFailure();
  const encoded = encode(value);
  if (parameter.style === "simple") return encoded;
  if (parameter.style === "label") return `.${encoded}`;
  if (parameter.style === "matrix")
    return `;${encode(parameter.name)}=${encoded}`;
  schemaFailure();
}

function queryValues(
  parameter: ParameterRecordV4,
  value: OpenApiValue,
): readonly [string, string][] {
  const name = encode(parameter.name);
  if (parameter.style === "deepObject") {
    if (!parameter.explode) schemaFailure();
    return flatObject(value).map(([key, entry]) => [
      `${name}%5B${encode(key)}%5D`,
      encode(entry),
    ]);
  }
  if (
    parameter.style === "spaceDelimited" ||
    parameter.style === "pipeDelimited"
  ) {
    if (parameter.explode) schemaFailure();
    const delimiter = parameter.style === "spaceDelimited" ? "%20" : "%7C";
    return [[name, arrayScalars(value).map(encode).join(delimiter)]];
  }
  if (parameter.style !== "form") schemaFailure();
  if (scalar(value)) return [[name, encode(value)]];
  if (Array.isArray(value)) {
    const entries = arrayScalars(value).map(encode);
    return parameter.explode
      ? entries.map((entry) => [name, entry])
      : [[name, entries.join(",")]];
  }
  const entries = flatObject(value);
  return parameter.explode
    ? entries.map(([key, entry]) => [encode(key), encode(entry)])
    : [
        [
          name,
          entries
            .flatMap(([key, entry]) => [encode(key), encode(entry)])
            .join(","),
        ],
      ];
}

function headerValue(
  parameter: ParameterRecordV4,
  value: OpenApiValue,
): string {
  if (parameter.style !== "simple" || typeof value !== "string")
    schemaFailure();
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if ((code <= 0x1f && code !== 0x09) || code === 0x7f)
      throw invalid("Header arguments are invalid");
  }
  return value;
}

function forbiddenHeader(name: string): boolean {
  const lower = name.toLowerCase();
  return (
    !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name) ||
    forbiddenHeaderNames.has(lower)
  );
}

function deepFreezeJson<T extends JsonValue>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value))
    return value;
  if (Array.isArray(value)) {
    for (const entry of value) deepFreezeJson(entry);
  } else {
    for (const entry of Object.values(value)) deepFreezeJson(entry);
  }
  return Object.freeze(value);
}

interface SnapshottedSerializerOptions {
  readonly limits: Readonly<Partial<RuntimeLimits>>;
  readonly reservedCredentialSlots: readonly Readonly<CredentialSlot>[];
  readonly reservedHeaderSlots: ReadonlySet<string>;
  readonly reservedQuerySlots: ReadonlySet<string>;
}

function snapshotSerializerOptions(
  value: SerializeArgumentsOptions,
): SnapshottedSerializerOptions {
  try {
    const json = canonicalJsonBounded(value as unknown as JsonValue, {
      maxBytes: maximumSerializerOptionsBytes,
      maxDepth: 4,
      maxNodes: 512,
    });
    const detached = parseJsonStrict(json, {
      maxBytes: maximumSerializerOptionsBytes,
      maxDepth: 4,
      maxKeys: 256,
    });
    if (!isObject(detached)) throw new Error();
    const optionKeys = Object.keys(detached);
    if (
      optionKeys.some(
        (key) => key !== "limits" && key !== "reservedCredentialSlots",
      )
    )
      throw new Error();

    const rawLimits = Object.hasOwn(detached, "limits") ? detached.limits : {};
    if (!isObject(rawLimits)) throw new Error();
    const limitNames = new Set(Object.keys(DEFAULT_RUNTIME_LIMITS));
    if (Object.keys(rawLimits).some((key) => !limitNames.has(key)))
      throw new Error();
    const limits = Object.freeze({ ...rawLimits }) as Readonly<
      Partial<RuntimeLimits>
    >;

    const rawSlots = Object.hasOwn(detached, "reservedCredentialSlots")
      ? detached.reservedCredentialSlots
      : [];
    if (!Array.isArray(rawSlots) || rawSlots.length > maximumCredentialSlots)
      throw new Error();
    const reservedHeaderSlots = new Set<string>();
    const reservedQuerySlots = new Set<string>();
    const slots = rawSlots.map((rawSlot) => {
      if (!isObject(rawSlot)) throw new Error();
      const keys = Object.keys(rawSlot).sort();
      if (keys.length !== 2 || keys[0] !== "name" || keys[1] !== "placement")
        throw new Error();
      const placement = rawSlot.placement;
      const name = rawSlot.name;
      if (
        (placement !== "header" && placement !== "query") ||
        typeof name !== "string" ||
        name.length === 0 ||
        new TextEncoder().encode(name).length >
          maximumCredentialSlotNameBytes ||
        hasAsciiControl(name)
      )
        throw new Error();
      if (
        placement === "header" &&
        !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name)
      )
        throw new Error();
      const wireName =
        placement === "header" ? name.toLowerCase() : encode(name);
      const target =
        placement === "header" ? reservedHeaderSlots : reservedQuerySlots;
      if (target.has(wireName)) throw new Error();
      target.add(wireName);
      return Object.freeze({ placement, name });
    });
    Object.freeze(slots);
    return Object.freeze({
      limits,
      reservedCredentialSlots: slots,
      reservedHeaderSlots: Object.freeze(reservedHeaderSlots),
      reservedQuerySlots: Object.freeze(reservedQuerySlots),
    });
  } catch {
    throw invalid("Serializer options are invalid");
  }
}

function section(
  arguments_: OpenApiArguments & JsonObject,
  name: "path" | "query" | "headers",
): JsonObject {
  const value = arguments_[name];
  return isObject(value) ? value : {};
}

function ensurePathTemplate(path: string): void {
  if (
    !path.startsWith("/") ||
    path.startsWith("//") ||
    path.includes("\\") ||
    path.includes("?") ||
    path.includes("#") ||
    /\r|\n/.test(path)
  )
    throw invalid("Operation path is invalid");
}

function chooseBodyMedia(operation: OperationRecordV4) {
  const requestBody = operation.requestBody;
  if (requestBody === null) return null;
  const supported = requestBody.content.filter(
    (entry) =>
      entry.mediaType === "application/json" ||
      entry.mediaType.endsWith("+json"),
  );
  if (supported.length !== 1 || requestBody.content.length !== 1)
    throw invalid("Request body media type is unsupported");
  if (supported[0].encoding.length !== 0)
    throw invalid("Request body encoding is unsupported");
  return supported[0];
}

/**
 * Detach, validate, and serialize one exact public argument envelope.
 * The result is authority-free and contains no caller-selected credentials.
 */
export function serializeArguments(
  operation: Readonly<OperationRecordV4>,
  schemas: ReadonlyMap<TypedSchemaId, Readonly<SchemaRecordV4>>,
  arguments_: unknown,
  optionsValue: SerializeArgumentsOptions = {},
): SerializedArguments {
  const options = snapshotSerializerOptions(optionsValue);
  let limits: RuntimeLimits;
  try {
    limits = resolveRuntimeLimits(options.limits);
  } catch {
    throw invalid("Serializer options are invalid");
  }
  const validation = validationContext(limits);
  const input = snapshotArguments(arguments_, limits);
  ensurePathTemplate(operation.path);
  const pathArguments = section(input, "path");
  const queryArguments = section(input, "query");
  const headerArguments = section(input, "headers");
  const consumed = {
    path: new Set<string>(),
    query: new Set<string>(),
    headers: new Set<string>(),
  };
  const normalized: JsonObject = {};
  const normalizedPath: JsonObject = {};
  const normalizedQuery: JsonObject = {};
  const normalizedHeaders: JsonObject = {};
  const outputHeaders: Record<string, string> = { accept: "application/json" };
  if (options.reservedHeaderSlots.has("accept"))
    throw invalid(
      "Reserved credential slot collides with a representation header",
    );
  const query: [string, string][] = [];
  const queryWireOwners = new Map<string, string>();
  let relativeUrl = operation.path;
  const declared = new Set<string>();

  for (const parameter of operation.parameters) {
    if (parameter.in === "cookie")
      throw invalid("Cookie parameters are unsupported");
    if (parameter.value.kind !== "schema")
      throw invalid("Parameter content is unsupported");
    if (parameter.allowReserved)
      throw invalid("Reserved parameter serialization is unsupported");
    if (parameter.in === "header" && forbiddenHeader(parameter.name))
      throw invalid("Credential or transport headers are forbidden");
    if (
      parameter.in === "header" &&
      options.reservedHeaderSlots.has(parameter.name.toLowerCase())
    )
      throw invalid("Declared header collides with a reserved credential slot");
    const identity = `${parameter.in}\0${
      parameter.in === "header" ? parameter.name.toLowerCase() : parameter.name
    }`;
    if (declared.has(identity))
      throw invalid("Parameter declaration is ambiguous");
    declared.add(identity);

    const source =
      parameter.in === "path"
        ? pathArguments
        : parameter.in === "query"
          ? queryArguments
          : headerArguments;
    let sourceKey = parameter.name;
    if (parameter.in === "header") {
      const matches = Object.keys(source).filter(
        (key) => key.toLowerCase() === parameter.name.toLowerCase(),
      );
      if (matches.length > 1) throw invalid("Header argument is ambiguous");
      sourceKey = matches[0] ?? parameter.name;
    }
    const present = Object.hasOwn(source, sourceKey);
    if (!present) {
      if (parameter.required) throw invalid("Required parameter is missing");
      continue;
    }
    const value = ownValue(source, sourceKey) as JsonValue;
    const schema = schemas.get(parameter.value.schemaId);
    if (schema === undefined) throw invalid("Declared schema is unavailable");
    validateReference(schema.id, schema.schema, value, schemas, 0, validation);

    if (parameter.in === "path") {
      const token = `{${parameter.name}}`;
      if (!relativeUrl.includes(token))
        throw invalid("Path parameter is not templated");
      relativeUrl = relativeUrl.split(token).join(pathValue(parameter, value));
      normalizedPath[parameter.name] = value;
      consumed.path.add(sourceKey);
    } else if (parameter.in === "query") {
      const serialized = queryValues(parameter, value);
      const intentionalRepeat =
        Array.isArray(value) && parameter.style === "form" && parameter.explode;
      const localKeys = new Set<string>();
      for (const [wireKey] of serialized) {
        if (options.reservedQuerySlots.has(wireKey))
          throw invalid(
            "Query parameter collides with a reserved credential slot",
          );
        const owner = queryWireOwners.get(wireKey);
        if (
          (localKeys.has(wireKey) && !intentionalRepeat) ||
          (owner !== undefined && owner !== identity)
        ) {
          throw invalid("Query parameter serialization is ambiguous");
        }
        localKeys.add(wireKey);
        queryWireOwners.set(wireKey, identity);
      }
      query.push(...serialized);
      normalizedQuery[parameter.name] = value;
      consumed.query.add(sourceKey);
    } else {
      const lower = parameter.name.toLowerCase();
      outputHeaders[lower] = headerValue(parameter, value);
      normalizedHeaders[parameter.name] = value;
      consumed.headers.add(sourceKey);
    }
  }

  if (/\{[^{}]+\}/.test(relativeUrl))
    throw invalid("Path parameter is missing");
  for (const [name, values] of [
    ["path", pathArguments],
    ["query", queryArguments],
    ["headers", headerArguments],
  ] as const) {
    if (Object.keys(values).some((key) => !consumed[name].has(key)))
      throw invalid("Unknown parameter argument");
  }

  if (Object.keys(normalizedHeaders).length > 0)
    normalized.headers = normalizedHeaders;
  if (Object.keys(normalizedPath).length > 0) normalized.path = normalizedPath;
  if (Object.keys(normalizedQuery).length > 0)
    normalized.query = normalizedQuery;
  if (query.length > 0)
    relativeUrl += `?${query.map(([key, value]) => `${key}=${value}`).join("&")}`;

  const bodyMedia = chooseBodyMedia(operation);
  const hasBody = Object.hasOwn(input, "body");
  let body: Uint8Array | null = null;
  if (bodyMedia === null) {
    if (hasBody) throw invalid("Request body is not declared");
  } else if (!hasBody) {
    if (operation.requestBody?.required)
      throw invalid("Required request body is missing");
  } else {
    const bodyValue = input.body as JsonValue;
    const bodySchema = schemas.get(bodyMedia.schemaId);
    if (bodySchema === undefined)
      throw invalid("Declared schema is unavailable");
    validateReference(
      bodySchema.id,
      bodySchema.schema,
      bodyValue,
      schemas,
      0,
      validation,
    );
    const bodyJson = canonicalJson(bodyValue);
    body = new TextEncoder().encode(bodyJson);
    if (options.reservedHeaderSlots.has("content-type"))
      throw invalid(
        "Reserved credential slot collides with a representation header",
      );
    outputHeaders["content-type"] = bodyMedia.mediaType;
    normalized.body = JSON.parse(bodyJson) as JsonValue;
  }

  // A second bound includes the canonical normalization performed above and
  // guarantees no partial result escapes if normalization grows unexpectedly.
  try {
    canonicalJsonBounded(normalized, {
      maxBytes: limits.maxArgumentsBytes,
      maxDepth: limits.maxJsonDepth,
      maxNodes: Math.max(1, limits.maxArgumentsBytes),
    });
  } catch {
    throw invalid();
  }

  const normalizedArguments = deepFreezeJson(normalized);
  const bodySnapshot = body === null ? null : new Uint8Array(body);
  return Object.freeze({
    normalizedArguments,
    relativeUrl,
    headers: Object.freeze(outputHeaders),
    get body(): Uint8Array | null {
      return bodySnapshot === null ? null : new Uint8Array(bodySnapshot);
    },
  });
}
