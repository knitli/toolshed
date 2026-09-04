import { OpenApiMcpError } from "./errors.ts";
import { canonicalJson, parseJsonStrict } from "./strict-json.ts";
import type {
  CatalogId,
  JsonObject,
  OperationRef,
  OperationRefPayload,
  ReleaseId,
  Sha256,
  TypedOperationId,
  TypedRecordId,
  TypedSchemaId,
} from "./types.ts";

const base64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const operationRefPrefix = "opref.v1.";
const maxShortSegmentLength = 128;
const maxTailLength = 512;
const maxOperationRefLength = 2048;
const digestPattern = /^[0-9a-f]{64}$/;
const standardSegmentPattern = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const schemaNamePattern = /^[A-Za-z0-9][A-Za-z0-9._~-]*$/;

function invalidReference(message: string): OpenApiMcpError {
  return new OpenApiMcpError("OPERATION_REF_INVALID", `OPERATION_REF_INVALID: ${message}`);
}

function assertSegment(value: string, maximumLength: number, pattern: RegExp, label: string): void {
  if (
    value.length === 0 ||
    value.length > maximumLength ||
    value === "." ||
    value === ".." ||
    !pattern.test(value)
  ) {
    throw invalidReference(`${label} is invalid`);
  }
}

function parseCatalogId(value: string): CatalogId {
  assertSegment(value, maxShortSegmentLength, standardSegmentPattern, "catalog ID");
  return value as CatalogId;
}

function parseReleaseId(value: string): ReleaseId {
  assertSegment(value, maxShortSegmentLength, standardSegmentPattern, "release ID");
  return value as ReleaseId;
}

function parseManifestDigest(value: string): Sha256 {
  if (!digestPattern.test(value)) throw invalidReference("manifest digest is invalid");
  return value as Sha256;
}

/** Validate a typed operation or schema record identifier before it is used as a key. */
export function parseTypedRecordId(value: string): TypedRecordId {
  if (value.startsWith("operation:")) {
    const parts = value.slice("operation:".length).split(":");
    if (parts.length !== 2) throw invalidReference("operation ID is invalid");
    const [api, operation] = parts;
    assertSegment(api, maxShortSegmentLength, standardSegmentPattern, "API segment");
    assertSegment(operation, maxTailLength, standardSegmentPattern, "operation segment");
    return value as TypedOperationId;
  }

  if (value.startsWith("schema:")) {
    const marker = ":#/components/schemas/";
    const body = value.slice("schema:".length);
    const markerIndex = body.indexOf(marker);
    if (markerIndex < 1) throw invalidReference("schema ID is invalid");
    const api = body.slice(0, markerIndex);
    const schemaName = body.slice(markerIndex + marker.length);
    assertSegment(api, maxShortSegmentLength, standardSegmentPattern, "API segment");
    assertSegment(schemaName, maxTailLength, schemaNamePattern, "schema segment");
    return value as TypedSchemaId;
  }

  throw invalidReference("record ID type is invalid");
}

function encodeBase64Url(bytes: Uint8Array): string {
  let accumulator = 0;
  let bits = 0;
  let encoded = "";
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      encoded += base64urlAlphabet[(accumulator >> bits) & 0x3f];
    }
  }
  if (bits > 0) encoded += base64urlAlphabet[(accumulator << (6 - bits)) & 0x3f];
  return encoded;
}

function decodeBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) return null;
  let accumulator = 0;
  let bits = 0;
  const bytes: number[] = [];
  for (const character of value) {
    const digit = base64urlAlphabet.indexOf(character);
    if (digit < 0) return null;
    accumulator = (accumulator << 6) | digit;
    bits += 6;
    while (bits >= 8) {
      bits -= 8;
      bytes.push((accumulator >> bits) & 0xff);
    }
  }
  if (bits > 0 && (accumulator & ((1 << bits) - 1)) !== 0) return null;
  const decoded = Uint8Array.from(bytes);
  return encodeBase64Url(decoded) === value ? decoded : null;
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizePayload(value: unknown): OperationRefPayload {
  if (!isJsonObject(value)) throw invalidReference("payload must be an object");
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype) {
    throw invalidReference("payload prototype is invalid");
  }
  const expectedKeys = ["catalogId", "manifestDigest", "operationId", "releaseId"];
  const keys = Object.keys(value).sort();
  if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index])) {
    throw invalidReference("payload shape is invalid");
  }
  const fields: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || typeof descriptor.value !== "string") {
      throw invalidReference("payload fields are invalid");
    }
    fields[key] = descriptor.value;
  }
  return {
    catalogId: parseCatalogId(fields.catalogId),
    releaseId: parseReleaseId(fields.releaseId),
    operationId: parseOperationId(fields.operationId),
    manifestDigest: parseManifestDigest(fields.manifestDigest),
  };
}

function parseOperationId(value: string): TypedOperationId {
  const parsed = parseTypedRecordId(value);
  if (!parsed.startsWith("operation:")) throw invalidReference("record ID is not an operation");
  return parsed as TypedOperationId;
}

/** Encode the exact, canonical, manifest-bound operation-reference wire format. */
export function encodeOperationRef(payload: OperationRefPayload): OperationRef {
  const normalized = normalizePayload(payload);
  const json = canonicalJson({
    catalogId: normalized.catalogId,
    releaseId: normalized.releaseId,
    operationId: normalized.operationId,
    manifestDigest: normalized.manifestDigest,
  });
  return `${operationRefPrefix}${encodeBase64Url(new TextEncoder().encode(json))}` as OperationRef;
}

/** Decode only canonical `opref.v1` data; authorization remains a later runtime concern. */
export function decodeOperationRef(reference: string): OperationRefPayload {
  if (!reference.startsWith(operationRefPrefix) || reference.length > maxOperationRefLength) {
    throw invalidReference("wire prefix or length is invalid");
  }
  const encoded = reference.slice(operationRefPrefix.length);
  const bytes = decodeBase64Url(encoded);
  if (bytes === null) throw invalidReference("wire encoding is invalid");
  let json: string;
  try {
    json = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw invalidReference("wire payload is not UTF-8");
  }
  let parsed: unknown;
  try {
    parsed = parseJsonStrict(json);
  } catch {
    throw invalidReference("wire payload is not strict JSON");
  }
  const payload = normalizePayload(parsed);
  let canonical: string;
  try {
    canonical = canonicalJson({
      catalogId: payload.catalogId,
      releaseId: payload.releaseId,
      operationId: payload.operationId,
      manifestDigest: payload.manifestDigest,
    });
  } catch {
    throw invalidReference("wire payload cannot be canonicalized");
  }
  if (json !== canonical) throw invalidReference("wire payload is not canonical");
  return payload;
}
