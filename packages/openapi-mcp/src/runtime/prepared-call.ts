import { sha256 } from "./digest.ts";
import { OpenApiMcpError } from "./errors.ts";
import { parseTypedRecordId } from "./references.ts";
import { canonicalJsonBounded } from "./strict-json.ts";
import type {
  ActionCardinality,
  ActionKind,
  CatalogId,
  HttpMethod,
  JsonObject,
  JsonValue,
  PaginationTokenState,
  PreparedCall,
  ReleaseId,
  Sha256,
  TypedOperationId,
} from "./types.ts";
import {
  DEFAULT_RUNTIME_LIMITS,
  PREPARED_CALL_VERSION,
  type RuntimeLimits,
} from "./versions.ts";

const preparedCallKeys = [
  "actionKind",
  "body",
  "cardinality",
  "catalogId",
  "credentialProfileDigest",
  "credentialProfileId",
  "reservedSlotsDigest",
  "headers",
  "inputDigest",
  "manifestDigest",
  "method",
  "normalizedArguments",
  "operationDigest",
  "operationId",
  "origin",
  "pageToken",
  "preparedCallDigest",
  "relativeUrl",
  "releaseId",
  "safety",
  "version",
] as const;
const inputKeys = preparedCallKeys.filter(
  (key) => key !== "inputDigest" && key !== "preparedCallDigest",
);
const digestPattern = /^[0-9a-f]{64}$/;
const headerNamePattern = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const shortIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const forbiddenJsonKeys = new Set(["__proto__", "constructor", "prototype"]);
const methods = new Set<HttpMethod>([
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
  "TRACE",
]);
const actionKinds = new Set<ActionKind>([
  "create",
  "update",
  "delete",
  "communicate",
  "authority",
  "transaction",
  "execute",
  "unknown",
]);
const forbiddenTransportHeaders = new Set([
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
  "x-auth-request-user",
  "x-auth-token",
  "x-azure-clientip",
  "x-aws-principal",
  "x-client-ip",
  "x-client-id",
  "x-client-secret",
  "x-cluster-client-ip",
  "x-envoy-external-address",
  "x-appengine-user-ip",
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
const maxHeaderCount = 64;
const maxHeaderNameLength = 128;
const maxHeaderValueLength = 4096;
const maxRelativeUrlLength = 8192;

export type PreparedCallInput = Omit<
  PreparedCall,
  "inputDigest" | "preparedCallDigest"
>;

interface ParsedPreparedCall {
  readonly version: 2;
  readonly catalogId: CatalogId;
  readonly releaseId: ReleaseId;
  readonly operationId: TypedOperationId;
  readonly operationDigest: Sha256;
  readonly manifestDigest: Sha256;
  readonly credentialProfileId: string;
  readonly credentialProfileDigest: Sha256;
  readonly reservedSlotsDigest: Sha256;
  readonly method: HttpMethod;
  readonly origin: string;
  readonly relativeUrl: string;
  readonly pageToken: string | null;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array | null;
  readonly normalizedArguments: JsonObject;
  readonly safety: "read" | "action";
  readonly actionKind: ActionKind | null;
  readonly cardinality: ActionCardinality | null;
  readonly inputDigest: Sha256;
  readonly preparedCallDigest: Sha256;
}

// An owned call exposes body copies through its public getter while retaining
// the immutable dispatch snapshot privately. Untrusted lookalikes never enter
// this map and must pass the strict own-data parser below.
const ownedPreparedCalls = new WeakMap<object, ParsedPreparedCall>();

function invalid(): OpenApiMcpError {
  return new OpenApiMcpError("INPUT_INVALID", "Prepared call is invalid");
}

function integrityFailure(): OpenApiMcpError {
  return new OpenApiMcpError(
    "INPUT_INVALID",
    "Prepared call integrity check failed",
  );
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function hasForbiddenHeaderValueCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if ((code <= 0x1f && code !== 0x09) || code === 0x7f) return true;
  }
  return false;
}

function forbiddenHeader(name: string): boolean {
  const lower = name.toLowerCase();
  return forbiddenTransportHeaders.has(lower);
}

function ownDataObject(
  value: unknown,
  keys: readonly string[] | null,
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw invalid();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw invalid();
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== "string")) throw invalid();
  const stringKeys = ownKeys as string[];
  if (
    keys !== null &&
    (stringKeys.length !== keys.length ||
      stringKeys.some((key) => !keys.includes(key)))
  ) {
    throw invalid();
  }
  for (const key of stringKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable
    ) {
      throw invalid();
    }
  }
  return value as Record<string, unknown>;
}

function ownValue(object: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (descriptor === undefined || !("value" in descriptor)) throw invalid();
  return descriptor.value;
}

function validShortId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 128 &&
    value !== "." &&
    value !== ".." &&
    shortIdPattern.test(value)
  );
}

function digest(value: unknown): Sha256 {
  if (typeof value !== "string" || !digestPattern.test(value)) throw invalid();
  return value as Sha256;
}

function operationId(value: unknown): TypedOperationId {
  if (typeof value !== "string") throw invalid();
  try {
    const parsed = parseTypedRecordId(value);
    if (!parsed.startsWith("operation:")) throw invalid();
    return parsed as TypedOperationId;
  } catch {
    throw invalid();
  }
}

function origin(value: unknown): string {
  if (typeof value !== "string" || value.length > 2048) throw invalid();
  try {
    const parsed = new URL(value);
    if (
      parsed.protocol !== "https:" ||
      parsed.username !== "" ||
      parsed.password !== "" ||
      parsed.origin !== value
    ) {
      throw invalid();
    }
    return value;
  } catch (error) {
    if (error instanceof OpenApiMcpError) throw error;
    throw invalid();
  }
}

function relativeUrl(value: unknown, callOrigin: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxRelativeUrlLength ||
    !value.startsWith("/") ||
    value.startsWith("//") ||
    value.includes("#") ||
    value.includes("\\") ||
    hasControlCharacter(value)
  ) {
    throw invalid();
  }
  try {
    if (new URL(value, callOrigin).origin !== callOrigin) throw invalid();
    return value;
  } catch (error) {
    if (error instanceof OpenApiMcpError) throw error;
    throw invalid();
  }
}

function cloneHeaders(value: unknown): Readonly<Record<string, string>> {
  const source = ownDataObject(value, null);
  const keys = Object.keys(source).sort();
  if (keys.length > maxHeaderCount) throw invalid();
  const result: Record<string, string> = Object.create(null);
  for (const key of keys) {
    const headerValue = ownValue(source, key);
    if (
      key.length === 0 ||
      key.length > maxHeaderNameLength ||
      !headerNamePattern.test(key) ||
      forbiddenHeader(key) ||
      typeof headerValue !== "string" ||
      headerValue.length > maxHeaderValueLength ||
      hasForbiddenHeaderValueCharacter(headerValue)
    ) {
      throw invalid();
    }
    const normalizedName = key.toLowerCase();
    if (Object.hasOwn(result, normalizedName)) throw invalid();
    result[normalizedName] = headerValue;
  }
  return Object.freeze(result);
}

function cloneJson(
  value: unknown,
  state: { nodes: number },
  depth = 0,
): JsonValue {
  if (state.nodes >= DEFAULT_RUNTIME_LIMITS.maxManifestRecords || depth >= 64)
    throw invalid();
  state.nodes += 1;
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw invalid();
    return value;
  }
  if (Array.isArray(value)) {
    const keys = Reflect.ownKeys(value);
    if (
      keys.length !== value.length + 1 ||
      keys.some(
        (key) =>
          key !== "length" &&
          (typeof key !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(key)),
      )
    ) {
      throw invalid();
    }
    const result: JsonValue[] = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        !descriptor.enumerable
      ) {
        throw invalid();
      }
      result.push(cloneJson(descriptor.value, state, depth + 1));
    }
    return Object.freeze(result) as unknown as JsonValue;
  }
  const source = ownDataObject(value, null);
  const result: JsonObject = Object.create(null);
  for (const key of Object.keys(source).sort()) {
    if (forbiddenJsonKeys.has(key)) throw invalid();
    result[key] = cloneJson(ownValue(source, key), state, depth + 1);
  }
  return Object.freeze(result);
}

function cloneBody(value: unknown): Uint8Array | null {
  if (value === null) return null;
  if (
    !(value instanceof Uint8Array) ||
    value.byteLength > DEFAULT_RUNTIME_LIMITS.maxArgumentsBytes
  )
    throw invalid();
  const copy = new Uint8Array(value);
  // Typed arrays with elements cannot be frozen. Preventing extension and
  // binding their byte digest still makes any later byte mutation detectable.
  Object.preventExtensions(copy);
  return copy;
}

function cardinality(value: unknown): ActionCardinality | null {
  if (value === null) return null;
  const source = ownDataObject(value, null);
  const kind = ownValue(source, "kind");
  if (kind === "bounded") {
    if (Reflect.ownKeys(source).length !== 2) throw invalid();
    const maxAffected = ownValue(source, "maxAffected");
    if (
      typeof maxAffected !== "number" ||
      !Number.isSafeInteger(maxAffected) ||
      maxAffected < 1
    ) {
      throw invalid();
    }
    return Object.freeze({ kind, maxAffected });
  }
  if (
    (kind === "single" || kind === "unbounded" || kind === "unknown") &&
    Reflect.ownKeys(source).length === 1
  ) {
    return Object.freeze({ kind });
  }
  throw invalid();
}

function parseUntrustedPreparedCall(value: unknown): ParsedPreparedCall {
  const source = ownDataObject(value, preparedCallKeys);
  const version = ownValue(source, "version");
  const catalogId = ownValue(source, "catalogId");
  const releaseId = ownValue(source, "releaseId");
  const parsedOperationId = operationId(ownValue(source, "operationId"));
  const method = ownValue(source, "method");
  const parsedOrigin = origin(ownValue(source, "origin"));
  const safety = ownValue(source, "safety");
  const pageToken = ownValue(source, "pageToken");
  const actionKind = ownValue(source, "actionKind");
  const parsedCardinality = cardinality(ownValue(source, "cardinality"));
  if (
    version !== PREPARED_CALL_VERSION ||
    !validShortId(catalogId) ||
    !validShortId(releaseId) ||
    typeof method !== "string" ||
    !methods.has(method as HttpMethod) ||
    (safety !== "read" && safety !== "action") ||
    (pageToken !== null &&
      (typeof pageToken !== "string" ||
        pageToken.length === 0 ||
        pageToken.length > 512 ||
        hasControlCharacter(pageToken) ||
        safety !== "read")) ||
    (actionKind !== null &&
      (typeof actionKind !== "string" ||
        !actionKinds.has(actionKind as ActionKind))) ||
    (safety === "read" &&
      (actionKind !== null || parsedCardinality !== null)) ||
    (safety === "action" && (actionKind === null || parsedCardinality === null))
  ) {
    throw invalid();
  }
  const normalized = cloneJson(ownValue(source, "normalizedArguments"), {
    nodes: 0,
  });
  if (
    typeof normalized !== "object" ||
    normalized === null ||
    Array.isArray(normalized)
  ) {
    throw invalid();
  }
  // This also rejects malformed Unicode and enforces the same byte limit used
  // for operation arguments before a canonical digest is computed.
  canonicalJsonBounded(normalized, {
    maxBytes: DEFAULT_RUNTIME_LIMITS.maxArgumentsBytes,
    maxDepth: DEFAULT_RUNTIME_LIMITS.maxJsonDepth,
    maxNodes: DEFAULT_RUNTIME_LIMITS.maxManifestRecords,
  });
  const credentialProfileId = ownValue(source, "credentialProfileId");
  if (!validShortId(credentialProfileId)) throw invalid();
  return {
    version,
    catalogId: catalogId as CatalogId,
    releaseId: releaseId as ReleaseId,
    operationId: parsedOperationId,
    operationDigest: digest(ownValue(source, "operationDigest")),
    manifestDigest: digest(ownValue(source, "manifestDigest")),
    credentialProfileId,
    credentialProfileDigest: digest(
      ownValue(source, "credentialProfileDigest"),
    ),
    reservedSlotsDigest: digest(ownValue(source, "reservedSlotsDigest")),
    method: method as HttpMethod,
    origin: parsedOrigin,
    relativeUrl: relativeUrl(ownValue(source, "relativeUrl"), parsedOrigin),
    pageToken: pageToken as string | null,
    headers: cloneHeaders(ownValue(source, "headers")),
    body: cloneBody(ownValue(source, "body")),
    normalizedArguments: normalized,
    safety,
    actionKind: actionKind as ActionKind | null,
    cardinality: parsedCardinality,
    inputDigest: digest(ownValue(source, "inputDigest")),
    preparedCallDigest: digest(ownValue(source, "preparedCallDigest")),
  };
}

function parsePreparedCall(value: unknown): ParsedPreparedCall {
  try {
    if (typeof value === "object" && value !== null) {
      const owned = ownedPreparedCalls.get(value);
      if (owned !== undefined) return owned;
    }
    return parseUntrustedPreparedCall(value);
  } catch {
    // Reflection and proxy traps are untrusted input. Do not expose their
    // messages or allow them to escape the stable runtime error boundary.
    throw invalid();
  }
}

function canonicalPayload(
  call: ParsedPreparedCall,
  bodyDigest: Sha256 | null,
): JsonObject {
  return {
    version: call.version,
    catalogId: call.catalogId,
    releaseId: call.releaseId,
    operationId: call.operationId,
    operationDigest: call.operationDigest,
    manifestDigest: call.manifestDigest,
    credentialProfileId: call.credentialProfileId,
    credentialProfileDigest: call.credentialProfileDigest,
    reservedSlotsDigest: call.reservedSlotsDigest,
    method: call.method,
    origin: call.origin,
    relativeUrl: call.relativeUrl,
    pageToken: call.pageToken,
    headers: call.headers as JsonObject,
    body: bodyDigest,
    normalizedArguments: call.normalizedArguments,
    safety: call.safety,
    actionKind: call.actionKind,
    cardinality: call.cardinality,
    inputDigest: call.inputDigest,
  };
}

/** Package-private defensive snapshot shared by the runtime and local codec. */
export function snapshotPaginationTokenState(
  value: unknown,
  limits: RuntimeLimits,
  now = Date.now(),
): Readonly<PaginationTokenState> {
  const data = ownDataObject(value, [
    "catalogId",
    "releaseId",
    "manifestDigest",
    "operationId",
    "inputDigest",
    "origin",
    "nextRelativeUrl",
    "expiresAt",
    "pageCount",
    "cumulativeBytes",
  ]);
  const parsedOrigin = origin(data.origin);
  const next = relativeUrl(data.nextRelativeUrl, parsedOrigin);
  const url = new URL(next, parsedOrigin);
  const expiresAt =
    typeof data.expiresAt === "string" ? Date.parse(data.expiresAt) : NaN;
  if (
    !validShortId(data.catalogId) ||
    !validShortId(data.releaseId) ||
    !Number.isFinite(now) ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= now ||
    expiresAt > now + 120_000 ||
    new Date(expiresAt).toISOString() !== data.expiresAt ||
    `${url.pathname}${url.search}` !== next ||
    !Number.isSafeInteger(data.pageCount) ||
    Number(data.pageCount) < 1 ||
    !Number.isSafeInteger(data.cumulativeBytes) ||
    Number(data.cumulativeBytes) < 0
  )
    throw invalid();
  const state = {
    catalogId: data.catalogId as CatalogId,
    releaseId: data.releaseId as ReleaseId,
    operationId: operationId(data.operationId),
    manifestDigest: digest(data.manifestDigest),
    inputDigest: digest(data.inputDigest),
    origin: parsedOrigin,
    nextRelativeUrl: next,
    expiresAt: data.expiresAt as string,
    pageCount: data.pageCount as number,
    cumulativeBytes: data.cumulativeBytes as number,
  };
  if (
    state.pageCount >= limits.maxPages ||
    state.cumulativeBytes >= limits.maxPaginationBytes
  )
    throw new OpenApiMcpError("PAGINATION_LIMIT_EXCEEDED");
  return Object.freeze(state);
}

function timingSafeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1)
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

async function digestNormalizedArguments(value: JsonObject): Promise<Sha256> {
  return await sha256("knitli.openapi-mcp.input.v1", value);
}

/** SHA-256 of raw request bytes, independent of JSON canonicalization. */
export async function digestBytes(value: Uint8Array): Promise<Sha256> {
  const copy = new Uint8Array(value);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", copy);
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("") as Sha256;
}

/** Compute the domain-separated call digest, deliberately omitting its own key. */
export async function digestPreparedCall(call: PreparedCall): Promise<Sha256> {
  const parsed = parsePreparedCall(call);
  return await sha256(
    "knitli.openapi-mcp.prepared-call.v2",
    canonicalPayload(
      parsed,
      parsed.body === null ? null : await digestBytes(parsed.body),
    ),
  );
}

/** Verify a prepared call locally; storage admission is rechecked separately. */
export async function verifyAndSnapshotPreparedCall(
  call: PreparedCall,
): Promise<Readonly<ParsedPreparedCall>> {
  const parsed = parsePreparedCall(call);
  const expectedInput = await digestNormalizedArguments(
    parsed.normalizedArguments,
  );
  const expectedCall = await sha256(
    "knitli.openapi-mcp.prepared-call.v2",
    canonicalPayload(
      parsed,
      parsed.body === null ? null : await digestBytes(parsed.body),
    ),
  );
  if (
    !timingSafeEqual(expectedInput, parsed.inputDigest) ||
    !timingSafeEqual(expectedCall, parsed.preparedCallDigest)
  ) {
    throw integrityFailure();
  }
  return parsed;
}

/** Verify a prepared call locally; storage admission is rechecked separately. */
export async function verifyPreparedCall(call: PreparedCall): Promise<void> {
  await verifyAndSnapshotPreparedCall(call);
}

/** Build an owned, detached prepared call and bind all fields to its digests. */
export async function createPreparedCall(
  input: PreparedCallInput,
): Promise<PreparedCall> {
  try {
    const source = ownDataObject(input, inputKeys);
    const provisional = {
      ...Object.fromEntries(
        inputKeys.map((key) => [key, ownValue(source, key)]),
      ),
      inputDigest: "0".repeat(64) as Sha256,
      preparedCallDigest: "0".repeat(64) as Sha256,
    } as PreparedCall;
    const parsed = parsePreparedCall(provisional);
    const inputDigest = await digestNormalizedArguments(
      parsed.normalizedArguments,
    );
    const withInput = { ...parsed, inputDigest };
    const preparedCallDigest = await sha256(
      "knitli.openapi-mcp.prepared-call.v2",
      canonicalPayload(
        withInput,
        parsed.body === null ? null : await digestBytes(parsed.body),
      ),
    );
    const snapshot = Object.freeze({ ...withInput, preparedCallDigest });
    const { body: _body, ...publicCall } = snapshot;
    const ownedCall = Object.freeze({
      ...publicCall,
      get body(): Uint8Array | null {
        return snapshot.body === null ? null : new Uint8Array(snapshot.body);
      },
    }) as PreparedCall;
    ownedPreparedCalls.set(ownedCall, snapshot);
    return ownedCall;
  } catch {
    throw invalid();
  }
}
