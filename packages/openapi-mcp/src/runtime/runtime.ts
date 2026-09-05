import { OpenApiMcpError } from "./errors.ts";
import {
  type AuthenticatedManifest,
  authenticateManifest,
  commitAuthenticatedManifestAtState,
  type ManifestTrust,
} from "./manifest.ts";
import { encodeOperationRef, parseTypedRecordId } from "./references.ts";
import { collectReferences } from "./schema-resolver.ts";
import { canonicalJson } from "./strict-json.ts";
import type {
  ActionCardinality,
  ActionKind,
  CandidateRef,
  CatalogStore,
  GenerationState,
  GenerationStore,
  JsonObject,
  OpenApiValue,
  OperationRecordV4,
  SchemaRecordV4,
  SearchInput,
  SearchResult,
  SearchResultItem,
  SearchWarning,
  TypedOperationId,
  TypedSchemaId,
} from "./types.ts";
import { verifyStoredRecord } from "./verify-record.ts";
import {
  DEFAULT_RUNTIME_LIMITS,
  type RuntimeLimits,
  resolveRuntimeLimits,
} from "./versions.ts";

export interface OpenApiRuntimeOptions {
  readonly store: CatalogStore;
  readonly trust: ManifestTrust;
  readonly generations: GenerationStore;
  readonly limits?: Partial<RuntimeLimits>;
}

function inputInvalid(message: string): OpenApiMcpError {
  return new OpenApiMcpError("INPUT_INVALID", message);
}

function upstreamUnavailable(message: string): OpenApiMcpError {
  return new OpenApiMcpError("UPSTREAM_ERROR", message, { retryable: true });
}

class GenerationStoreUnavailable extends OpenApiMcpError {
  constructor() {
    super("UPSTREAM_ERROR", "Generation state is unavailable", {
      retryable: true,
    });
  }
}

function manifestKey(catalogId: string, releaseId: string): string {
  return `${catalogId}\0${releaseId}`;
}

const maximumSearchReleases = 8;
const maximumInventorySchemaBatch = 128;
// State churn may require reproof, but one search may spend no more than the
// same eight-release compatibility envelope used for manifest authentication.
const maximumCompleteReleaseProofs = maximumSearchReleases;

interface CompleteVerificationBudget {
  proofsRemaining: number;
  bytesRemaining: number;
  workRemaining: number;
  storeCallsRemaining: number;
}

function cappedProduct(left: number, right: number): number {
  return Math.min(Number.MAX_SAFE_INTEGER, left * right);
}

function completeReleaseByteLimit(limits: RuntimeLimits): number {
  return (
    limits.maxReleaseInventoryBytes ??
    DEFAULT_RUNTIME_LIMITS.maxReleaseInventoryBytes
  );
}

function createCompleteVerificationBudget(
  limits: RuntimeLimits,
): CompleteVerificationBudget {
  const perReleaseBytes = completeReleaseByteLimit(limits);
  // Record verification, one schema-document traversal, references, and
  // bounded closure visits are charged independently.
  const perReleaseWork =
    limits.maxManifestRecords * (limits.maxSchemaRefHops + 3);
  return {
    proofsRemaining: maximumCompleteReleaseProofs,
    // All releases share one inventory envelope. Authentication may consider
    // eight releases, but search never receives eight independent 128 MiB
    // proof allocations.
    bytesRemaining: perReleaseBytes,
    workRemaining: cappedProduct(perReleaseWork, maximumSearchReleases),
    storeCallsRemaining: cappedProduct(
      limits.maxManifestRecords * 2,
      maximumSearchReleases,
    ),
  };
}

function chargeCompleteVerification(
  budget: CompleteVerificationBudget,
  charge: {
    readonly proofs?: number;
    readonly bytes?: number;
    readonly work?: number;
    readonly storeCalls?: number;
  },
): void {
  const proofs = charge.proofs ?? 0;
  const bytes = charge.bytes ?? 0;
  const work = charge.work ?? 0;
  const storeCalls = charge.storeCalls ?? 0;
  if (
    proofs > budget.proofsRemaining ||
    bytes > budget.bytesRemaining ||
    work > budget.workRemaining ||
    storeCalls > budget.storeCallsRemaining
  ) {
    throw new OpenApiMcpError(
      "RECORD_NOT_ADMITTED",
      "Search admission verification budget exhausted",
    );
  }
  budget.proofsRemaining -= proofs;
  budget.bytesRemaining -= bytes;
  budget.workRemaining -= work;
  budget.storeCallsRemaining -= storeCalls;
}

function sameGenerationState(
  left: GenerationState | null,
  right: GenerationState | null,
): boolean {
  return (
    left === right ||
    (left !== null &&
      right !== null &&
      left.revision === right.revision &&
      left.highestGeneration === right.highestGeneration &&
      left.highestManifestDigest === right.highestManifestDigest &&
      left.activeGeneration === right.activeGeneration &&
      left.activeManifestDigest === right.activeManifestDigest)
  );
}

function snapshotRows(value: unknown, maximum: number): readonly unknown[] {
  try {
    if (!Array.isArray(value)) throw new Error();
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    if (
      lengthDescriptor === undefined ||
      !("value" in lengthDescriptor) ||
      !Number.isSafeInteger(lengthDescriptor.value) ||
      lengthDescriptor.value < 0 ||
      lengthDescriptor.value > maximum
    )
      throw new Error();
    const length = lengthDescriptor.value as number;
    const keys = Reflect.ownKeys(value);
    if (
      keys.length !== length + 1 ||
      keys.some(
        (key) =>
          typeof key !== "string" ||
          (key !== "length" && !/^(0|[1-9][0-9]*)$/.test(key)),
      )
    )
      throw new Error();
    const snapshot: unknown[] = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        !descriptor.enumerable
      )
        throw new Error();
      snapshot.push(descriptor.value);
    }
    return snapshot;
  } catch {
    throw new OpenApiMcpError(
      "RECORD_NOT_ADMITTED",
      "Release inventory lookup result is invalid",
    );
  }
}

async function verifyCompleteRelease(
  store: CatalogStore,
  authenticated: AuthenticatedManifest,
  limits: RuntimeLimits,
  searchBudget: CompleteVerificationBudget,
): Promise<void> {
  chargeCompleteVerification(searchBudget, { proofs: 1 });
  // CatalogStore addresses immutable release identities but has no snapshot
  // handle. Verify the complete observed release view before admission; later
  // use-time reads remain independently verified because availability can
  // still change after this pass.
  const operationIds: TypedOperationId[] = [];
  const schemaIds: TypedSchemaId[] = [];
  for (const id of Object.keys(authenticated.manifest.records).sort()) {
    const parsed = parseTypedRecordId(id);
    if (parsed.startsWith("operation:"))
      operationIds.push(parsed as TypedOperationId);
    else schemaIds.push(parsed as TypedSchemaId);
  }

  const encoder = new TextEncoder();
  const maximumBytes = completeReleaseByteLimit(limits);
  const maximumWork = limits.maxManifestRecords * (limits.maxSchemaRefHops + 2);
  let aggregateBytes = 0;
  let aggregateWork = 0;
  const accountRecord = (record: JsonObject): number => {
    const bytes = encoder.encode(canonicalJson(record)).byteLength;
    chargeCompleteVerification(searchBudget, { bytes });
    aggregateBytes += bytes;
    aggregateWork += 1;
    if (aggregateBytes > maximumBytes || aggregateWork > maximumWork) {
      throw new OpenApiMcpError(
        "RECORD_NOT_ADMITTED",
        "Release inventory verification exceeds its aggregate limit",
      );
    }
    return bytes;
  };
  const operationRoots: TypedSchemaId[][] = [];
  for (const id of operationIds) {
    chargeCompleteVerification(searchBudget, { work: 1, storeCalls: 1 });
    const row = await store.getOperation(
      authenticated.manifest.catalogId,
      authenticated.manifest.releaseId,
      id,
    );
    if (row === null) {
      throw new OpenApiMcpError(
        "RECORD_NOT_ADMITTED",
        "Release inventory operation is missing",
      );
    }
    const operation = await verifyStoredRecord(authenticated, row, limits);
    if (!operation.id.startsWith("operation:") || operation.id !== id) {
      throw new OpenApiMcpError(
        "RECORD_DIGEST_MISMATCH",
        "Release inventory operation identity does not match",
      );
    }
    accountRecord(operation as unknown as JsonObject);
    operationRoots.push(
      [...new Set(operation.schemaIds)].sort() as TypedSchemaId[],
    );
  }

  const schemaBatchSize = Math.max(
    1,
    Math.min(
      maximumInventorySchemaBatch,
      Math.floor(limits.maxSchemaClosureBytes / limits.maxRecordBytes),
    ),
  );
  const schemas = new Map<
    TypedSchemaId,
    { readonly record: SchemaRecordV4; readonly bytes: number }
  >();
  let offset = 0;
  while (offset < schemaIds.length) {
    const ids: TypedSchemaId[] = [];
    let requestBytes = 0;
    while (offset < schemaIds.length && ids.length < schemaBatchSize) {
      const id = schemaIds[offset];
      const idBytes = encoder.encode(id).byteLength;
      if (
        idBytes > limits.maxSchemaClosureBytes ||
        (ids.length > 0 &&
          requestBytes + idBytes > limits.maxSchemaClosureBytes)
      )
        break;
      ids.push(id);
      requestBytes += idBytes;
      offset += 1;
    }
    if (ids.length === 0) {
      throw new OpenApiMcpError(
        "RECORD_NOT_ADMITTED",
        "Release inventory schema request exceeds its byte limit",
      );
    }
    chargeCompleteVerification(searchBudget, {
      work: ids.length,
      storeCalls: 1,
    });
    const result = await store.getSchemas(
      authenticated.manifest.catalogId,
      authenticated.manifest.releaseId,
      ids,
    );
    const rows = snapshotRows(result, ids.length);
    const verified = await Promise.all(
      rows.map((row) =>
        verifyStoredRecord(authenticated, row as never, limits),
      ),
    );
    const returned = new Set(verified.map((record) => record.id));
    if (
      returned.size !== ids.length ||
      verified.length !== ids.length ||
      ids.some((id) => !returned.has(id)) ||
      verified.some((record) => !record.id.startsWith("schema:"))
    ) {
      throw new OpenApiMcpError(
        "RECORD_NOT_ADMITTED",
        "Release inventory schema is missing or ambiguous",
      );
    }
    for (const record of verified) {
      const schema = record as SchemaRecordV4;
      schemas.set(schema.id, {
        record: schema,
        bytes: accountRecord(schema as unknown as JsonObject),
      });
    }
  }

  const schemaReferences = new Map<TypedSchemaId, readonly TypedSchemaId[]>();
  for (const [id, { record }] of schemas) {
    const references = collectReferences(record.schema);
    chargeCompleteVerification(searchBudget, {
      work: references.length + 1,
    });
    schemaReferences.set(id, references);
    aggregateWork += references.length;
    if (
      aggregateWork > maximumWork ||
      references.some((reference) => !schemas.has(reference))
    ) {
      throw new OpenApiMcpError(
        "RECORD_NOT_ADMITTED",
        "Release schema graph is incomplete or exceeds its work limit",
      );
    }
  }

  const verifiedClosures = new Set<string>();
  for (const roots of operationRoots) {
    const cacheKey = roots.join("\0");
    if (verifiedClosures.has(cacheKey)) continue;
    let frontier = roots;
    const visited = new Set<TypedSchemaId>();
    let closureBytes = 0;
    let hop = 0;
    while (frontier.length > 0) {
      if (hop > limits.maxSchemaRefHops) {
        throw new OpenApiMcpError(
          "SCHEMA_RESOLUTION_LIMIT",
          "Schema reference hop limit exceeded",
        );
      }
      const next = new Set<TypedSchemaId>();
      for (const id of frontier) {
        if (visited.has(id)) continue;
        const schema = schemas.get(id);
        if (schema === undefined) {
          throw new OpenApiMcpError(
            "RECORD_NOT_ADMITTED",
            "Operation schema root is not in the verified inventory",
          );
        }
        visited.add(id);
        closureBytes += schema.bytes;
        aggregateWork += 1;
        chargeCompleteVerification(searchBudget, { work: 1 });
        if (
          closureBytes > limits.maxSchemaClosureBytes ||
          aggregateWork > maximumWork
        ) {
          throw new OpenApiMcpError(
            "SCHEMA_RESOLUTION_LIMIT",
            "Schema closure exceeds its aggregate limit",
          );
        }
        for (const reference of schemaReferences.get(id) ?? []) {
          if (!visited.has(reference)) next.add(reference);
        }
      }
      frontier = [...next].sort();
      hop += 1;
    }
    verifiedClosures.add(cacheKey);
  }
}

const markdownCharacters = new Map([
  ["#", "＃"],
  ["`", "ˋ"],
  ["*", "＊"],
  [">", "›"],
  ["<", "‹"],
  ["[", "【"],
  ["]", "】"],
]);
const unsafeUnicodeCategory = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

function safeText(value: string, maximum: number): string {
  let safe = "";
  // Strip control, format, and Unicode line/paragraph separator code points.
  // Iteration is by code point so supplementary-plane format controls cannot
  // hide behind a surrogate pair.
  for (const character of value) {
    const replacement = unsafeUnicodeCategory.test(character)
      ? " "
      : (markdownCharacters.get(character) ?? character);
    if (safe.length + replacement.length > maximum) break;
    safe += replacement;
  }
  return safe;
}

function safeSummary(value: string | null): string | null {
  return value === null ? null : safeText(value, 600);
}

function inputOutline(operation: OperationRecordV4): JsonObject {
  const outline: Record<string, unknown> = {
    path: [],
    query: [],
    headers: [],
    body:
      operation.requestBody?.content
        .slice(0, 16)
        .map((entry) => safeText(entry.mediaType, 128)) ?? [],
  };
  for (const parameter of operation.parameters) {
    const item = {
      name: safeText(parameter.name, 128),
      required: parameter.required,
    };
    if (parameter.in === "path" && (outline.path as unknown[]).length < 32)
      (outline.path as unknown[]).push(item);
    if (parameter.in === "query" && (outline.query as unknown[]).length < 32)
      (outline.query as unknown[]).push(item);
    if (parameter.in === "header" && (outline.headers as unknown[]).length < 32)
      (outline.headers as unknown[]).push(item);
  }
  return outline as JsonObject;
}

function classification(operation: OperationRecordV4): {
  safety: "read" | "action";
  actionKind: ActionKind | null;
  cardinality: ActionCardinality | null;
} {
  const batch =
    operation.path.toLowerCase().includes("$batch") ||
    /(?:^|[._-])batch(?:$|[._-])/i.test(operation.operationId);
  if ((operation.method === "GET" || operation.method === "HEAD") && !batch) {
    return { safety: "read", actionKind: null, cardinality: null };
  }
  return {
    safety: "action",
    actionKind: "unknown",
    cardinality: { kind: "unknown" },
  };
}

function safeJsonValue(
  value: OpenApiValue,
  state: { nodes: number },
  depth = 0,
): OpenApiValue | undefined {
  if (state.nodes >= 64 || depth > 4) return undefined;
  state.nodes += 1;
  if (typeof value === "string") return safeText(value, 128);
  if (value === null || typeof value === "boolean" || typeof value === "number")
    return value;
  if (Array.isArray(value)) {
    const result: OpenApiValue[] = [];
    for (const entry of value.slice(0, 32)) {
      const safe = safeJsonValue(entry, state, depth + 1);
      if (safe !== undefined) result.push(safe);
    }
    return result;
  }
  const result: JsonObject = {};
  for (const key of Object.keys(value).sort().slice(0, 32)) {
    const safe = safeJsonValue(value[key], state, depth + 1);
    if (safe !== undefined) result[safeText(key, 64)] = safe;
  }
  return result;
}

function advisoryPermissions(advisory: JsonObject): JsonObject {
  const safe: JsonObject = {};
  const state = { nodes: 0 };
  for (const key of [
    "permissionConfidence",
    "permissionIds",
    "permissions",
    "privilegeLevel",
    "requiredPermissions",
    "scopes",
  ]) {
    if (Object.hasOwn(advisory, key)) {
      const value = safeJsonValue(advisory[key], state);
      if (value !== undefined) safe[key] = value;
    }
  }
  return safe;
}

function warning(error: unknown): SearchWarning {
  if (error instanceof OpenApiMcpError) {
    if (error.code === "RECORD_DIGEST_MISMATCH") {
      return {
        code: "RECORD_DIGEST_MISMATCH",
        message: "Search candidate rejected",
      };
    }
    if (error.code === "RECORD_NOT_ADMITTED") {
      return {
        code: "RECORD_NOT_ADMITTED",
        message: "Search candidate not admitted",
      };
    }
    if (error.code.startsWith("MANIFEST_")) {
      return {
        code: error.code,
        message: "Search candidate manifest rejected",
      };
    }
  }
  return {
    code: "UPSTREAM_ERROR",
    message: "Search candidate unavailable",
  };
}

function normalizeCandidate(value: unknown): CandidateRef {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new OpenApiMcpError(
      "RECORD_DIGEST_MISMATCH",
      "Search candidate shape is invalid",
    );
  }
  const prototype = Object.getPrototypeOf(value);
  const expected = ["catalogId", "operationId", "releaseId"];
  const keys = Reflect.ownKeys(value).sort();
  if (
    (prototype !== null && prototype !== Object.prototype) ||
    keys.length !== expected.length ||
    keys.some((key, index) => key !== expected[index])
  ) {
    throw new OpenApiMcpError(
      "RECORD_DIGEST_MISMATCH",
      "Search candidate shape is invalid",
    );
  }
  const snapshot: Record<string, string> = Object.create(null);
  for (const key of expected) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable ||
      typeof descriptor.value !== "string"
    ) {
      throw new OpenApiMcpError(
        "RECORD_DIGEST_MISMATCH",
        "Search candidate fields are invalid",
      );
    }
    snapshot[key] = descriptor.value;
  }
  // The operation-ref codec owns the public identity grammar. Encoding a
  // detached snapshot validates every segment before it can drive a lookup.
  encodeOperationRef({
    catalogId: snapshot.catalogId as CandidateRef["catalogId"],
    releaseId: snapshot.releaseId as CandidateRef["releaseId"],
    operationId: snapshot.operationId as CandidateRef["operationId"],
    manifestDigest: "0".repeat(64) as never,
  });
  return Object.freeze({
    catalogId: snapshot.catalogId as CandidateRef["catalogId"],
    releaseId: snapshot.releaseId as CandidateRef["releaseId"],
    operationId: snapshot.operationId as CandidateRef["operationId"],
  });
}

function snapshotCandidates(
  value: unknown,
  maximum: number,
): readonly unknown[] {
  try {
    if (!Array.isArray(value)) throw new Error();
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    if (
      lengthDescriptor === undefined ||
      !("value" in lengthDescriptor) ||
      !Number.isSafeInteger(lengthDescriptor.value) ||
      lengthDescriptor.value < 0 ||
      lengthDescriptor.value > maximum
    )
      throw new Error();
    const length = lengthDescriptor.value as number;
    const keys = Reflect.ownKeys(value);
    if (
      keys.length !== length + 1 ||
      keys.some(
        (key) =>
          typeof key !== "string" ||
          (key !== "length" && !/^(0|[1-9][0-9]*)$/.test(key)),
      )
    )
      throw new Error();
    const snapshot: unknown[] = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        !descriptor.enumerable
      )
        throw new Error();
      snapshot.push(descriptor.value);
    }
    return snapshot;
  } catch {
    throw new OpenApiMcpError(
      "RECORD_DIGEST_MISMATCH",
      "Search candidate result is invalid",
    );
  }
}

function snapshotSearchInput(value: unknown): SearchInput {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value))
      throw new Error();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== null && prototype !== Object.prototype) throw new Error();
    const keys = Reflect.ownKeys(value).sort();
    const allowed = ["api", "limit", "query"];
    if (
      keys.some((key) => typeof key !== "string" || !allowed.includes(key)) ||
      !keys.includes("query")
    )
      throw new Error();
    const snapshot: Record<string, unknown> = Object.create(null);
    for (const key of keys as string[]) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        !descriptor.enumerable
      )
        throw new Error();
      snapshot[key] = descriptor.value;
    }
    return Object.freeze(snapshot) as unknown as SearchInput;
  } catch {
    throw inputInvalid("Search input is invalid");
  }
}

function validateSearchInput(value: unknown, limits: RuntimeLimits) {
  const input = snapshotSearchInput(value);
  if (
    typeof input.query !== "string" ||
    input.query.trim().length === 0 ||
    input.query.length > 1024
  )
    throw inputInvalid("Search input is invalid");
  if (
    input.api !== undefined &&
    (typeof input.api !== "string" ||
      input.api.length === 0 ||
      input.api.length > 128 ||
      input.api === "." ||
      input.api === ".." ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(input.api))
  )
    throw inputInvalid("Search input is invalid");
  const limit =
    input.limit ??
    Math.min(limits.defaultSearchResults, limits.maxSearchResults);
  if (
    !Number.isSafeInteger(limit) ||
    limit < 1 ||
    limit > limits.maxSearchResults
  ) {
    throw inputInvalid("Search input is invalid");
  }
  return { api: input.api, limit, query: input.query };
}

/** Construct the portable verified-search portion of the runtime. */
export function createOpenApiRuntime(options: OpenApiRuntimeOptions): {
  search(input: SearchInput): Promise<SearchResult>;
} {
  const limits = resolveRuntimeLimits(options.limits);
  const committingGenerations: GenerationStore = {
    get(catalogId, issuer) {
      return options.generations.get(catalogId, issuer);
    },
    async accept(catalogId, issuer, transition) {
      try {
        return await options.generations.accept(catalogId, issuer, transition);
      } catch {
        throw new GenerationStoreUnavailable();
      }
    },
  };

  return {
    async search(input: SearchInput): Promise<SearchResult> {
      const query = validateSearchInput(input, limits);
      const completeVerificationBudget =
        createCompleteVerificationBudget(limits);
      const emptyBytes = new TextEncoder().encode(
        canonicalJson({ operations: [], warnings: [] }),
      ).length;
      if (emptyBytes > limits.maxResponseBytes) {
        throw new OpenApiMcpError(
          "RESPONSE_LIMIT_EXCEEDED",
          "Search response limit is too small",
        );
      }
      const candidateLimit = Math.min(query.limit * 3, 150);
      let candidateResult: unknown;
      try {
        candidateResult = await options.store.searchCandidates({
          ...query,
          limit: candidateLimit,
        });
      } catch {
        throw upstreamUnavailable("Search candidate lookup is unavailable");
      }
      const candidates = snapshotCandidates(candidateResult, candidateLimit);
      const operations: Array<{
        readonly admission: {
          readonly catalogId: string;
          readonly releaseId: string;
          readonly issuer: string;
          readonly generation: number;
          readonly digest: string;
        };
        readonly id: string;
        readonly item: SearchResultItem;
        readonly rank: number;
      }> = [];
      const warnings: SearchWarning[] = [];
      const seen = new Set<string>();
      const manifests = new Map<
        string,
        { authenticated: AuthenticatedManifest }
      >();
      const failedManifests = new Set<string>();
      let releaseAttempts = 0;
      const authenticateCandidateRelease = async (
        catalogId: CandidateRef["catalogId"],
        releaseId: CandidateRef["releaseId"],
      ): Promise<{
        authenticated: AuthenticatedManifest;
      } | null> => {
        const key = manifestKey(catalogId, releaseId);
        const cached = manifests.get(key);
        if (cached !== undefined) return cached;
        if (failedManifests.has(key)) {
          throw new OpenApiMcpError(
            "RECORD_NOT_ADMITTED",
            "Search candidate manifest was already rejected",
          );
        }
        if (releaseAttempts >= maximumSearchReleases) {
          return null;
        }
        releaseAttempts += 1;
        try {
          const envelope = await options.store.getManifest(
            catalogId,
            releaseId,
          );
          const authenticated = await authenticateManifest(
            envelope,
            options.trust,
            limits,
          );
          if (
            authenticated.manifest.catalogId !== catalogId ||
            authenticated.manifest.releaseId !== releaseId
          ) {
            throw new OpenApiMcpError(
              "RECORD_NOT_ADMITTED",
              "Search candidate release identity does not match its manifest",
            );
          }
          const entry = { authenticated };
          manifests.set(key, entry);
          return entry;
        } catch (error) {
          failedManifests.add(key);
          throw error;
        }
      };
      const responseFits = (
        items: readonly SearchResultItem[],
        candidateWarnings: readonly SearchWarning[],
      ): boolean =>
        new TextEncoder().encode(
          canonicalJson({
            operations: [...items],
            warnings: [...candidateWarnings],
          } as unknown as JsonObject),
        ).length <= limits.maxResponseBytes;
      const limitWarning: SearchWarning = {
        code: "RESPONSE_LIMIT_EXCEEDED",
        message: "Search response limit reached",
      };
      const addWarning = (candidateWarning: SearchWarning): boolean => {
        if (!responseFits([], [...warnings, candidateWarning, limitWarning]))
          return false;
        warnings.push(candidateWarning);
        return true;
      };
      let responseLimited = false;
      let admissionLimited = false;

      for (const [rank, rawCandidate] of candidates.entries()) {
        let candidate: CandidateRef;
        try {
          candidate = normalizeCandidate(rawCandidate);
        } catch (error) {
          if (!addWarning(warning(error))) responseLimited = true;
          continue;
        }
        if (
          query.api !== undefined &&
          !candidate.operationId.startsWith(`operation:${query.api}:`)
        ) {
          if (
            !addWarning(warning(new OpenApiMcpError("RECORD_DIGEST_MISMATCH")))
          )
            responseLimited = true;
          continue;
        }
        const key = manifestKey(candidate.catalogId, candidate.releaseId);
        const identity = `${key}\0${candidate.operationId}`;
        if (seen.has(identity)) continue;
        seen.add(identity);
        try {
          const entry = await authenticateCandidateRelease(
            candidate.catalogId,
            candidate.releaseId,
          );
          if (entry === null) {
            admissionLimited = true;
            continue;
          }
          const row = await options.store.getOperation(
            candidate.catalogId,
            candidate.releaseId,
            candidate.operationId,
          );
          if (row === null) {
            throw new OpenApiMcpError(
              "RECORD_NOT_ADMITTED",
              "Search candidate record is missing",
            );
          }
          const operation = await verifyStoredRecord(
            entry.authenticated,
            row,
            limits,
          );
          if (operation.id !== candidate.operationId) {
            throw new OpenApiMcpError(
              "RECORD_DIGEST_MISMATCH",
              "Search candidate identity does not match its record",
            );
          }
          if (query.api !== undefined && operation.api !== query.api) {
            throw new OpenApiMcpError(
              "RECORD_DIGEST_MISMATCH",
              "Search candidate API does not match its filter",
            );
          }
          const runtimeClassification = classification(operation);
          const retained = {
            admission: {
              catalogId: entry.authenticated.manifest.catalogId,
              releaseId: entry.authenticated.manifest.releaseId,
              issuer: entry.authenticated.manifest.issuer,
              generation: entry.authenticated.manifest.generation,
              digest: entry.authenticated.manifestDigest,
            },
            id: `${candidate.catalogId}\0${candidate.releaseId}\0${operation.id}`,
            rank,
            item: {
              operation: encodeOperationRef({
                catalogId: candidate.catalogId,
                releaseId: candidate.releaseId,
                operationId: operation.id,
                manifestDigest: entry.authenticated.manifestDigest,
              }),
              summary: safeSummary(operation.summary),
              inputOutline: inputOutline(operation),
              ...runtimeClassification,
              deprecated: operation.deprecated,
              advisory: advisoryPermissions(operation.advisory),
            },
          };
          operations.push(retained);
        } catch (error) {
          if (!addWarning(warning(error))) responseLimited = true;
        }
      }

      if (admissionLimited) {
        if (
          !addWarning({
            code: "RECORD_NOT_ADMITTED",
            message: "Search release admission limit reached",
          })
        )
          responseLimited = true;
      }

      const stagedOperations = operations.splice(0);
      const warnedOperations = new Set<string>();
      const warnOperations = (
        candidates: typeof stagedOperations,
        error: unknown,
      ): void => {
        for (const candidate of candidates) {
          if (warnedOperations.has(candidate.id)) continue;
          warnedOperations.add(candidate.id);
          if (!addWarning(warning(error))) responseLimited = true;
        }
      };
      const groups = new Map<string, typeof stagedOperations>();
      for (const staged of stagedOperations) {
        const groupKey = `${staged.admission.catalogId}\0${staged.admission.issuer}`;
        const group = groups.get(groupKey);
        if (group === undefined) groups.set(groupKey, [staged]);
        else group.push(staged);
      }

      for (const group of groups.values()) {
        const byGeneration = new Map<
          number,
          Map<string, typeof stagedOperations>
        >();
        for (const staged of group) {
          let releases = byGeneration.get(staged.admission.generation);
          if (releases === undefined) {
            releases = new Map();
            byGeneration.set(staged.admission.generation, releases);
          }
          const release = releases.get(staged.admission.digest);
          if (release === undefined)
            releases.set(staged.admission.digest, [staged]);
          else release.push(staged);
        }

        let selected: typeof stagedOperations | undefined;
        const generations = [...byGeneration.keys()].sort(
          (left, right) => right - left,
        );
        let selectionSettled = false;
        const initialTransitionKinds = new Map<string, "normal" | "rollback">();
        for (
          let selectionAttempt = 0;
          selectionAttempt < 32;
          selectionAttempt += 1
        ) {
          let capturedState: GenerationState | null;
          try {
            capturedState = await options.generations.get(
              group[0].admission.catalogId as CandidateRef["catalogId"],
              group[0].admission.issuer,
            );
          } catch {
            throw upstreamUnavailable("Generation state is unavailable");
          }
          const attemptWarnings: Array<{
            readonly candidates: typeof stagedOperations;
            readonly error: unknown;
          }> = [];
          let restartSelection = false;
          for (const generation of generations) {
            const releases = byGeneration.get(generation);
            if (releases === undefined) continue;
            let alreadyActive = false;
            let candidates: typeof stagedOperations | undefined;
            if (releases.size !== 1) {
              const activeDigest =
                capturedState?.activeGeneration === generation
                  ? capturedState.activeManifestDigest
                  : undefined;
              candidates =
                activeDigest === undefined
                  ? undefined
                  : releases.get(activeDigest);
              alreadyActive = candidates !== undefined;
              if (candidates === undefined) {
                for (const conflicting of releases.values())
                  attemptWarnings.push({
                    candidates: conflicting,
                    error: new OpenApiMcpError("MANIFEST_GENERATION_CONFLICT"),
                  });
                continue;
              }
            } else {
              candidates = releases.values().next().value;
            }
            if (candidates === undefined || candidates.length === 0) continue;
            const admission = candidates[0].admission;
            const key = manifestKey(admission.catalogId, admission.releaseId);
            const entry = manifests.get(key);
            if (entry === undefined) continue;
            try {
              if (alreadyActive) {
                await verifyCompleteRelease(
                  options.store,
                  entry.authenticated,
                  limits,
                  completeVerificationBudget,
                );
                let currentState: GenerationState | null;
                try {
                  currentState = await options.generations.get(
                    admission.catalogId as CandidateRef["catalogId"],
                    admission.issuer,
                  );
                } catch {
                  throw new GenerationStoreUnavailable();
                }
                if (!sameGenerationState(capturedState, currentState)) {
                  restartSelection = true;
                  break;
                }
              } else {
                await verifyCompleteRelease(
                  options.store,
                  entry.authenticated,
                  limits,
                  completeVerificationBudget,
                );
                const transitionKind =
                  capturedState !== null &&
                  admission.generation < capturedState.highestGeneration
                    ? "rollback"
                    : "normal";
                const initialTransitionKind = initialTransitionKinds.get(
                  admission.digest,
                );
                if (initialTransitionKind === undefined) {
                  initialTransitionKinds.set(admission.digest, transitionKind);
                } else if (initialTransitionKind !== transitionKind) {
                  throw new OpenApiMcpError(
                    "MANIFEST_GENERATION_CONFLICT",
                    "Generation state changed the selected transition kind",
                  );
                }
                const admitted = await commitAuthenticatedManifestAtState(
                  entry.authenticated,
                  options.trust,
                  committingGenerations,
                  capturedState,
                );
                if (admitted === null) {
                  restartSelection = true;
                  break;
                }
              }
              selected = candidates;
              operations.push(...candidates);
              break;
            } catch (error) {
              if (error instanceof GenerationStoreUnavailable) throw error;
              failedManifests.add(key);
              attemptWarnings.push({ candidates, error });
            }
          }

          if (restartSelection) {
            selected = undefined;
            continue;
          }
          if (selected === undefined) {
            let currentState: GenerationState | null;
            try {
              currentState = await options.generations.get(
                group[0].admission.catalogId as CandidateRef["catalogId"],
                group[0].admission.issuer,
              );
            } catch {
              throw upstreamUnavailable("Generation state is unavailable");
            }
            if (!sameGenerationState(capturedState, currentState)) continue;
          }
          for (const pending of attemptWarnings)
            warnOperations(pending.candidates, pending.error);
          selectionSettled = true;
          break;
        }
        if (!selectionSettled) {
          warnOperations(
            group,
            new OpenApiMcpError(
              "MANIFEST_GENERATION_CONFLICT",
              "Generation state changed too many times; retry search",
            ),
          );
        }

        const selectedSet = new Set(selected ?? []);
        for (const staged of group) {
          if (selectedSet.has(staged) || warnedOperations.has(staged.id))
            continue;
          warnOperations([staged], new OpenApiMcpError("RECORD_NOT_ADMITTED"));
        }
      }

      const finalStates = new Map<
        string,
        {
          activeGeneration: number;
          activeManifestDigest: string;
        } | null
      >();
      for (const { admission } of operations) {
        const key = `${admission.catalogId}\0${admission.issuer}`;
        if (finalStates.has(key)) continue;
        try {
          const state = await options.generations.get(
            admission.catalogId as CandidateRef["catalogId"],
            admission.issuer,
          );
          finalStates.set(
            key,
            state === null
              ? null
              : {
                  activeGeneration: state.activeGeneration,
                  activeManifestDigest: state.activeManifestDigest,
                },
          );
        } catch {
          throw upstreamUnavailable("Generation state is unavailable");
        }
      }

      for (let index = operations.length - 1; index >= 0; index -= 1) {
        const admission = operations[index].admission;
        const state = finalStates.get(
          `${admission.catalogId}\0${admission.issuer}`,
        );
        if (
          state === undefined ||
          state === null ||
          state.activeGeneration !== admission.generation ||
          state.activeManifestDigest !== admission.digest
        ) {
          operations.splice(index, 1);
          if (!addWarning(warning(new OpenApiMcpError("RECORD_NOT_ADMITTED"))))
            responseLimited = true;
        }
      }

      operations.sort((left, right) => {
        if (left.item.deprecated !== right.item.deprecated) {
          return left.item.deprecated ? 1 : -1;
        }
        if (left.rank !== right.rank) return left.rank - right.rank;
        return left.id < right.id ? -1 : left.id > right.id ? 1 : 0;
      });
      const returnedOperations = operations.slice(0, query.limit);
      if (
        !responseFits(
          returnedOperations.map(({ item }) => item),
          warnings,
        )
      )
        responseLimited = true;
      if (responseLimited) {
        while (
          !responseFits(
            returnedOperations.map(({ item }) => item),
            [...warnings, limitWarning],
          )
        ) {
          if (returnedOperations.pop() === undefined) {
            throw new OpenApiMcpError(
              "RESPONSE_LIMIT_EXCEEDED",
              "Search response limit is too small",
            );
          }
        }
        warnings.push(limitWarning);
      }
      return {
        operations: returnedOperations.map(({ item }) => item),
        warnings,
      };
    },
  };
}
