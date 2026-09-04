import { OpenApiMcpError } from "./errors.ts";
import {
  type AdmittedManifest,
  type AuthenticatedManifest,
  admitAuthenticatedManifest,
  authenticateManifest,
  type ManifestTrust,
} from "./manifest.ts";
import { encodeOperationRef } from "./references.ts";
import { canonicalJson } from "./strict-json.ts";
import type {
  ActionCardinality,
  ActionKind,
  CandidateRef,
  CatalogStore,
  GenerationStore,
  JsonObject,
  OpenApiValue,
  OperationRecordV4,
  SearchInput,
  SearchResult,
  SearchResultItem,
  SearchWarning,
} from "./types.ts";
import { verifyStoredRecord } from "./verify-record.ts";
import { type RuntimeLimits, resolveRuntimeLimits } from "./versions.ts";

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

function manifestKey(catalogId: string, releaseId: string): string {
  return `${catalogId}\0${releaseId}`;
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
  const limit = input.limit ?? limits.defaultSearchResults;
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

  return {
    async search(input: SearchInput): Promise<SearchResult> {
      const query = validateSearchInput(input, limits);
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
        { authenticated: AuthenticatedManifest; admitted?: AdmittedManifest }
      >();
      const failedManifests = new Set<string>();
      let admissionAttempts = 0;
      const authenticateCandidateRelease = async (
        catalogId: CandidateRef["catalogId"],
        releaseId: CandidateRef["releaseId"],
      ): Promise<{
        authenticated: AuthenticatedManifest;
        admitted?: AdmittedManifest;
      }> => {
        const key = manifestKey(catalogId, releaseId);
        const cached = manifests.get(key);
        if (cached !== undefined) return cached;
        if (failedManifests.has(key)) {
          throw new OpenApiMcpError(
            "RECORD_NOT_ADMITTED",
            "Search candidate manifest was already rejected",
          );
        }
        if (admissionAttempts >= 8) {
          throw new OpenApiMcpError(
            "RECORD_NOT_ADMITTED",
            "Search release admission limit reached",
          );
        }
        admissionAttempts += 1;
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
          if (manifests.size >= 4) {
            const oldest = manifests.keys().next().value;
            if (oldest !== undefined) manifests.delete(oldest);
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
          let admitted = entry.admitted;
          if (admitted === undefined) {
            try {
              admitted = await admitAuthenticatedManifest(
                entry.authenticated,
                options.trust,
                options.generations,
              );
            } catch (error) {
              failedManifests.add(key);
              manifests.delete(key);
              throw error;
            }
            entry.admitted = admitted;
          }
          const runtimeClassification = classification(operation);
          const retained = {
            admission: {
              catalogId: admitted.manifest.catalogId,
              issuer: admitted.manifest.issuer,
              generation: admitted.manifest.generation,
              digest: admitted.manifestDigest,
            },
            id: `${candidate.catalogId}\0${candidate.releaseId}\0${operation.id}`,
            rank,
            item: {
              operation: encodeOperationRef({
                catalogId: candidate.catalogId,
                releaseId: candidate.releaseId,
                operationId: operation.id,
                manifestDigest: admitted.manifestDigest,
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
          if (
            error instanceof OpenApiMcpError &&
            error.message === "Search release admission limit reached"
          ) {
            admissionLimited = true;
            break;
          }
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
