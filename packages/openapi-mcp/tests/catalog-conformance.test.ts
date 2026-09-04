import { expect, test } from "bun:test";
import {
  type CatalogStoreFactoryResult,
  type ConformanceTestAdapter,
  RUNTIME_CONFORMANCE_FIXTURE as fixture,
  runRuntimeConformanceSuite,
} from "../src/conformance/index.ts";
import type { RuntimeConformanceScenario } from "../src/conformance/runtime-suite.ts";
import {
  CATALOG_STORE_PUBLIC_MESSAGES,
  OpenApiMcpError,
  parseTypedRecordId,
} from "../src/runtime/index.ts";

const adapter: ConformanceTestAdapter = {
  test,
  equal: (actual, expected, message) =>
    expect(actual, message).toEqual(expected),
  deepEqual: (actual, expected, message) =>
    expect(actual, message).toEqual(expected),
  ok: (value, message) => expect(value, message).toBeTruthy(),
  rejects: async (run, code) => {
    await expect(run()).rejects.toMatchObject({ code });
  },
};

test("the exported conformance fixture is deeply frozen", () => {
  expect(Object.isFrozen(fixture)).toBe(true);
  expect(Object.isFrozen(fixture.operationA.record)).toBe(true);
  expect(Object.isFrozen(fixture.operationA.record.schemaIds)).toBe(true);
  expect(Object.isFrozen(fixture.schemasA[0])).toBe(true);
  expect(Object.isFrozen(fixture.schemasA[0]?.record)).toBe(true);
  expect(Object.isFrozen(fixture.schemasA[0]?.record.schema)).toBe(true);
});

test("the shared suite registers candidate transport poison scenarios", () => {
  const registered: string[] = [];
  const registrationAdapter: ConformanceTestAdapter = {
    ...adapter,
    test: (name) => {
      registered.push(name);
    },
  };

  runRuntimeConformanceSuite(inMemoryFactory, {
    testAdapter: registrationAdapter,
  });

  expect(registered).toEqual(
    expect.arrayContaining([
      "catalog rejects malformed candidate transport rows",
      "catalog rejects candidate transport rows with non-operation IDs",
      "catalog rejects cross-API candidate transport rows",
    ]),
  );
});

function invalidIdentity(message: string): never {
  throw new OpenApiMcpError("INPUT_INVALID", message);
}

function normalizedDriverError(
  error: unknown,
  code: "INPUT_INVALID" | "MANIFEST_INVALID" | "RECORD_DIGEST_MISMATCH",
  message: string,
): never {
  void error;
  throw new OpenApiMcpError(code, message);
}

function plainSearchSnapshot(value: unknown): {
  readonly query: unknown;
  readonly api?: unknown;
  readonly limit: unknown;
} {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return invalidIdentity(CATALOG_STORE_PUBLIC_MESSAGES.searchQueryInvalid);
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.some(
      (key) =>
        typeof key !== "string" ||
        (key !== "query" && key !== "api" && key !== "limit"),
    )
  ) {
    return invalidIdentity(CATALOG_STORE_PUBLIC_MESSAGES.searchQueryInvalid);
  }
  const data = (key: "query" | "api" | "limit", required: boolean) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined && !required) return undefined;
    if (!descriptor?.enumerable || !("value" in descriptor)) {
      return invalidIdentity(CATALOG_STORE_PUBLIC_MESSAGES.searchQueryInvalid);
    }
    return descriptor.value;
  };
  const query = data("query", true);
  const api = data("api", false);
  const limit = data("limit", true);
  return api === undefined ? { query, limit } : { query, api, limit };
}

function schemaIdsSnapshot(value: unknown): readonly string[] {
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype
  ) {
    return invalidIdentity(CATALOG_STORE_PUBLIC_MESSAGES.schemaRequestInvalid);
  }
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  if (
    lengthDescriptor === undefined ||
    !("value" in lengthDescriptor) ||
    !Number.isSafeInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < 0
  ) {
    return invalidIdentity(CATALOG_STORE_PUBLIC_MESSAGES.schemaRequestInvalid);
  }
  const length = lengthDescriptor.value as number;
  const allowedKeys = new Set<string>(["length"]);
  for (let index = 0; index < length; index += 1) {
    allowedKeys.add(String(index));
  }
  if (
    Reflect.ownKeys(value).some(
      (key) => typeof key !== "string" || !allowedKeys.has(key),
    )
  ) {
    return invalidIdentity(CATALOG_STORE_PUBLIC_MESSAGES.schemaRequestInvalid);
  }
  const result: string[] = [];
  for (let index = 0; index < length; index += 1) {
    const key = String(index);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !("value" in descriptor)) {
      return invalidIdentity(
        CATALOG_STORE_PUBLIC_MESSAGES.schemaRequestInvalid,
      );
    }
    result.push(schemaIdentity(descriptor.value));
  }
  return result;
}

function segment(value: unknown, message: string): string {
  if (typeof value !== "string") return invalidIdentity(message);
  try {
    parseTypedRecordId(`operation:${value}:x`);
    return value;
  } catch {
    return invalidIdentity(message);
  }
}

function operationIdentity(value: unknown): string {
  if (typeof value !== "string")
    return invalidIdentity(
      CATALOG_STORE_PUBLIC_MESSAGES.operationIdentityInvalid,
    );
  try {
    const parsed = parseTypedRecordId(value);
    if (!parsed.startsWith("operation:")) throw new Error();
    return parsed;
  } catch {
    return invalidIdentity(
      CATALOG_STORE_PUBLIC_MESSAGES.operationIdentityInvalid,
    );
  }
}

function schemaIdentity(value: unknown): string {
  if (typeof value !== "string")
    return invalidIdentity(CATALOG_STORE_PUBLIC_MESSAGES.schemaIdentityInvalid);
  try {
    const parsed = parseTypedRecordId(value);
    if (!parsed.startsWith("schema:")) throw new Error();
    return parsed;
  } catch {
    return invalidIdentity(CATALOG_STORE_PUBLIC_MESSAGES.schemaIdentityInvalid);
  }
}

function inMemoryFactory(
  scenario?: RuntimeConformanceScenario,
): CatalogStoreFactoryResult {
  return {
    fixture,
    store: {
      async getManifest(catalog, release) {
        const checkedCatalog = segment(
          catalog,
          CATALOG_STORE_PUBLIC_MESSAGES.catalogIdentityInvalid,
        );
        const checkedRelease = segment(
          release,
          CATALOG_STORE_PUBLIC_MESSAGES.releaseIdentityInvalid,
        );
        if (scenario?.fault === "driver-manifest") {
          return normalizedDriverError(
            new Error(scenario.injectedDriverError),
            "MANIFEST_INVALID",
            CATALOG_STORE_PUBLIC_MESSAGES.manifestTransportUnavailable,
          );
        }
        if (scenario?.fault === "duplicate-manifest") {
          throw new OpenApiMcpError(
            "MANIFEST_INVALID",
            CATALOG_STORE_PUBLIC_MESSAGES.manifestTransportAbsentOrAmbiguous,
          );
        }
        if (checkedCatalog !== fixture.catalogId) {
          throw new OpenApiMcpError(
            "MANIFEST_INVALID",
            CATALOG_STORE_PUBLIC_MESSAGES.manifestTransportAbsentOrAmbiguous,
          );
        }
        if (checkedRelease === fixture.releaseA) return fixture.envelopeA;
        if (checkedRelease === fixture.releaseB) return fixture.envelopeB;
        throw new OpenApiMcpError(
          "MANIFEST_INVALID",
          CATALOG_STORE_PUBLIC_MESSAGES.manifestTransportAbsentOrAmbiguous,
        );
      },
      async searchCandidates(query) {
        const snapshot = plainSearchSnapshot(query);
        if (typeof snapshot.query !== "string" || snapshot.query.length === 0) {
          throw new OpenApiMcpError(
            "INPUT_INVALID",
            CATALOG_STORE_PUBLIC_MESSAGES.searchQueryInvalid,
          );
        }
        if (snapshot.query === '"') {
          throw new OpenApiMcpError(
            "INPUT_INVALID",
            CATALOG_STORE_PUBLIC_MESSAGES.searchExpressionInvalid,
          );
        }
        if (snapshot.api !== undefined) {
          segment(
            snapshot.api,
            CATALOG_STORE_PUBLIC_MESSAGES.catalogIdentityInvalid,
          );
        }
        if (!Number.isSafeInteger(snapshot.limit)) {
          throw new OpenApiMcpError(
            "INPUT_INVALID",
            CATALOG_STORE_PUBLIC_MESSAGES.searchLimitInvalid,
          );
        }
        if (scenario?.fault === "driver-candidates") {
          return normalizedDriverError(
            new Error(scenario.injectedDriverError),
            "INPUT_INVALID",
            CATALOG_STORE_PUBLIC_MESSAGES.searchExpressionInvalid,
          );
        }
        if (scenario?.fault === "duplicate-candidates") {
          throw new OpenApiMcpError(
            "RECORD_DIGEST_MISMATCH",
            CATALOG_STORE_PUBLIC_MESSAGES.searchTransportDuplicateRows,
          );
        }
        if (scenario?.fault === "candidate-malformed-operation-id") {
          throw new OpenApiMcpError(
            "RECORD_DIGEST_MISMATCH",
            CATALOG_STORE_PUBLIC_MESSAGES.storedOperationIdentifierInvalid,
          );
        }
        if (scenario?.fault === "candidate-non-operation-id") {
          throw new OpenApiMcpError(
            "RECORD_DIGEST_MISMATCH",
            CATALOG_STORE_PUBLIC_MESSAGES.storedOperationIdentifierInvalid,
          );
        }
        if (scenario?.fault === "candidate-cross-api") {
          throw new OpenApiMcpError(
            "RECORD_DIGEST_MISMATCH",
            CATALOG_STORE_PUBLIC_MESSAGES.searchTransportOutsideRequestedApi,
          );
        }
        return fixture.expectedCandidates
          .filter(
            () => snapshot.api === undefined || snapshot.api === fixture.api,
          )
          .slice(0, snapshot.limit as number);
      },
      async getOperation(catalog, release, id) {
        const checkedCatalog = segment(
          catalog,
          CATALOG_STORE_PUBLIC_MESSAGES.catalogIdentityInvalid,
        );
        const checkedRelease = segment(
          release,
          CATALOG_STORE_PUBLIC_MESSAGES.releaseIdentityInvalid,
        );
        const checkedId = operationIdentity(id);
        if (scenario?.fault === "driver-operation") {
          return normalizedDriverError(
            new Error(scenario.injectedDriverError),
            "RECORD_DIGEST_MISMATCH",
            CATALOG_STORE_PUBLIC_MESSAGES.recordTransportUnavailable,
          );
        }
        if (scenario?.fault === "duplicate-operation") {
          throw new OpenApiMcpError(
            "RECORD_DIGEST_MISMATCH",
            CATALOG_STORE_PUBLIC_MESSAGES.operationRowAmbiguous,
          );
        }
        if (
          checkedCatalog !== fixture.catalogId ||
          checkedId !== fixture.operationId
        )
          return null;
        if (checkedRelease === fixture.releaseA) return fixture.operationA;
        if (checkedRelease === fixture.releaseB) return fixture.operationB;
        return null;
      },
      async getSchemas(catalog, release, ids) {
        const checkedCatalog = segment(
          catalog,
          CATALOG_STORE_PUBLIC_MESSAGES.catalogIdentityInvalid,
        );
        const checkedRelease = segment(
          release,
          CATALOG_STORE_PUBLIC_MESSAGES.releaseIdentityInvalid,
        );
        const checkedIds = schemaIdsSnapshot(ids);
        if (scenario?.fault === "driver-schemas") {
          return normalizedDriverError(
            new Error(scenario.injectedDriverError),
            "RECORD_DIGEST_MISMATCH",
            CATALOG_STORE_PUBLIC_MESSAGES.recordTransportUnavailable,
          );
        }
        if (scenario?.fault === "duplicate-schemas") {
          throw new OpenApiMcpError(
            "RECORD_DIGEST_MISMATCH",
            CATALOG_STORE_PUBLIC_MESSAGES.schemaTransportTooManyRows,
          );
        }
        if (checkedIds.length === 0) return [];
        const rows =
          checkedCatalog === fixture.catalogId &&
          checkedRelease === fixture.releaseA
            ? fixture.schemasA
            : checkedCatalog === fixture.catalogId &&
                checkedRelease === fixture.releaseB
              ? fixture.schemasB
              : undefined;
        const requested = new Set<string>(checkedIds);
        const result = rows?.filter(({ id }) => requested.has(id)) ?? [];
        if (result.length !== requested.size) {
          throw new OpenApiMcpError(
            "RECORD_DIGEST_MISMATCH",
            CATALOG_STORE_PUBLIC_MESSAGES.schemaRowsIncomplete,
          );
        }
        return result;
      },
    },
  };
}

test("the shared suite fails an adapter that accepts cross-API candidates", async () => {
  let crossApiCheck: (() => void | Promise<void>) | undefined;
  let observedApi: unknown;
  const registrationAdapter: ConformanceTestAdapter = {
    ...adapter,
    test: (name, run) => {
      if (name === "catalog rejects cross-API candidate transport rows") {
        crossApiCheck = run;
      }
    },
  };
  const nonconformingFactory = (
    scenario?: RuntimeConformanceScenario,
  ): CatalogStoreFactoryResult => {
    const value = inMemoryFactory();
    if (scenario?.fault !== "candidate-cross-api") return value;
    return {
      ...value,
      store: {
        ...value.store,
        async searchCandidates(query) {
          observedApi = query.api;
          return [
            {
              catalogId: fixture.catalogId,
              releaseId: fixture.releaseA,
              operationId:
                "operation:other-api:get-item" as typeof fixture.operationId,
            },
          ];
        },
      },
    };
  };

  runRuntimeConformanceSuite(nonconformingFactory, {
    testAdapter: registrationAdapter,
  });

  const check = crossApiCheck;
  if (check === undefined)
    throw new Error("Cross-API conformance check missing");
  await expect(Promise.resolve().then(check)).rejects.toThrow();
  expect(observedApi).toBe(fixture.api);
});

runRuntimeConformanceSuite(inMemoryFactory, { testAdapter: adapter });
