import {
  admitManifest,
  CATALOG_STORE_PUBLIC_MESSAGES,
  type CatalogId,
  type CatalogStore,
  type GenerationState,
  type GenerationStore,
  type GenerationTransition,
  type TypedOperationId,
  type TypedSchemaId,
  verifyStoredRecord,
} from "../runtime/index.ts";
import type { RuntimeConformanceFixture } from "./fixtures.ts";

export interface CatalogStoreFactoryResult {
  readonly store: CatalogStore;
  readonly fixture: RuntimeConformanceFixture;
  readonly dispose?: () => void | Promise<void>;
}
export type RuntimeConformanceDuplicateFault =
  | "duplicate-candidates"
  | "duplicate-manifest"
  | "duplicate-operation"
  | "duplicate-schemas";
export type RuntimeConformanceCandidateFault =
  | "candidate-malformed-operation-id"
  | "candidate-non-operation-id"
  | "candidate-cross-api";
export type RuntimeConformanceDriverFault =
  | "driver-candidates"
  | "driver-manifest"
  | "driver-operation"
  | "driver-schemas";
export type RuntimeConformanceScenario =
  | { readonly fault: RuntimeConformanceDuplicateFault }
  | { readonly fault: RuntimeConformanceCandidateFault }
  | {
      readonly fault: RuntimeConformanceDriverFault;
      readonly injectedDriverError: string;
    };
export type CatalogStoreFactory = (
  scenario?: RuntimeConformanceScenario,
) => CatalogStoreFactoryResult | Promise<CatalogStoreFactoryResult>;
export interface ConformanceTestAdapter {
  test(name: string, run: () => void | Promise<void>): void;
  equal(actual: unknown, expected: unknown, message?: string): void;
  deepEqual(actual: unknown, expected: unknown, message?: string): void;
  ok(value: unknown, message?: string): void;
  rejects(
    run: () => unknown | Promise<unknown>,
    code: string,
    message?: string,
  ): Promise<void>;
}
export interface RuntimeConformanceOptions {
  readonly testAdapter: ConformanceTestAdapter;
}

async function assertPublicError(
  adapter: ConformanceTestAdapter,
  run: () => unknown | Promise<unknown>,
  code: string,
  message: string,
  forbidden?: string,
): Promise<void> {
  let caught: unknown;
  try {
    await run();
  } catch (error) {
    caught = error;
  }
  adapter.ok(caught);
  const error = caught as {
    readonly code?: unknown;
    readonly details?: unknown;
    readonly message?: unknown;
    readonly retryable?: unknown;
  };
  adapter.equal(error.code, code);
  adapter.deepEqual(error.details, {});
  adapter.equal(error.retryable, false);
  adapter.equal(error.message, message);
  if (forbidden !== undefined) {
    adapter.equal(JSON.stringify(error).includes(forbidden), false);
    adapter.equal(String(error.message).includes(forbidden), false);
  }
}

function attemptMutation(run: () => void): void {
  try {
    run();
  } catch {
    // Frozen results may reject mutation; mutable results must be detached.
  }
}

class ConformanceGenerationStore implements GenerationStore {
  readonly #states = new Map<string, GenerationState>();

  async get(
    catalogId: CatalogId,
    issuer: string,
  ): Promise<GenerationState | null> {
    return this.#states.get(`${catalogId}\0${issuer}`) ?? null;
  }

  async accept(
    catalogId: CatalogId,
    issuer: string,
    transition: GenerationTransition,
  ): Promise<GenerationState | null> {
    const key = `${catalogId}\0${issuer}`;
    const current = this.#states.get(key) ?? null;
    if ((current?.revision ?? null) !== transition.expectedRevision)
      return null;
    this.#states.set(key, transition.next);
    return transition.next;
  }
}

/** Register the transport-independent CatalogStore contract against a factory. */
export function runRuntimeConformanceSuite(
  factory: CatalogStoreFactory,
  options: RuntimeConformanceOptions,
): void {
  const { testAdapter: adapter } = options;
  const use = (
    name: string,
    run: (value: CatalogStoreFactoryResult) => void | Promise<void>,
  ) => {
    adapter.test(name, async () => {
      const value = await factory();
      try {
        await run(value);
      } finally {
        await value.dispose?.();
      }
    });
  };
  const useFault = (
    name: string,
    scenario: RuntimeConformanceScenario,
    run: (value: CatalogStoreFactoryResult) => void | Promise<void>,
  ) => {
    adapter.test(name, async () => {
      const value = await factory(scenario);
      try {
        await run(value);
      } finally {
        await value.dispose?.();
      }
    });
  };

  use(
    "catalog candidates are bounded, exact, and duplicate-free",
    async ({ store, fixture }) => {
      adapter.deepEqual(
        await store.searchCandidates({
          query: fixture.searchQuery,
          api: fixture.api,
          limit: 1,
        }),
        fixture.expectedCandidates.slice(0, 1),
      );
      adapter.deepEqual(
        await store.searchCandidates({
          query: fixture.searchQuery,
          api: fixture.api,
          limit: fixture.expectedCandidates.length,
        }),
        fixture.expectedCandidates,
      );
    },
  );

  useFault(
    "catalog rejects duplicate candidate transport rows",
    { fault: "duplicate-candidates" },
    async ({ store, fixture }) => {
      await assertPublicError(
        adapter,
        () =>
          store.searchCandidates({
            query: fixture.searchQuery,
            api: fixture.api,
            limit: fixture.expectedCandidates.length,
          }),
        "RECORD_DIGEST_MISMATCH",
        CATALOG_STORE_PUBLIC_MESSAGES.searchTransportDuplicateRows,
      );
    },
  );
  useFault(
    "catalog rejects malformed candidate transport rows",
    { fault: "candidate-malformed-operation-id" },
    async ({ store, fixture }) => {
      await assertPublicError(
        adapter,
        () =>
          store.searchCandidates({
            query: fixture.searchQuery,
            api: fixture.api,
            limit: 1,
          }),
        "RECORD_DIGEST_MISMATCH",
        CATALOG_STORE_PUBLIC_MESSAGES.storedOperationIdentifierInvalid,
      );
    },
  );
  useFault(
    "catalog rejects candidate transport rows with non-operation IDs",
    { fault: "candidate-non-operation-id" },
    async ({ store, fixture }) => {
      await assertPublicError(
        adapter,
        () =>
          store.searchCandidates({
            query: fixture.searchQuery,
            api: fixture.api,
            limit: 1,
          }),
        "RECORD_DIGEST_MISMATCH",
        CATALOG_STORE_PUBLIC_MESSAGES.storedOperationIdentifierInvalid,
      );
    },
  );
  useFault(
    "catalog rejects cross-API candidate transport rows",
    { fault: "candidate-cross-api" },
    async ({ store, fixture }) => {
      await assertPublicError(
        adapter,
        () =>
          store.searchCandidates({
            query: fixture.searchQuery,
            api: fixture.api,
            limit: 1,
          }),
        "RECORD_DIGEST_MISMATCH",
        CATALOG_STORE_PUBLIC_MESSAGES.searchTransportOutsideRequestedApi,
      );
    },
  );
  useFault(
    "catalog rejects duplicate manifest transport rows",
    { fault: "duplicate-manifest" },
    async ({ store, fixture }) => {
      await assertPublicError(
        adapter,
        () => store.getManifest(fixture.catalogId, fixture.releaseA),
        "MANIFEST_INVALID",
        CATALOG_STORE_PUBLIC_MESSAGES.manifestTransportAbsentOrAmbiguous,
      );
    },
  );
  useFault(
    "catalog rejects duplicate operation transport rows",
    { fault: "duplicate-operation" },
    async ({ store, fixture }) => {
      await assertPublicError(
        adapter,
        () =>
          store.getOperation(
            fixture.catalogId,
            fixture.releaseA,
            fixture.operationId,
          ),
        "RECORD_DIGEST_MISMATCH",
        CATALOG_STORE_PUBLIC_MESSAGES.operationRowAmbiguous,
      );
    },
  );
  useFault(
    "catalog rejects duplicate schema transport rows",
    { fault: "duplicate-schemas" },
    async ({ store, fixture }) => {
      await assertPublicError(
        adapter,
        () =>
          store.getSchemas(
            fixture.catalogId,
            fixture.releaseA,
            fixture.schemaIds,
          ),
        "RECORD_DIGEST_MISMATCH",
        CATALOG_STORE_PUBLIC_MESSAGES.schemaTransportTooManyRows,
      );
    },
  );

  const injectedDriverError = "conformance-private-driver-secret";
  useFault(
    "catalog redacts candidate driver failures",
    { fault: "driver-candidates", injectedDriverError },
    async ({ store, fixture }) => {
      await assertPublicError(
        adapter,
        () =>
          store.searchCandidates({
            query: fixture.searchQuery,
            api: fixture.api,
            limit: 1,
          }),
        "INPUT_INVALID",
        CATALOG_STORE_PUBLIC_MESSAGES.searchExpressionInvalid,
        injectedDriverError,
      );
    },
  );
  useFault(
    "catalog redacts manifest driver failures",
    { fault: "driver-manifest", injectedDriverError },
    async ({ store, fixture }) => {
      await assertPublicError(
        adapter,
        () => store.getManifest(fixture.catalogId, fixture.releaseA),
        "MANIFEST_INVALID",
        CATALOG_STORE_PUBLIC_MESSAGES.manifestTransportUnavailable,
        injectedDriverError,
      );
    },
  );
  useFault(
    "catalog redacts operation driver failures",
    { fault: "driver-operation", injectedDriverError },
    async ({ store, fixture }) => {
      await assertPublicError(
        adapter,
        () =>
          store.getOperation(
            fixture.catalogId,
            fixture.releaseA,
            fixture.operationId,
          ),
        "RECORD_DIGEST_MISMATCH",
        CATALOG_STORE_PUBLIC_MESSAGES.recordTransportUnavailable,
        injectedDriverError,
      );
    },
  );
  useFault(
    "catalog redacts schema driver failures",
    { fault: "driver-schemas", injectedDriverError },
    async ({ store, fixture }) => {
      await assertPublicError(
        adapter,
        () =>
          store.getSchemas(
            fixture.catalogId,
            fixture.releaseA,
            fixture.schemaIds,
          ),
        "RECORD_DIGEST_MISMATCH",
        CATALOG_STORE_PUBLIC_MESSAGES.recordTransportUnavailable,
        injectedDriverError,
      );
    },
  );

  use(
    "catalog operations bind catalog and release",
    async ({ store, fixture }) => {
      adapter.deepEqual(
        await store.getOperation(
          fixture.catalogId,
          fixture.releaseA,
          fixture.operationId,
        ),
        fixture.operationA,
      );
      adapter.deepEqual(
        await store.getOperation(
          fixture.catalogId,
          fixture.releaseB,
          fixture.operationId,
        ),
        fixture.operationB,
      );
      adapter.equal(
        await store.getOperation(
          fixture.catalogId,
          "missing-release" as never,
          fixture.operationId,
        ),
        null,
      );
      adapter.equal(
        await store.getOperation(
          fixture.catalogId,
          fixture.releaseA,
          fixture.missingOperationId,
        ),
        null,
      );
    },
  );

  use(
    "catalog schemas are batched, unique, ordered, and empty-safe",
    async ({ store, fixture }) => {
      const firstSchemaId = fixture.schemaIds[0];
      if (firstSchemaId === undefined)
        throw new Error("Conformance fixture has no schema");
      adapter.deepEqual(
        await store.getSchemas(
          fixture.catalogId,
          fixture.releaseA,
          [...fixture.schemaIds].reverse().concat(firstSchemaId),
        ),
        fixture.schemasA,
      );
      adapter.deepEqual(
        await store.getSchemas(
          fixture.catalogId,
          fixture.releaseB,
          [...fixture.schemaIds].reverse(),
        ),
        fixture.schemasB,
      );
      adapter.deepEqual(
        await store.getSchemas(fixture.catalogId, fixture.releaseA, []),
        [],
      );
    },
  );

  use(
    "catalog manifests admit and authenticate logical records",
    async ({ store, fixture }) => {
      const admittedA = await admitManifest(
        await store.getManifest(fixture.catalogId, fixture.releaseA),
        fixture.trust,
        new ConformanceGenerationStore(),
      );
      adapter.equal(admittedA.manifest.catalogId, fixture.catalogId);
      adapter.equal(admittedA.manifest.releaseId, fixture.releaseA);
      const operationA = await store.getOperation(
        fixture.catalogId,
        fixture.releaseA,
        fixture.operationId,
      );
      adapter.ok(operationA);
      if (operationA === null)
        throw new Error("Conformance operation A is absent");
      adapter.deepEqual(
        await verifyStoredRecord(admittedA, operationA),
        fixture.operationA.record,
      );
      const schemasA = await store.getSchemas(
        fixture.catalogId,
        fixture.releaseA,
        fixture.schemaIds,
      );
      for (const [index, row] of schemasA.entries()) {
        adapter.deepEqual(
          await verifyStoredRecord(admittedA, row),
          fixture.schemasA[index]?.record,
        );
      }

      const admittedB = await admitManifest(
        await store.getManifest(fixture.catalogId, fixture.releaseB),
        fixture.trust,
        new ConformanceGenerationStore(),
      );
      adapter.equal(admittedB.manifest.catalogId, fixture.catalogId);
      adapter.equal(admittedB.manifest.releaseId, fixture.releaseB);
      const operationB = await store.getOperation(
        fixture.catalogId,
        fixture.releaseB,
        fixture.operationId,
      );
      adapter.ok(operationB);
      if (operationB === null)
        throw new Error("Conformance operation B is absent");
      adapter.deepEqual(
        await verifyStoredRecord(admittedB, operationB),
        fixture.operationB.record,
      );
    },
  );

  use(
    "catalog verification rejects tampered logical content",
    async ({ store, fixture }) => {
      const admitted = await admitManifest(
        await store.getManifest(fixture.catalogId, fixture.releaseA),
        fixture.trust,
        new ConformanceGenerationStore(),
      );
      const operation = await store.getOperation(
        fixture.catalogId,
        fixture.releaseA,
        fixture.operationId,
      );
      adapter.ok(operation);
      if (operation === null)
        throw new Error("Conformance operation is absent");
      await adapter.rejects(
        () =>
          verifyStoredRecord(admitted, {
            ...operation,
            record: { ...operation.record, summary: "tampered" },
          }),
        "RECORD_DIGEST_MISMATCH",
      );
    },
  );

  use(
    "catalog identity and absence are enforced across every record kind",
    async ({ store, fixture }) => {
      const wrongCatalog = "missing-catalog" as CatalogId;
      const missingRelease = "missing-release" as never;
      const missingSchema =
        "schema:conformance:#/components/schemas/Missing" as TypedSchemaId;
      for (const [catalogId, releaseId] of [
        [wrongCatalog, fixture.releaseA],
        [fixture.catalogId, missingRelease],
      ] as const) {
        await adapter.rejects(
          () => store.getManifest(catalogId, releaseId),
          "MANIFEST_INVALID",
        );
        adapter.equal(
          await store.getOperation(catalogId, releaseId, fixture.operationId),
          null,
        );
        await adapter.rejects(
          () => store.getSchemas(catalogId, releaseId, fixture.schemaIds),
          "RECORD_DIGEST_MISMATCH",
        );
      }
      await adapter.rejects(
        () =>
          store.getSchemas(fixture.catalogId, fixture.releaseA, [
            missingSchema,
          ]),
        "RECORD_DIGEST_MISMATCH",
      );
      await assertPublicError(
        adapter,
        () =>
          store.searchCandidates({ query: '"', api: fixture.api, limit: 1 }),
        "INPUT_INVALID",
        CATALOG_STORE_PUBLIC_MESSAGES.searchExpressionInvalid,
      );
    },
  );

  use(
    "catalog rejects malformed caller identities",
    async ({ store, fixture }) => {
      await assertPublicError(
        adapter,
        () =>
          store.getOperation(
            fixture.catalogId,
            fixture.releaseA,
            "schema:conformance:not-an-operation" as TypedOperationId,
          ),
        "INPUT_INVALID",
        CATALOG_STORE_PUBLIC_MESSAGES.operationIdentityInvalid,
      );
      await assertPublicError(
        adapter,
        () =>
          store.getSchemas(fixture.catalogId, fixture.releaseA, [
            "operation:conformance:not-a-schema" as TypedSchemaId,
          ]),
        "INPUT_INVALID",
        CATALOG_STORE_PUBLIC_MESSAGES.schemaIdentityInvalid,
      );
    },
  );

  use(
    "catalog rejects non-string identity values without coercion",
    async ({ store, fixture }) => {
      let coercions = 0;
      const coercible = Object.freeze({
        toString() {
          coercions += 1;
          return fixture.catalogId;
        },
      });
      for (const [label, invalid] of [
        ["number", 42],
        ["null", null],
        ["object", coercible],
      ] as const) {
        const attempts: readonly [() => unknown | Promise<unknown>, string][] =
          [
            [
              () => store.getManifest(invalid as never, fixture.releaseA),
              CATALOG_STORE_PUBLIC_MESSAGES.catalogIdentityInvalid,
            ],
            [
              () => store.getManifest(fixture.catalogId, invalid as never),
              CATALOG_STORE_PUBLIC_MESSAGES.releaseIdentityInvalid,
            ],
            [
              () =>
                store.searchCandidates({
                  query: fixture.searchQuery,
                  api: invalid as never,
                  limit: 1,
                }),
              CATALOG_STORE_PUBLIC_MESSAGES.catalogIdentityInvalid,
            ],
            [
              () =>
                store.getOperation(
                  invalid as never,
                  fixture.releaseA,
                  fixture.operationId,
                ),
              CATALOG_STORE_PUBLIC_MESSAGES.catalogIdentityInvalid,
            ],
            [
              () =>
                store.getOperation(
                  fixture.catalogId,
                  invalid as never,
                  fixture.operationId,
                ),
              CATALOG_STORE_PUBLIC_MESSAGES.releaseIdentityInvalid,
            ],
            [
              () =>
                store.getOperation(
                  fixture.catalogId,
                  fixture.releaseA,
                  invalid as never,
                ),
              CATALOG_STORE_PUBLIC_MESSAGES.operationIdentityInvalid,
            ],
            [
              () =>
                store.getSchemas(
                  invalid as never,
                  fixture.releaseA,
                  fixture.schemaIds,
                ),
              CATALOG_STORE_PUBLIC_MESSAGES.catalogIdentityInvalid,
            ],
            [
              () =>
                store.getSchemas(
                  fixture.catalogId,
                  invalid as never,
                  fixture.schemaIds,
                ),
              CATALOG_STORE_PUBLIC_MESSAGES.releaseIdentityInvalid,
            ],
            [
              () =>
                store.getSchemas(fixture.catalogId, fixture.releaseA, [
                  invalid as never,
                ]),
              CATALOG_STORE_PUBLIC_MESSAGES.schemaIdentityInvalid,
            ],
          ];
        for (const [run, message] of attempts) {
          await assertPublicError(adapter, run, "INPUT_INVALID", message);
        }
        adapter.equal(coercions, 0, `${label} was coerced`);
      }
    },
  );

  use(
    "catalog snapshots only plain data-only search and schema requests",
    async ({ store, fixture }) => {
      let searchGetterCalls = 0;
      const changingSearch = {} as Record<string, unknown>;
      for (const [key, first, second] of [
        ["query", fixture.searchQuery, '"'],
        ["api", fixture.api, "other-api"],
        ["limit", 1, 2],
      ] as const) {
        let current: string | number = first;
        Object.defineProperty(changingSearch, key, {
          enumerable: true,
          get() {
            searchGetterCalls += 1;
            const result = current;
            current = second;
            return result;
          },
        });
      }
      const inheritedSearch = Object.create({
        query: fixture.searchQuery,
        api: fixture.api,
        limit: 1,
      }) as Record<string, unknown>;
      for (const hostile of [changingSearch, inheritedSearch]) {
        await assertPublicError(
          adapter,
          () => store.searchCandidates(hostile as never),
          "INPUT_INVALID",
          CATALOG_STORE_PUBLIC_MESSAGES.searchQueryInvalid,
        );
      }
      adapter.equal(searchGetterCalls, 0);

      let iteratorCalls = 0;
      const nonPlain = Object.setPrototypeOf(
        [...fixture.schemaIds],
        Object.create(Array.prototype),
      );
      const sparse = new Array(fixture.schemaIds.length) as TypedSchemaId[];
      const extraKey = [...fixture.schemaIds] as TypedSchemaId[] & {
        extra?: string;
      };
      extraKey.extra = "untrusted";
      const customIterator = [...fixture.schemaIds] as TypedSchemaId[];
      Object.defineProperty(customIterator, Symbol.iterator, {
        enumerable: false,
        value: function* () {
          iteratorCalls += 1;
          yield* fixture.schemaIds;
        },
      });
      for (const hostile of [nonPlain, sparse, extraKey, customIterator]) {
        await assertPublicError(
          adapter,
          () => store.getSchemas(fixture.catalogId, fixture.releaseA, hostile),
          "INPUT_INVALID",
          CATALOG_STORE_PUBLIC_MESSAGES.schemaRequestInvalid,
        );
      }
      adapter.equal(iteratorCalls, 0);
    },
  );

  use(
    "catalog results are detached from subsequent reads",
    async ({ store, fixture }) => {
      const operation = await store.getOperation(
        fixture.catalogId,
        fixture.releaseA,
        fixture.operationId,
      );
      if (operation === null)
        throw new Error("Conformance operation is absent");
      attemptMutation(() => {
        (operation as { logicalDigest: string }).logicalDigest = "0".repeat(64);
      });
      attemptMutation(() => {
        (operation.record as { summary: string }).summary = "mutated";
      });
      attemptMutation(() => {
        (operation.record.schemaIds as TypedSchemaId[]).push(
          "schema:conformance:#/components/schemas/Mutation" as TypedSchemaId,
        );
      });
      const schemas = await store.getSchemas(
        fixture.catalogId,
        fixture.releaseA,
        fixture.schemaIds,
      );
      attemptMutation(() => {
        (schemas[0] as { logicalDigest: string }).logicalDigest = "0".repeat(
          64,
        );
      });
      attemptMutation(() => {
        const schema = schemas[0]?.record.schema as { title?: string };
        schema.title = "mutated";
      });
      adapter.deepEqual(
        await store.getOperation(
          fixture.catalogId,
          fixture.releaseA,
          fixture.operationId,
        ),
        fixture.operationA,
      );
      adapter.deepEqual(
        await store.getSchemas(
          fixture.catalogId,
          fixture.releaseA,
          fixture.schemaIds,
        ),
        fixture.schemasA,
      );
    },
  );
}
