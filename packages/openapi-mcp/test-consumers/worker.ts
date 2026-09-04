import {
  type CatalogStoreFactory,
  type ConformanceTestAdapter,
  RUNTIME_CONFORMANCE_FIXTURE,
} from "../src/conformance/index.ts";
import type {
  CallOutcome,
  OperationRefPayload,
  PaginationTokenState,
  SearchResult,
  SearchResultItem,
  SearchWarning,
} from "../src/runtime/index.ts";
import {
  ARTIFACT_FORMAT_VERSION,
  createD1CatalogStore,
  PREPARED_CALL_VERSION,
  RUNTIME_CONTRACT_VERSION,
} from "../src/runtime/index.ts";

type Equal<Actual, Expected> =
  (<Value>() => Value extends Actual ? 1 : 2) extends <
    Value,
  >() => Value extends Expected ? 1 : 2
    ? true
    : false;
type Assert<Condition extends true> = Condition;

type _operationRefPayloadIsManifestBound = Assert<
  Equal<
    keyof OperationRefPayload,
    "catalogId" | "releaseId" | "operationId" | "manifestDigest"
  >
>;
type _paginationStateBindsOrigin = Assert<
  Equal<PaginationTokenState["origin"], string>
>;
type _searchResultUsesOperationsAndWarnings = Assert<
  Equal<keyof SearchResult, "operations" | "warnings">
>;
type _searchItemHasJsonSafeInputOutline = Assert<
  Equal<
    SearchResultItem["inputOutline"],
    import("../src/runtime/index.ts").JsonObject
  >
>;
type _warningCarriesAStableCode = Assert<
  Equal<
    SearchWarning["code"],
    import("../src/runtime/index.ts").OpenApiMcpErrorCode
  >
>;
type _callOutcomeUsesKindOnly = Assert<Equal<keyof CallOutcome, "kind">>;

type _compilerOwnedReferenceMap =
  // @ts-expect-error Reference maps remain compiler-owned until Task 4.
  import("../src/runtime/index.ts").ReferenceMapV1;

type _workerConformanceFactory = Assert<
  Equal<CatalogStoreFactory extends () => unknown ? true : false, true>
>;
type _workerConformanceAdapter = Assert<
  Equal<
    ConformanceTestAdapter["test"] extends (...args: never[]) => unknown
      ? true
      : false,
    true
  >
>;

void [
  ARTIFACT_FORMAT_VERSION,
  PREPARED_CALL_VERSION,
  RUNTIME_CONTRACT_VERSION,
  createD1CatalogStore,
  RUNTIME_CONFORMANCE_FIXTURE,
];
