import {
  type CatalogStoreFactory,
  type ConformanceTestAdapter,
  RUNTIME_CONFORMANCE_FIXTURE,
} from "../src/conformance/index.ts";
import type {
  ActionDispatchPermit,
  AuthorizationContext,
  AuthorizationId,
  CallOutcome,
  CredentialAuthorizationBinding,
  OperationRefPayload,
  PaginationTokenState,
  SearchResult,
  SearchResultItem,
  SearchWarning,
  VerifiedActionRequestState,
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

type _actionPermitCannotBeForged = Assert<
  Equal<object extends ActionDispatchPermit ? true : false, false>
>;
type _authorizationIdCannotBeForged = Assert<
  Equal<object extends AuthorizationId ? true : false, false>
>;
type _requestStateCannotBeForged = Assert<
  Equal<object extends VerifiedActionRequestState ? true : false, false>
>;
type _authorizationContextIsExplicit = Assert<
  Equal<AuthorizationContext["kind"], "initial" | "resume">
>;
type _resumeRequiresVerifiedState = Assert<
  Equal<
    Extract<AuthorizationContext, { kind: "resume" }>["requestState"],
    VerifiedActionRequestState
  >
>;
type _credentialBindingUsesPortableScopes = Assert<
  Equal<CredentialAuthorizationBinding["scopes"], readonly string[]>
>;
type _actionAuthorizationBoundaryIsPrivate =
  // @ts-expect-error Authorization boundary creation is engine-private.
  typeof import("../src/runtime/index.ts").createActionAuthorizationBoundary;

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
