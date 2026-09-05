import type { OpenApiMcpErrorCode } from "./errors.ts";
import type { RuntimeLimits } from "./versions.ts";

export type Sha256 = string & { readonly __sha256: unique symbol };
export type CatalogId = string & { readonly __catalogId: unique symbol };
export type ReleaseId = string & { readonly __releaseId: unique symbol };
export type TypedOperationId = `operation:${string}`;
export type TypedSchemaId = `schema:${string}`;
export type TypedRecordId = TypedOperationId | TypedSchemaId;

export type OpenApiValue =
  | null
  | boolean
  | number
  | string
  | OpenApiValue[]
  | { [key: string]: OpenApiValue };
export type JsonValue = OpenApiValue;
export type JsonObject = { [key: string]: JsonValue };
export type JsonSchemaV4 = JsonObject | boolean;

export interface OpenApiArguments {
  path?: Readonly<Record<string, string | number | boolean>>;
  query?: Readonly<Record<string, OpenApiValue>>;
  headers?: Readonly<Record<string, string>>;
  body?: OpenApiValue;
}

/** A host-owned transport location reserved for later credential injection. */
export interface CredentialSlot {
  readonly placement: "header" | "query";
  readonly name: string;
}

/** Host-only serializer policy. This is deliberately outside OpenApiArguments. */
export interface SerializeArgumentsOptions {
  readonly limits?: Readonly<Partial<RuntimeLimits>>;
  readonly reservedCredentialSlots?: readonly CredentialSlot[];
}

export type HttpMethod =
  | "GET"
  | "HEAD"
  | "POST"
  | "PUT"
  | "PATCH"
  | "DELETE"
  | "OPTIONS"
  | "TRACE";

export interface ReleaseManifestV4 {
  /** v4 records omit operation tags; v5 records require signed tags. */
  format: 4 | 5;
  contract: 1;
  catalogId: CatalogId;
  releaseId: ReleaseId;
  generation: number;
  issuer: string;
  keyId: string;
  policyId: string;
  allowedOrigins: readonly string[];
  compiledAt: string;
  compilerVersion: string;
  source: {
    uri: string;
    revision: string;
    contentSha256: Sha256;
    referenceGraphDigest: Sha256;
  };
  records: Readonly<Record<TypedRecordId, Sha256>>;
}

export interface ManifestSignature {
  algorithm: "Ed25519";
  keyId: string;
  signature: string;
}

export interface RollbackAuthorization {
  id: string;
  catalogId: CatalogId;
  issuer: string;
  currentHighestGeneration: number;
  targetGeneration: number;
  targetManifestDigest: Sha256;
  reason: string;
  expiresAt: string;
  keyId: string;
  algorithm: "Ed25519";
  signature: string;
}

export interface ManifestEnvelope {
  manifestJson: string;
  signature: ManifestSignature;
  rollback?: RollbackAuthorization;
}

export interface StoredRecord<TRecord> {
  id: TypedRecordId;
  logicalDigest: Sha256;
  record: TRecord;
}

/** Logical operation data normalized from v4 or admitted through signed v5. */
export type ParameterLocationV4 = "path" | "query" | "header" | "cookie";

export type ParameterStyleV4 =
  | "matrix"
  | "label"
  | "form"
  | "simple"
  | "spaceDelimited"
  | "pipeDelimited"
  | "deepObject";

export type CanonicalMediaTypeV4 = string & {
  readonly __canonicalMediaTypeV4: unique symbol;
};

export type SchemaUseV4 =
  | { readonly kind: "schema"; readonly schemaId: TypedSchemaId }
  | {
      readonly kind: "content";
      readonly mediaType: CanonicalMediaTypeV4;
      readonly schemaId: TypedSchemaId;
    };

export interface ParameterRecordV4 {
  readonly name: string;
  readonly in: ParameterLocationV4;
  readonly required: boolean;
  readonly deprecated: boolean;
  readonly style: ParameterStyleV4;
  readonly explode: boolean;
  readonly allowReserved: boolean;
  readonly value: SchemaUseV4;
}

export interface EncodingHeaderV4 {
  readonly name: string;
  readonly required: boolean;
  readonly value: SchemaUseV4;
}

export interface MediaEncodingV4 {
  readonly property: string;
  readonly contentType: CanonicalMediaTypeV4 | null;
  readonly style: ParameterStyleV4 | null;
  readonly explode: boolean | null;
  readonly allowReserved: boolean;
  readonly headers: readonly EncodingHeaderV4[];
}

export interface RequestBodyMediaV4 {
  readonly mediaType: CanonicalMediaTypeV4;
  readonly schemaId: TypedSchemaId;
  readonly encoding: readonly MediaEncodingV4[];
}

export interface RequestBodyRecordV4 {
  readonly required: boolean;
  readonly content: readonly RequestBodyMediaV4[];
}

export interface OperationRecordV4 {
  id: TypedOperationId;
  api: string;
  operationId: string;
  method: HttpMethod;
  path: string;
  origin: string;
  summary: string | null;
  tags: readonly string[];
  deprecated: boolean;
  parameters: readonly ParameterRecordV4[];
  requestBody: RequestBodyRecordV4 | null;
  schemaIds: readonly TypedSchemaId[];
  advisory: JsonObject;
}

/** Logical schema data admitted through a signed v4/v5 manifest. */
export interface SchemaRecordV4 {
  id: TypedSchemaId;
  schema: JsonSchemaV4;
}

export interface SearchQuery {
  query: string;
  api?: string;
  limit: number;
}

export interface CandidateRef {
  catalogId: CatalogId;
  releaseId: ReleaseId;
  operationId: TypedOperationId;
}

export interface CatalogStore {
  getManifest(
    catalogId: CatalogId,
    releaseId: ReleaseId,
  ): Promise<ManifestEnvelope>;
  searchCandidates(query: SearchQuery): Promise<readonly CandidateRef[]>;
  getOperation(
    catalogId: CatalogId,
    releaseId: ReleaseId,
    id: TypedOperationId,
  ): Promise<StoredRecord<OperationRecordV4> | null>;
  getSchemas(
    catalogId: CatalogId,
    releaseId: ReleaseId,
    ids: readonly TypedSchemaId[],
  ): Promise<readonly StoredRecord<SchemaRecordV4>[]>;
}

/** Immutable high-water data plus the release currently admitted for use. */
export interface GenerationState {
  revision: number;
  highestGeneration: number;
  highestManifestDigest: Sha256;
  activeGeneration: number;
  activeManifestDigest: Sha256;
  consumedRollbackAuthorizationIds: readonly string[];
}

/** A compare-and-swap transition expected to move state from one revision. */
export interface GenerationTransition {
  expectedRevision: number | null;
  next: GenerationState;
}

export interface GenerationStore {
  get(catalogId: CatalogId, issuer: string): Promise<GenerationState | null>;
  accept(
    catalogId: CatalogId,
    issuer: string,
    transition: GenerationTransition,
  ): Promise<GenerationState | null>;
}

export interface OperationRefPayload {
  catalogId: CatalogId;
  releaseId: ReleaseId;
  operationId: TypedOperationId;
  manifestDigest: Sha256;
}

/** Opaque `opref.v1.*` wire representation. */
export type OperationRef = string & { readonly __operationRef: unique symbol };

export interface SearchInput {
  query: string;
  api?: string;
  limit?: number;
}

export interface SearchResultItem {
  operation: OperationRef;
  summary: string | null;
  inputOutline: JsonObject;
  safety: "read" | "action";
  actionKind: ActionKind | null;
  cardinality: ActionCardinality | null;
  deprecated: boolean;
  advisory: JsonObject;
}

/** A bounded, already-redacted warning emitted while searching candidates. */
export interface SearchWarning {
  code: OpenApiMcpErrorCode;
  message: string;
  details?: Readonly<Record<string, OpenApiValue>>;
}

export interface SearchResult {
  operations: readonly SearchResultItem[];
  warnings: readonly SearchWarning[];
}

export interface PrepareInput {
  operation: OperationRef;
  arguments: OpenApiArguments;
  pageToken?: string;
}

export type ActionKind =
  | "create"
  | "update"
  | "delete"
  | "communicate"
  | "authority"
  | "transaction"
  | "execute"
  | "unknown";

export type ActionCardinality =
  | { kind: "single" }
  | { kind: "bounded"; maxAffected: number }
  | { kind: "unbounded" }
  | { kind: "unknown" };

export interface PreparedCall {
  version: 2;
  catalogId: CatalogId;
  releaseId: ReleaseId;
  operationId: TypedOperationId;
  operationDigest: Sha256;
  manifestDigest: Sha256;
  /** Stable operator-selected profile identifier; never a user or token identifier. */
  credentialProfileId: string;
  /** Commits the selected profile's complete non-secret configuration. */
  credentialProfileDigest: Sha256;
  /** Binds the host-selected credential injection locations, never secrets. */
  reservedSlotsDigest: Sha256;
  method: HttpMethod;
  origin: string;
  relativeUrl: string;
  headers: Readonly<Record<string, string>>;
  body: Uint8Array | null;
  normalizedArguments: JsonObject;
  safety: "read" | "action";
  actionKind: ActionKind | null;
  cardinality: ActionCardinality | null;
  inputDigest: Sha256;
  preparedCallDigest: Sha256;
}

export interface OpenApiRuntime {
  search(input: SearchInput): Promise<SearchResult>;
  prepareRead(input: PrepareInput): Promise<PreparedCall>;
  prepareAction(input: PrepareInput): Promise<PreparedCall>;
  revalidate(call: PreparedCall): Promise<PreparedCall>;
}

export interface AuthorizationContext {
  now: Date;
  requestState?: string;
}

export interface SafeApprovalPresentation {
  catalogId: string;
  releaseId: string;
  operationId: string;
  method: HttpMethod;
  origin: string;
  relativeUrl: string;
  actionKind: ActionKind;
  cardinality: ActionCardinality;
  normalizedArguments: string;
  preparedCallDigest: Sha256;
}

export interface ActionAuthorizer {
  authorize(
    call: PreparedCall,
    context: AuthorizationContext,
  ): Promise<AuthorizationDecision>;
}

export type AuthorizationDecision =
  | {
      status: "authorized";
      callDigest: Sha256;
      path: "per-call" | "exact-policy";
    }
  | { status: "confirmation-required"; presentation: SafeApprovalPresentation }
  | { status: "denied"; reason: string };

export type AuthProfile =
  | { type: "bearer-env"; env: string }
  | {
      type: "api-key-env";
      env: string;
      placement: "header" | "query";
      name: string;
    }
  | {
      type: "oauth2-pkce";
      authorizationEndpoint: string;
      tokenEndpoint: string;
      clientId: string;
      scopes: readonly string[];
      resource?: string;
    };

export interface SecretStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}

export type Credential =
  | { type: "bearer"; token: string }
  | {
      type: "api-key";
      placement: "header" | "query";
      name: string;
      value: string;
    };

export type CredentialResolution =
  | { status: "ready"; credential: Credential }
  | { status: "auth-required"; authorizationUrl: string; expiresAt: string };

export interface CredentialProvider {
  resolve(): Promise<CredentialResolution>;
}

export interface DestinationPolicy {
  allows(origin: string): Promise<boolean>;
}

/** Exact verified operation identity exposed to host credential-slot policy. */
export interface CredentialSlotContext {
  readonly catalogId: CatalogId;
  readonly releaseId: ReleaseId;
  readonly operationId: TypedOperationId;
  readonly operationDigest: Sha256;
  readonly manifestDigest: Sha256;
  readonly method: HttpMethod;
  readonly origin: string;
}

/**
 * Host-owned policy for selecting a non-secret credential profile commitment.
 * Implementations return a profile ID, profile digest, and injection slots;
 * credentials never enter preparation.
 */
export interface CredentialProfileBinding {
  readonly profileId: string;
  readonly profileDigest: Sha256;
  readonly slots: readonly CredentialSlot[];
}

export interface CredentialBindingResolver {
  resolve(
    context: Readonly<CredentialSlotContext>,
  ): Promise<CredentialProfileBinding>;
}

export interface PaginationTokenState {
  catalogId: CatalogId;
  releaseId: ReleaseId;
  manifestDigest: Sha256;
  operationId: TypedOperationId;
  inputDigest: Sha256;
  origin: string;
  nextRelativeUrl: string;
  expiresAt: string;
  pageCount: number;
  cumulativeBytes: number;
}

/** Host-owned opaque continuation token codec; implementations must bind every field. */
export interface PaginationTokenCodec {
  encode(state: PaginationTokenState): Promise<string>;
  decode(token: string): Promise<PaginationTokenState>;
}

export type CallOutcome =
  | {
      kind: "success";
      statusCode: number;
      headers: Readonly<Record<string, string>>;
      body: Uint8Array;
      pageToken?: string;
    }
  | { kind: "redirect-blocked"; location: string | null }
  | { kind: "not-modified" };

export interface AuthorizedTransport {
  dispatch(call: PreparedCall, credential: Credential): Promise<CallOutcome>;
}
