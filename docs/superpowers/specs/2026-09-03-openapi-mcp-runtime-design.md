# OpenAPI MCP Runtime and Local stdio Server — Design

**Date:** 2026-09-03
**Status:** Approved architecture, implementation pending
**Scope:** Phase 2 of `@knitli/openapi-mcp`: a public local stdio MCP server for provider-neutral OpenAPI 3.x APIs, including bounded digest-pinned multi-document schemas, and the host-neutral runtime contract later consumed by other hosts.

## 1. Decision and supersession

Phase 1—the compiler now present in `packages/openapi-mcp`—remains completed history. Its v3 SQLite format is a useful prototype and migration input. This document supersedes the runtime, tool-surface, authentication, deployment, artifact-trust, and distribution decisions in §§3 and 6–12 of `2026-09-01-openapi-mcp-engine-design.md`. Where the old document conflicts with this one, this document controls.

Phase 2 ships two related public capabilities:

1. A local stdio MCP server that can mount an arbitrary number of explicitly configured OpenAPI releases while exposing exactly three global tools: `search`, `read`, and `action`.
2. A Web-standards-only runtime contract that verifies catalogs, resolves schemas, validates inputs, prepares credential-free calls, and can be used later by a Worker host.

Phase 2 does **not** ship a hosted remote MCP endpoint. It contains no Cloudflare OS, Cap'n Web, Gatekeeper, Durable Object, D1 binding, Access, or Knitli deployment types. Phase 3 owns the native OS Gatekeeper implementation in the infra/web monorepo. This package exports the portable contract and conformance suite that Phase 3 consumes.

## 2. Product shape

```text
MCP client
    │ stdio: search / read / action
    ▼
local server (@knitli/openapi-mcp/stdio; Node only)
    ├── ActionAuthorizer (exact prepared-call authorization)
    ├── local auth profiles + process-memory SecretStore
    ├── guarded Node transport
    └── runtime (@knitli/openapi-mcp/runtime; Web/Worker safe)
          ├── signed release verification
          ├── CatalogStore semantic port
          ├── schema/input validation and serialization
          └── credential-free PreparedCall
                    │ host injects credential after authorization
                    ▼
              arbitrary HTTPS API
```

The package is an engine, not a universal permission oracle. An OpenAPI document describes request shapes; it does not prove that an operation is safe, that a credential is appropriately scoped, or that the configured user intended the call.

## 3. Public entry points and platform boundary

The package exposes focused subpaths:

| Export | Environment | Responsibility |
|---|---|---|
| `@knitli/openapi-mcp/compiler` | Node/Bun | OpenAPI ingestion and immutable v5 release production |
| `@knitli/openapi-mcp/runtime` | Web/Worker/Node/Bun | contracts, canonicalization, verification, search, resolution, preparation, revalidation, errors |
| `@knitli/openapi-mcp/sqlite` | Node | local SQLite store, generation state, guarded HTTP, local auth |
| `@knitli/openapi-mcp/stdio` | Node | modern/legacy-compatible MCP stdio server and CLI |
| `@knitli/openapi-mcp/conformance` | test environments | host-adapter contract tests and fixtures |
| `@knitli/openapi-mcp` | Node/Bun | compatibility exports for the existing compiler API |

`runtime` and `conformance` may import only Web Platform APIs and sibling Worker-safe modules. They must not import `node:*`, `bun:*`, the MCP server SDK, SQLite, Cloudflare packages, or Cap'n Web. A Worker import smoke test enforces this boundary.

## 4. Stable cross-repository contract

Phase 3 depends on a published, pinned package version rather than a production cross-repository workspace link. The compatibility tuple is:

```ts
export const RUNTIME_CONTRACT_VERSION = 1 as const;
export const ARTIFACT_FORMAT_VERSION = 5 as const;
export const PREPARED_CALL_VERSION = 2 as const;
```

Semver covers TypeScript/API compatibility. The three explicit versions cover wire and stored representations independently. The stable contract includes:

- coherent signed release bundles: either complete historical tagless v4 manifest/record shapes and domains or complete v5 shapes and domains, with every mixed-version pairing rejected;
- semantic `CatalogStore`, `GenerationStore`, `DestinationPolicy`, `CredentialProvider`, `ActionAuthorizer`, and `AuthorizedTransport` ports;
- operation-reference and `PreparedCall` encodings;
- stable machine-readable error codes;
- the adapter conformance suite.

Cloudflare-specific storage, identity, grants, approvals, observations, secrets, and deployment configuration remain Phase 3 concerns.

## 5. Artifact v5: signed logical records

### 5.1 Release files

A release is immutable and consists of:

```text
<release>.sqlite
<release>.manifest.json
<release>.manifest.sig
```

The SQLite file is a transport and query index. Its rows, metadata, FTS index, and stored digests are untrusted. The security root is one bounded canonical manifest signed with Ed25519. Exact-file signing from v3 remains available as `signArtifact`/`verifyArtifact` for legacy transport checks, but it is not v5 record admission and is never described as equivalent.

The canonical manifest shape is:

```ts
export interface ReleaseManifestV4 {
  /** Compatibility-era name; v4 is read-only legacy and v5 is current. */
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
  };
  records: Readonly<Record<TypedRecordId, Sha256>>;
}

export type TypedRecordId = `operation:${string}` | `schema:${string}`;
```

`records` is one flat typed ID-to-digest map. Operation IDs are `operation:<api>:<operationId>`; schema IDs are `schema:<api>:#/components/schemas/<escaped-name>`. `catalogId`, `releaseId`, API names, operation IDs, and schema IDs follow an ASCII grammar and length bounds. Ambiguous separators, control characters, Unicode confusables, `.`/`..`, and empty segments are rejected.

The signature file is a small JSON envelope containing `algorithm: "Ed25519"`, `keyId`, and a base64url signature over `domainSeparator || canonicalUtf8(manifest)`. Current manifests use `knitli.openapi-mcp.release-manifest.v5\0`; historical v4 manifests are verified only under `knitli.openapi-mcp.release-manifest.v4\0`.

### 5.2 Canonicalization and parsing

All signed and hashed logical JSON uses RFC 8785-style deterministic canonical JSON: UTF-8, lexicographically sorted object keys, JSON number rules, and no insignificant whitespace. Parsing rejects duplicate object keys, `__proto__`, `prototype`, and `constructor` keys, non-finite numbers, unpaired surrogates, excessive nesting, and any input beyond the application limits below. Lookups use own properties only.

Operation and schema record digests are SHA-256 over a record-specific domain separator plus canonical JSON. Current releases use `knitli.openapi-mcp.operation-record.v5` and `knitli.openapi-mcp.schema-record.v5`. Historical v4 operation records must have the exact original key set without `tags` and are normalized to `tags: []` only after verification under the corresponding v4 domain; v5 operation records require bounded, unique, signed `tags`. A D1 import or SQLite rebuild may change page layout and exact file bytes without changing these logical digests.

### 5.3 Admission and use-time verification

Manifest verification proves the signature, trusted issuer/key relationship, compatibility versions, bounds, IDs, origins, and generation policy before a release becomes visible. Verification does not bless SQLite rows. Search admission is stronger than candidate hydration: before it mutates generation state or returns any operation from a selected release, it proves the complete manifested release inventory observed through the store. Every manifested operation is retrieved and every requested schema response must be exact; each member passes typed-ID and digest verification and fits the release inventory budget. Every schema reference must remain inside that verified inventory, and every operation-root closure must fit the closure/hop limits. A missing, duplicate, substituted, extra-reference, malformed, or over-budget member rejects that release as a whole.

Search applies one shared proof envelope to the whole request: at most eight candidate releases and eight complete-release proofs, with one aggregate `maxReleaseInventoryBytes` budget rather than one 128 MiB allowance per candidate, plus bounded verification work and store calls. It groups verified candidates by `(catalogId, issuer)` and exposes operations only from the one generation/digest that is active after admission. It may fall back from a rejected higher candidate to an otherwise valid lower candidate, but only under the ordinary generation/rollback rule; conflicting digests at one generation are not interchangeable. Admission proves a complete release before its compare-and-swap generation transition. On a CAS miss, it rereads generation state, reselects the generation/digest, and reproves the selected release under the remaining search-wide budget; it never reuses a proof made for an abandoned state snapshot. A candidate first interpreted as a normal advance cannot be reinterpreted as a rollback after state churn, and rollback authorization is consumed only by the successful state transition, never by an abandoned attempt.

Search reports individual rejected candidates as bounded safe warnings and omits them; candidate lookup or generation-state availability failure is the retryable `UPSTREAM_ERROR`. Reaching the release-admission/proof budget produces a bounded admission warning. Response sizing may remove otherwise verified ranked items and adds `RESPONSE_LIMIT_EXCEEDED`; if even the empty response cannot fit, search fails with that error. Verification does not create a durable store snapshot: after admission, every result is checked again against final active generation state, and every later read/prepare/revalidation independently verifies the identity and logical record at use time. An immutable release identity narrows substitution; it cannot make a record that disappears or changes after the observed proof available.

At every `search` result hydration, `prepareRead`, `prepareAction`, schema lookup, and revalidation, the runtime:

1. reconstructs the logical record from the store result;
2. canonicalizes and hashes it;
3. checks the typed ID and digest against the admitted manifest;
4. rejects missing, extra, mismatched, or malformed records.

FTS is candidate generation only. A poisoned FTS table can reduce availability or ranking quality; it cannot cause an unmanifested operation to execute.

### 5.4 Generation and rollback

`GenerationStore` records `{ highestGeneration, highestManifestDigest }` and the active generation/digest per `(catalogId, issuer)`. A normally signed release at a lower generation is rejected. An equal generation is idempotent only when its canonical manifest digest equals `highestManifestDigest`; a different digest fails with `MANIFEST_GENERATION_CONFLICT`. Rolling back requires a second `RollbackAuthorization` signed by a separately configured rollback key and binding the catalog, issuer, current highest generation, target generation, target manifest digest, reason, and expiry. Rollback authorizations are single-use and replay-protected, but are consumed only with a successful conditional state transition. After an authorized rollback, the accepted-generation state records the event rather than forgetting history.

For local stdio, generation state is an atomically replaced user-only file (`0600`) outside the artifact directory. A host may provide a stronger implementation. Failure to read or persist generation state fails closed.

### 5.5 Publication and migration

Production compilation never appends into a published database. It builds a new release under temporary names, closes and syncs it, verifies every logical digest, renames the SQLite payload, then publishes the signature and manifest with the manifest renamed last. Consumers admit only a complete manifest-last release.

The local reader recognizes v3, v4, and v5 during migration. A v3 artifact is inventory/search-only because it lacks a signed logical record map and generation binding. Historical v4 releases remain executable only with their exact tagless logical-record shape and v4 domains. New `compile-release` produces immutable v5 releases, and SQLite/D1 adapters read exactly v4 or v5 with runtime contract 1. Existing `compile --append` remains a clearly labeled legacy v3 command until removal under a semver-major change.

## 6. Application-owned limits

These are security and availability contracts, not reflections of a Cloudflare plan:

```ts
export const DEFAULT_RUNTIME_LIMITS = {
  maxManifestBytes: 8 * 1024 * 1024,
  maxManifestRecords: 100_000,
  maxRecordBytes: 1 * 1024 * 1024,
  // Aggregate verified operation and schema inventory per release and search.
  // This matches the compiler's maximum aggregate source input while avoiding
  // a separate 128 MiB allocation for every authenticated release.
  maxReleaseInventoryBytes: 128 * 1024 * 1024,
  maxJsonDepth: 64,
  maxSchemaClosureBytes: 4 * 1024 * 1024,
  maxSchemaRefHops: 16,
  maxSearchResults: 50,
  defaultSearchResults: 10,
  maxArgumentsBytes: 256 * 1024,
  maxResponseBytes: 8 * 1024 * 1024,
  maxPages: 10,
  maxPaginationBytes: 16 * 1024 * 1024,
  maxRedirects: 3,
  requestDeadlineMs: 30_000,
} as const;

export const DEFAULT_COMPILER_LIMITS = {
  maxSourceBytes: 128 * 1024 * 1024,
  maxReferencedDocuments: 1_024,
  maxPaths: 100_000,
  maxOperations: 100_000,
  maxSchemas: 50_000,
  maxParametersPerOperation: 256,
  maxPropertiesPerSchema: 10_000,
  maxStringBytes: 1 * 1024 * 1024,
  maxRefLength: 2_048,
  maxJsonDepth: 64,
  maxRecordBytes: 1 * 1024 * 1024,
} as const;
```

Every adapter receives validated limits from the application; stores cannot silently raise them. Tests exercise exact boundaries. Operational documentation may link current official Cloudflare limits for Phase 3 deployers, but package behavior never hardcodes plan quotas.

## 7. Compiler hardening

The v5 compiler enforces `DEFAULT_COMPILER_LIMITS` before and during traversal. JSON uses the strict duplicate-key-rejecting parser. YAML uses the existing `yaml` dependency's document API with unique-key errors enabled, bounded alias expansion, and an explicit node/depth/count walk before conversion to plain null-prototype data. It rejects unsupported OpenAPI versions and structural ambiguity rather than coercing it. The legacy v3 loader remains unchanged until the legacy command is removed.

Local JSON Pointer resolution decodes `~1` and `~0` exactly once, rejects invalid escapes, traverses own properties only, and blocks prototype keys. Array indices are canonical decimal indices.

Non-fragment `$ref`s use an explicit deterministic reference map rather than ambient filesystem or network access. Each normalized source URI maps to a file beneath one operator-selected realpath root and an expected SHA-256 digest. The compiler rejects missing map entries, digest mismatches, duplicate normalized URIs, query credentials, path traversal, symlink escape, unsupported media types, excessive reference depth/document count/aggregate bytes, and cycles that cannot be represented safely. URI fragments are resolved only after the mapped document has passed the same strict JSON/YAML parsing and pointer rules as the root document. Credentialed or remote source acquisition happens outside the compiler; operators may download those documents into the mapped bundle, but credentials never enter the release or diagnostics. A host may provide an equivalent bounded `ReferenceResolver` port, but every returned byte sequence must match the reviewed reference map before use.

The manifest source metadata binds a canonical `referenceGraphDigest` over the sorted normalized URI and content-digest pairs. Recompilation therefore cannot silently substitute a different external document even when its URI is unchanged. Self-contained documents need no reference map.

Source provenance stores a normalized public URI or operator-supplied opaque label. It never embeds an absolute local path, username, home directory, query credential, or URL fragment. Compiler diagnostics redact authorization material and local source roots.

Compiler `safety`, `risk`, action classification, cardinality, and permission mappings are hints. Runtime recomputes security-relevant classification from the verified method, path, operation ID, and validated input. Permission mapping remains advisory and cannot authorize a request.

## 8. CatalogStore and conformance

Storage is an asynchronous semantic port, not arbitrary SQL:

```ts
export interface CatalogStore {
  getManifest(catalogId: CatalogId, releaseId: ReleaseId): Promise<ManifestEnvelope>;
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
```

Every record lookup includes the immutable catalog and release identity; typed operation and schema IDs are not globally unique across releases. The Node-only SQLite adapter translates synchronous `node:sqlite` work into this async contract. The Worker-safe package exports structural D1-like adapter helpers against a minimal async prepared-statement interface, but imports no Cloudflare types. The conformance suite checks release isolation, candidate bounding, exact identity, missing/duplicate rows, tampered rows, parameter binding, batched schema reads, stable errors, and manifest admission. Phase 3 runs the same suite against its D1 adapter.

The suite's public entry point is `runRuntimeConformanceSuite(adapterFactory, options)`, where `options.testAdapter` supplies the host test-framework adapter. It registers the same behavioral cases against any `CatalogStore` factory and does not claim D1 parity until it has run against an actual D1 execution environment.

## 9. Operation references and runtime methods

`search` returns an opaque, qualified, digest-bound `OperationRef` encoded as `opref.v1.<base64url(canonical-json)>`. The decoded payload contains only `catalogId`, `releaseId`, typed operation ID, and its manifest digest. It is not a credential or authorization token. Any modification is detected when the runtime compares it with the admitted manifest.

```ts
export interface OpenApiRuntime {
  search(input: SearchInput): Promise<SearchResult>;
  prepareRead(input: PrepareInput): Promise<PreparedCall>;
  prepareAction(input: PrepareInput): Promise<PreparedCall>;
  revalidate(call: PreparedCall): Promise<PreparedCall>;
}

export function digestPreparedCall(call: PreparedCall): Promise<Sha256>;
export function verifyPreparedCall(call: PreparedCall): Promise<void>;

export interface PrepareInput {
  operation: OperationRef;
  arguments: OpenApiArguments;
  pageToken?: string;
}

export type OpenApiValue =
  | null
  | boolean
  | number
  | string
  | OpenApiValue[]
  | { [key: string]: OpenApiValue };

export interface OpenApiArguments {
  path?: Readonly<Record<string, string | number | boolean>>;
  query?: Readonly<Record<string, OpenApiValue>>;
  headers?: Readonly<Record<string, string>>;
  body?: OpenApiValue;
}
```

The runtime resolves only the requested operation's schema closure breadth-first, in batched store reads, with cycle, hop, and byte bounds. It validates path, query, non-sensitive header parameters declared by the operation, and body inputs; applies OpenAPI style/explode serialization; rejects unknown or duplicate parameters; and refuses unsupported polymorphism rather than guessing. Cookie parameters are refused in v1 because the dispatch boundary never carries caller/model cookies. The model never supplies an HTTP method, URL, arbitrary header, origin, authentication value, or credential.

Before serialization, the host returns a bounded credential-profile binding: a stable profile ID, a domain-separated digest of the operator-owned non-secret profile configuration, and credential injection slots containing only a `header` or `query` placement and name. The runtime validates the profile ID, digest, and slots; rejects collisions with model-supplied parameters; sorts the slots deterministically; and commits the canonical slot list with `sha256("knitli.openapi-mcp.credential-slots.v1", slots)`. Prepared-call header validation preserves legal U+0009 HTAB field-value content while rejecting every other C0 control and DEL. `PreparedCall` contains the profile ID, `credentialProfileDigest`, and `reservedSlotsDigest`; credentials, credential values, token hashes, and OAuth subject identifiers never enter it. Later credential resolution is valid only while the configured profile and canonical slot commitments both match.

`digestPreparedCall` computes the versioned domain-separated digest and includes the credential-profile and reserved-slot commitments with every other public field except the self-digest. `verifyPreparedCall` verifies the self-digest and structural invariants without consulting storage. `OpenApiRuntime.revalidate` first calls `verifyPreparedCall`, then re-reads and re-verifies the active manifest, operation, and schema closure, reruns destination and credential-binding policy, and returns a freshly prepared call only when its operation, manifest, input, credential-profile, reserved-slot, and complete prepared-call digests are unchanged. These exact names are part of the Phase 3 contract.

`prepareRead` accepts only recomputed reads. `prepareAction` accepts only recomputed mutations. A mismatch fails with a stable error naming the correct tool.

```ts
export interface CredentialProfileBinding {
  profileId: string;
  profileDigest: Sha256;
  slots: readonly CredentialSlot[];
}

export interface CredentialBindingResolver {
  resolve(context: Readonly<CredentialSlotContext>): Promise<CredentialProfileBinding>;
}
```

## 10. PreparedCall and action classification

`PreparedCall` is credential-free and canonicalizable:

```ts
export interface PreparedCall {
  version: 2;
  catalogId: CatalogId;
  releaseId: ReleaseId;
  operationId: TypedOperationId;
  operationDigest: Sha256;
  manifestDigest: Sha256;
  /** Stable operator-selected profile identifier; never a user or token identifier. */
  credentialProfileId: string;
  /** Commitment to non-secret configured profile authority and revision. */
  credentialProfileDigest: Sha256;
  /** Commitment to host-selected injection locations, never credential values. */
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
```

`headers` may contain only runtime-generated representation headers such as `accept` and `content-type` plus validated, operation-declared non-credential header parameters. It never contains authentication, cookies, forwarding headers, or arbitrary caller-supplied transport headers. The digest binds every field except itself using `knitli.openapi-mcp.prepared-call.v2` canonical encoding, with `body` represented by its SHA-256 digest, `credentialProfileDigest` binding the selected non-secret profile configuration, and `reservedSlotsDigest` binding the separately domain-separated canonical credential-slot list.

```ts
export type ActionKind =
  | "create" | "update" | "delete" | "communicate"
  | "authority" | "transaction" | "execute" | "unknown";

export type ActionCardinality =
  | { kind: "single" }
  | { kind: "bounded"; maxAffected: number }
  | { kind: "unbounded" }
  | { kind: "unknown" };
```

Classification is conservative. `DELETE` is `delete`; messaging/sharing/invitation is `communicate`; role/grant/permission/membership changes are `authority`; payment/transfer/refund is `transaction`; run/deploy/invoke is `execute`; clear create/update evidence maps those kinds; everything else is `unknown`. A concrete required resource identifier yields `single`; an input array with a verified `maxItems` yields `bounded`; explicit bulk/all semantics yield `unbounded`; absence of proof yields `unknown`.

Every action requires an `ActionAuthorizer` decision in v1. Per-call confirmation is the default; an exact constrained operator policy is treated as the operator's standing out-of-band confirmation. Only create/update actions with single or bounded cardinality and a finite `maxAffected` may use that standing confirmation. `unknown`, high-risk, `delete`, `communicate`, `authority`, `transaction`, `execute`, and unknown/unbounded cardinality always require fresh per-call confirmation and can never be policy-auto-approved.

Exact-policy authorization is release-exact in v1. Startup configuration contains templates, because a static file cannot know the random live grant ID created in a new process. Every template binds `catalogId`, `releaseId`, `manifestDigest`, `operationId`, `operationDigest`, `credentialProfileDigest`, action kind, a versioned closed-world argument constraint tree, cardinality, finite `maxAffected`, and expiry. Constraint leaves are exact JSON values, closed allowed-string sets, or finite numeric bounds; objects require an exact key set and recursively constrain every value; arrays have a finite item bound and recursively constrain every item. There is no regex, callback, schema reference, unbounded collection, or implicit `additionalProperties` escape. A missing constraint is denial, never a wildcard, and neither a generation range nor a familiar release name authorizes an unseen manifest or schema closure. A new release, manifest, or profile configuration requires a new reviewed template.

A template is not active merely because it is present at startup. The first matching call in each process/live credential grant requires fresh per-call confirmation. Acceptance records a bounded process-local activation binding the canonical `policyDigest` to the current `credentialBindingDigest` and expiry, and also mints the single-use receipt for that exact call. Later matching calls may use the activation, but each still receives its own single-use receipt. Restart, environment-secret rotation, OAuth relogin/account switch, profile change, or expiry makes the activation unusable and requires fresh confirmation; no old activation is rebound automatically.

Sensitive action-token matching includes bounded plural normalization; dangerous families take precedence over routine create/update evidence. For cardinality, a concrete required resource identifier means the exact required target placeholder is the terminal path segment. A parent-resource identifier before a collection does not prove `single`; absent another verified finite bound, that action remains `unknown` cardinality and high-risk.

## 11. Engine-owned action authorization

An MCP client's remembered permission for the global `action` tool is insufficient. Authorization is inside the engine and binds one exact `PreparedCall.preparedCallDigest` plus the live non-secret credential binding selected for that call:

```ts
export type VerifiedActionRequestState = object & {
  readonly __verifiedActionRequestState: unique symbol;
};

export type AuthorizationContext =
  | { kind: "initial" }
  | {
      kind: "resume";
      requestState: VerifiedActionRequestState;
      inputResponses: unknown;
    };

export interface ActionAuthorizer {
  authorize(
    call: PreparedCall,
    credential: CredentialAuthorizationBinding,
    context: AuthorizationContext,
  ): Promise<AuthorizationDecision>;
  /** Atomically validates and consumes one configured-authorizer receipt. */
  consume(
    decision: AuthorizedActionDecision,
    call: PreparedCall,
    credential: CredentialAuthorizationBinding,
  ): Promise<void>;
}

export interface AuthorizedActionDecision {
  status: "authorized";
  callDigest: Sha256;
  credentialBindingDigest: Sha256;
  path: "per-call" | "exact-policy";
  authorizationId: AuthorizationId;
  policyDigest?: Sha256;
}

export type AuthorizationDecision =
  | AuthorizedActionDecision
  | {
      status: "input-required";
      presentation: SafeApprovalPresentation;
      requestState: string;
    }
  | { status: "denied"; reason: string };
```

`VerifiedActionRequestState`, `AuthorizationId`, and `ActionDispatchPermit` are opaque capabilities, not caller-constructible strings or structural records. Runtime WeakSet/WeakMap registration is authoritative in addition to nominal TypeScript branding. A permit is registered in module-private runtime state, binds exact call and credential-binding digests, and is synchronously deleted by action dispatch before its first `await`. Copied, forged, mismatched, missing, or reused capabilities fail before secret-bearing request construction or network I/O.

Default is deny. The stdio server ships a client-mediated per-call authorizer using the modern MCP SDK's `input_required` elicitation flow. The confirmation presentation contains escaped, length-bounded trusted labels and clearly quoted untrusted values: exact API/release/operation, method, origin and relative path, selected credential profile/audience/scopes, action kind/cardinality, normalized argument summary, prepared-call digest, and credential-binding digest. A model-callable `confirm` argument does not exist.

The MCP response and `requestState` are untrusted. The authorizer owns an HMAC-SHA256 request-state codec with at least 32 random process bytes and an internal clock; caller-supplied time is never authoritative. Its verifier is installed as the SDK request-state hook and returns an opaque verified-state capability, so SDK validation is defense in depth and a direct authorizer caller cannot substitute decoded state. Every versioned state payload is strictly decoded and matched field-for-field against bounded process-local ledger state.

The portable flow uses two handler entries, which both modern MCP and the SDK's legacy shim can drive. On the first entry, the authorizer records a single-use pending-confirmation tuple bound to call and credential digests and returns the closed `input-required` decision with presentation and minted request-state string. The stdio handler alone maps that decision to `inputRequired({ inputRequests: { confirm: inputRequired.elicit(...) }, requestState })`. On the second entry, the handler passes only the authorizer-verified opaque state plus raw input responses; `inputResponse` distinguishes decline/cancel/missing data and `acceptedContent` validates accepted content inside the authorizer. The engine freshly re-prepares and revalidates the call and credential binding; the authorizer atomically consumes the pending-confirmation tuple, generates a random authorization ID with at least 128 bits, and records one unused authorization receipt. It then returns an authorized decision directly—there is no state-only third round. Replaying the accepted response cannot mint a second receipt.

Every successful exact-policy match also creates a fresh random receipt in the same bounded ledger; a standing rule is reusable, but each resulting dispatch decision is single-use. Receipts bind authorization ID, call digest, credential-binding digest, path, optional canonical policy digest, and expiry. `ActionAuthorizer.consume` performs lookup, full tuple and expiry validation, and deletion synchronously with no intervening `await`. Expired entries are pruned under a bounded budget; capacity exhaustion rejects rather than evicts a live entry. Reuse, concurrent double-consume, missing ledger state, tuple mismatch, expiry, or permit reuse denies. Unsupported elicitation, decline/cancel, changed arguments or credentials, malformed/missing state, and policy mismatch also deny.

An engine-owned, unexported `ActionAuthorizationBroker` verifies the decision/call/live-binding tuple, awaits the configured authorizer's atomic `consume`, then synchronously issues the registered one-use permit before returning to the sole action dispatch helper. External authorizers return decisions and atomically consume their own out-of-band receipt/claim; they never receive the private permit issuer and cannot manufacture a transport-accepted permit. Selecting a permissive external authorizer is an explicit trusted operator configuration, not a model-controlled path. stdio owns stdin/stdout; all status and diagnostic output goes to stderr.

This trusts the locally configured MCP client to present its dedicated elicitation UI to the human; the protocol cannot cryptographically prove a human clicked. Operators who do not accept that local client boundary must configure an external `ActionAuthorizer` that verifies and atomically consumes an out-of-band signed decision; the engine-owned broker supplies the transport permit only after that succeeds. The public interface supports it without weakening the default.

## 12. Authentication profiles and secret storage

Authentication is explicit configuration per API profile and never inferred from the OpenAPI `security` section:

```ts
export type AuthProfile =
  | { type: "bearer-env"; env: string }
  | { type: "api-key-env"; env: string; placement: "header" | "query"; name: string }
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

export interface CredentialAuthorizationBinding {
  profileId: string;
  profileDigest: Sha256;
  grantId: string;
  audience?: string;
  scopes: readonly string[];
  slotsDigest: Sha256;
  bindingDigest: Sha256;
}

export interface CredentialSnapshot {
  credential: Credential;
  binding: CredentialAuthorizationBinding;
}
```

Environment profiles name variables in operator-owned configuration; the names and values are absent from tool schemas and results. OAuth endpoints, client ID, resource, and scopes are fixed trusted configuration. `profileDigest` commits the stable profile ID and complete non-secret auth configuration and changes on any configuration revision. Each provider also assigns a random process-local `grantId`: a new OAuth login/account or changed environment secret rotates it, while ordinary refresh within the same OAuth grant retains it. `bindingDigest` domain-separates and commits the profile digest, grant ID, audience, normalized scope set, and slot digest; it never includes a credential, credential hash, refresh token, provider subject, or other secret-derived identifier.

Authorization-code PKCE uses S256, at least 32 random bytes of state, a loopback listener on `127.0.0.1` with an ephemeral port, an exact redirect URI, a one-use callback, and a short deadline. Codes, verifier, tokens, token error bodies, and callback query strings are never logged or returned to the model.

The concrete safe v1 storage choice is `MemorySecretStore`: OAuth access and refresh tokens live only in process memory and disappear on server exit. This costs reauthorization after restart and avoids pretending that a `0600` plaintext file protects secrets from same-user processes. Persistent OS-keychain implementations may be added behind `SecretStore` after their platform behavior and packaging are reviewed; they are not required for Phase 2. Environment credentials remain in the operator's environment and are read only at dispatch.

## 13. Guarded dispatch

Only an `AuthorizedTransport` can add credentials, and only after authorization (for actions) and immediate revalidation. The effective destination set is the intersection of signed manifest origins and the operator's trusted profile origins; either side may narrow access and neither may widen the other:

```ts
export interface AuthorizedTransport {
  /** Performs binding, destination, and DNS checks without sending upstream bytes. */
  prepareDispatch(
    call: PreparedCall,
    credential: CredentialSnapshot,
  ): Promise<PreparedDispatch>;
  /** Rechecks opaque plan ownership and exact call/live-binding tuple without I/O. */
  verifyPlan(
    plan: PreparedDispatch,
    call: PreparedCall,
    credential: CredentialAuthorizationBinding,
  ): void;
  dispatchRead(plan: PreparedDispatch): Promise<CallOutcome>;
  dispatchAction(
    plan: PreparedDispatch,
    permit: ActionDispatchPermit,
  ): Promise<CallOutcome>;
}
```

`prepareDispatch` first derives the canonical credential-slot list and credential binding from the actual immutable snapshot. It timing-safely matches the profile ID/digest and slot commitments against the prepared call, stores the snapshot's live `bindingDigest` in private plan state, applies destination policy, resolves and pins allowed addresses, and returns an opaque short-lived plan without constructing a secret-bearing request or sending bytes to the upstream API. `verifyPlan` then checks plan registration/expiry plus exact plan/call/live-binding digests synchronously before authorization consumption. A mismatch fails before receipt consumption. The raw HTTP primitive remains unexported.

For actions, the stdio execution path resolves one immutable credential snapshot, completes authorization, prepares the dispatch plan, freshly revalidates the exact call and active manifest at the last practical point, verifies the plan/decision/call/binding tuple, atomically consumes the single-use receipt into a permit, and immediately calls `dispatchAction(plan, permit)` exactly once. `dispatchAction` synchronously authenticates and deletes the permit and rechecks immutable plan bindings before its first `await`, request construction, secret injection, or network I/O. It never retries an action. A failed or outcome-unknown dispatch leaves the receipt and permit consumed. `dispatchRead` rejects action plans, and `dispatchAction` rejects read plans or a bare `PreparedCall`, so the package transport exposes no convention-only action bypass.

The active-manifest check is performed immediately before receipt consumption. An active-generation transition racing after that check cannot alter the digest-pinned call or dispatch plan, but may finish just before request bytes are sent; Phase 2 does not claim a cross-process lease across that irreducible boundary. Phase 3 may strengthen this with a Gatekeeper transaction/lease around grant consumption and dispatch admission.

The Node local implementation defaults to public HTTPS. Each profile has a mandatory exact-origin destination policy. Before connecting, it resolves every A/AAAA address, rejects loopback, private, link-local, multicast, documentation, benchmarking, reserved, IPv4-mapped-private, and metadata destinations, and pins the approved address for the connection so DNS rebinding cannot swap it after validation.

Fetch uses `redirect: "manual"`, a maximum of three redirects, destination and DNS revalidation on every hop, and an origin comparison. Credentials and bodies are stripped before any cross-origin follow. Authorization, proxy authorization, cookies, `Host`, connection/transfer/upgrade headers, forwarding headers, and provider identity headers are denied from model/runtime inputs. Cross-origin redirects requiring authentication are returned as bounded redirect outcomes, not followed with credentials.

Content length is checked before reading and decompressed bytes are counted while streaming. The request deadline, response limit, page limit, and cumulative pagination bytes use the limits in §6. Pagination links are validated and converted to opaque process-HMAC tokens; the model never receives a reusable authenticated URL. Reads may retry only explicitly classified transient failures within one deadline and only when the operation is idempotent. Actions are never automatically retried. A disconnect or timeout after bytes may have reached the upstream returns `UPSTREAM_OUTCOME_UNKNOWN`, never a false failure that invites an automatic repeat.

## 14. Three global MCP tools

The entire local server advertises exactly:

```text
search({ query, api?, limit? })
read({ operation, arguments, pageToken? })
action({ operation, arguments })
```

- `search` performs bounded cross-catalog search and returns operation refs, summaries, input outlines, recomputed safety/action metadata, deprecation, and advisory permission information.
- `read` prepares, revalidates, authenticates, and dispatches a read. Continuations use opaque page tokens.
- `action` prepares an action, resolves and binds the selected credential grant, runs engine-owned authorization, prepares a no-upstream-bytes dispatch plan, freshly revalidates, atomically consumes the single-use receipt into an opaque permit, and dispatches exactly once.

Tool schemas contain no URL, method, arbitrary transport header, authorization, credential, API token, client ID, confirmation flag, action classification, cardinality, digest override, or risk override field. Structured `arguments.headers` accepts only values for non-credential header parameters declared by the selected operation. Catalog/profile configuration is operator-owned startup configuration.

The server uses `McpServer` from `@modelcontextprotocol/server` and `serveStdio` from `@modelcontextprotocol/server/stdio`. Version 2.0.0 is the implementation baseline. `serveOpenApiStdio` calls `serveStdio(() => createOpenApiMcpServer(options))`, supplying a fresh-server factory rather than a prebuilt server or a directly constructed `StdioServerTransport`; the SDK owns framing and connection lifecycle. One handler supports the modern 2026-07-28 input-required flow and the SDK's legacy-era shim. Protocol compatibility tests cover both eras. See the official [first-server guide](https://github.com/modelcontextprotocol/typescript-sdk/blob/main/docs/get-started/first-server.md), [input-required guide](https://github.com/modelcontextprotocol/typescript-sdk/blob/main/docs/servers/input-required.md), and [protocol-version guide](https://github.com/modelcontextprotocol/typescript-sdk/blob/main/docs/protocol-versions.md).

## 15. Stable errors, rendering, and audit

`OpenApiMcpError` exposes a stable `code`, safe message, retryability, and bounded safe details. Initial codes include:

```text
ARTIFACT_FORMAT_UNSUPPORTED      MANIFEST_INVALID
MANIFEST_SIGNATURE_INVALID      MANIFEST_ROLLBACK_REJECTED
MANIFEST_GENERATION_CONFLICT
RECORD_NOT_ADMITTED             RECORD_DIGEST_MISMATCH
OPERATION_REF_INVALID           OPERATION_NOT_FOUND
SCHEMA_RESOLUTION_LIMIT         INPUT_INVALID
TOOL_SAFETY_MISMATCH            ACTION_CONFIRMATION_REQUIRED
ACTION_DENIED                   ACTION_CONFIRMATION_EXPIRED
AUTH_PROFILE_INVALID            AUTH_REQUIRED
DESTINATION_DENIED              RESPONSE_LIMIT_EXCEEDED
PAGINATION_LIMIT_EXCEEDED       UPSTREAM_ERROR
UPSTREAM_OUTCOME_UNKNOWN
```

Approval text, MCP results, errors, and logs use separate renderers. Upstream read content is explicitly marked untrusted and is never reused as trusted approval prose. Untrusted strings are length-bounded, control characters removed, Markdown fences/headings defused, and values quoted as data. Logs redact authorization, cookies, API keys, OAuth codes/verifiers/tokens, configured secret environment values, sensitive query keys, bodies by default, and local source paths. Audit events contain release/operation/call digests, classification, authorization path, timing, and outcome—not credentials or raw bodies.

## 16. Testing and release gates

Tests are behavior-first and run through `mise exec --`:

- canonical JSON fixtures, duplicate keys, prototype keys, manifest limits, signatures, logical row tampering, generation downgrade, signed rollback, and manifest-last publication;
- OpenAPI complexity limits, JSON Pointer escaping, own-property traversal, digest-pinned multi-document reference maps, root/symlink escape, ID grammar, path redaction, conservative runtime classification, advisory permissions;
- the same `CatalogStore` conformance suite against in-memory, Node SQLite, and the structural D1 test adapter;
- search bounds, batched resolution, schema cycles/limits, serialization, digest binding, and revalidation after catalog mutation;
- confirmation decline/accept/tampered state/changed input/unsupported client/exact-policy constraints;
- environment bearer/API key and OAuth PKCE state/callback/token redaction using a loopback test issuer and `MemorySecretStore`;
- DNS and redirect attacks, credential/body stripping, header denylist, response/decompression/pagination/deadline bounds, action no-retry, and outcome-unknown handling;
- exact three-tool discovery and calls over stdio in modern and legacy protocol eras, with stdout corruption checks;
- Node 24, current Bun, Worker import/bundle, packed-tarball install, exports, CLI, and consumer type tests.

The root `CLAUDE.md` currently says the repository has no compiled code or tests. Updating that stale guidance is an implementation task, not part of this design-document edit.

Publishing is observed, not inferred: a clean packed tarball must pass consumer tests before merge; CI, semantic-release, trusted publishing, npm package visibility, tag, provenance, and a fresh install are separate gates. No plan step may claim a release until those external states are observed. Because npm does not permit configuring this package's trusted publisher before its first version exists, the one-time bootstrap publishes the tested `0.0.0` tarball from a protected GitHub job under a non-default `bootstrap` dist-tag with a short-lived granular token. Bun builds and packs but never authenticates or publishes. After package creation, the operator configures the exact OIDC trust relationship, deletes and revokes the token path, and only then allows semantic-release to create the first real `latest` release. Registry attestation metadata alone is not provenance proof: both the bootstrap and every real release must pass `npm audit signatures --json --include-attestations` in a clean npm consumer, and the retained handoff must bind the verified package version, integrity, tarball, build workflow, source commit, and CI run.

## 17. Rollback and operational recovery

Code rollback means installing the prior known-good package version. Data rollback is not file replacement alone: it requires the signed rollback authorization in §5.4 or publication of a corrected higher generation. If a v5 rollout fails, operators keep the previous immutable release and generation state, disable the new catalog profile, and restore the prior package. Credentials remain process-local and vanish on process exit.

Phase 2 is complete when a fresh public install can configure a signed provider-neutral v5 release—self-contained or resolved through the bounded reference-map contract—discover it through only three tools, execute reads with explicit user credentials, require exact engine-owned authorization for every action, and pass the same portable runtime contracts that Phase 3 will implement against D1. Historical tagless v4 releases remain a read-compatibility path, not the production compiler target.
