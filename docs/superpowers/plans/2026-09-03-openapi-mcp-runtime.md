# OpenAPI MCP Runtime and Local stdio Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a public local stdio MCP server for provider-neutral signed OpenAPI releases, including bounded digest-pinned multi-document schemas, exposing only `search`, `read`, and `action`, plus a host-neutral runtime contract that a later Cloudflare OS Gatekeeper can consume.

**Architecture:** The existing compiler remains available while a new immutable v4 release format signs canonical logical records rather than SQLite file layout. A Web/Worker-safe runtime verifies every hydrated record, prepares credential-free digest-bound calls, and delegates secrets, authorization, and transport to host ports; Node-only adapters provide SQLite, local auth, guarded HTTP, and stdio MCP.

**Tech Stack:** TypeScript strict, Node 24, current mise-managed Bun, Web Crypto, `node:sqlite`, `@modelcontextprotocol/server@2.0.0`, Zod 4 selected and pinned by the implementation lockfile, Bun test, Biome.

**Spec:** `docs/superpowers/specs/2026-09-03-openapi-mcp-runtime-design.md`

## Global Constraints

- Phase 2 is public/local stdio plus a host-neutral Web/Worker-safe runtime; it contains no hosted HTTP MCP, Cloudflare OS, Gatekeeper, Cap'n Web, Durable Object, Access, or Cloudflare binding types.
- The only model-visible tool names are exactly `search`, `read`, and `action`.
- Tool arguments contain no URL, HTTP method, arbitrary transport header, auth value, credential, confirmation flag, risk override, digest override, or action-classification override. Structured operation arguments may supply only non-credential header parameters declared by the selected operation.
- `ARTIFACT_FORMAT_VERSION` is exactly `4`; v4 execution requires a verified Ed25519 manifest and use-time logical record membership/digest checks.
- Production v4 releases are immutable and manifest-last. Existing v3 append/file-signing APIs remain explicitly legacy; v3 is inventory/search-only in the new runtime.
- The runtime contract exports the exact names `CatalogStore`, `OpenApiRuntime`, `PreparedCall`, `verifyPreparedCall`, `digestPreparedCall`, and `runRuntimeConformanceSuite`.
- `@knitli/openapi-mcp/runtime` and `/conformance` import only Web Platform APIs and Worker-safe sibling files. Node, Bun, MCP SDK, SQLite, Cloudflare, and Cap'n Web imports stay outside those graphs.
- Every action passes `ActionAuthorizer`; default is deny. Authorization binds the exact `PreparedCall.preparedCallDigest`, then the call is revalidated before credentials are injected.
- Runtime classification is authoritative. Compiler safety/risk/action/cardinality and permission mappings are advisory.
- The concrete v1 secret store is process-memory-only. Environment credentials are read at dispatch; OAuth refresh tokens are not persisted.
- Public HTTPS, an exact-origin policy, DNS-aware local enforcement, manual redirects, bounded response/pagination/deadline behavior, and no automatic action retry are mandatory.
- Application limits are the exact reduction-only `DEFAULT_RUNTIME_LIMITS` values in the spec, including the 128 MiB aggregate release-inventory/search-proof ceiling; Cloudflare plan quotas do not define runtime behavior.
- Compiler limits are the exact `DEFAULT_COMPILER_LIMITS` values in the spec, including 128 MiB source, 100,000 paths/operations, 50,000 schemas, depth 64, and 1 MiB logical records.
- Every non-fragment `$ref` must resolve through an explicit URI-to-local-file-and-SHA-256 reference map beneath one approved realpath root. The compiler never performs ambient or credentialed network fetches.
- Run repository commands through `mise exec --`. A trust/setup failure is environment evidence, not a test result.
- TypeScript uses strict mode and `verbatimModuleSyntax`; use `import type` for type-only imports. Biome uses double quotes and 2-space indentation.
- Commit scope is `openapi-mcp`. Executors commit only after the task's focused and regression tests pass.
- Root `CLAUDE.md` is stale about compiled code and tests; Task 12 updates it after the implementation makes the replacement statements true.

---

## File Structure

Existing compiler modules stay in place to avoid a high-risk move while the v4 boundary is introduced.

```text
packages/openapi-mcp/
  src/
    index.ts                         MOD — legacy root compiler compatibility exports
    compiler.ts                      NEW — explicit public compiler barrel
    cli.ts                           MOD — compile-release, serve, and auth commands
    load.ts                          MOD — bounded structural OpenAPI loading
    operations.ts                    MOD — safe pointer handling, IDs, provenance inputs
    schema.ts                        MOD — name v3 legacy version explicitly
    sign.ts                          MOD — label exact-file signing as legacy transport checksum
    runtime/
      index.ts                       NEW — Worker-safe public barrel
      versions.ts                    NEW — explicit contract/format/call versions and limits
      types.ts                       NEW — branded IDs, records, ports, PreparedCall
      errors.ts                      NEW — stable error codes and safe details
      strict-json.ts                 NEW — duplicate-key rejecting parser and canonical JSON
      digest.ts                      NEW — Web Crypto hashing, signature, domain separation
      references.ts                  NEW — ID grammar and OperationRef encoding
      manifest.ts                    NEW — admission, generation, rollback validation
      store.ts                       NEW — CatalogStore and structural D1-like adapter
      verify-record.ts               NEW — use-time record membership/digest verification
      schema-resolver.ts             NEW — bounded breadth-first batched resolution
      classify.ts                    NEW — authoritative safety/action/cardinality/risk
      serialize.ts                   NEW — OpenAPI validation and style/explode serialization
      prepared-call.ts               NEW — prepare/digest/verify/revalidate
      runtime.ts                     NEW — OpenApiRuntime implementation and bounded search
    release/
      load-v4.ts                       NEW — bounded duplicate-key-safe JSON/YAML loading
      schema-v4.ts                   NEW — v4 SQLite transport schema
      manifest-builder.ts            NEW — canonical record construction and manifest signing
      compile-release.ts             NEW — bounded compiler orchestration
      publish.ts                     NEW — immutable manifest-last publication
    sqlite/
      index.ts                       NEW — Node-only public barrel
      catalog-store.ts               NEW — node:sqlite CatalogStore
      generation-store.ts            NEW — atomic 0600 generation state
      destination-guard.ts           NEW — DNS resolution and address policy
      auth.ts                        NEW — auth profiles and local OAuth PKCE
      guarded-fetch.ts               NEW — bounded pinned-address HTTP transport
    stdio/
      index.ts                       NEW — Node-only public barrel
      config.ts                      NEW — strict operator configuration
      authorizer.ts                  NEW — exact policy plus input-required confirmation
      server.ts                      NEW — only three MCP tools
      render.ts                      NEW — safe approval/result/log rendering
    conformance/
      index.ts                       NEW — public runRuntimeConformanceSuite export
      runtime-suite.ts               NEW — host-neutral adapter behavior suite
      fixtures.ts                    NEW — canonical signed in-memory fixture
  tests/
    canonical-json.test.ts           NEW
    manifest-v4.test.ts              NEW
    compiler-hardening.test.ts       NEW
    release-v4.test.ts               NEW
    catalog-conformance.test.ts      NEW
    sqlite-catalog.test.ts           NEW
    d1-structural.test.ts            NEW
    runtime-search.test.ts           NEW
    runtime-prepare.test.ts          NEW
    action-authorizer.test.ts        NEW
    auth.test.ts                     NEW
    guarded-fetch.test.ts            NEW
    stdio-server.test.ts             NEW
    package-consumers.test.ts        NEW
    fixtures/v3.sqlite               NEW — frozen current-format migration fixture
    fixtures/strict-config.json      NEW — non-secret local config example
  test-consumers/
    node.mts                         NEW — packed-package Node import consumer
    bun.ts                           NEW — packed-package Bun import consumer
    worker.ts                        NEW — browser/Worker-target import consumer
```

---

### Task 1: Freeze the portable contract and export boundary

**Files:**
- Create: `packages/openapi-mcp/src/compiler.ts`
- Create: `packages/openapi-mcp/src/runtime/versions.ts`
- Create: `packages/openapi-mcp/src/runtime/types.ts`
- Create: `packages/openapi-mcp/src/runtime/errors.ts`
- Create: `packages/openapi-mcp/src/runtime/index.ts`
- Modify: `packages/openapi-mcp/src/index.ts`
- Modify: `packages/openapi-mcp/src/schema.ts`
- Modify: `packages/openapi-mcp/package.json`
- Create: `packages/openapi-mcp/tests/package-consumers.test.ts`
- Create: `packages/openapi-mcp/test-consumers/worker.ts`

**Interfaces:**
- Consumes: existing `compile`, signing, and compiler record APIs.
- Produces: `RUNTIME_CONTRACT_VERSION`, `ARTIFACT_FORMAT_VERSION`, `PREPARED_CALL_VERSION`, `DEFAULT_RUNTIME_LIMITS`, branded ID/digest types, `CatalogStore`, `GenerationStore`, `OpenApiRuntime`, `PreparedCall`, host ports, and `OpenApiMcpError`.

- [ ] **Step 1: Write the failing Worker-boundary and contract-name tests**

```ts
import { expect, test } from "bun:test";

test("runtime exposes the Phase 3 contract versions", async () => {
  const runtime = await import("../src/runtime/index.ts");
  expect(runtime.ARTIFACT_FORMAT_VERSION).toBe(4);
  expect(runtime.RUNTIME_CONTRACT_VERSION).toBe(1);
  expect(runtime.PREPARED_CALL_VERSION).toBe(1);
});

test("runtime bundles for a Worker target without Node shims", async () => {
  const result = await Bun.build({
    entrypoints: [`${import.meta.dir}/../test-consumers/worker.ts`],
    target: "browser",
    throw: false,
  });
  expect(result.success).toBe(true);
  expect(result.logs.map(String).join("\n")).not.toMatch(/node:|bun:/);
});
```

- [ ] **Step 2: Run the test and record the red result**

Run: `mise exec -- bun test packages/openapi-mcp/tests/package-consumers.test.ts`
Expected: FAIL because `src/runtime/index.ts` and the named exports do not exist.

- [ ] **Step 3: Define versions, limits, errors, and the exact public types**

Use this contract as the implementation spine:

```ts
export type Sha256 = string & { readonly __sha256: unique symbol };
export type CatalogId = string & { readonly __catalogId: unique symbol };
export type ReleaseId = string & { readonly __releaseId: unique symbol };
export type TypedOperationId = `operation:${string}`;
export type TypedSchemaId = `schema:${string}`;

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

export interface OpenApiRuntime {
  search(input: SearchInput): Promise<SearchResult>;
  prepareRead(input: PrepareInput): Promise<PreparedCall>;
  prepareAction(input: PrepareInput): Promise<PreparedCall>;
  revalidate(call: PreparedCall): Promise<PreparedCall>;
}
```

Copy every `PreparedCall`, action, manifest, auth, and port field exactly from the spec into `types.ts`. Define `OpenApiMcpError` with readonly `code`, `retryable`, and already-redacted `details`; constrain `code` to the list in spec §15. Export only constants and types that are implemented in this task; do not add throwing or placeholder implementations for `digestPreparedCall`, `verifyPreparedCall`, or any later runtime function.

- [ ] **Step 4: Add explicit subpath exports without breaking the existing root**

Set `src/compiler.ts` to re-export the current compiler/file-signing surface. Keep `src/index.ts` as a compatibility re-export of `./compiler.ts`. Add export map entries for the implemented `./compiler` and `./runtime` entry points, with types/default paths under `dist`. Do not advertise a subpath until its real source entry point exists: Task 3 adds `./sqlite`, Task 5 adds `./conformance`, and Task 11 adds `./stdio`. Add a consumer regression that maps every advertised JavaScript/declaration target back to an emit-capable source entry point. Rename the current schema constant to `LEGACY_FORMAT_VERSION = 3` and update current compiler/tests to import that name; v4 uses only `ARTIFACT_FORMAT_VERSION`.

- [ ] **Step 5: Make the focused tests pass**

Run: `mise exec -- bun test packages/openapi-mcp/tests/package-consumers.test.ts packages/openapi-mcp/tests/schema.test.ts`
Expected: PASS; browser target resolves `/runtime` without a Node builtin.

- [ ] **Step 6: Run current compiler regression tests**

Run: `mise exec -- bun test packages/openapi-mcp`
Expected: all pre-Phase-2 tests PASS with v3 behavior unchanged.

- [ ] **Step 7: Commit**

```bash
git add packages/openapi-mcp
git commit -m "feat(openapi-mcp): define portable runtime contract"
```

---

### Task 2: Strict JSON, canonical digests, and operation references

**Files:**
- Create: `packages/openapi-mcp/src/runtime/strict-json.ts`
- Create: `packages/openapi-mcp/src/runtime/digest.ts`
- Create: `packages/openapi-mcp/src/runtime/references.ts`
- Create: `packages/openapi-mcp/tests/canonical-json.test.ts`

**Interfaces:**
- Consumes: branded IDs, `Sha256`, and limits from Task 1.
- Produces: `parseJsonStrict(text, limits)`, `canonicalJson(value)`, `sha256(domain, value)`, `verifyEd25519(payload, signature, key)`, `parseTypedRecordId`, `encodeOperationRef`, and `decodeOperationRef`.

- [ ] **Step 1: Write failing adversarial parser and reference tests**

```ts
import { expect, test } from "bun:test";
import { canonicalJson, parseJsonStrict } from "../src/runtime/strict-json.ts";
import { decodeOperationRef, encodeOperationRef } from "../src/runtime/references.ts";

test("canonical JSON is independent of insertion order", () => {
  expect(canonicalJson({ z: 1, a: [true, "x"] })).toBe('{"a":[true,"x"],"z":1}');
});

test("strict parsing rejects duplicate and prototype keys", () => {
  expect(() => parseJsonStrict('{"a":1,"a":2}')).toThrow(/duplicate/i);
  expect(() => parseJsonStrict('{"__proto__":{}}')).toThrow(/forbidden/i);
});

test("operation refs bind catalog release id and digest", () => {
  const ref = encodeOperationRef({
    catalogId: "work" as never,
    releaseId: "2026-09" as never,
    operationId: "operation:graph:users.List" as const,
    operationDigest: "a".repeat(64) as never,
  });
  expect(decodeOperationRef(ref).operationDigest).toBe("a".repeat(64));
  expect(() => decodeOperationRef(`${ref}x`)).toThrow(/OPERATION_REF_INVALID/);
});
```

- [ ] **Step 2: Run the test and record the red result**

Run: `mise exec -- bun test packages/openapi-mcp/tests/canonical-json.test.ts`
Expected: FAIL because the strict parser, digest functions, and ref codec are absent.

- [ ] **Step 3: Implement the strict recursive-descent parser**

Implement tokens directly over the input string so duplicate keys are observable before object construction. Track byte length, depth, key count, numeric grammar, and surrogate pairing. Build objects with `Object.create(null)`, reject `__proto__`, `prototype`, and `constructor`, and use `Object.hasOwn` for duplicate detection. Accept only JSON values; trailing bytes fail.

```ts
export function parseJsonStrict(
  text: string,
  limits: StrictJsonLimits = DEFAULT_STRICT_JSON_LIMITS,
): JsonValue {
  if (new TextEncoder().encode(text).byteLength > limits.maxBytes) {
    throw new OpenApiMcpError("MANIFEST_INVALID", "JSON input exceeds its byte limit");
  }
  const parser = new StrictJsonParser(text, limits);
  const value = parser.value(0);
  parser.requireEnd();
  return value;
}
```

- [ ] **Step 4: Implement canonical JSON and Web Crypto primitives**

Sort object keys by UTF-16 code units as required by JSON canonicalization, serialize finite numbers with JSON's shortest form, and reject values outside `JsonValue`. Hash `TextEncoder.encode(domain + "\0" + canonicalJson(value))` with `crypto.subtle.digest("SHA-256", ...)`. Import Ed25519 SPKI keys through Web Crypto and return false on malformed key/signature input.

- [ ] **Step 5: Implement and bound the ID/ref grammar**

Accept 1–128 ASCII characters for catalog/release/API segments and 1–512 for operation/schema tails; reject controls, whitespace edges, empty path segments, `.`/`..`, and separators not defined by the grammar. Encode refs exactly as `opref.v1.<base64url(canonical-json)>`; decoding validates the prefix, canonical shape, IDs, and bounds before returning branded values. The runtime detects a syntactically valid mutation by resolving the embedded catalog/release identity and comparing its manifest digest with the admitted manifest.

- [ ] **Step 6: Run focused and boundary tests**

Run: `mise exec -- bun test packages/openapi-mcp/tests/canonical-json.test.ts`
Expected: PASS including exact max-depth/max-byte boundaries, invalid `~` escape cases, negative zero normalization, unpaired surrogates, a malformed ref mutation, and a syntactically valid manifest-digest mutation rejected during resolution.

- [ ] **Step 7: Commit**

```bash
git add packages/openapi-mcp/src/runtime packages/openapi-mcp/tests/canonical-json.test.ts
git commit -m "feat(openapi-mcp): add canonical signed-data primitives"
```

---

### Task 3: Manifest admission, generation monotonicity, and signed rollback

**Files:**
- Create: `packages/openapi-mcp/src/runtime/manifest.ts`
- Create: `packages/openapi-mcp/src/runtime/verify-record.ts`
- Create: `packages/openapi-mcp/src/sqlite/generation-store.ts`
- Create: `packages/openapi-mcp/src/sqlite/index.ts`
- Modify: `packages/openapi-mcp/package.json`
- Create: `packages/openapi-mcp/tests/manifest-v4.test.ts`

**Interfaces:**
- Consumes: strict parsing, canonicalization, Web Crypto, manifest types, IDs, and `GenerationStore`.
- Produces: `admitManifest(envelope, trust, generations, limits)`, `verifyStoredRecord(manifest, record)`, `FileGenerationStore`, and signed rollback verification.

- [ ] **Step 1: Write failing trust-boundary tests**

```ts
test("row digest and manifest membership are both required", async () => {
  const admitted = await admitFixture();
  const row = fixtureOperation();
  await expect(verifyStoredRecord(admitted, { ...row, summary: "tampered" }))
    .rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
  await expect(verifyStoredRecord(admitted, { ...row, id: "operation:tiny:extra" }))
    .rejects.toMatchObject({ code: "RECORD_NOT_ADMITTED" });
});

test("a normally signed lower generation is rejected", async () => {
  const generations = new MemoryGenerationStore([
    ["tiny:issuer", { highestGeneration: 8, highestManifestDigest: digestForGeneration8 }],
  ]);
  await expect(admitManifest(signedManifest({ generation: 7 }), trust, generations))
    .rejects.toMatchObject({ code: "MANIFEST_ROLLBACK_REJECTED" });
});
```

Also test wrong issuer/key, wrong `keyId`, missing record, excess record count, origin normalization, manifest byte limit, malformed base64url, equal-generation/same-digest idempotence, equal-generation/different-digest `MANIFEST_GENERATION_CONFLICT`, expired or replayed rollback authorization, wrong current/target generation, and a rollback signature from the ordinary release key.

- [ ] **Step 2: Run the test and record the red result**

Run: `mise exec -- bun test packages/openapi-mcp/tests/manifest-v4.test.ts`
Expected: FAIL because manifest admission and record verification do not exist.

- [ ] **Step 3: Implement manifest and rollback admission**

```ts
export async function admitManifest(
  envelope: ManifestEnvelope,
  trust: ManifestTrust,
  generations: GenerationStore,
  limits: RuntimeLimits = DEFAULT_RUNTIME_LIMITS,
): Promise<AdmittedManifest> {
  const manifest = parseReleaseManifest(envelope.manifestJson, limits);
  await requireReleaseSignature(manifest, envelope.signature, trust);
  const manifestDigest = await digestReleaseManifest(manifest);
  const state = await generations.get(manifest.catalogId, manifest.issuer);
  if (state !== null && manifest.generation === state.highestGeneration) {
    if (manifestDigest !== state.highestManifestDigest) {
      throw new OpenApiMcpError("MANIFEST_GENERATION_CONFLICT");
    }
  } else if (state !== null && manifest.generation < state.highestGeneration) {
    await requireAndConsumeRollbackAuthorization(
      manifest,
      manifestDigest,
      state,
      envelope.rollback,
      trust,
    );
  }
  await generations.accept(manifest.catalogId, manifest.issuer, {
    generation: manifest.generation,
    manifestDigest,
  });
  return freezeAdmittedManifest(manifest);
}
```

Update generation state only after the whole manifest passes. Preserve the high-water generation/digest across an authorized rollback and record consumed rollback-authorization IDs so replay fails. Serialize concurrent accepts in `FileGenerationStore`; write a sibling with `open(..., 0o600)`, sync, rename, then sync the parent directory. Reject symlinks, non-regular files, ownership mismatch, group/world permissions, corruption, and a failed atomic write.

- [ ] **Step 4: Implement use-time record verification**

Reconstruct the logical record without transport-only row IDs or FTS fields, enforce its typed ID, recompute its domain-separated SHA-256, compare the row's stored logical digest for diagnostics, then compare the manifest map. Return a deeply frozen verified record; no caller receives the unverified row.

- [ ] **Step 5: Run focused tests and mutation checks**

Run: `mise exec -- bun test packages/openapi-mcp/tests/manifest-v4.test.ts`
Expected: PASS. Then temporarily invert the generation comparison, confirm the downgrade test fails, restore it, and rerun to PASS.

- [ ] **Step 6: Commit**

```bash
git add packages/openapi-mcp/src/runtime packages/openapi-mcp/src/sqlite/generation-store.ts packages/openapi-mcp/tests/manifest-v4.test.ts
git commit -m "feat(openapi-mcp): verify v4 manifests and logical records"
```

---

### Task 4: Harden OpenAPI ingestion and compile immutable v4 releases

**Files:**
- Modify: `packages/openapi-mcp/src/load.ts`
- Modify: `packages/openapi-mcp/src/operations.ts`
- Modify: `packages/openapi-mcp/src/schemas.ts`
- Modify: `packages/openapi-mcp/src/types.ts`
- Modify: `packages/openapi-mcp/src/sign.ts`
- Create: `packages/openapi-mcp/src/release/schema-v4.ts`
- Create: `packages/openapi-mcp/src/release/load-v4.ts`
- Create: `packages/openapi-mcp/src/release/reference-map.ts`
- Create: `packages/openapi-mcp/src/release/manifest-builder.ts`
- Create: `packages/openapi-mcp/src/release/compile-release.ts`
- Create: `packages/openapi-mcp/src/release/publish.ts`
- Modify: `packages/openapi-mcp/src/compiler.ts`
- Modify: `packages/openapi-mcp/src/cli.ts`
- Create: `packages/openapi-mcp/tests/compiler-hardening.test.ts`
- Create: `packages/openapi-mcp/tests/release-v4.test.ts`
- Create: `packages/openapi-mcp/tests/fixtures/v3.sqlite`

**Interfaces:**
- Consumes: v4 types, canonical logical digests, ID parser, manifest signing, compiler v3 extraction.
- Produces: `compileRelease(options): Promise<CompiledRelease>`, `publishRelease(compiled, target)`, CLI `compile-release`, and frozen v3 migration fixture.

- [ ] **Step 1: Write failing compiler-hardening tests**

```ts
test("JSON Pointer decodes once and never traverses a prototype", () => {
  const doc = Object.create(null);
  doc.components = { schemas: { "a/b~c": { type: "string" } } };
  expect(resolveLocalPointer(doc, "#/components/schemas/a~1b~0c")).toEqual({ type: "string" });
  expect(() => resolveLocalPointer(doc, "#/constructor/prototype"))
    .toThrow(/forbidden/i);
  expect(() => resolveLocalPointer(doc, "#/components/~2bad"))
    .toThrow(/escape/i);
});

test("source provenance does not disclose local paths", async () => {
  const release = await compileFixture({ sourceLabel: "graph-v1" });
  expect(release.manifest.source.uri).toBe("urn:openapi-source:graph-v1");
  expect(JSON.stringify(release.manifest)).not.toContain(process.cwd());
});
```

Add exact-limit cases for source bytes, paths, operations, schemas, parameters, properties, JSON depth, ref length, referenced-document count and aggregate bytes, record bytes, invalid IDs, path/operation server overrides, and unsupported OpenAPI versions. Add multi-document cases for relative and absolute URI normalization, missing reference-map entries, digest mismatch, duplicate normalized URI, JSON/YAML parser parity, query credentials, traversal and symlink escape, unsupported media type, excessive depth, and safe cycles.

- [ ] **Step 2: Write failing immutable-release tests**

Assert v4 tables include `record_id`, `record_json`, and `logical_digest`; every manifest digest matches canonical row content; FTS fields are outside the digest; rebuilding D1-shaped rows preserves logical digests; `compile-release` refuses an existing release ID; a simulated failure retains the previous release; and directory enumeration cannot see the new manifest before payload/signature are complete.

- [ ] **Step 3: Run both files and record the red result**

Run: `mise exec -- bun test packages/openapi-mcp/tests/compiler-hardening.test.ts packages/openapi-mcp/tests/release-v4.test.ts`
Expected: FAIL because bounded loading and v4 release compilation are absent.

- [ ] **Step 4: Harden loading and pointer traversal**

Add `CompilerLimits` with the exact `DEFAULT_COMPILER_LIMITS` values in spec §6, including `maxReferencedDocuments: 1_024`; apply `maxSourceBytes` to aggregate root-plus-reference bytes and `maxJsonDepth` to reference traversal depth. Count before allocation where possible. `loadSpecV4` uses `parseJsonStrict` for JSON and the `yaml` document API with unique-key errors enabled, bounded aliases, and an explicit node/depth/count walk before conversion to null-prototype data; the existing v3 loader stays compatible. Replace `resolveLocal` with exported `resolveLocalPointer` that checks `Object.hasOwn`, decodes `~1` then `~0` exactly once, validates canonical array indices, and rejects prototype keys. Sanitize thrown paths through `redactSourcePath(path, sourceLabel)`.

Implement `ReferenceMapV1` and a bounded `ReferenceResolver` port. The CLI accepts `--reference-root` and `--reference-map`; both are required when the graph contains a non-fragment `$ref`. Map entries bind a normalized URI to a relative file and expected SHA-256. Resolve every file through `realpath`, require it remain under the selected root, read it once within aggregate limits, verify the digest before parsing, then resolve its fragment with the same strict pointer logic. Reject ambient HTTP fetching. Compute the canonical sorted `referenceGraphDigest` and bind it into manifest source metadata.

- [ ] **Step 5: Define v4 transport tables and logical records**

Use ordinary SQLite tables for operations, schemas, release metadata, and lower-case `fts5`. Store one canonical `record_json` and its `logical_digest`; project indexed columns from the same validated record at compile time. Add SQL constraints for typed ID uniqueness and digest length. Permission and compiler classifications remain inside the signed record as advisory fields.

- [ ] **Step 6: Implement release construction and signing**

```ts
export interface CompileReleaseOptions {
  specPath: string;
  sourceUri: string;
  sourceRevision: string;
  catalogId: string;
  releaseId: string;
  generation: number;
  issuer: string;
  keyId: string;
  policyId: string;
  allowedOrigins: readonly string[];
  outDir: string;
  privateKeyPem: string;
  permissionsPath?: string;
  referenceRoot?: string;
  referenceMapPath?: string;
  referenceResolver?: ReferenceResolver;
}
```

Build into a fresh `mkdtemp` directory under `outDir`, close and sync SQLite, reread every record through the v4 parser, create one flat record map, canonicalize/sign the manifest, and verify the result with the derived public key before publication.

- [ ] **Step 7: Publish manifest last and preserve v3 explicitly**

Rename the immutable SQLite payload first, signature second, and manifest last. Refuse overwrite rather than append. Keep `compile --append`, `signArtifact`, and `verifyArtifact` under legacy help text. Add `compile-release` with all required flags; do not accept a local path as source provenance unless `--source-uri` or `--source-label` is supplied.

- [ ] **Step 8: Freeze the v3 reader fixture and run tests**

Generate `tests/fixtures/v3.sqlite` once from `tiny-api.yaml` using the existing compiler before changing its version symbol. Run: `mise exec -- bun test packages/openapi-mcp/tests/compiler-hardening.test.ts packages/openapi-mcp/tests/release-v4.test.ts packages/openapi-mcp/tests/compile.test.ts packages/openapi-mcp/tests/cli.test.ts`
Expected: PASS; v3 tests retain old behavior and v4 tests prove immutable publication.

- [ ] **Step 9: Commit**

```bash
git add packages/openapi-mcp
git commit -m "feat(openapi-mcp): compile immutable signed v4 releases"
```

---

### Task 5: Build semantic stores and the reusable conformance suite

**Files:**
- Create: `packages/openapi-mcp/src/runtime/store.ts`
- Create: `packages/openapi-mcp/src/sqlite/catalog-store.ts`
- Modify: `packages/openapi-mcp/src/sqlite/index.ts`
- Create: `packages/openapi-mcp/src/conformance/fixtures.ts`
- Create: `packages/openapi-mcp/src/conformance/runtime-suite.ts`
- Create: `packages/openapi-mcp/src/conformance/index.ts`
- Modify: `packages/openapi-mcp/package.json`
- Create: `packages/openapi-mcp/tests/catalog-conformance.test.ts`
- Create: `packages/openapi-mcp/tests/sqlite-catalog.test.ts`
- Create: `packages/openapi-mcp/tests/d1-structural.test.ts`

**Interfaces:**
- Consumes: `CatalogStore`, signed fixture release, manifest/record verification.
- Produces: `SqliteCatalogStore`, `createD1CatalogStore(binding)`, and `runRuntimeConformanceSuite(adapterFactory, options)`.

- [ ] **Step 1: Write the failing reusable suite**

```ts
export interface RuntimeConformanceOptions {
  testAdapter: ConformanceTestAdapter;
}

export function runRuntimeConformanceSuite(
  factory: CatalogStoreFactory,
  options: RuntimeConformanceOptions,
): void {
  const t = options.testAdapter;
  t.test("bounds candidates before hydration", async () => {
    const { store, fixture } = await factory();
    const hits = await store.searchCandidates({ ...fixture.query, limit: 2 });
    t.equal(hits.length, 2);
  });
  t.test("returns exact typed identities and null for missing rows", async () => {
    const { store, fixture } = await factory();
    t.equal(
      (
        await store.getOperation(
          fixture.catalogId,
          fixture.releaseId,
          fixture.operationId,
        )
      )?.id,
      fixture.operationId,
    );
    t.equal(
      await store.getOperation(
        fixture.catalogId,
        fixture.releaseId,
        "operation:tiny:missing" as never,
      ),
      null,
    );
  });
}
```

Register additional cases for bound parameters, malicious FTS candidates, duplicate result rows, tampered logical content, batched `getSchemas`, empty arrays, stable errors, catalog/release identity isolation, the same typed record ID in two releases, and no arbitrary SQL escape hatch.

- [ ] **Step 2: Run conformance tests and record the red result**

Run: `mise exec -- bun test packages/openapi-mcp/tests/catalog-conformance.test.ts packages/openapi-mcp/tests/sqlite-catalog.test.ts packages/openapi-mcp/tests/d1-structural.test.ts`
Expected: FAIL because no adapters or public suite exist.

- [ ] **Step 3: Implement the Node SQLite adapter**

Open databases read-only with `node:sqlite`, check format/meta before queries, prepare fixed SQL strings internally, and map rows to structural records. Support v3 detection as `legacyInventoryOnly: true`; search may return legacy inventory, while `getOperation` for execution throws `ARTIFACT_FORMAT_UNSUPPORTED` with a migration-safe message.

- [ ] **Step 4: Implement the Worker-safe D1-shaped adapter**

Define local structural types containing only `prepare(sql)`, `bind(...values)`, `all<T>()`, and `first<T>()`. Build `createD1CatalogStore` against those types with fixed queries. Do not import `@cloudflare/workers-types`. The unit test uses a strict fake that records SQL and bindings and fails on interpolation.

- [ ] **Step 5: Export and run the suite against memory, SQLite, and the strict D1 fake**

Run: `mise exec -- bun test packages/openapi-mcp/tests/catalog-conformance.test.ts packages/openapi-mcp/tests/sqlite-catalog.test.ts packages/openapi-mcp/tests/d1-structural.test.ts`
Expected: PASS for all shared behaviors. Label the strict fake as structural coverage; do not claim actual D1 parity.

- [ ] **Step 6: Commit**

```bash
git add packages/openapi-mcp/src/runtime packages/openapi-mcp/src/sqlite packages/openapi-mcp/src/conformance packages/openapi-mcp/tests
git commit -m "feat(openapi-mcp): add catalog store conformance contract"
```

---

### Task 6: Verify search results and resolve bounded schema closures

**Files:**
- Create: `packages/openapi-mcp/src/runtime/schema-resolver.ts`
- Create: `packages/openapi-mcp/src/runtime/runtime.ts`
- Create: `packages/openapi-mcp/tests/runtime-search.test.ts`

**Interfaces:**
- Consumes: admitted manifests, stores, `verifyStoredRecord`, ref codec, limits.
- Produces: `createOpenApiRuntime(options)`, `OpenApiRuntime.search`, and `resolveSchemaClosure`.

- [ ] **Step 1: Write failing search and resolver tests**

```ts
test("search drops a poisoned FTS candidate after record verification", async () => {
  const runtime = await runtimeWithCandidate({ recordJson: '{"method":"DELETE"}' });
  const result = await runtime.search({ query: "widgets", limit: 10 });
  expect(result.operations).toEqual([]);
  expect(result.warnings).toContainEqual(expect.objectContaining({ code: "RECORD_DIGEST_MISMATCH" }));
});

test("schema resolution batches each breadth-first hop", async () => {
  const { store, calls } = schemaGraphStore();
  await resolveSchemaClosure(store, rootSchemaId, DEFAULT_RUNTIME_LIMITS);
  expect(calls).toEqual([[rootSchemaId], [ownerSchemaId, partSchemaId]]);
});
```

Also cover blank/overlong query, limit 0/51, default 10, deprecated demotion, stable tie ordering, opaque ref output, cycles, missing schemas, hop 16/17, schema byte boundary, oversized single schema, exact/+1 aggregate release-inventory bytes, and manifest mismatch. Add whole-release admission fixtures: an otherwise matching operation must not become visible or mutate generation state until every manifested operation/schema and its closed schema graph verify. Cover duplicate/missing/substituted inventory rows, shared-schema reuse, the eight-release/shared-proof-byte budget, final active-state filtering, multi-generation fallback, same-generation digest conflicts, and response-warning/redaction behavior.

- [ ] **Step 2: Run the test and record the red result**

Run: `mise exec -- bun test packages/openapi-mcp/tests/runtime-search.test.ts`
Expected: FAIL because the runtime and resolver are absent.

- [ ] **Step 3: Implement bounded verified search**

Ask stores for at most `min(limit * 3, 150)` candidates, hydrate and verify each candidate, and recompute classification. Before accepting a release, enumerate its complete manifest record map, retrieve every manifested operation, require exact schema batch results, prove schema-reference and operation-root closure completeness, and charge the one search-wide proof/byte/work/store-call envelope. Do this before generation-state mutation. Group candidates by `(catalogId, issuer)` and select only one active generation/digest per group; a rejected higher candidate may fall back only through ordinary generation/rollback admission, never by mixing releases or accepting conflicting same-generation digests. Commit against the captured generation state. On a CAS miss, discard the selection, reread state, reselect, and reprove under the remaining shared budget; never reinterpret an abandoned normal transition as rollback or consume its rollback authorization. Final-recheck active state before returning, then demote deprecated results, sort deterministically, and stop at the requested bound. Return safe truncated summaries and input outlines plus encoded digest-bound operation refs. Rejected candidates become bounded safe warnings; unavailable candidate/state services fail retryably, and response-budget truncation adds its bounded warning. Do not return raw record JSON or origins outside the safe display fields.

- [ ] **Step 4: Implement breadth-first batched schema resolution**

Collect local `$ref`s from verified root/body/parameter schemas, parse their IDs, request the whole next frontier with one `getSchemas` call, verify every record, and track visited IDs. Throw `SCHEMA_RESOLUTION_LIMIT` before crossing hop or byte limits; never return a partially trusted schema for execution.

- [ ] **Step 5: Run focused and store regression tests**

Run: `mise exec -- bun test packages/openapi-mcp/tests/runtime-search.test.ts packages/openapi-mcp/tests/catalog-conformance.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add packages/openapi-mcp/src/runtime packages/openapi-mcp/tests/runtime-search.test.ts
git commit -m "feat(openapi-mcp): add verified search and schema resolution"
```

---

### Task 7: Validate inputs, classify actions, and prepare digest-bound calls

**Files:**
- Create: `packages/openapi-mcp/src/runtime/classify.ts`
- Create: `packages/openapi-mcp/src/runtime/serialize.ts`
- Create: `packages/openapi-mcp/src/runtime/prepared-call.ts`
- Modify: `packages/openapi-mcp/src/runtime/runtime.ts`
- Create: `packages/openapi-mcp/tests/runtime-prepare.test.ts`

**Interfaces:**
- Consumes: verified operation/schema records, exact origin policy, operation refs, limits.
- Produces: `classifyOperation`, `serializeArguments`, `digestPreparedCall`, `verifyPreparedCall`, `prepareRead`, `prepareAction`, and `OpenApiRuntime.revalidate`.

- [ ] **Step 1: Write failing preparation and classification tests**

```ts
test("exports prepared-call integrity functions", async () => {
  const runtimeModule = await import("../src/runtime/index.ts");
  expect(typeof runtimeModule.digestPreparedCall).toBe("function");
  expect(typeof runtimeModule.verifyPreparedCall).toBe("function");
});

test("prepared calls contain no credentials and bind every input", async () => {
  const call = await runtime.prepareAction({
    operation: createRef,
    arguments: { body: { name: "Ada" } },
  });
  expect(call.origin).toBe("https://api.example.test");
  expect(call.relativeUrl).toBe("/widgets");
  expect(JSON.stringify(call)).not.toMatch(/authorization|token|credential/i);
  expect(await digestPreparedCall({ ...call, normalizedArguments: { body: { name: "Grace" } } }))
    .not.toBe(call.preparedCallDigest);
});

test("action cannot be called through read", async () => {
  await expect(runtime.prepareRead({ operation: deleteRef, arguments: { path: { id: "7" } } }))
    .rejects.toMatchObject({ code: "TOOL_SAFETY_MISMATCH" });
});
```

Add a table covering all eight `ActionKind` values and all four cardinality shapes, runtime override of poisoned compiler hints, unknown fields, required fields, path escaping, query arrays, style/explode forms, safe declared headers, rejected cookie parameters, content type, request bodies, oneOf discriminator refusal, max argument bytes, origin mismatch, and record mutation between prepare/revalidate.

- [ ] **Step 2: Run the test and record the red result**

Run: `mise exec -- bun test packages/openapi-mcp/tests/runtime-prepare.test.ts`
Expected: FAIL because classification, serialization, and preparation are absent.

- [ ] **Step 3: Implement conservative runtime classification**

Pin GET/HEAD to read except batch; pin mutating methods to action unless the verified runtime override table explicitly names the API and operation. Derive action kind from method plus bounded normalized tokens in operation ID/path/tags. Derive cardinality only from a concrete required resource ID, verified array `maxItems`, or explicit bulk semantics; otherwise use `unknown`. Mark dangerous kinds and unknown/unbounded cardinality high-risk independently of advisory permissions.

- [ ] **Step 4: Implement validation and OpenAPI serialization**

Validate the exact public `OpenApiArguments` envelope and JSON Schema types, required/properties/additionalProperties, bounds, enums, arrays, nullable, and supported composition. Resolve discriminators only when one branch is uniquely selected. Serialize path/query and declared non-credential headers according to OpenAPI style/explode rules; runtime creates representation headers. Reject cookie parameters in v1 and reject transport/auth header names even if a source schema declares them.

- [ ] **Step 5: Implement prepared-call digest and structural verification**

```ts
export async function digestPreparedCall(call: PreparedCall): Promise<Sha256> {
  return sha256("knitli.openapi-mcp.prepared-call.v1", {
    ...call,
    body: call.body === null ? null : await digestBytes(call.body),
    preparedCallDigest: undefined,
  });
}

export async function verifyPreparedCall(call: PreparedCall): Promise<void> {
  validatePreparedCallShape(call);
  if ((await digestPreparedCall(call)) !== call.preparedCallDigest) {
    throw new OpenApiMcpError("INPUT_INVALID", "Prepared call digest mismatch");
  }
}
```

Omit the self-digest key entirely from canonical input rather than serializing `undefined`.

- [ ] **Step 6: Implement revalidation as fresh preparation**

`revalidate` calls `verifyPreparedCall`, reloads the admitted manifest and operation/schema records, prepares from `normalizedArguments`, and compares operation, manifest, input, and call digests with timing-safe byte comparison. Any release/store/policy change denies rather than updating the authorized call.

- [ ] **Step 7: Run focused tests and mutation check**

Run: `mise exec -- bun test packages/openapi-mcp/tests/runtime-prepare.test.ts`
Expected: PASS. Temporarily trust stored `safety`, verify the poisoned-hint test fails, restore runtime classification, and rerun to PASS.

- [ ] **Step 8: Commit**

```bash
git add packages/openapi-mcp/src/runtime packages/openapi-mcp/tests/runtime-prepare.test.ts
git commit -m "feat(openapi-mcp): prepare and revalidate exact API calls"
```

---

### Task 8: Add exact-call action authorization and safe approval rendering

**Files:**
- Create: `packages/openapi-mcp/src/stdio/authorizer.ts`
- Create: `packages/openapi-mcp/src/stdio/render.ts`
- Modify: `packages/openapi-mcp/package.json`
- Modify: `bun.lock`
- Create: `packages/openapi-mcp/tests/action-authorizer.test.ts`

**Interfaces:**
- Consumes: `ActionAuthorizer`, `PreparedCall`, classification, `verifyPreparedCall`, safe errors.
- Produces: `DenyActionAuthorizer`, `ExactPolicyActionAuthorizer`, `ClientElicitationActionAuthorizer`, `renderApproval`, and authorization receipt state.

- [ ] **Step 1: Write failing authorization matrix tests**

```ts
test.each(["delete", "communicate", "authority", "transaction", "execute", "unknown"])(
  "%s can never be policy-auto-approved",
  async (actionKind) => {
    const decision = await policyAuthorizer.authorize(call({ actionKind }), context);
    expect(decision.status).not.toBe("authorized");
  },
);

test("authorization is invalid after any argument change", async () => {
  const first = call({ normalizedArguments: { id: "1" } });
  const decision = await authorizer.authorize(first, contextWithAcceptedConfirmation());
  expect(decision).toMatchObject({ status: "authorized", callDigest: first.preparedCallDigest });
  expect(() => requireDecisionForCall(decision, call({ normalizedArguments: { id: "2" } })))
    .toThrow(/digest/i);
});
```

Cover default deny, bounded create/update exact constraints, maxAffected, unknown/unbounded, high risk, missing elicitation capability, decline/cancel, malformed input response, expired/tampered HMAC state, state minted before acceptance, changed args across rounds, and Markdown/control-character injection in approval values.

- [ ] **Step 2: Run the test and record the red result**

Run: `mise exec -- bun test packages/openapi-mcp/tests/action-authorizer.test.ts`
Expected: FAIL because authorizers and rendering are absent.

- [ ] **Step 3: Install and pin the modern split MCP server SDK**

Run: `mise exec -- bun add --exact --cwd packages/openapi-mcp @modelcontextprotocol/server@2.0.0 zod`
Expected: `@modelcontextprotocol/server` is exactly `2.0.0`; Bun selects one exact Zod 4 version in `package.json` and `bun.lock`. Verify compatible licenses and confirm `@modelcontextprotocol/sdk` is not a direct dependency with `mise exec -- bun pm ls --all`.

- [ ] **Step 4: Implement deny and exact constrained policy authorizers**

Policy rules bind catalog ID, release ID or allowed generation range, exact operation ID/digest, action kind, allowed argument keys/values or numeric/string bounds, cardinality, maxAffected, and expiry. Match all constraints; a missing constraint is not a wildcard. Refuse policy authorization unless kind is create/update, risk is routine, and cardinality is single or finite bounded.

- [ ] **Step 5: Implement safe approval rendering**

Render trusted field labels separately from values. Replace controls, defuse Markdown fence/heading/link syntax, cap each value and the whole prompt, summarize bodies structurally, and include the exact call digest. Unit tests use malicious summaries and arguments such as `````\n# APPROVED`` and verify they remain quoted data.

- [ ] **Step 6: Implement the three-round input-required receipt flow**

Round 1 returns one `inputRequired.elicit` confirmation. Round 2 reads `acceptedContent` through a Zod schema; after acceptance, it re-prepares and digest-checks, then returns `inputRequired({ requestState: await codec.mint({ confirmedDigest, expiresAt }) })`. Round 3 receives only SDK-verified request state, revalidates again, and returns an authorized decision when the digest still matches. Configure `createRequestStateCodec` with 32 random process bytes and a 120-second TTL. Never mint proof before acceptance and never accept a model tool argument as confirmation.

- [ ] **Step 7: Run focused tests**

Run: `mise exec -- bun test packages/openapi-mcp/tests/action-authorizer.test.ts`
Expected: PASS, including changed-input and state-tamper denial.

- [ ] **Step 8: Prove the receipt gate with a mutation check**

Temporarily make `requireDecisionForCall` accept a mismatched call digest. Run `mise exec -- bun test packages/openapi-mcp/tests/action-authorizer.test.ts` and require the changed-input or tampered-state case to fail. Restore the exact digest comparison and rerun to PASS.

- [ ] **Step 9: Commit**

```bash
git add packages/openapi-mcp/src/stdio packages/openapi-mcp/tests/action-authorizer.test.ts packages/openapi-mcp/package.json bun.lock
git commit -m "feat(openapi-mcp): authorize exact action digests"
```

---

### Task 9: Add explicit auth profiles, memory-only secrets, and OAuth2 PKCE

**Files:**
- Create: `packages/openapi-mcp/src/sqlite/auth.ts`
- Create: `packages/openapi-mcp/tests/auth.test.ts`
- Create: `packages/openapi-mcp/tests/fixtures/strict-config.json`

**Interfaces:**
- Consumes: `AuthProfile`, `SecretStore`, `CredentialProvider`, destination policy, safe errors.
- Produces: `MemorySecretStore`, `createCredentialProvider(profile, options)`, PKCE loopback flow, and credential revocation.

- [ ] **Step 1: Write failing auth and redaction tests**

```ts
test("MemorySecretStore forgets tokens with the process object", async () => {
  const store = new MemorySecretStore();
  await store.set("oauth:tiny", "refresh-secret");
  expect(await store.get("oauth:tiny")).toBe("refresh-secret");
  expect(await new MemorySecretStore().get("oauth:tiny")).toBeNull();
});

test("PKCE callback rejects wrong state without leaking code", async () => {
  const flow = await startTestFlow({ expectedState: "right" });
  const response = await fetch(`${flow.callback}?state=wrong&code=super-secret-code`);
  expect(response.status).toBe(400);
  expect(flow.logs.join("\n")).not.toContain("super-secret-code");
});
```

Cover missing env variables, header/query API key placement, forbidden header names, fixed endpoints, HTTPS endpoints, S256 challenge, random state, exact redirect, one-use callback, deadline, token error redaction, refresh, revocation, resource/scope binding, listener only on `127.0.0.1`, and tokens absent from MCP-facing errors.

- [ ] **Step 2: Run the test and record the red result**

Run: `mise exec -- bun test packages/openapi-mcp/tests/auth.test.ts`
Expected: FAIL because auth adapters do not exist.

- [ ] **Step 3: Implement environment credential profiles**

Validate profile configuration at startup and require its exact origins to intersect the signed manifest origins. Read the named environment variable only when `credential()` is invoked, return an opaque credential object, and redact both configured names and resolved values from errors. Reject API-key placement in authorization/cookie/forwarding headers; only the transport turns the credential into a header or query value.

- [ ] **Step 4: Implement MemorySecretStore and PKCE**

Use `crypto.getRandomValues`, SHA-256 S256 challenge, an ephemeral `node:http` listener on `127.0.0.1`, constant-time state comparison, one callback, and `AbortSignal.timeout`. Validate token JSON with the strict parser and store access/refresh tokens only in the provided `SecretStore`. Default construction always supplies a new `MemorySecretStore`.

- [ ] **Step 5: Expose in-process login and forget behavior**

The credential provider returns a typed `AUTH_REQUIRED` challenge containing an authorization URL suitable for `inputRequired.elicitUrl`; it never opens a browser silently. The `serve` process completes the callback and retains tokens in its own `MemorySecretStore`. Expose `forget(profileId)` to delete those in-process tokens. A separate login subprocess would lose memory-only tokens as soon as it exited, so v1 deliberately has no standalone login command. Document process restart as local token forgetting and link the provider's account-side revocation procedure for invalidating the upstream grant.

- [ ] **Step 6: Run focused tests**

Run: `mise exec -- bun test packages/openapi-mcp/tests/auth.test.ts`
Expected: PASS with no secret in captured stderr, errors, or result objects.

- [ ] **Step 7: Commit**

```bash
git add packages/openapi-mcp/src/sqlite/auth.ts packages/openapi-mcp/tests/auth.test.ts packages/openapi-mcp/tests/fixtures/strict-config.json
git commit -m "feat(openapi-mcp): add explicit local authentication profiles"
```

---

### Task 10: Enforce destinations and dispatch bounded HTTP safely

**Files:**
- Create: `packages/openapi-mcp/src/sqlite/destination-guard.ts`
- Create: `packages/openapi-mcp/src/sqlite/guarded-fetch.ts`
- Modify: `packages/openapi-mcp/src/sqlite/index.ts`
- Modify: `packages/openapi-mcp/package.json`
- Create: `packages/openapi-mcp/tests/guarded-fetch.test.ts`

**Interfaces:**
- Consumes: `PreparedCall`, exact destination policy, credentials, runtime limits.
- Produces: `NodeDestinationGuard`, `GuardedFetchTransport implements AuthorizedTransport`, bounded `CallOutcome`, and opaque pagination-token codec.

- [ ] **Step 1: Write failing SSRF, redirect, and uncertainty tests**

```ts
test.each(["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "fc00::1"])(
  "rejects non-public address %s",
  async (address) => {
    await expect(guardFor(address).authorize(new URL("https://api.example.test/x")))
      .rejects.toMatchObject({ code: "DESTINATION_DENIED" });
  },
);

test("cross-origin redirect strips credential and body", async () => {
  const outcome = await transport.dispatch(actionCall, bearer("secret"));
  expect(secondHop.headers.authorization).toBeUndefined();
  expect(secondHop.bodyBytes).toBe(0);
  expect(outcome.kind).toBe("redirect-blocked");
});

test("action timeout after request write is outcome unknown and is not retried", async () => {
  await expect(transport.dispatch(actionCall, bearer("secret")))
    .rejects.toMatchObject({ code: "UPSTREAM_OUTCOME_UNKNOWN" });
  expect(upstream.requestCount).toBe(1);
});
```

Cover every private/reserved IPv4/IPv6 range including mapped IPv4, mixed DNS answers, DNS rebind attempt, HTTPS default, origin mismatch, redirect 3/4, downgrade to HTTP, same-origin auth retention, header denylist, response `Content-Length`, streamed decompressed bytes, deadline, pagination page/byte limits, opaque token tamper, read retry eligibility, and action no-retry.

- [ ] **Step 2: Run the test and record the red result**

Run: `mise exec -- bun test packages/openapi-mcp/tests/guarded-fetch.test.ts`
Expected: FAIL because local destination and transport enforcement are absent.

- [ ] **Step 3: Pin the tested HTTP implementation dependency**

Run: `mise exec -- bun add --exact --cwd packages/openapi-mcp undici`
Expected: `package.json` and `bun.lock` record one exact tested version. Inspect its license and Node 24 compatibility before continuing; fail the task if either is incompatible.

- [ ] **Step 4: Implement DNS-aware destination authorization**

Normalize exact configured origins, resolve all A/AAAA records with `dns.promises.lookup({ all: true, verbatim: true })`, reject the destination if any answer is non-public, and return an expiring approved-address set. Configure Undici's lookup hook to choose only from that set while preserving hostname/SNI; re-run resolution and policy for every redirect.

- [ ] **Step 5: Implement bounded manual fetch and credential injection**

Start from `PreparedCall.origin + relativeUrl`, add credentials inside the transport, enforce the header denylist, use manual redirects, and strip credential/body on cross-origin redirect. Count decompressed stream bytes. Return opaque HMAC continuation tokens binding catalog/release/operation/origin/next URL/expiry; validate them before preparing the next read.

- [ ] **Step 6: Encode retry and outcome rules**

Reads retry only 429/502/503/504 or pre-connect failures, within the original deadline, at most twice, honoring bounded `Retry-After`. Actions never retry. If an action fails after connect/request transmission begins, throw `UPSTREAM_OUTCOME_UNKNOWN` with the prepared-call digest and no raw body.

- [ ] **Step 7: Run focused tests and regression suite**

Run: `mise exec -- bun test packages/openapi-mcp/tests/guarded-fetch.test.ts packages/openapi-mcp/tests/runtime-prepare.test.ts packages/openapi-mcp/tests/auth.test.ts`
Expected: PASS.

- [ ] **Step 8: Prove egress and no-retry gates with mutation checks**

Temporarily allow one private-address fixture and require its SSRF case to fail; restore the address policy and rerun to PASS. Then temporarily allow one automatic action retry, require the action request-count case to fail, restore no-retry behavior, and rerun to PASS.

- [ ] **Step 9: Commit**

```bash
git add packages/openapi-mcp/src/sqlite packages/openapi-mcp/tests/guarded-fetch.test.ts packages/openapi-mcp/package.json bun.lock
git commit -m "feat(openapi-mcp): guard local upstream dispatch"
```

---

### Task 11: Serve exactly three tools over modern and legacy stdio MCP

**Files:**
- Create: `packages/openapi-mcp/src/stdio/config.ts`
- Create: `packages/openapi-mcp/src/stdio/server.ts`
- Create: `packages/openapi-mcp/src/stdio/index.ts`
- Modify: `packages/openapi-mcp/src/cli.ts`
- Modify: `packages/openapi-mcp/package.json`
- Create: `packages/openapi-mcp/tests/stdio-server.test.ts`

**Interfaces:**
- Consumes: runtime, catalog profiles, credential providers, transport, action authorizer, renderer.
- Produces: `createOpenApiMcpServer(options): McpServer`, `serveOpenApiStdio(config)`, and CLI `serve --config <path>`.

- [ ] **Step 1: Write failing surface and protocol tests**

```ts
test("discovery advertises exactly three global tools", async () => {
  const client = await connectTestClient({ era: "modern" });
  const names = (await client.listTools()).tools.map((tool) => tool.name).sort();
  expect(names).toEqual(["action", "read", "search"]);
});

test("tool schemas expose no transport auth or confirmation controls", async () => {
  const client = await connectTestClient({ era: "legacy" });
  const tools = (await client.listTools()).tools;
  for (const tool of tools) {
    const topLevelKeys = Object.keys(tool.inputSchema.properties ?? {});
    expect(topLevelKeys).not.toEqual(
      expect.arrayContaining(["url", "method", "headers", "authorization", "credential", "token", "confirm"]),
    );
  }
  expect(JSON.stringify(tools)).not.toMatch(
    /"(authorization|credential|token|confirm[^\"]*)"\s*:/i,
  );
});
```

Cover search/read/action routing, qualified refs, declared non-credential `arguments.headers`, rejection of credential/hop-by-hop header names and cookie parameters, action decline, accepted three-round confirmation, exact policy, changed args, unsupported elicitation, OAuth URL elicitation, stable errors, modern 2026-07-28, legacy shim, SIGTERM cleanup, and a subprocess assertion that stdout contains only protocol frames while logs use stderr.

- [ ] **Step 2: Run the tests and record the red result**

Run: `mise exec -- bun test packages/openapi-mcp/tests/stdio-server.test.ts`
Expected: FAIL because the server and SDK dependencies are absent.

- [ ] **Step 3: Verify the MCP dependency boundary established by Task 8**

Run: `mise exec -- bun pm ls --all`
Expected: `@modelcontextprotocol/server@2.0.0` and one exact Zod 4 version are present; `@modelcontextprotocol/sdk` is not a direct dependency and neither package is reachable from the `/runtime` browser bundle.

- [ ] **Step 4: Parse strict operator configuration**

Config names immutable release paths, trusted release/rollback public keys, exact allowed origins, auth profiles, runtime limit reductions, and optional exact policies. Reject unknown keys, relative origin URLs, secrets embedded directly in JSON, duplicate profile/catalog IDs, and attempts to raise compiled maximum limits.

- [ ] **Step 5: Register only `search`, `read`, and `action`**

Use `McpServer` from `@modelcontextprotocol/server`, `serveStdio` from `@modelcontextprotocol/server/stdio`, and Zod 4 input schemas:

```ts
server.registerTool("search", { inputSchema: SearchToolInput }, handleSearch);
server.registerTool("read", { inputSchema: ReadToolInput }, handleRead);
server.registerTool("action", { inputSchema: ActionToolInput }, handleAction);
```

`handleRead` prepares, revalidates, obtains a credential, and dispatches. `handleAction` prepares, runs the three-round authorizer or exact policy, checks the decision digest, revalidates, obtains a credential, and dispatches exactly once. Map `OpenApiMcpError` to bounded safe MCP results.

- [ ] **Step 6: Protect request state and stdio**

Construct `createRequestStateCodec` with 32 random bytes and 120-second TTL; pass `verify` in `McpServer` options. Leave the SDK legacy input-required shim enabled. Never call `console.log`; the CLI banner and audit sink write to stderr. Zero in-memory secret buffers where APIs permit and close databases/listeners on termination.

- [ ] **Step 7: Run modern, legacy, and full package tests**

Run: `mise exec -- bun test packages/openapi-mcp/tests/stdio-server.test.ts`
Expected: PASS in both protocol eras.
Run: `mise exec -- bun test packages/openapi-mcp`
Expected: all package tests PASS.

- [ ] **Step 8: Prove the surface and stdout gates with mutation checks**

Temporarily register a fourth tool and require the exact-discovery assertion to fail; restore the three-tool registration and rerun to PASS. Then temporarily write one banner to stdout, require the subprocess protocol-frame assertion to fail, restore stderr-only diagnostics, and rerun to PASS.

- [ ] **Step 9: Commit**

```bash
git add packages/openapi-mcp bun.lock
git commit -m "feat(openapi-mcp): serve three global tools over stdio"
```

---

### Task 12: Prove package consumption, document migration, and gate release

**Files:**
- Modify: `.github/workflows/release.yml`
- Read: `scripts/generate.mts`
- Modify: `packages/openapi-mcp/README.md`
- Modify: `packages/openapi-mcp/package.json`
- Modify: `packages/openapi-mcp/tsconfig.json`
- Create: `packages/openapi-mcp/LICENSE-MIT`
- Create: `packages/openapi-mcp/LICENSE-APACHE`
- Modify: `CLAUDE.md`
- Create: `packages/openapi-mcp/test-consumers/node.mts`
- Create: `packages/openapi-mcp/test-consumers/bun.ts`
- Modify: `packages/openapi-mcp/test-consumers/worker.ts`
- Modify: `packages/openapi-mcp/tests/package-consumers.test.ts`

**Interfaces:**
- Consumes: all Phase 2 exports, CLI, conformance suite, release files, and runtime config.
- Produces: publishable tarball, public setup/migration/security documentation, and observed release/rollback checklist.

- [ ] **Step 1: Write failing packed-package consumer tests**

Build and pack into a temporary directory, install the tarball into isolated Node and Bun consumer directories, and assert:

```ts
import { ARTIFACT_FORMAT_VERSION, digestPreparedCall } from "@knitli/openapi-mcp/runtime";
import { compileRelease } from "@knitli/openapi-mcp/compiler";
import { SqliteCatalogStore } from "@knitli/openapi-mcp/sqlite";
import { createOpenApiMcpServer } from "@knitli/openapi-mcp/stdio";
import { runRuntimeConformanceSuite } from "@knitli/openapi-mcp/conformance";

if (ARTIFACT_FORMAT_VERSION !== 4) throw new Error("wrong artifact format");
void [digestPreparedCall, compileRelease, SqliteCatalogStore, createOpenApiMcpServer, runRuntimeConformanceSuite];
```

The Worker consumer imports `/runtime`, `/conformance`, and `createD1CatalogStore`, bundles for browser/Worker, and asserts no `node:`/`bun:` import or MCP/Undici code appears.

- [ ] **Step 2: Run the consumer test and record the red result**

Run: `mise exec -- bun test packages/openapi-mcp/tests/package-consumers.test.ts`
Expected: FAIL until export targets, declarations, files list, and tarball contents are complete.

- [ ] **Step 3: Finalize declarations, licenses, and package contents**

Ensure `tsc` emits declarations for every subpath, `files` includes the complete `dist` tree plus `LICENSE-MIT` and `LICENSE-APACHE`, the binary targets `dist/cli.js`, and package dependencies are runtime-complete. Copy the repository's existing MIT text into the package-local MIT file and the unmodified Apache License 2.0 text from Apache's official license into the package-local Apache file; keep `license: "MIT OR Apache-2.0"` only when both ship. Keep Node types out of the runtime declarations by compiling a second Worker-only typecheck config with `lib: ["ES2023", "WebWorker"]` and `types: []`.

Normalize registry-facing metadata before invoking npm tooling: published `engines` values must be concrete semver rather than `catalog:`, remove the package-local malformed `devEngines` object while retaining the root Bun policy, and set `publishConfig.provenance: true`. Run the existing authoritative `bun scripts/generate.mts`, confirm the generated OpenAPI release configuration ends with catch-all `{ release: false }`, and require `bun scripts/generate.mts --check` to pass. This explicitly repairs the current generated-file drift rather than weakening the repository's Bun engine enforcement.

- [ ] **Step 4: Rewrite public README around executable user tasks**

Document installation, key generation, `compile-release`, strict config with environment variable names only, OAuth PKCE behavior, `serve`, MCP-client configuration, three tool examples, action confirmation, memory-only token lifetime, revocation, artifact/key rotation, signed rollback, v3 inventory-only migration, error troubleshooting, and the Phase 3 contract boundary. Clearly distinguish legacy exact-file signing from v4 manifest trust.

- [ ] **Step 5: Correct stale repository guidance**

Update root `CLAUDE.md` to state that `packages/openapi-mcp` is compiled TypeScript with Bun tests and list only observed commands. Preserve unrelated plugin-marketplace guidance.

- [ ] **Step 6: Run formatting, types, tests, build, validation, and tarball inspection**

```bash
mise exec -- bunx biome check --write packages/openapi-mcp CLAUDE.md docs/superpowers
mise exec -- bun test packages/openapi-mcp
mise exec -- bun --cwd packages/openapi-mcp run build
mise exec -- bun scripts/generate.mts
mise exec -- bun run validate
mise exec -- bun --cwd packages/openapi-mcp pm pack --dry-run
```

Expected: every command exits 0; dry-run lists all five subpath entry points, declarations, binary, README, and both license files, and lists no fixtures, secrets, temporary databases, source specs, or local paths.

- [ ] **Step 7: Test the actual tarball under Node, Bun, and Worker targets**

Run: `mise exec -- bun test packages/openapi-mcp/tests/package-consumers.test.ts`
Expected: PASS after installing the produced tarball into isolated temporary consumers. Run `mise exec -- node packages/openapi-mcp/test-consumers/node.mts` against that install and the corresponding Bun/Worker harnesses; all exit 0.

- [ ] **Step 8: Record rollback evidence before release**

In the release PR, record the prior known-good package version, prior immutable fixture generation, package downgrade command, catalog-disable procedure, credential process-restart behavior, and the signed-data rollback rule. Exercise a failed new release admission and show the prior release still serves search/read.

- [ ] **Step 9: Gate publishing on observed external state**

Make the `release-openapi-mcp` job OIDC-ready with GitHub-hosted runners, `id-token: write`, exact repository metadata, the protected `npmrelease` environment, and provenance enabled. The steady-state job must not provide `NPM_TOKEN` or `NODE_AUTH_TOKEN`; it publishes through the npm trusted-publisher relationship bound to `knitli/toolshed`, `release.yml`, and `npmrelease`.

The first-publication bootstrap is a separate, explicit exception because npm will not create the trusted-publisher relationship until this package exists. Obtain named owner approval, then have a protected GitHub Actions bootstrap job in `.github/workflows/release.yml`, with `id-token: write`, build and test with Bun, create the exact tested `0.0.0` tarball with `bun pm pack`, upload/rehash that artifact, and invoke npm from a clean directory under `RUNNER_TEMP` to publish that tarball with `--access public --tag bootstrap --provenance`. The bootstrap job alone receives one short-lived granular publish token from the protected `npmrelease` environment. It must not run `bun publish`, publish from the repository/workspace directory, create a `latest` tag, or let semantic-release/tag/GitHub-release steps describe `0.0.0` as the real release.

After `npm view @knitli/openapi-mcp@0.0.0` proves the bootstrap artifact's version, integrity, tarball, and non-default dist-tag and reports attestation metadata, create a clean npm consumer under `RUNNER_TEMP`, install exactly `@knitli/openapi-mcp@0.0.0`, and run `npm audit signatures --json --include-attestations`. Require exit 0 and a verified registry signature and provenance bundle bound to the observed package/integrity, the exact `knitli/toolshed` source commit, and the `.github/workflows/release.yml` run. Retain the JSON output as an immutable protected job artifact and record its SHA-256 and verified fields in the Phase 2 release handoff; metadata from `npm view` alone is not proof. Then configure the npm trusted publisher for exactly `knitli/toolshed`, `release.yml`, and `npmrelease`. Remove the bootstrap job's token environment variables and GitHub secret, revoke the granular token, and commit the steady-state OIDC-only workflow before permitting semantic-release to publish the first real `latest` version. Never place a token in a local shell transcript, file, plan evidence, artifact, or commit.

After merge, separately observe: CI success, semantic-release completion, npm package/version visibility, Git tag/release, trusted-publisher configuration, absence and revocation of the bootstrap token when that lane was needed, and a fresh public install of the exact real release in a clean npm consumer. Repeat `npm audit signatures --json --include-attestations` there, require the verified package/integrity, trusted release workflow, source commit, and CI run to match the release, and retain the output plus SHA-256 in the Phase 2 release handoff. If any gate is unobserved or the cryptographic verification fails, report that gate as pending and do not claim publication. The current package version is `0.0.0`; this plan does not assert that a release already exists.

- [ ] **Step 10: Commit**

```bash
git add packages/openapi-mcp CLAUDE.md docs/superpowers .github/workflows/release.yml
git commit -m "docs(openapi-mcp): document runtime setup and release gates"
```

---

## Execution order and review gates

Tasks are sequential because each establishes contracts consumed by the next. Review after every task; Tasks 3, 7, 8, 10, and 11 are security gates and require both the focused test output and the named mutation check before proceeding. Task 5's structural D1 fake proves contract shape only. Actual D1 conformance belongs to Phase 3 and must call the exported `runRuntimeConformanceSuite` in a real Workers test environment.

Phase 2 implementation is complete only after Task 12's tarball consumers pass and external publishing state is either observed successful or explicitly reported pending. Implementation success and npm publication are separate outcomes.
