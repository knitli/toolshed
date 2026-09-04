import { sha256, verifyEd25519 } from "./digest.ts";
import { OpenApiMcpError } from "./errors.ts";
import { parseTypedRecordId } from "./references.ts";
import { canonicalJson, parseJsonStrict } from "./strict-json.ts";
import type {
  CatalogId,
  GenerationState,
  GenerationStore,
  JsonObject,
  ManifestEnvelope,
  ManifestSignature,
  ReleaseId,
  ReleaseManifestV4,
  RollbackAuthorization,
  Sha256,
  TypedRecordId,
} from "./types.ts";
import { DEFAULT_RUNTIME_LIMITS, type RuntimeLimits } from "./versions.ts";

const manifestSignatureDomain = "knitli.openapi-mcp.release-manifest.v4\0";
const manifestDigestDomain = "knitli.openapi-mcp.release-manifest.v4";
const rollbackSignatureDomain =
  "knitli.openapi-mcp.rollback-authorization.v1\0";
const digestPattern = /^[0-9a-f]{64}$/;
const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const boundedAsciiPattern = /^[\x21-\x7e]+$/;
const manifestKeys = [
  "allowedOrigins",
  "catalogId",
  "compiledAt",
  "compilerVersion",
  "contract",
  "format",
  "generation",
  "issuer",
  "keyId",
  "policyId",
  "records",
  "releaseId",
  "source",
] as const;
const sourceKeys = [
  "contentSha256",
  "referenceGraphDigest",
  "revision",
  "uri",
] as const;
const signatureKeys = ["algorithm", "keyId", "signature"] as const;
const rollbackKeys = [
  "algorithm",
  "catalogId",
  "currentHighestGeneration",
  "expiresAt",
  "id",
  "issuer",
  "keyId",
  "reason",
  "signature",
  "targetGeneration",
  "targetManifestDigest",
] as const;
const envelopeRequiredKeys = ["manifestJson", "signature"] as const;

export interface TrustedManifestKey {
  issuer: string;
  keyId: string;
  /** Base64url-encoded Ed25519 SPKI public key. */
  publicKey: string;
}

export interface ManifestTrust {
  releaseKeys: readonly TrustedManifestKey[];
  rollbackKeys: readonly TrustedManifestKey[];
  now?: () => Date;
}

export interface AdmittedManifest {
  readonly manifest: ReleaseManifestV4;
  readonly manifestDigest: Sha256;
}

function manifestInvalid(message: string): OpenApiMcpError {
  return new OpenApiMcpError("MANIFEST_INVALID", message);
}

function rollbackRejected(message: string): OpenApiMcpError {
  return new OpenApiMcpError("MANIFEST_ROLLBACK_REJECTED", message);
}

function isObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === null || prototype === Object.prototype;
}

function ownData(value: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (
    descriptor === undefined ||
    !("value" in descriptor) ||
    !descriptor.enumerable
  ) {
    throw manifestInvalid(`${key} must be an own data property`);
  }
  return descriptor.value;
}

function requireExactShape(
  value: unknown,
  expected: readonly string[],
  label: string,
): Record<string, unknown> {
  if (!isObject(value)) throw manifestInvalid(`${label} must be an object`);
  if (Reflect.ownKeys(value).some((key) => typeof key !== "string")) {
    throw manifestInvalid(`${label} has a symbol property`);
  }
  const keys = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (
    keys.length !== sortedExpected.length ||
    keys.some((key, index) => key !== sortedExpected[index])
  ) {
    throw manifestInvalid(`${label} shape is invalid`);
  }
  for (const key of sortedExpected) ownData(value, key);
  return value;
}

function requireString(
  value: unknown,
  label: string,
  maximum: number,
  pattern?: RegExp,
): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    (pattern && !pattern.test(value))
  ) {
    throw manifestInvalid(`${label} is invalid`);
  }
  return value;
}

function requireIdentifier(value: unknown, label: string): string {
  const result = requireString(value, label, 128, identifierPattern);
  if (result === "." || result === "..")
    throw manifestInvalid(`${label} is invalid`);
  return result;
}

function requireInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0)
    throw manifestInvalid(`${label} is invalid`);
  return value as number;
}

function requireDigest(value: unknown, label: string): Sha256 {
  if (typeof value !== "string" || !digestPattern.test(value))
    throw manifestInvalid(`${label} is invalid`);
  return value as Sha256;
}

function requireTimestamp(value: unknown, label: string): string {
  const timestamp = requireString(value, label, 64, boundedAsciiPattern);
  const parsed = new Date(timestamp);
  if (
    !Number.isFinite(parsed.getTime()) ||
    parsed.toISOString() !== timestamp
  ) {
    throw manifestInvalid(`${label} must be a canonical UTC timestamp`);
  }
  return timestamp;
}

function requireOrigin(value: unknown): string {
  const candidate = requireString(
    value,
    "allowed origin",
    2048,
    boundedAsciiPattern,
  );
  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    throw manifestInvalid("allowed origin is invalid");
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.origin !== candidate
  ) {
    throw manifestInvalid(
      "allowed origin must be an exact canonical HTTPS origin",
    );
  }
  return candidate;
}

function parseManifest(text: string, limits: RuntimeLimits): ReleaseManifestV4 {
  const parsed = parseJsonStrict(text, {
    maxBytes: limits.maxManifestBytes,
    maxDepth: limits.maxJsonDepth,
    maxKeys: limits.maxManifestRecords + 32,
  });
  const value = requireExactShape(parsed, manifestKeys, "manifest");
  if (ownData(value, "format") !== 4 || ownData(value, "contract") !== 1) {
    throw manifestInvalid("manifest versions are unsupported");
  }
  const catalogId = requireIdentifier(
    ownData(value, "catalogId"),
    "catalog ID",
  ) as CatalogId;
  const releaseId = requireIdentifier(
    ownData(value, "releaseId"),
    "release ID",
  ) as ReleaseId;
  const generation = requireInteger(ownData(value, "generation"), "generation");
  const issuer = requireString(
    ownData(value, "issuer"),
    "issuer",
    256,
    boundedAsciiPattern,
  );
  const keyId = requireIdentifier(ownData(value, "keyId"), "key ID");
  const policyId = requireIdentifier(ownData(value, "policyId"), "policy ID");
  const compilerVersion = requireString(
    ownData(value, "compilerVersion"),
    "compiler version",
    128,
    boundedAsciiPattern,
  );
  const compiledAt = requireTimestamp(
    ownData(value, "compiledAt"),
    "compiledAt",
  );

  const rawOrigins = ownData(value, "allowedOrigins");
  if (!Array.isArray(rawOrigins) || rawOrigins.length === 0)
    throw manifestInvalid("allowedOrigins is invalid");
  const allowedOrigins = rawOrigins.map(requireOrigin);
  if (new Set(allowedOrigins).size !== allowedOrigins.length)
    throw manifestInvalid("allowedOrigins contains a duplicate");

  const rawSource = requireExactShape(
    ownData(value, "source"),
    sourceKeys,
    "manifest source",
  );
  const source = {
    uri: requireString(ownData(rawSource, "uri"), "source URI", 4096),
    revision: requireString(
      ownData(rawSource, "revision"),
      "source revision",
      512,
      boundedAsciiPattern,
    ),
    contentSha256: requireDigest(
      ownData(rawSource, "contentSha256"),
      "source content digest",
    ),
    referenceGraphDigest: requireDigest(
      ownData(rawSource, "referenceGraphDigest"),
      "reference graph digest",
    ),
  };

  const rawRecords = ownData(value, "records");
  if (!isObject(rawRecords)) throw manifestInvalid("records must be an object");
  const recordKeys = Reflect.ownKeys(rawRecords);
  if (recordKeys.length > limits.maxManifestRecords)
    throw manifestInvalid("manifest exceeds its record limit");
  const records = Object.create(null) as Record<TypedRecordId, Sha256>;
  for (const rawId of recordKeys) {
    if (typeof rawId !== "string")
      throw manifestInvalid("records has a symbol key");
    let id: TypedRecordId;
    try {
      id = parseTypedRecordId(rawId);
    } catch {
      throw manifestInvalid("manifest record ID is invalid");
    }
    records[id] = requireDigest(ownData(rawRecords, rawId), "record digest");
  }

  return {
    format: 4,
    contract: 1,
    catalogId,
    releaseId,
    generation,
    issuer,
    keyId,
    policyId,
    allowedOrigins,
    compiledAt,
    compilerVersion,
    source,
    records,
  };
}

function parseSignature(value: ManifestSignature): ManifestSignature {
  const object = requireExactShape(value, signatureKeys, "manifest signature");
  if (ownData(object, "algorithm") !== "Ed25519")
    throw manifestInvalid("manifest signature algorithm is invalid");
  return {
    algorithm: "Ed25519",
    keyId: requireIdentifier(ownData(object, "keyId"), "signature key ID"),
    signature: requireString(
      ownData(object, "signature"),
      "manifest signature",
      256,
      /^[A-Za-z0-9_-]+$/,
    ),
  };
}

function findKey(
  keys: readonly TrustedManifestKey[],
  issuer: string,
  keyId: string,
): TrustedManifestKey | null {
  const matches = keys.filter(
    (key) => key.issuer === issuer && key.keyId === keyId,
  );
  return matches.length === 1 ? matches[0] : null;
}

async function requireReleaseSignature(
  manifest: ReleaseManifestV4,
  canonical: string,
  signatureValue: ManifestSignature,
  trust: ManifestTrust,
): Promise<void> {
  let signature: ManifestSignature;
  try {
    signature = parseSignature(signatureValue);
  } catch {
    throw new OpenApiMcpError(
      "MANIFEST_SIGNATURE_INVALID",
      "Manifest signature envelope is invalid",
    );
  }
  if (signature.keyId !== manifest.keyId) {
    throw new OpenApiMcpError(
      "MANIFEST_SIGNATURE_INVALID",
      "Manifest signature key does not match the manifest",
    );
  }
  const key = findKey(trust.releaseKeys, manifest.issuer, signature.keyId);
  if (
    key === null ||
    !(await verifyEd25519(
      `${manifestSignatureDomain}${canonical}`,
      signature.signature,
      key.publicKey,
    ))
  ) {
    throw new OpenApiMcpError(
      "MANIFEST_SIGNATURE_INVALID",
      "Manifest signature is not trusted",
    );
  }
}

function rollbackUnsigned(value: RollbackAuthorization): JsonObject {
  return {
    id: value.id,
    catalogId: value.catalogId,
    issuer: value.issuer,
    currentHighestGeneration: value.currentHighestGeneration,
    targetGeneration: value.targetGeneration,
    targetManifestDigest: value.targetManifestDigest,
    reason: value.reason,
    expiresAt: value.expiresAt,
    keyId: value.keyId,
    algorithm: value.algorithm,
  };
}

async function requireRollback(
  manifest: ReleaseManifestV4,
  manifestDigest: Sha256,
  state: GenerationState,
  candidate: RollbackAuthorization | undefined,
  trust: ManifestTrust,
): Promise<string> {
  if (candidate === undefined)
    throw rollbackRejected("A signed rollback authorization is required");
  let value: RollbackAuthorization;
  try {
    const object = requireExactShape(
      candidate,
      rollbackKeys,
      "rollback authorization",
    );
    value = {
      id: requireIdentifier(ownData(object, "id"), "rollback authorization ID"),
      catalogId: requireIdentifier(
        ownData(object, "catalogId"),
        "rollback catalog ID",
      ) as CatalogId,
      issuer: requireString(
        ownData(object, "issuer"),
        "rollback issuer",
        256,
        boundedAsciiPattern,
      ),
      currentHighestGeneration: requireInteger(
        ownData(object, "currentHighestGeneration"),
        "rollback current generation",
      ),
      targetGeneration: requireInteger(
        ownData(object, "targetGeneration"),
        "rollback target generation",
      ),
      targetManifestDigest: requireDigest(
        ownData(object, "targetManifestDigest"),
        "rollback target digest",
      ),
      reason: requireString(ownData(object, "reason"), "rollback reason", 1024),
      expiresAt: requireTimestamp(
        ownData(object, "expiresAt"),
        "rollback expiry",
      ),
      keyId: requireIdentifier(ownData(object, "keyId"), "rollback key ID"),
      algorithm: ownData(object, "algorithm") as "Ed25519",
      signature: requireString(
        ownData(object, "signature"),
        "rollback signature",
        256,
        /^[A-Za-z0-9_-]+$/,
      ),
    };
    if (value.algorithm !== "Ed25519")
      throw manifestInvalid("rollback algorithm is invalid");
  } catch {
    throw rollbackRejected("Rollback authorization is malformed");
  }
  if (
    value.catalogId !== manifest.catalogId ||
    value.issuer !== manifest.issuer ||
    value.currentHighestGeneration !== state.highestGeneration ||
    value.targetGeneration !== manifest.generation ||
    value.targetManifestDigest !== manifestDigest ||
    state.consumedRollbackAuthorizationIds.includes(value.id)
  ) {
    throw rollbackRejected(
      "Rollback authorization does not match current state and target",
    );
  }
  const now = trust.now?.() ?? new Date();
  if (new Date(value.expiresAt).getTime() <= now.getTime())
    throw rollbackRejected("Rollback authorization has expired");
  const key = findKey(trust.rollbackKeys, manifest.issuer, value.keyId);
  if (
    key === null ||
    trust.releaseKeys.some(
      (releaseKey) => releaseKey.publicKey === key.publicKey,
    )
  ) {
    throw rollbackRejected("Rollback key is not separately trusted");
  }
  const valid = await verifyEd25519(
    `${rollbackSignatureDomain}${canonicalJson(rollbackUnsigned(value))}`,
    value.signature,
    key.publicKey,
  );
  if (!valid) throw rollbackRejected("Rollback signature is invalid");
  return value.id;
}

function nextNormalState(
  state: GenerationState | null,
  manifest: ReleaseManifestV4,
  digest: Sha256,
): GenerationState | null {
  if (state === null) {
    return {
      revision: 0,
      highestGeneration: manifest.generation,
      highestManifestDigest: digest,
      activeGeneration: manifest.generation,
      activeManifestDigest: digest,
      consumedRollbackAuthorizationIds: [],
    };
  }
  if (manifest.generation > state.highestGeneration) {
    return {
      ...state,
      revision: state.revision + 1,
      highestGeneration: manifest.generation,
      highestManifestDigest: digest,
      activeGeneration: manifest.generation,
      activeManifestDigest: digest,
    };
  }
  if (manifest.generation === state.highestGeneration) {
    if (digest !== state.highestManifestDigest) {
      throw new OpenApiMcpError(
        "MANIFEST_GENERATION_CONFLICT",
        "Equal manifest generation has a different digest",
      );
    }
    if (
      state.activeGeneration === manifest.generation &&
      state.activeManifestDigest === digest
    )
      return null;
    return {
      ...state,
      revision: state.revision + 1,
      activeGeneration: manifest.generation,
      activeManifestDigest: digest,
    };
  }
  return null;
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value))
    return value;
  for (const key of Reflect.ownKeys(value))
    deepFreeze((value as Record<PropertyKey, unknown>)[key]);
  return Object.freeze(value);
}

function detachedManifest(manifest: ReleaseManifestV4): ReleaseManifestV4 {
  return parseManifest(
    canonicalJson(manifest as unknown as JsonObject),
    DEFAULT_RUNTIME_LIMITS,
  );
}

/** Verify a v4 manifest and atomically admit its generation policy transition. */
export async function admitManifest(
  envelope: ManifestEnvelope,
  trust: ManifestTrust,
  generations: GenerationStore,
  limitOverrides: RuntimeLimits = DEFAULT_RUNTIME_LIMITS,
): Promise<AdmittedManifest> {
  const limits = {
    ...DEFAULT_RUNTIME_LIMITS,
    ...limitOverrides,
  } as RuntimeLimits;
  if (!isObject(envelope))
    throw manifestInvalid("manifest envelope must be an object");
  const envelopeKeys = Object.hasOwn(envelope, "rollback")
    ? [...envelopeRequiredKeys, "rollback"]
    : envelopeRequiredKeys;
  const checkedEnvelope = requireExactShape(
    envelope,
    envelopeKeys,
    "manifest envelope",
  );
  const manifestJson = ownData(checkedEnvelope, "manifestJson");
  if (typeof manifestJson !== "string")
    throw manifestInvalid("manifestJson must be a string");
  const signature = ownData(checkedEnvelope, "signature") as ManifestSignature;
  const rollback =
    envelopeKeys.length === 3
      ? (ownData(checkedEnvelope, "rollback") as RollbackAuthorization)
      : undefined;
  let manifest: ReleaseManifestV4;
  try {
    manifest = parseManifest(manifestJson, limits);
  } catch (error) {
    if (error instanceof OpenApiMcpError) throw error;
    throw manifestInvalid("Manifest parsing failed");
  }
  const canonical = canonicalJson(manifest as unknown as JsonObject);
  await requireReleaseSignature(manifest, canonical, signature, trust);
  const manifestDigest = await sha256(
    manifestDigestDomain,
    manifest as unknown as JsonObject,
  );

  for (let attempt = 0; attempt < 32; attempt += 1) {
    const state = await generations.get(manifest.catalogId, manifest.issuer);
    let next = nextNormalState(state, manifest, manifestDigest);
    if (state !== null && manifest.generation < state.highestGeneration) {
      const rollbackId = await requireRollback(
        manifest,
        manifestDigest,
        state,
        rollback,
        trust,
      );
      next = {
        ...state,
        revision: state.revision + 1,
        activeGeneration: manifest.generation,
        activeManifestDigest: manifestDigest,
        consumedRollbackAuthorizationIds: [
          ...state.consumedRollbackAuthorizationIds,
          rollbackId,
        ],
      };
    }
    if (next === null)
      return deepFreeze({
        manifest: detachedManifest(manifest),
        manifestDigest,
      });
    const accepted = await generations.accept(
      manifest.catalogId,
      manifest.issuer,
      {
        expectedRevision: state?.revision ?? null,
        next,
      },
    );
    if (accepted !== null)
      return deepFreeze({
        manifest: detachedManifest(manifest),
        manifestDigest,
      });
  }
  throw new OpenApiMcpError(
    "MANIFEST_GENERATION_CONFLICT",
    "Generation state changed too many times; retry admission",
  );
}
