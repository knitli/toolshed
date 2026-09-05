import { timingSafeEqual } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import {
  digestCredentialAuthorizationBinding,
  snapshotCredentialAuthorizationBinding,
} from "../runtime/credential-binding.ts";
import { sha256 } from "../runtime/digest.ts";
import { OpenApiMcpError } from "../runtime/errors.ts";
import {
  canonicalJsonBounded,
  parseJsonStrict,
} from "../runtime/strict-json.ts";
import type {
  AuthProfile,
  Credential,
  CredentialAuthorizationBinding,
  CredentialBindingResolver,
  CredentialProfileBinding,
  CredentialProvider,
  CredentialResolution,
  CredentialSlot,
  CredentialSlotContext,
  CredentialSnapshot,
  JsonObject,
  JsonValue,
  LocalAuthProfile,
  SecretStore,
  Sha256,
} from "../runtime/types.ts";
import { isOAuthResource } from "./oauth-resource.ts";

const PROFILE_DIGEST_DOMAIN = "knitli.openapi-mcp.credential-profile.v1";
const SLOT_DIGEST_DOMAIN = "knitli.openapi-mcp.credential-slots.v1";
const PROFILE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const ENV_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const HEADER_NAME_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const FORBIDDEN_API_KEY_HEADERS = new Set([
  "accept",
  "authorization",
  "connection",
  "cookie",
  "forwarded",
  "host",
  "proxy-authenticate",
  "proxy-authorization",
  "set-cookie",
  "transfer-encoding",
  "upgrade",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-real-ip",
]);
const CALLBACK_PATH = "/oauth/callback";
const DEFAULT_AUTHORIZATION_DEADLINE_MS = 120_000;
const DEFAULT_TOKEN_DEADLINE_MS = 30_000;
const DEFAULT_MAX_TOKEN_RESPONSE_BYTES = 64 * 1024;
const MAX_CALLBACK_PARAMETERS = 64;
const MAX_CALLBACK_PARAMETER_NAME_LENGTH = 128;
const MAX_CALLBACK_EXTENSION_VALUE_LENGTH = 2_048;
let providerInstanceSequence = 0;

interface ValidatedProfile {
  readonly value: LocalAuthProfile;
  readonly auth: AuthProfile;
  readonly allowedOrigins: readonly string[];
  readonly effectiveOrigins: ReadonlySet<string>;
  readonly scopes: readonly string[];
  readonly audience?: string;
  readonly slots: readonly CredentialSlot[];
}

/** @internal Dependency seams exist only for deterministic local adapter tests. */
export interface CredentialProviderOptions {
  readonly manifestOrigins: readonly string[];
  readonly secretStore?: SecretStore;
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly fetch?: typeof globalThis.fetch;
  readonly now?: () => number;
  readonly randomBytes?: (size: number) => Uint8Array;
  readonly authorizationDeadlineMs?: number;
  readonly tokenDeadlineMs?: number;
  readonly maxTokenResponseBytes?: number;
}

export interface LocalCredentialProvider extends CredentialProvider {
  readonly bindingResolver: CredentialBindingResolver;
  /**
   * Clears process-local credentials only. To invalidate the upstream grant,
   * use the provider account's documented revocation procedure; v1 does not
   * invent or call a provider revocation endpoint.
   */
  forget(): Promise<void>;
  close(): Promise<void>;
}

export class MemorySecretStore implements SecretStore {
  readonly #values = new Map<string, string>();

  async get(key: string): Promise<string | null> {
    return this.#values.get(key) ?? null;
  }

  async set(key: string, value: string): Promise<void> {
    this.#values.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.#values.delete(key);
  }
}

function invalidProfile(): OpenApiMcpError {
  return new OpenApiMcpError(
    "AUTH_PROFILE_INVALID",
    "Authentication profile is invalid",
  );
}

function snapshotObject(value: unknown): JsonObject {
  try {
    const json = canonicalJsonBounded(value as JsonValue, {
      maxBytes: 32 * 1024,
      maxDepth: 6,
      maxNodes: 512,
    });
    const snapshot = parseJsonStrict(json, {
      maxBytes: 32 * 1024,
      maxDepth: 6,
      maxKeys: 512,
    });
    if (
      snapshot === null ||
      Array.isArray(snapshot) ||
      typeof snapshot !== "object"
    ) {
      throw invalidProfile();
    }
    return snapshot;
  } catch {
    throw invalidProfile();
  }
}

function exactKeys(
  value: JsonObject,
  required: readonly string[],
  optional: readonly string[] = [],
): void {
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  if (
    required.some((key) => !Object.hasOwn(value, key)) ||
    keys.some((key) => !allowed.has(key))
  ) {
    throw invalidProfile();
  }
}

function validateOrigin(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048) {
    throw invalidProfile();
  }
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      url.username !== "" ||
      url.password !== "" ||
      url.pathname !== "/" ||
      url.search !== "" ||
      url.hash !== "" ||
      url.origin !== value
    ) {
      throw invalidProfile();
    }
    return value;
  } catch {
    throw invalidProfile();
  }
}

function validateStringArray(
  value: unknown,
  maximum: number,
  allowSpace: boolean,
): readonly string[] {
  if (!Array.isArray(value) || value.length > maximum) throw invalidProfile();
  const normalized: string[] = [];
  for (const entry of value) {
    if (
      typeof entry !== "string" ||
      entry.length === 0 ||
      entry.length > 256 ||
      [...entry].some((character) => {
        const code = character.charCodeAt(0);
        return code <= (allowSpace ? 0x1f : 0x20) || code === 0x7f;
      }) ||
      normalized.includes(entry)
    ) {
      throw invalidProfile();
    }
    normalized.push(entry);
  }
  normalized.sort();
  return Object.freeze(normalized);
}

function validateOptionalText(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 2048 ||
    [...value].some((character) => {
      const code = character.charCodeAt(0);
      return code < 0x20 || code === 0x7f;
    })
  ) {
    throw invalidProfile();
  }
  return value;
}

function validateResource(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (!isOAuthResource(value)) throw invalidProfile();
  return value;
}

function validateEndpoint(value: unknown): string {
  if (typeof value !== "string" || value.length > 2048) throw invalidProfile();
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      url.username !== "" ||
      url.password !== "" ||
      url.hash !== "" ||
      url.toString() !== value
    ) {
      throw invalidProfile();
    }
    return value;
  } catch {
    throw invalidProfile();
  }
}

function validateAuth(value: unknown): AuthProfile {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw invalidProfile();
  }
  const auth = value as JsonObject;
  if (auth.type === "bearer-env") {
    exactKeys(auth, ["env", "type"]);
    if (typeof auth.env !== "string" || !ENV_PATTERN.test(auth.env)) {
      throw invalidProfile();
    }
    return Object.freeze({ type: "bearer-env", env: auth.env });
  }
  if (auth.type === "api-key-env") {
    exactKeys(auth, ["env", "name", "placement", "type"]);
    if (
      typeof auth.env !== "string" ||
      !ENV_PATTERN.test(auth.env) ||
      (auth.placement !== "header" && auth.placement !== "query") ||
      typeof auth.name !== "string" ||
      auth.name.length === 0 ||
      auth.name.length > 256
    ) {
      throw invalidProfile();
    }
    if (
      auth.placement === "header" &&
      (!HEADER_NAME_PATTERN.test(auth.name) ||
        FORBIDDEN_API_KEY_HEADERS.has(auth.name.toLowerCase()) ||
        auth.name.toLowerCase().startsWith("x-forwarded-"))
    ) {
      throw invalidProfile();
    }
    if (
      auth.placement === "query" &&
      [...auth.name].some((character) => {
        const code = character.charCodeAt(0);
        return code <= 0x20 || code === 0x7f;
      })
    ) {
      throw invalidProfile();
    }
    return Object.freeze({
      type: "api-key-env",
      env: auth.env,
      placement: auth.placement,
      name: auth.placement === "header" ? auth.name.toLowerCase() : auth.name,
    });
  }
  if (auth.type === "oauth2-pkce") {
    exactKeys(
      auth,
      ["authorizationEndpoint", "clientId", "scopes", "tokenEndpoint", "type"],
      ["resource"],
    );
    if (
      typeof auth.clientId !== "string" ||
      auth.clientId.length === 0 ||
      auth.clientId.length > 2048
    ) {
      throw invalidProfile();
    }
    const scopes = validateStringArray(auth.scopes, 64, false);
    const resource = validateResource(auth.resource);
    const validated: AuthProfile = {
      type: "oauth2-pkce",
      authorizationEndpoint: validateEndpoint(auth.authorizationEndpoint),
      tokenEndpoint: validateEndpoint(auth.tokenEndpoint),
      clientId: auth.clientId,
      scopes,
      ...(resource === undefined ? {} : { resource }),
    };
    return Object.freeze(validated);
  }
  throw invalidProfile();
}

function validateProfile(
  raw: LocalAuthProfile,
  manifestOrigins: readonly string[],
): ValidatedProfile {
  const profile = snapshotObject(raw);
  exactKeys(
    profile,
    ["allowedOrigins", "auth", "profileId", "revision"],
    ["audience", "scopes"],
  );
  if (
    typeof profile.profileId !== "string" ||
    !PROFILE_PATTERN.test(profile.profileId) ||
    typeof profile.revision !== "number" ||
    !Number.isSafeInteger(profile.revision) ||
    profile.revision <= 0 ||
    !Array.isArray(profile.allowedOrigins) ||
    profile.allowedOrigins.length === 0 ||
    profile.allowedOrigins.length > 64
  ) {
    throw invalidProfile();
  }
  const allowedOrigins = profile.allowedOrigins.map(validateOrigin);
  if (new Set(allowedOrigins).size !== allowedOrigins.length) {
    throw invalidProfile();
  }
  allowedOrigins.sort();
  const manifests = manifestOrigins.map(validateOrigin);
  const effectiveOrigins = new Set(
    allowedOrigins.filter((origin) => manifests.includes(origin)),
  );
  if (effectiveOrigins.size === 0) throw invalidProfile();

  const auth = validateAuth(profile.auth);
  const audience = validateOptionalText(profile.audience);
  let scopes: readonly string[];
  if (auth.type === "oauth2-pkce") {
    if (Object.hasOwn(profile, "scopes")) throw invalidProfile();
    scopes = auth.scopes;
  } else {
    scopes = Object.hasOwn(profile, "scopes")
      ? validateStringArray(profile.scopes, 64, false)
      : Object.freeze([]);
  }

  const slots: readonly CredentialSlot[] = Object.freeze([
    Object.freeze(
      auth.type === "api-key-env"
        ? { placement: auth.placement, name: auth.name }
        : { placement: "header" as const, name: "authorization" },
    ),
  ]);
  const value = Object.freeze({
    profileId: profile.profileId,
    revision: profile.revision,
    allowedOrigins: Object.freeze(allowedOrigins),
    auth,
    ...(audience === undefined ? {} : { audience }),
    ...(auth.type === "oauth2-pkce" ? {} : { scopes }),
  }) as LocalAuthProfile;
  return {
    value,
    auth,
    allowedOrigins: value.allowedOrigins,
    effectiveOrigins,
    scopes,
    audience:
      audience ?? (auth.type === "oauth2-pkce" ? auth.resource : undefined),
    slots,
  };
}

function defaultRandom(size: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(size));
}

function randomIdentifier(randomBytes: (size: number) => Uint8Array): string {
  let bytes: Uint8Array;
  try {
    bytes = randomBytes(24);
  } catch {
    throw invalidProfile();
  }
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 24) {
    throw invalidProfile();
  }
  return Buffer.from(bytes).toString("base64url");
}

async function digestSlots(slots: readonly CredentialSlot[]): Promise<Sha256> {
  const canonicalSlots = slots
    .map((slot) => ({ placement: slot.placement, name: slot.name }))
    .sort((left, right) =>
      `${left.placement}:${left.name}`.localeCompare(
        `${right.placement}:${right.name}`,
      ),
    );
  return sha256(SLOT_DIGEST_DOMAIN, canonicalSlots);
}

/** Validate local profile semantics without resolving credentials or performing I/O. */
export function validateLocalAuthProfile(
  profile: LocalAuthProfile,
): LocalAuthProfile {
  const snapshot = snapshotObject(profile);
  if (!Array.isArray(snapshot.allowedOrigins)) throw invalidProfile();
  return validateProfile(
    snapshot as unknown as LocalAuthProfile,
    snapshot.allowedOrigins as string[],
  ).value;
}

export async function digestCredentialProfile(
  profile: LocalAuthProfile,
): Promise<Sha256> {
  return sha256(
    PROFILE_DIGEST_DOMAIN,
    snapshotObject(validateLocalAuthProfile(profile)),
  );
}

async function createBinding(
  profile: ValidatedProfile,
  profileDigest: Sha256,
  slotsDigest: Sha256,
  grantId: string,
  scopes: readonly string[],
): Promise<CredentialAuthorizationBinding> {
  const payload = {
    profileId: profile.value.profileId,
    profileDigest,
    grantId,
    ...(profile.audience === undefined ? {} : { audience: profile.audience }),
    scopes,
    slotsDigest,
  };
  return snapshotCredentialAuthorizationBinding({
    ...payload,
    bindingDigest: await digestCredentialAuthorizationBinding(payload),
  });
}

function createBindingResolver(
  profile: ValidatedProfile,
  profileDigest: Sha256,
): CredentialBindingResolver {
  const frozenSlots = profile.slots;
  const binding: CredentialProfileBinding = Object.freeze({
    profileId: profile.value.profileId,
    profileDigest,
    slots: frozenSlots,
  });
  return Object.freeze({
    async resolve(
      context: Readonly<CredentialSlotContext>,
    ): Promise<CredentialProfileBinding> {
      if (!profile.effectiveOrigins.has(context.origin)) {
        throw new OpenApiMcpError(
          "DESTINATION_DENIED",
          "Credential profile does not allow destination",
        );
      }
      return binding;
    },
  });
}

function freezeCredential(credential: Credential): Credential {
  return Object.freeze({ ...credential });
}

function freezeSnapshot(
  credential: Credential,
  binding: CredentialAuthorizationBinding,
): CredentialSnapshot {
  return Object.freeze({ credential: freezeCredential(credential), binding });
}

interface OAuthTokenResponse {
  readonly accessToken: string;
  readonly refreshToken?: string;
  readonly expiresAt: number;
  readonly scopes: readonly string[];
}

interface PendingAuthorization {
  readonly generation: number;
  readonly server: Server;
  readonly authorizationUrl: string;
  readonly expiresAt: string;
  readonly state: string;
  readonly verifier: string;
  readonly redirectUri: string;
  timer: ReturnType<typeof setTimeout>;
  terminal: boolean;
}

function boundedPositiveOption(
  value: number | undefined,
  defaultValue: number,
): number {
  if (value === undefined) return defaultValue;
  if (!Number.isSafeInteger(value) || value <= 0 || value > defaultValue) {
    throw invalidProfile();
  }
  return value;
}

function randomOpaque(
  randomBytes: (size: number) => Uint8Array,
  size = 32,
): string {
  let bytes: Uint8Array;
  try {
    bytes = randomBytes(size);
  } catch {
    throw invalidProfile();
  }
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== size) {
    throw invalidProfile();
  }
  return Buffer.from(bytes).toString("base64url");
}

function equalState(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  if (leftBytes.byteLength !== rightBytes.byteLength) return false;
  return timingSafeEqual(leftBytes, rightBytes);
}

function callbackReply(
  response: ServerResponse,
  status: number,
  message:
    | "OAuth callback rejected"
    | "Authorization complete"
    | "Authorization failed",
): void {
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "text/plain; charset=utf-8",
    "x-content-type-options": "nosniff",
  });
  response.end(message);
}

async function readBoundedResponse(
  response: Response,
  maximumBytes: number,
): Promise<string> {
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    if (!Number.isSafeInteger(length) || length < 0 || length > maximumBytes) {
      throw new Error("token response rejected");
    }
  }
  if (response.body === null) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      bytes += item.value.byteLength;
      if (bytes > maximumBytes) {
        await reader.cancel();
        throw new Error("token response rejected");
      }
      chunks.push(item.value);
    }
  } finally {
    reader.releaseLock();
  }
  const joined = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(joined);
}

function parseTokenScopes(
  value: unknown,
  requested: readonly string[],
): readonly string[] {
  if (value === undefined) return Object.freeze([...requested].sort());
  if (typeof value !== "string") throw new Error("token response rejected");
  const scopes = value === "" ? [] : value.split(" ");
  if (
    scopes.some(
      (scope, index) =>
        scope.length === 0 ||
        scope.length > 256 ||
        scopes.indexOf(scope) !== index ||
        !requested.includes(scope),
    )
  ) {
    throw new Error("token response rejected");
  }
  return Object.freeze([...scopes].sort());
}

async function parseTokenResponse(
  response: Response,
  requestedScopes: readonly string[],
  now: () => number,
  maximumBytes: number,
): Promise<OAuthTokenResponse> {
  if (
    response.redirected ||
    (response.status >= 300 && response.status < 400)
  ) {
    throw new Error("token response rejected");
  }
  if (!response.ok) throw new Error("token response rejected");
  const text = await readBoundedResponse(response, maximumBytes);
  const parsed = parseJsonStrict(text, {
    maxBytes: maximumBytes,
    maxDepth: 4,
    maxKeys: 64,
  });
  if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error("token response rejected");
  }
  const token = parsed as JsonObject;
  if (
    typeof token.access_token !== "string" ||
    token.access_token.length === 0 ||
    token.access_token.length > maximumBytes ||
    typeof token.token_type !== "string" ||
    token.token_type.toLowerCase() !== "bearer" ||
    (Object.hasOwn(token, "refresh_token") &&
      (typeof token.refresh_token !== "string" ||
        token.refresh_token.length === 0 ||
        token.refresh_token.length > maximumBytes)) ||
    (Object.hasOwn(token, "expires_in") &&
      (typeof token.expires_in !== "number" ||
        !Number.isSafeInteger(token.expires_in) ||
        token.expires_in <= 0))
  ) {
    throw new Error("token response rejected");
  }
  const expiresAt = Object.hasOwn(token, "expires_in")
    ? now() + (token.expires_in as number) * 1000
    : Number.MAX_SAFE_INTEGER;
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= now()) {
    throw new Error("token response rejected");
  }
  return Object.freeze({
    accessToken: token.access_token,
    ...(typeof token.refresh_token === "string"
      ? { refreshToken: token.refresh_token }
      : {}),
    expiresAt,
    scopes: parseTokenScopes(token.scope, requestedScopes),
  });
}

function closeServer(server: Server): void {
  try {
    server.close();
  } catch {
    // Closing an already-closed listener is intentionally idempotent.
  }
}

async function listenLoopback(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    const onError = () =>
      reject(
        new OpenApiMcpError("AUTH_REQUIRED", "Authorization could not start"),
      );
    server.once("error", onError);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", onError);
      const address = server.address();
      if (
        address === null ||
        typeof address === "string" ||
        address.address !== "127.0.0.1"
      ) {
        closeServer(server);
        reject(
          new OpenApiMcpError("AUTH_REQUIRED", "Authorization could not start"),
        );
        return;
      }
      resolve(address.port);
    });
  });
}

function createOAuthProvider(
  profile: ValidatedProfile & {
    readonly auth: Extract<AuthProfile, { type: "oauth2-pkce" }>;
  },
  profileDigest: Sha256,
  slotsDigest: Sha256,
  bindingResolver: CredentialBindingResolver,
  options: CredentialProviderOptions,
  randomBytes: (size: number) => Uint8Array,
): LocalCredentialProvider {
  const secretStore = options.secretStore ?? new MemorySecretStore();
  const fetchToken = options.fetch ?? globalThis.fetch;
  const now = options.now ?? Date.now;
  const authorizationDeadlineMs = boundedPositiveOption(
    options.authorizationDeadlineMs,
    DEFAULT_AUTHORIZATION_DEADLINE_MS,
  );
  const tokenDeadlineMs = boundedPositiveOption(
    options.tokenDeadlineMs,
    DEFAULT_TOKEN_DEADLINE_MS,
  );
  const maxTokenResponseBytes = boundedPositiveOption(
    options.maxTokenResponseBytes,
    DEFAULT_MAX_TOKEN_RESPONSE_BYTES,
  );
  providerInstanceSequence += 1;
  if (!Number.isSafeInteger(providerInstanceSequence)) throw invalidProfile();
  const storageNamespace = `${randomOpaque(randomBytes)}.${providerInstanceSequence.toString(36)}`;
  const tokenKeys = (ownedGeneration: number) =>
    Object.freeze({
      access: `oauth:${profile.value.profileId}:${storageNamespace}:${ownedGeneration}:access`,
      refresh: `oauth:${profile.value.profileId}:${storageNamespace}:${ownedGeneration}:refresh`,
    });
  let generation = 0;
  let closed = false;
  let pending: PendingAuthorization | undefined;
  let authorizationPromise: Promise<CredentialResolution> | undefined;
  let refreshPromise: Promise<CredentialResolution> | undefined;
  let grantId: string | undefined;
  let liveScopes: readonly string[] = Object.freeze([...profile.scopes]);
  let expiresAt = 0;

  const safeGet = async (key: string): Promise<string | null> => {
    try {
      return await secretStore.get(key);
    } catch {
      throw new OpenApiMcpError(
        "AUTH_REQUIRED",
        "Credential storage is unavailable",
      );
    }
  };

  const safeSet = async (key: string, value: string): Promise<void> => {
    try {
      await secretStore.set(key, value);
    } catch {
      throw new OpenApiMcpError(
        "AUTH_REQUIRED",
        "Credential storage is unavailable",
      );
    }
  };

  const safeDelete = async (key: string): Promise<void> => {
    try {
      await secretStore.delete(key);
    } catch {
      throw new OpenApiMcpError(
        "AUTH_REQUIRED",
        "Credential storage is unavailable",
      );
    }
  };

  const deleteTokens = async (ownedGeneration: number): Promise<void> => {
    const keys = tokenKeys(ownedGeneration);
    let deletionFailed = false;
    try {
      await safeDelete(keys.access);
    } catch {
      deletionFailed = true;
    }
    try {
      await safeDelete(keys.refresh);
    } catch {
      deletionFailed = true;
    }
    if (deletionFailed) {
      throw new OpenApiMcpError(
        "AUTH_REQUIRED",
        "Credential storage is unavailable",
      );
    }
  };

  const commitToken = async (
    token: OAuthTokenResponse,
    expectedGeneration: number,
    refreshFallback?: string,
  ): Promise<boolean> => {
    try {
      if (generation !== expectedGeneration || closed) return false;
      const keys = tokenKeys(expectedGeneration);
      await safeSet(keys.access, token.accessToken);
      if (generation !== expectedGeneration || closed) {
        await deleteTokens(expectedGeneration);
        return false;
      }
      const nextRefresh = token.refreshToken ?? refreshFallback;
      if (nextRefresh === undefined) await safeDelete(keys.refresh);
      else await safeSet(keys.refresh, nextRefresh);
      if (generation !== expectedGeneration || closed) {
        await deleteTokens(expectedGeneration);
        return false;
      }
      expiresAt = token.expiresAt;
      liveScopes = token.scopes;
      return true;
    } catch {
      try {
        await deleteTokens(expectedGeneration);
      } catch {
        // Best effort: an unreliable SecretStore may retain physical bytes.
      }
      throw new OpenApiMcpError(
        "AUTH_REQUIRED",
        "Credential storage is unavailable",
      );
    }
  };

  const exchange = async (
    body: URLSearchParams,
    requestedScopes: readonly string[],
    expectedGeneration: number,
    refreshFallback?: string,
  ): Promise<boolean> => {
    const response = await fetchToken(profile.auth.tokenEndpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
      redirect: "manual",
      signal: AbortSignal.timeout(tokenDeadlineMs),
    });
    if (generation !== expectedGeneration || closed) return false;
    const token = await parseTokenResponse(
      response,
      requestedScopes,
      now,
      maxTokenResponseBytes,
    );
    if (generation !== expectedGeneration || closed) return false;
    return commitToken(token, expectedGeneration, refreshFallback);
  };

  const snapshot = async (
    accessToken: string,
    expectedGeneration: number,
  ): Promise<CredentialResolution> => {
    if (generation !== expectedGeneration || closed) {
      throw new OpenApiMcpError("AUTH_REQUIRED", "Authorization was cancelled");
    }
    if (grantId === undefined)
      throw new OpenApiMcpError("AUTH_REQUIRED", "Authorization is required");
    const binding = await createBinding(
      profile,
      profileDigest,
      slotsDigest,
      grantId,
      liveScopes,
    );
    if (generation !== expectedGeneration || closed) {
      throw new OpenApiMcpError("AUTH_REQUIRED", "Authorization was cancelled");
    }
    return Object.freeze({
      status: "ready" as const,
      snapshot: freezeSnapshot({ type: "bearer", token: accessToken }, binding),
    });
  };

  const beginAuthorization = async (): Promise<CredentialResolution> => {
    if (closed)
      throw new OpenApiMcpError(
        "AUTH_REQUIRED",
        "Credential provider is closed",
      );
    if (pending !== undefined) {
      return Object.freeze({
        status: "auth-required" as const,
        authorizationUrl: pending.authorizationUrl,
        expiresAt: pending.expiresAt,
      });
    }
    const expectedGeneration = generation;
    const state = randomOpaque(randomBytes);
    const verifier = randomOpaque(randomBytes);
    const challengeDigest = await globalThis.crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(verifier),
    );
    if (generation !== expectedGeneration || closed) {
      throw new OpenApiMcpError("AUTH_REQUIRED", "Authorization was cancelled");
    }

    let currentPending: PendingAuthorization | undefined;
    const handler = (
      request: IncomingMessage,
      response: ServerResponse,
    ): void => {
      if (
        currentPending === undefined ||
        pending !== currentPending ||
        currentPending.terminal ||
        request.method !== "GET" ||
        typeof request.url !== "string" ||
        request.url.length > 8192 ||
        request.headers.host !==
          `127.0.0.1:${new URL(currentPending.redirectUri).port}`
      ) {
        callbackReply(response, 400, "OAuth callback rejected");
        return;
      }
      let callback: URL;
      try {
        callback = new URL(request.url, currentPending.redirectUri);
      } catch {
        callbackReply(response, 400, "OAuth callback rejected");
        return;
      }
      const states = callback.searchParams.getAll("state");
      const codes = callback.searchParams.getAll("code");
      const errors = callback.searchParams.getAll("error");
      const callbackParameters = [...callback.searchParams.entries()];
      const code = codes.length === 1 ? codes[0] : undefined;
      const oauthError = errors.length === 1 ? errors[0] : undefined;
      if (
        callback.pathname !== CALLBACK_PATH ||
        callback.origin !== new URL(currentPending.redirectUri).origin ||
        callback.hash !== "" ||
        callbackParameters.length > MAX_CALLBACK_PARAMETERS ||
        callbackParameters.some(([key, value]) => {
          const maximumValueLength =
            key === "code"
              ? 4_096
              : key === "error"
                ? 256
                : key === "state"
                  ? 128
                  : MAX_CALLBACK_EXTENSION_VALUE_LENGTH;
          return (
            key.length === 0 ||
            key.length > MAX_CALLBACK_PARAMETER_NAME_LENGTH ||
            value.length > maximumValueLength
          );
        }) ||
        states.length !== 1 ||
        !equalState(states[0] ?? "", currentPending.state) ||
        ((code === undefined || code === "" || code.length > 4096) &&
          (oauthError === undefined ||
            oauthError === "" ||
            oauthError.length > 256)) ||
        (code !== undefined && oauthError !== undefined) ||
        codes.length > 1 ||
        errors.length > 1
      ) {
        callbackReply(response, 400, "OAuth callback rejected");
        return;
      }

      currentPending.terminal = true;
      clearTimeout(currentPending.timer);
      closeServer(currentPending.server);
      if (oauthError !== undefined || code === undefined) {
        pending = undefined;
        callbackReply(response, 400, "Authorization failed");
        return;
      }
      const body = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: currentPending.redirectUri,
        client_id: profile.auth.clientId,
        code_verifier: currentPending.verifier,
      });
      if (profile.auth.resource !== undefined) {
        body.set("resource", profile.auth.resource);
      }
      void exchange(body, profile.scopes, expectedGeneration)
        .then((committed) => {
          if (!committed || generation !== expectedGeneration || closed) {
            callbackReply(response, 409, "Authorization failed");
            return;
          }
          grantId = randomIdentifier(randomBytes);
          callbackReply(response, 200, "Authorization complete");
        })
        .catch(() => callbackReply(response, 502, "Authorization failed"))
        .finally(() => {
          if (pending === currentPending) pending = undefined;
        });
    };
    const server = createServer(handler);
    const port = await listenLoopback(server);
    if (generation !== expectedGeneration || closed) {
      closeServer(server);
      throw new OpenApiMcpError("AUTH_REQUIRED", "Authorization was cancelled");
    }
    const redirectUri = `http://127.0.0.1:${port}${CALLBACK_PATH}`;
    const authorization = new URL(profile.auth.authorizationEndpoint);
    authorization.searchParams.set("response_type", "code");
    authorization.searchParams.set("client_id", profile.auth.clientId);
    authorization.searchParams.set("redirect_uri", redirectUri);
    authorization.searchParams.set("scope", profile.scopes.join(" "));
    authorization.searchParams.set("state", state);
    authorization.searchParams.set(
      "code_challenge",
      Buffer.from(challengeDigest).toString("base64url"),
    );
    authorization.searchParams.set("code_challenge_method", "S256");
    if (profile.auth.resource !== undefined) {
      authorization.searchParams.set("resource", profile.auth.resource);
    }
    const deadline = now() + authorizationDeadlineMs;
    if (!Number.isSafeInteger(deadline)) {
      closeServer(server);
      throw invalidProfile();
    }
    currentPending = {
      generation: expectedGeneration,
      server,
      authorizationUrl: authorization.toString(),
      expiresAt: new Date(deadline).toISOString(),
      state,
      verifier,
      redirectUri,
      terminal: false,
      timer: setTimeout(() => {
        const flow = currentPending;
        if (flow !== undefined && pending === flow && !flow.terminal) {
          flow.terminal = true;
          pending = undefined;
          closeServer(server);
        }
      }, authorizationDeadlineMs),
    };
    pending = currentPending;
    return Object.freeze({
      status: "auth-required" as const,
      authorizationUrl: currentPending.authorizationUrl,
      expiresAt: currentPending.expiresAt,
    });
  };

  const startAuthorization = (): Promise<CredentialResolution> => {
    if (pending !== undefined) {
      return Promise.resolve(
        Object.freeze({
          status: "auth-required" as const,
          authorizationUrl: pending.authorizationUrl,
          expiresAt: pending.expiresAt,
        }),
      );
    }
    authorizationPromise ??= beginAuthorization().finally(() => {
      authorizationPromise = undefined;
    });
    return authorizationPromise;
  };

  const refresh = async (
    refreshToken: string,
  ): Promise<CredentialResolution> => {
    const expectedGeneration = generation;
    const keys = tokenKeys(expectedGeneration);
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: profile.auth.clientId,
    });
    if (liveScopes.length > 0) body.set("scope", liveScopes.join(" "));
    if (profile.auth.resource !== undefined)
      body.set("resource", profile.auth.resource);
    try {
      const committed = await exchange(
        body,
        liveScopes,
        expectedGeneration,
        refreshToken,
      );
      if (!committed || generation !== expectedGeneration || closed) {
        throw new OpenApiMcpError(
          "AUTH_REQUIRED",
          "Authorization was cancelled",
        );
      }
      const access = await safeGet(keys.access);
      if (generation !== expectedGeneration || closed || access === null) {
        throw new OpenApiMcpError(
          "AUTH_REQUIRED",
          "Authorization was cancelled",
        );
      }
      return snapshot(access, expectedGeneration);
    } catch {
      if (generation === expectedGeneration && !closed) {
        await deleteTokens(expectedGeneration);
        if (generation !== expectedGeneration || closed) {
          throw new OpenApiMcpError(
            "AUTH_REQUIRED",
            "Authorization was cancelled",
          );
        }
        expiresAt = 0;
        grantId = undefined;
        liveScopes = Object.freeze([...profile.scopes]);
        return startAuthorization();
      }
      throw new OpenApiMcpError("AUTH_REQUIRED", "Authorization was cancelled");
    }
  };

  const provider: LocalCredentialProvider = {
    bindingResolver,
    async resolve(): Promise<CredentialResolution> {
      if (closed)
        throw new OpenApiMcpError(
          "AUTH_REQUIRED",
          "Credential provider is closed",
        );
      if (pending !== undefined || authorizationPromise !== undefined)
        return startAuthorization();
      const expectedGeneration = generation;
      const keys = tokenKeys(expectedGeneration);
      const access = await safeGet(keys.access);
      if (generation !== expectedGeneration || closed) {
        throw new OpenApiMcpError(
          "AUTH_REQUIRED",
          "Authorization was cancelled",
        );
      }
      if (access !== null && grantId !== undefined && expiresAt > now()) {
        return snapshot(access, expectedGeneration);
      }
      const refreshToken = await safeGet(keys.refresh);
      if (generation !== expectedGeneration || closed) {
        throw new OpenApiMcpError(
          "AUTH_REQUIRED",
          "Authorization was cancelled",
        );
      }
      if (refreshToken !== null && grantId !== undefined) {
        refreshPromise ??= refresh(refreshToken).finally(() => {
          refreshPromise = undefined;
        });
        return refreshPromise;
      }
      return startAuthorization();
    },
    async forget(): Promise<void> {
      const obsoleteGeneration = generation;
      generation += 1;
      grantId = undefined;
      expiresAt = 0;
      liveScopes = Object.freeze([...profile.scopes]);
      if (pending !== undefined) {
        clearTimeout(pending.timer);
        pending.terminal = true;
        closeServer(pending.server);
        pending = undefined;
      }
      await deleteTokens(obsoleteGeneration);
    },
    async close(): Promise<void> {
      const obsoleteGeneration = generation;
      generation += 1;
      closed = true;
      grantId = undefined;
      expiresAt = 0;
      if (pending !== undefined) {
        clearTimeout(pending.timer);
        pending.terminal = true;
        closeServer(pending.server);
        pending = undefined;
      }
      await deleteTokens(obsoleteGeneration);
    },
  };
  return Object.freeze(provider);
}

export async function createCredentialProvider(
  rawProfile: LocalAuthProfile,
  options: CredentialProviderOptions,
): Promise<LocalCredentialProvider> {
  if (!options || !Array.isArray(options.manifestOrigins))
    throw invalidProfile();
  const profile = validateProfile(rawProfile, options.manifestOrigins);
  const profileDigest = await digestCredentialProfile(profile.value);
  const slotsDigest = await digestSlots(profile.slots);
  const bindingResolver = createBindingResolver(profile, profileDigest);
  const randomBytes = options.randomBytes ?? defaultRandom;

  if (profile.auth.type === "oauth2-pkce") {
    return createOAuthProvider(
      profile as ValidatedProfile & {
        readonly auth: Extract<AuthProfile, { type: "oauth2-pkce" }>;
      },
      profileDigest,
      slotsDigest,
      bindingResolver,
      options,
      randomBytes,
    );
  }

  const environmentAuth = profile.auth;
  const environment = options.environment ?? process.env;
  let previousSecret: string | undefined;
  let grantId: string | undefined;
  let generation = 0;
  let closed = false;

  return Object.freeze({
    bindingResolver,
    async resolve(): Promise<CredentialResolution> {
      if (closed)
        throw new OpenApiMcpError(
          "AUTH_REQUIRED",
          "Credential provider is closed",
        );
      const expectedGeneration = generation;
      let secret: string | undefined;
      try {
        secret = environment[environmentAuth.env];
      } catch {
        throw new OpenApiMcpError(
          "AUTH_REQUIRED",
          "Credential is not available",
        );
      }
      if (typeof secret !== "string" || secret.length === 0) {
        throw new OpenApiMcpError(
          "AUTH_REQUIRED",
          "Credential is not available",
        );
      }
      if (secret !== previousSecret || grantId === undefined) {
        previousSecret = secret;
        grantId = randomIdentifier(randomBytes);
      }
      const binding = await createBinding(
        profile,
        profileDigest,
        slotsDigest,
        grantId,
        profile.scopes,
      );
      if (generation !== expectedGeneration || closed) {
        throw new OpenApiMcpError(
          "AUTH_REQUIRED",
          "Authorization was cancelled",
        );
      }
      const credential: Credential =
        environmentAuth.type === "bearer-env"
          ? { type: "bearer", token: secret }
          : {
              type: "api-key",
              placement: environmentAuth.placement,
              name: environmentAuth.name,
              value: secret,
            };
      return {
        status: "ready",
        snapshot: freezeSnapshot(credential, binding),
      };
    },
    async forget(): Promise<void> {
      generation += 1;
      previousSecret = undefined;
      grantId = undefined;
    },
    async close(): Promise<void> {
      generation += 1;
      closed = true;
      previousSecret = undefined;
      grantId = undefined;
    },
  });
}
