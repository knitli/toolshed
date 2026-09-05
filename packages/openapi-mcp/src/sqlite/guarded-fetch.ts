import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import tls from "node:tls";
import { Client, Dispatcher, fetch, type Response } from "undici";
import type { ActionDispatchPermit } from "../runtime/action-permit.ts";
import { snapshotCredentialAuthorizationBinding } from "../runtime/credential-binding.ts";
import { sha256 } from "../runtime/digest.ts";
import { OpenApiMcpError } from "../runtime/errors.ts";
import {
  snapshotPaginationTokenState,
  verifyAndSnapshotPreparedCall,
} from "../runtime/prepared-call.ts";
import {
  canonicalJsonBounded,
  parseJsonStrict,
} from "../runtime/strict-json.ts";
import type {
  ActionAuthorizer,
  AuthorizedTransport,
  CallOutcome,
  CredentialAuthorizationBinding,
  CredentialSnapshot,
  JsonValue,
  LocalAuthProfile,
  PaginationTokenCodec,
  PaginationTokenState,
  PreparedCall,
  PreparedDispatch,
} from "../runtime/types.ts";
import {
  type RuntimeLimits,
  resolveRuntimeLimits,
} from "../runtime/versions.ts";
import { createActionAuthorizationBoundary } from "../stdio/action-broker.ts";
import { digestCredentialProfile } from "./auth.ts";
import {
  type ApprovedDestination,
  type DestinationGuardOptions,
  NodeDestinationGuard,
} from "./destination-guard.ts";

export interface LocalDispatchOptions {
  readonly profile: LocalAuthProfile;
  /** Host authority must consult verified manifests/current catalog policy. */
  readonly allowsManifestOrigin: (
    context: Readonly<
      Pick<
        PreparedCall,
        "catalogId" | "releaseId" | "manifestDigest" | "origin"
      >
    >,
  ) => boolean | Promise<boolean>;
  readonly lookup?: DestinationGuardOptions["lookup"];
  readonly now?: () => number;
  readonly planTtlMs?: number;
  readonly tokenTtlMs?: number;
  readonly tokenCapacity?: number;
  readonly limits?: Partial<RuntimeLimits>;
}

function denied(): OpenApiMcpError {
  return new OpenApiMcpError(
    "ACTION_DENIED",
    "Dispatch capability is invalid or expired",
  );
}
function invalidCredential(): OpenApiMcpError {
  return new OpenApiMcpError(
    "AUTH_PROFILE_INVALID",
    "Credential snapshot does not match its profile and call",
  );
}
function equal(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.byteLength === b.byteLength && timingSafeEqual(a, b);
}
function canonical(value: unknown): string {
  return canonicalJsonBounded(value as JsonValue, {
    maxBytes: 1024 * 1024,
    maxDepth: 64,
    maxNodes: 100_000,
  });
}
function detach<T>(value: T): T {
  return parseJsonStrict(canonical(value), {
    maxBytes: 1024 * 1024,
    maxDepth: 64,
    maxKeys: 100_000,
  }) as T;
}
function fingerprint(call: PreparedCall): string {
  const { body, normalizedArguments, ...metadata } = call;
  // Keep independently bounded payloads out of the envelope's JSON traversal:
  // raw bytes must not become JSON nodes, nor may metadata consume the admitted
  // arguments' node/depth budget. Named fields and null preserve framing.
  const bodyCommitment =
    body === null
      ? null
      : {
          byteLength: body.byteLength,
          sha256: createHash("sha256").update(body).digest("hex"),
        };
  const argumentCommitment = createHash("sha256")
    .update(canonical(normalizedArguments))
    .digest("hex");
  return createHash("sha256")
    .update("knitli.openapi-mcp.dispatch-fingerprint.v1\0")
    .update(
      canonical({
        ...metadata,
        body: bodyCommitment,
        normalizedArguments: argumentCommitment,
      }),
    )
    .digest("hex");
}

interface PlanState {
  readonly call: PreparedCall;
  readonly fingerprint: string;
  readonly snapshot: CredentialSnapshot;
  readonly destination: ApprovedDestination;
  readonly expiresAt: number;
  readonly pagination: Readonly<PaginationTokenState> | null;
}

// Fetch does not forward an `idempotent` RequestInit field. This private
// dispatcher imposes it at the actual Client boundary on every attempt.
class SingleAttemptDispatcher extends Dispatcher {
  readonly #client: Client;
  constructor(client: Client) {
    super();
    this.#client = client;
  }
  override dispatch(
    options: Dispatcher.DispatchOptions,
    handler: Dispatcher.DispatchHandler,
  ): boolean {
    return this.#client.dispatch({ ...options, idempotent: false }, handler);
  }
}

function upstreamError(): OpenApiMcpError {
  return new OpenApiMcpError("UPSTREAM_ERROR", "Upstream request failed");
}

async function boundedBody(
  response: Response,
  maximum: number,
  limitCode: "RESPONSE_LIMIT_EXCEEDED" | "PAGINATION_LIMIT_EXCEEDED",
): Promise<Uint8Array> {
  const length = response.headers.get("content-length");
  if (
    length !== null &&
    (!/^\d+$/.test(length) ||
      !Number.isSafeInteger(Number(length)) ||
      Number(length) > maximum)
  )
    throw new OpenApiMcpError(limitCode);
  const encodings = (response.headers.get("content-encoding") ?? "identity")
    .split(",")
    .map((value) => value.trim().toLowerCase());
  if (
    encodings.some(
      (value) =>
        !["identity", "gzip", "x-gzip", "deflate", "br", "zstd"].includes(
          value,
        ),
    ) ||
    (encodings.length > 1 && encodings.includes("identity"))
  )
    throw upstreamError();
  const reader = response.body?.getReader();
  if (!reader) return new Uint8Array();
  let size = 0;
  const chunks: Uint8Array[] = [];
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximum) throw new OpenApiMcpError(limitCode);
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  const result = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

function nextLink(header: string | null): string | null {
  if (header === null) return null;
  if (header.length > 8192)
    throw new OpenApiMcpError(
      "INPUT_INVALID",
      "Continuation header is invalid",
    );
  let next: string | null = null;
  for (const part of header.split(/,(?=\s*<)/)) {
    const match = /^\s*<([^<>]*)>\s*(.*)$/.exec(part);
    if (!match)
      throw new OpenApiMcpError(
        "INPUT_INVALID",
        "Continuation header is invalid",
      );
    const rel = /(?:^|;)\s*rel\s*=\s*(?:"([^"]*)"|([^;\s,]+))/i.exec(
      match[2] ?? "",
    );
    if (
      !(rel?.[1] ?? rel?.[2] ?? "").toLowerCase().split(/\s+/).includes("next")
    )
      continue;
    if (next !== null)
      throw new OpenApiMcpError(
        "INPUT_INVALID",
        "Continuation header is ambiguous",
      );
    next = match[1] ?? "";
  }
  return next;
}

/** Only this factory pairs permit issuance with the private HTTP implementation. */
export function createLocalDispatchBoundary(
  authorizer: ActionAuthorizer,
  options: LocalDispatchOptions,
) {
  // Detach host configuration synchronously before digest or DNS awaits.
  const profile = detach(options.profile);
  const allowsManifestOrigin = options.allowsManifestOrigin;
  if (typeof allowsManifestOrigin !== "function")
    throw new OpenApiMcpError(
      "DESTINATION_DENIED",
      "Verified manifest origin policy is required",
    );
  const limits = resolveRuntimeLimits(options.limits);
  const now = options.now ?? Date.now;
  const ttl = options.planTtlMs ?? 30_000;
  const tokenTtl = options.tokenTtlMs ?? 120_000;
  const capacity = options.tokenCapacity ?? 1024;
  if (!Number.isSafeInteger(ttl) || ttl < 1 || ttl > 30_000)
    throw new RangeError("Plan TTL must only lower 30000ms");
  if (
    !Number.isSafeInteger(tokenTtl) ||
    tokenTtl < 1 ||
    tokenTtl > 120_000 ||
    !Number.isSafeInteger(capacity) ||
    capacity < 1 ||
    capacity > 1024
  )
    throw new RangeError("Token bounds must only lower their defaults");
  const guard = new NodeDestinationGuard({
    allowedOrigins: profile.allowedOrigins,
    lookup: options.lookup,
    now,
    ttlMs: Math.min(ttl, limits.requestDeadlineMs),
  });
  const boundary = createActionAuthorizationBoundary(authorizer, { now });
  let plans = new WeakMap<object, PlanState>();
  let closed = false;
  const shutdown = new AbortController();
  const activeClients = new Set<Client>();
  const connectingSockets = new Set<tls.TLSSocket>();
  const tokenKey = randomBytes(32);
  const tokens = new Map<
    string,
    { state: Readonly<PaginationTokenState>; mac: string }
  >();
  const tokenMac = (id: string, tokenState: Readonly<PaginationTokenState>) =>
    createHmac("sha256", tokenKey)
      .update(`knitli.openapi-mcp.page.v1\0${id}\0${canonical(tokenState)}`)
      .digest("base64url");
  const paginationTokenCodec: PaginationTokenCodec = Object.freeze({
    async encode(input: PaginationTokenState): Promise<string> {
      if (closed) throw denied();
      const time = now();
      const tokenState = snapshotPaginationTokenState(
        detach(input),
        limits,
        time,
      );
      if (Date.parse(tokenState.expiresAt) > time + tokenTtl)
        throw new OpenApiMcpError("INPUT_INVALID");
      for (const [key, value] of tokens)
        if (Date.parse(value.state.expiresAt) <= time) tokens.delete(key);
      while (tokens.size >= capacity) {
        const oldest = tokens.keys().next().value;
        if (oldest === undefined) throw new OpenApiMcpError("INPUT_INVALID");
        tokens.delete(oldest);
      }
      const id = randomBytes(24).toString("base64url");
      const mac = tokenMac(id, tokenState);
      tokens.set(id, { state: tokenState, mac });
      return `page.v1.${id}.${mac}`;
    },
    async decode(token: string): Promise<PaginationTokenState> {
      if (closed) throw denied();
      if (
        typeof token !== "string" ||
        !/^page\.v1\.[A-Za-z0-9_-]{32}\.[A-Za-z0-9_-]{43}$/.test(token)
      )
        throw new OpenApiMcpError("INPUT_INVALID");
      const [, , id = "", mac = ""] = token.split(".");
      const entry = tokens.get(id);
      if (
        !entry ||
        !equal(entry.mac, mac) ||
        !equal(tokenMac(id, entry.state), mac)
      )
        throw new OpenApiMcpError("INPUT_INVALID");
      try {
        return snapshotPaginationTokenState(entry.state, limits, now());
      } catch (error) {
        tokens.delete(id);
        throw error;
      }
    },
  });

  function state(plan: PreparedDispatch): PlanState {
    if (closed) throw denied();
    const value =
      typeof plan === "object" && plan !== null ? plans.get(plan) : undefined;
    const time = now();
    if (!value || !Number.isFinite(time) || time >= value.expiresAt)
      throw denied();
    return value;
  }

  async function authorizeDestination(
    call: PreparedCall,
    url: URL,
    signal: AbortSignal,
  ): Promise<ApprovedDestination> {
    if (closed) throw denied();
    const context = Object.freeze({
      catalogId: call.catalogId,
      releaseId: call.releaseId,
      manifestDigest: call.manifestDigest,
      origin: url.origin,
    });
    try {
      if (
        (await withDeadline(
          Promise.resolve(allowsManifestOrigin(context)),
          signal,
        )) !== true
      )
        throw new Error();
    } catch {
      throw new OpenApiMcpError(
        "DESTINATION_DENIED",
        "Verified manifest origin policy denied the destination",
      );
    }
    if (closed) throw denied();
    return guard.authorize(url, signal);
  }

  const transport: AuthorizedTransport = Object.freeze({
    async prepareDispatch(
      untrustedCall: PreparedCall,
      untrustedSnapshot: CredentialSnapshot,
    ): Promise<PreparedDispatch> {
      if (closed) throw denied();
      const signal = AbortSignal.any([
        shutdown.signal,
        AbortSignal.timeout(limits.requestDeadlineMs),
      ]);
      let snapshot: CredentialSnapshot;
      try {
        snapshot = detach(untrustedSnapshot);
      } catch {
        throw invalidCredential();
      }
      const call = await verifyAndSnapshotPreparedCall(untrustedCall);
      if (["GET", "HEAD"].includes(call.method) && call.body !== null)
        throw new OpenApiMcpError(
          "INPUT_INVALID",
          "The local HTTP adapter does not support GET or HEAD request bodies",
        );
      const binding = await snapshotCredentialAuthorizationBinding(
        snapshot.binding,
      );
      const profileDigest = await digestCredentialProfile(profile);
      const credential = snapshot.credential;
      const auth = profile.auth;
      let slot: { placement: "header" | "query"; name: string };
      if (auth.type === "api-key-env") {
        if (
          credential.type !== "api-key" ||
          credential.placement !== auth.placement ||
          credential.name !== auth.name
        )
          throw invalidCredential();
        slot = {
          placement: credential.placement,
          name:
            credential.placement === "header"
              ? credential.name.toLowerCase()
              : credential.name,
        };
      } else {
        if (credential.type !== "bearer") throw invalidCredential();
        slot = { placement: "header", name: "authorization" };
      }
      const secret =
        credential.type === "bearer" ? credential.token : credential.value;
      const expectedKeys =
        credential.type === "bearer"
          ? ["token", "type"]
          : ["name", "placement", "type", "value"];
      if (
        Object.keys(snapshot).sort().join() !== "binding,credential" ||
        Object.keys(credential).sort().join() !== expectedKeys.join() ||
        typeof secret !== "string" ||
        secret.length < 1 ||
        secret.length > 16_384 ||
        Array.from(secret).some(
          (character) =>
            character.charCodeAt(0) <= 32 || character.charCodeAt(0) === 127,
        )
      )
        throw invalidCredential();
      const slotsDigest = await sha256(
        "knitli.openapi-mcp.credential-slots.v1",
        [slot],
      );
      const configuredScopes = [
        ...(auth.type === "oauth2-pkce" ? auth.scopes : (profile.scopes ?? [])),
      ].sort();
      const audience =
        profile.audience ??
        (auth.type === "oauth2-pkce" ? auth.resource : undefined);
      if (
        !equal(profile.profileId, binding.profileId) ||
        !equal(profileDigest, binding.profileDigest) ||
        !equal(call.credentialProfileId, binding.profileId) ||
        !equal(call.credentialProfileDigest, binding.profileDigest) ||
        !equal(call.reservedSlotsDigest, slotsDigest) ||
        !equal(binding.slotsDigest, slotsDigest) ||
        audience !== binding.audience ||
        binding.scopes.some((scope) => !configuredScopes.includes(scope)) ||
        (auth.type !== "oauth2-pkce" &&
          configuredScopes.join("\0") !== binding.scopes.join("\0"))
      )
        throw invalidCredential();
      const url = new URL(call.relativeUrl, call.origin);
      const pagination =
        call.pageToken === null
          ? null
          : await paginationTokenCodec.decode(call.pageToken);
      if (
        pagination &&
        (pagination.catalogId !== call.catalogId ||
          pagination.releaseId !== call.releaseId ||
          pagination.operationId !== call.operationId ||
          pagination.origin !== call.origin ||
          pagination.nextRelativeUrl !== call.relativeUrl ||
          !equal(pagination.manifestDigest, call.manifestDigest) ||
          !equal(pagination.inputDigest, call.inputDigest))
      )
        throw new OpenApiMcpError("INPUT_INVALID");
      if (
        (slot.placement === "query" &&
          [...url.searchParams.keys()].some(
            (key) => key.toLowerCase() === slot.name.toLowerCase(),
          )) ||
        (slot.placement === "header" &&
          Object.keys(call.headers).some(
            (key) => key.toLowerCase() === slot.name.toLowerCase(),
          ))
      )
        throw invalidCredential();
      const destination = await authorizeDestination(call, url, signal);
      if (closed) throw denied();
      const plan = Object.freeze(Object.create(null)) as PreparedDispatch;
      plans.set(plan, {
        call,
        fingerprint: fingerprint(call),
        snapshot: { credential, binding },
        destination,
        pagination,
        expiresAt: Math.min(
          destination.expiresAt,
          now() + ttl,
          pagination ? Date.parse(pagination.expiresAt) : Infinity,
        ),
      });
      return plan;
    },
    verifyPlan(
      plan: PreparedDispatch,
      call: PreparedCall,
      binding: CredentialAuthorizationBinding,
    ): void {
      try {
        const value = state(plan);
        if (
          !equal(value.fingerprint, fingerprint(call)) ||
          !equal(canonical(value.snapshot.binding), canonical(binding))
        )
          throw denied();
      } catch {
        throw denied();
      }
    },
    async dispatchRead(plan: PreparedDispatch): Promise<CallOutcome> {
      const value = state(plan);
      if (
        value.call.safety !== "read" ||
        !["GET", "HEAD", "OPTIONS"].includes(value.call.method)
      )
        throw denied();
      plans.delete(plan);
      return dispatch(value);
    },
    async dispatchAction(
      plan: PreparedDispatch,
      permit: ActionDispatchPermit,
    ): Promise<CallOutcome> {
      const value = state(plan);
      if (value.call.safety !== "action") throw denied();
      boundary.permits.consume(
        permit,
        value.call.preparedCallDigest,
        value.snapshot.binding.bindingDigest,
      );
      plans.delete(plan);
      return dispatch(value);
    },
  });
  async function dispatch(value: PlanState): Promise<CallOutcome> {
    const { call, snapshot } = value;
    const deadline = Date.now() + limits.requestDeadlineMs;
    const signal = AbortSignal.any([
      shutdown.signal,
      AbortSignal.timeout(limits.requestDeadlineMs),
    ]);
    let destination = value.destination;
    let url = new URL(call.relativeUrl, call.origin);
    let retries = 0;
    let redirects = 0;
    let actionConnectionBegan = false;
    const readEligible =
      call.safety === "read" &&
      ["GET", "HEAD", "OPTIONS"].includes(call.method);
    for (;;) {
      let connectionBegan = false;
      let positivelyPreConnect = false;
      let client: Client | undefined;
      let response: Response | undefined;
      let retryWait: number | undefined;
      try {
        signal.throwIfAborted();
        if (now() >= destination.expiresAt)
          throw new OpenApiMcpError("DESTINATION_DENIED");
        const remaining = deadline - Date.now();
        if (remaining <= 0) throw upstreamError();
        client = new Client(url.origin, {
          allowH2: false,
          pipelining: 0,
          connect(options, callback) {
            connectionBegan = true;
            if (call.safety === "action") actionConnectionBegan = true;
            // Observe TCP establishment directly: a TLS failure happens after
            // TCP connect and must never be reported as safe action failure.
            let connected = false;
            const connectOptions: tls.ConnectionOptions & {
              autoSelectFamily: boolean;
            } = {
              host: options.hostname,
              servername: options.servername || options.hostname,
              port: Number(options.port) || 443,
              lookup: destination.lookup,
              autoSelectFamily: false,
              rejectUnauthorized: true,
              ALPNProtocols: ["http/1.1"],
            };
            const socket = tls.connect(connectOptions);
            connectingSockets.add(socket);
            socket.once("close", () => connectingSockets.delete(socket));
            const timeout = setTimeout(
              () => socket.destroy(upstreamError()),
              remaining,
            );
            socket.once("connect", () => {
              connected = true;
            });
            const failed = (error: Error) => {
              clearTimeout(timeout);
              if (
                !connected &&
                ["ECONNREFUSED", "ENETUNREACH", "EHOSTUNREACH"].includes(
                  (error as NodeJS.ErrnoException).code ?? "",
                )
              ) {
                positivelyPreConnect = true;
                actionConnectionBegan = false;
              }
              callback(error, null);
            };
            socket.once("error", failed);
            socket.once("secureConnect", () => {
              clearTimeout(timeout);
              connectingSockets.delete(socket);
              socket.removeListener("error", failed);
              callback(null, socket);
            });
          },
        });
        activeClients.add(client);
        const requestUrl = new URL(url);
        const headers = { ...call.headers };
        const credential = snapshot.credential;
        if (credential.type === "bearer")
          headers.authorization = `Bearer ${credential.token}`;
        else if (credential.placement === "header")
          headers[credential.name] = credential.value;
        else requestUrl.searchParams.set(credential.name, credential.value);
        response = await fetch(requestUrl, {
          method: call.method,
          headers,
          body: call.body,
          redirect: "manual",
          dispatcher: new SingleAttemptDispatcher(client),
          signal,
        });
        if ([301, 302, 303, 307, 308].includes(response.status)) {
          const location = response.headers.get("location");
          if (
            call.safety === "action" ||
            !location ||
            location.length > 8192 ||
            redirects >= limits.maxRedirects
          )
            return { kind: "redirect-blocked", location: null };
          let next: URL;
          try {
            next = new URL(location, url);
          } catch {
            return { kind: "redirect-blocked", location: null };
          }
          if (
            next.origin !== call.origin ||
            next.protocol !== "https:" ||
            next.username ||
            next.password ||
            next.hash
          )
            return { kind: "redirect-blocked", location: null };
          if (
            credential.type === "api-key" &&
            credential.placement === "query" &&
            [...next.searchParams.keys()].some(
              (key) => key.toLowerCase() === credential.name.toLowerCase(),
            )
          )
            return { kind: "redirect-blocked", location: null };
          redirects++;
          destination = await authorizeDestination(call, next, signal);
          url = next;
          continue;
        }
        if (
          readEligible &&
          retries < 2 &&
          [429, 502, 503, 504].includes(response.status)
        ) {
          const after = response.headers.get("retry-after");
          const wait =
            after === null
              ? 0
              : /^\d+$/.test(after)
                ? Number(after) * 1000
                : Date.parse(after) - Date.now();
          if (
            Number.isFinite(wait) &&
            Math.max(0, wait) < deadline - Date.now()
          )
            retryWait = Math.max(0, wait);
        }
        if (retryWait === undefined) {
          if (response.status === 304) return { kind: "not-modified" };
          const paginationRemaining =
            limits.maxPaginationBytes -
            (value.pagination?.cumulativeBytes ?? 0);
          const maximum = Math.min(
            limits.maxResponseBytes,
            paginationRemaining,
          );
          const body =
            call.method === "HEAD"
              ? new Uint8Array()
              : await boundedBody(
                  response,
                  maximum,
                  paginationRemaining < limits.maxResponseBytes
                    ? "PAGINATION_LIMIT_EXCEEDED"
                    : "RESPONSE_LIMIT_EXCEEDED",
                );
          let pageToken: string | undefined;
          const link =
            call.safety === "read"
              ? nextLink(response.headers.get("link"))
              : null;
          if (link !== null) {
            const next = new URL(link, url);
            if (
              next.origin !== call.origin ||
              next.username ||
              next.password ||
              next.hash
            )
              throw new OpenApiMcpError("DESTINATION_DENIED");
            if (
              credential.type === "api-key" &&
              credential.placement === "query" &&
              [...next.searchParams.keys()].some(
                (key) => key.toLowerCase() === credential.name.toLowerCase(),
              )
            )
              throw new OpenApiMcpError("INPUT_INVALID");
            await authorizeDestination(call, next, signal);
            pageToken = await paginationTokenCodec.encode({
              catalogId: call.catalogId,
              releaseId: call.releaseId,
              manifestDigest: call.manifestDigest,
              operationId: call.operationId,
              inputDigest: call.inputDigest,
              origin: call.origin,
              nextRelativeUrl: `${next.pathname}${next.search}`,
              expiresAt: new Date(now() + tokenTtl).toISOString(),
              pageCount: (value.pagination?.pageCount ?? 0) + 1,
              cumulativeBytes:
                (value.pagination?.cumulativeBytes ?? 0) + body.byteLength,
            });
          }
          // A small allowlist excludes cookies, Location, and Link, which can
          // contain authenticated URLs. Pagination is carried only by tokens.
          const safeHeaders: Record<string, string> = {};
          for (const name of ["content-type", "etag", "last-modified"]) {
            const header = response.headers.get(name);
            if (header !== null && header.length <= 4096)
              safeHeaders[name] = header;
          }
          return {
            kind: "success",
            statusCode: response.status,
            headers: safeHeaders,
            body,
            ...(pageToken === undefined ? {} : { pageToken }),
          };
        }
      } catch (error) {
        if (call.safety === "action" && actionConnectionBegan)
          throw new OpenApiMcpError(
            "UPSTREAM_OUTCOME_UNKNOWN",
            "Upstream action outcome is unknown",
            { details: { preparedCallDigest: call.preparedCallDigest } },
          );
        if (
          readEligible &&
          (!connectionBegan || positivelyPreConnect) &&
          retries < 2 &&
          !signal.aborted &&
          !(error instanceof OpenApiMcpError)
        )
          retryWait = 0;
        else if (error instanceof OpenApiMcpError) throw error;
        else throw upstreamError();
      } finally {
        await response?.body?.cancel().catch(() => {});
        await client?.destroy().catch(() => {});
        if (client) activeClients.delete(client);
      }
      if (retryWait !== undefined) {
        retries++;
        try {
          await delay(retryWait, undefined, { signal });
        } catch {
          throw upstreamError();
        }
      }
    }
  }
  async function close(): Promise<void> {
    closed = true;
    plans = new WeakMap();
    tokens.clear();
    tokenKey.fill(0);
    shutdown.abort();
    for (const socket of connectingSockets) socket.destroy(upstreamError());
    await Promise.allSettled(
      [...activeClients].map((client) => client.destroy()),
    );
  }
  return Object.freeze({
    broker: boundary.broker,
    transport,
    paginationTokenCodec,
    close,
  });
}

async function withDeadline<T>(
  operation: Promise<T>,
  signal: AbortSignal,
): Promise<T> {
  signal.throwIfAborted();
  let abort: () => void = () => {};
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_, reject) => {
        abort = () => reject(upstreamError());
        signal.addEventListener("abort", abort, { once: true });
      }),
    ]);
  } finally {
    signal.removeEventListener("abort", abort);
  }
}
