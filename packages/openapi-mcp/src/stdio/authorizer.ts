import {
  acceptedContent,
  inputResponse,
  type ServerContext,
} from "@modelcontextprotocol/server";
import { z } from "zod";
import { snapshotCredentialAuthorizationBinding } from "../runtime/credential-binding.ts";
import { OpenApiMcpError } from "../runtime/errors.ts";
import { verifyAndSnapshotPreparedCall } from "../runtime/prepared-call.ts";
import type {
  ActionAuthorizer,
  AuthorizationContext,
  AuthorizationDecision,
  AuthorizationId,
  AuthorizedActionDecision,
  CredentialAuthorizationBinding,
  PreparedCall,
  Sha256,
  VerifiedActionRequestState,
} from "../runtime/types.ts";
import {
  type CompiledExactPolicy,
  matchesExactPolicy,
} from "./exact-policy.ts";
import { renderApproval } from "./render.ts";
import {
  createVerifiedRequestStateCodec,
  type PendingRequestStatePayload,
} from "./request-state.ts";

const PENDING_TTL_MS = 120_000;
const RECEIPT_TTL_MS = 120_000;
const ACTIVATION_TTL_MS = 900_000;
const DEFAULT_LIMITS = Object.freeze({
  pending: 256,
  receipts: 1_024,
  activations: 256,
});
const confirmationSchema = z.object({ confirm: z.literal(true) }).strict();
const activationConfirmationSchema = z
  .object({
    confirm: z.literal(true),
    activatePolicy: z.literal(true),
  })
  .strict();

interface InternalLimits {
  readonly pending: number;
  readonly receipts: number;
  readonly activations: number;
}

export interface AuthorizerTestOptions {
  /** Test seam. Production callers should leave this unset. */
  readonly now?: () => number;
  /** Test seam. Production callers should leave this unset. */
  readonly randomBytes?: (size: number) => Uint8Array;
  /** Test seam; values may only lower the production bounds. */
  readonly limits?: Readonly<Partial<InternalLimits>>;
}

export interface ClientElicitationAuthorizerOptions
  extends AuthorizerTestOptions {
  readonly elicitationAvailable: () => boolean;
}

export interface ExactPolicyAuthorizerOptions extends AuthorizerTestOptions {
  readonly templates: readonly CompiledExactPolicy[];
  readonly elicitationAvailable: () => boolean;
}

export interface StatefulActionAuthorizer extends ActionAuthorizer {
  readonly requestStateVerifier: (
    state: string,
    context?: ServerContext,
  ) => Promise<VerifiedActionRequestState>;
}

interface PendingConfirmation {
  readonly pendingId: string;
  readonly callDigest: Sha256;
  readonly credentialBindingDigest: Sha256;
  readonly expiresAt: number;
  readonly policy?: CompiledExactPolicy;
  readonly activationExpiresAt?: number;
}

interface Receipt {
  readonly randomId: string;
  readonly decision: AuthorizedActionDecision;
  readonly callDigest: Sha256;
  readonly credentialBindingDigest: Sha256;
  readonly path: "per-call" | "exact-policy";
  readonly policyDigest?: Sha256;
  readonly expiresAt: number;
}

interface Activation {
  readonly policyDigest: Sha256;
  readonly credentialBindingDigest: Sha256;
  readonly expiresAt: number;
}

function deny(reason: string): AuthorizationDecision {
  return Object.freeze({ status: "denied", reason });
}

function deniedError(reason = "Action authorization denied"): OpenApiMcpError {
  return new OpenApiMcpError("ACTION_DENIED", reason);
}

function defaultRandom(size: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(size));
}

function normalizeLimits(
  value?: Readonly<Partial<InternalLimits>>,
): InternalLimits {
  const result: { pending: number; receipts: number; activations: number } = {
    ...DEFAULT_LIMITS,
  };
  for (const key of Object.keys(DEFAULT_LIMITS) as (keyof InternalLimits)[]) {
    const proposed = value?.[key];
    if (proposed === undefined) continue;
    if (
      !Number.isSafeInteger(proposed) ||
      proposed < 1 ||
      proposed > DEFAULT_LIMITS[key]
    ) {
      throw new RangeError(`Invalid ${key} authorizer limit`);
    }
    result[key] = proposed;
  }
  return Object.freeze(result);
}

function hexRandom(randomBytes: (size: number) => Uint8Array): string {
  const bytes = randomBytes(16);
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 16) {
    throw new TypeError("Random source returned an invalid byte sequence");
  }
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function exactPayloadMatch(
  payload: PendingRequestStatePayload,
  pending: PendingConfirmation,
): boolean {
  return (
    payload.pendingId === pending.pendingId &&
    payload.callDigest === pending.callDigest &&
    payload.credentialBindingDigest === pending.credentialBindingDigest &&
    payload.expiresAt === pending.expiresAt
  );
}

function credentialMatchesOwnedCall(
  credential: CredentialAuthorizationBinding,
  call: Pick<
    PreparedCall,
    "credentialProfileId" | "credentialProfileDigest" | "reservedSlotsDigest"
  >,
): boolean {
  return (
    credential.profileId === call.credentialProfileId &&
    credential.profileDigest === call.credentialProfileDigest &&
    credential.slotsDigest === call.reservedSlotsDigest
  );
}

function plainResponses(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return undefined;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return undefined;
  return value as Record<string, unknown>;
}

function ownDataValue(object: object, key: PropertyKey): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (
    descriptor === undefined ||
    !("value" in descriptor) ||
    !descriptor.enumerable
  ) {
    throw deniedError();
  }
  return descriptor.value;
}

function snapshotResponseValue(value: unknown, depth = 0): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value !== "object" || Array.isArray(value) || depth >= 3) {
    throw deniedError();
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw deniedError();
  const keys = Reflect.ownKeys(value);
  if (keys.length > 16 || keys.some((key) => typeof key !== "string")) {
    throw deniedError();
  }
  const copy: Record<string, unknown> = Object.create(null);
  for (const key of keys as string[]) {
    copy[key] = snapshotResponseValue(ownDataValue(value, key), depth + 1);
  }
  return Object.freeze(copy);
}

function snapshotContext(context: AuthorizationContext): AuthorizationContext {
  if (
    typeof context !== "object" ||
    context === null ||
    Array.isArray(context)
  ) {
    throw deniedError();
  }
  const prototype = Object.getPrototypeOf(context);
  if (prototype !== Object.prototype && prototype !== null) throw deniedError();
  const keys = Reflect.ownKeys(context);
  if (keys.some((key) => typeof key !== "string")) throw deniedError();
  const kind = ownDataValue(context, "kind");
  if (kind === "initial" && keys.length === 1) {
    return Object.freeze({ kind: "initial" });
  }
  if (
    kind === "resume" &&
    keys.length === 3 &&
    keys.includes("requestState") &&
    keys.includes("inputResponses")
  ) {
    const requestState = ownDataValue(context, "requestState");
    if (typeof requestState !== "object" || requestState === null)
      throw deniedError();
    let inputResponses: unknown;
    try {
      inputResponses = snapshotResponseValue(
        ownDataValue(context, "inputResponses"),
      );
    } catch {
      // Preserve the registered request-state capability so #resume can burn
      // the corresponding pending entry as a terminal malformed response.
      inputResponses = Object.freeze(Object.create(null));
    }
    return Object.freeze({
      kind,
      requestState: requestState as VerifiedActionRequestState,
      inputResponses,
    });
  }
  throw deniedError();
}

class LedgerActionAuthorizer implements StatefulActionAuthorizer {
  readonly requestStateVerifier: (
    state: string,
    context?: ServerContext,
  ) => Promise<VerifiedActionRequestState>;

  readonly #elicitationAvailable: () => boolean;
  readonly #now: () => number;
  readonly #randomBytes: (size: number) => Uint8Array;
  readonly #limits: InternalLimits;
  readonly #policies: readonly CompiledExactPolicy[];
  readonly #pending = new Map<string, PendingConfirmation>();
  readonly #receipts = new Map<AuthorizationId, Receipt>();
  readonly #decisions = new WeakMap<AuthorizedActionDecision, Receipt>();
  readonly #activations = new Map<string, Activation>();
  readonly #requestState: ReturnType<typeof createVerifiedRequestStateCodec>;

  constructor(
    options: ClientElicitationAuthorizerOptions,
    policies: readonly CompiledExactPolicy[] = [],
  ) {
    this.#elicitationAvailable = options.elicitationAvailable;
    this.#now = options.now ?? Date.now;
    this.#randomBytes = options.randomBytes ?? defaultRandom;
    this.#limits = normalizeLimits(options.limits);
    this.#policies = Object.freeze([...policies]);
    const key = this.#randomBytes(32);
    if (!(key instanceof Uint8Array) || key.byteLength !== 32) {
      throw new TypeError("Random source returned an invalid HMAC key");
    }
    this.#requestState = createVerifiedRequestStateCodec({
      key,
      now: this.#now,
      isPending: (payload) => {
        const pending = this.#pending.get(payload.pendingId);
        return pending !== undefined && exactPayloadMatch(payload, pending);
      },
    });
    this.requestStateVerifier = this.#requestState.verify;
    Object.freeze(this);
  }

  async authorize(
    call: PreparedCall,
    credential: CredentialAuthorizationBinding,
    context: AuthorizationContext,
  ): Promise<AuthorizationDecision> {
    let ownedContext: AuthorizationContext | undefined;
    try {
      ownedContext = snapshotContext(context);
      // Each helper takes its caller-owned snapshot synchronously before its
      // first await; starting both before awaiting closes the mutation window.
      const callPromise = verifyAndSnapshotPreparedCall(call);
      const credentialPromise = snapshotCredentialAuthorizationBinding(
        credential,
        call,
      );
      const [ownedCall, ownedCredential] = await Promise.all([
        callPromise,
        credentialPromise,
      ]);
      if (!credentialMatchesOwnedCall(ownedCredential, ownedCall)) {
        throw deniedError();
      }
      const prepared = ownedCall as unknown as PreparedCall;

      // Resume is deliberately handled before active-policy matching. An
      // echoed confirmation can never be bypassed by a newly active policy.
      if (ownedContext.kind === "resume") {
        return await this.#resume(prepared, ownedCredential, ownedContext);
      }

      const now = this.#now();
      this.#prune(now);
      const policy = this.#matchingPolicy(prepared, now);
      if (policy !== undefined) {
        const activationExpiresAt = Math.min(
          policy.template.expiresAt,
          now + ACTIVATION_TTL_MS,
        );
        const activation = this.#activations.get(
          this.#activationKey(
            policy.policyDigest,
            ownedCredential.bindingDigest,
          ),
        );
        if (activation !== undefined && now < activation.expiresAt) {
          return this.#mintReceipt(
            prepared,
            ownedCredential,
            "exact-policy",
            policy.policyDigest,
            Math.min(now + RECEIPT_TTL_MS, activation.expiresAt),
          );
        }
        return await this.#requestConfirmation(
          prepared,
          ownedCredential,
          policy,
          activationExpiresAt,
        );
      }
      return await this.#requestConfirmation(prepared, ownedCredential);
    } catch {
      if (ownedContext?.kind === "resume") {
        const payload = this.#requestState.read(ownedContext.requestState);
        const pending =
          payload === undefined
            ? undefined
            : this.#pending.get(payload.pendingId);
        if (
          payload !== undefined &&
          pending !== undefined &&
          exactPayloadMatch(payload, pending)
        ) {
          this.#pending.delete(payload.pendingId);
        }
      }
      return deny("Action authorization denied");
    }
  }

  consume(
    decision: AuthorizedActionDecision,
    call: PreparedCall,
    credential: CredentialAuthorizationBinding,
  ): Promise<void> {
    const receipt = this.#decisions.get(decision);
    if (
      receipt === undefined ||
      receipt.decision !== decision ||
      this.#receipts.get(decision.authorizationId) !== receipt ||
      this.#now() >= receipt.expiresAt ||
      decision.callDigest !== receipt.callDigest ||
      decision.credentialBindingDigest !== receipt.credentialBindingDigest ||
      decision.path !== receipt.path ||
      decision.policyDigest !== receipt.policyDigest ||
      call.preparedCallDigest !== receipt.callDigest ||
      credential.bindingDigest !== receipt.credentialBindingDigest
    ) {
      return Promise.reject(deniedError());
    }

    // The capability is spent before this method returns a promise and before
    // any integrity verification can yield, so concurrent callers cannot win.
    this.#receipts.delete(decision.authorizationId);
    this.#decisions.delete(decision);
    return Promise.all([
      verifyAndSnapshotPreparedCall(call),
      snapshotCredentialAuthorizationBinding(credential, call),
    ]).then(
      ([verifiedCall, verifiedCredential]) => {
        if (
          verifiedCall.preparedCallDigest !== receipt.callDigest ||
          verifiedCredential.bindingDigest !==
            receipt.credentialBindingDigest ||
          !credentialMatchesOwnedCall(verifiedCredential, verifiedCall)
        ) {
          throw deniedError();
        }
      },
      () => {
        throw deniedError();
      },
    );
  }

  async #resume(
    call: PreparedCall,
    credential: CredentialAuthorizationBinding,
    context: Extract<AuthorizationContext, { kind: "resume" }>,
  ): Promise<AuthorizationDecision> {
    const payload = this.#requestState.read(context.requestState);
    if (payload === undefined) return deny("Invalid confirmation state");
    const pending = this.#pending.get(payload.pendingId);
    if (pending === undefined || !exactPayloadMatch(payload, pending)) {
      return deny("Invalid confirmation state");
    }
    const now = this.#now();
    if (
      now >= pending.expiresAt ||
      call.preparedCallDigest !== pending.callDigest ||
      credential.bindingDigest !== pending.credentialBindingDigest
    ) {
      this.#pending.delete(pending.pendingId);
      return deny("Confirmation expired or no longer matches");
    }

    const responses = plainResponses(context.inputResponses);
    let response: ReturnType<typeof inputResponse>;
    let confirmed = false;
    try {
      response = inputResponse(responses, "confirm");
      if (pending.policy === undefined) {
        confirmed =
          acceptedContent(responses, "confirm", confirmationSchema)?.confirm ===
          true;
      } else {
        const content = acceptedContent(
          responses,
          "confirm",
          activationConfirmationSchema,
        );
        confirmed =
          content?.confirm === true && content.activatePolicy === true;
      }
    } catch {
      this.#pending.delete(pending.pendingId);
      return deny("Malformed confirmation response");
    }
    if (response.kind !== "elicit" || response.action !== "accept") {
      this.#pending.delete(pending.pendingId);
      return deny("Confirmation was not accepted");
    }
    if (!confirmed) {
      this.#pending.delete(pending.pendingId);
      return deny("Malformed confirmation response");
    }

    this.#prune(now);
    const policy = pending.policy;
    const activationExpiresAt = pending.activationExpiresAt;
    if ((policy === undefined) !== (activationExpiresAt === undefined)) {
      this.#pending.delete(pending.pendingId);
      return deny("Invalid confirmation state");
    }
    const activationKey = policy
      ? this.#activationKey(policy.policyDigest, credential.bindingDigest)
      : undefined;
    const newActivation =
      activationKey !== undefined && !this.#activations.has(activationKey);
    if (
      this.#receipts.size >= this.#limits.receipts ||
      (newActivation && this.#activations.size >= this.#limits.activations)
    ) {
      // Capacity denial is retriable and must not spend a valid human answer.
      return deny("Authorization capacity is exhausted");
    }

    let decision: AuthorizedActionDecision;
    try {
      decision = this.#mintReceipt(
        call,
        credential,
        policy ? "exact-policy" : "per-call",
        policy?.policyDigest,
        Math.min(
          now + RECEIPT_TTL_MS,
          activationExpiresAt ?? Number.MAX_SAFE_INTEGER,
        ),
      );
    } catch {
      return deny("Authorization capacity is exhausted");
    }
    if (
      policy !== undefined &&
      activationKey !== undefined &&
      activationExpiresAt !== undefined
    ) {
      this.#activations.set(
        activationKey,
        Object.freeze({
          policyDigest: policy.policyDigest,
          credentialBindingDigest: credential.bindingDigest,
          expiresAt: activationExpiresAt,
        }),
      );
    }
    this.#pending.delete(pending.pendingId);
    return decision;
  }

  async #requestConfirmation(
    call: PreparedCall,
    credential: CredentialAuthorizationBinding,
    policy?: CompiledExactPolicy,
    activationExpiresAt?: number,
  ): Promise<AuthorizationDecision> {
    if (!this.#elicitationAvailable()) {
      return deny("Client elicitation is unavailable");
    }
    const now = this.#now();
    this.#prune(now);
    if (this.#pending.size >= this.#limits.pending) {
      return deny("Authorization capacity is exhausted");
    }
    let pendingId: string | undefined;
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const candidate = hexRandom(this.#randomBytes);
      if (!this.#pending.has(candidate)) {
        pendingId = candidate;
        break;
      }
    }
    if (pendingId === undefined)
      return deny("Authorization identifier collision");
    const expiresAt = now + PENDING_TTL_MS;
    if (policy !== undefined && activationExpiresAt === undefined) {
      return deny("Policy activation is invalid");
    }
    const pending = Object.freeze({
      pendingId,
      callDigest: call.preparedCallDigest,
      credentialBindingDigest: credential.bindingDigest,
      expiresAt,
      ...(policy === undefined ? {} : { policy }),
      ...(activationExpiresAt === undefined ? {} : { activationExpiresAt }),
    });
    const presentation = renderApproval(
      call,
      credential,
      policy === undefined
        ? undefined
        : {
            policyDigest: policy.policyDigest,
            expiresAt: activationExpiresAt as number,
            template: policy.template,
          },
    );
    this.#pending.set(pendingId, pending);
    try {
      const requestState = await this.#requestState.mint({
        version: 1,
        pendingId,
        callDigest: pending.callDigest,
        credentialBindingDigest: pending.credentialBindingDigest,
        expiresAt,
      });
      return Object.freeze({
        status: "input-required",
        presentation,
        requestState,
      });
    } catch {
      if (this.#pending.get(pendingId) === pending) {
        this.#pending.delete(pendingId);
      }
      throw deniedError();
    }
  }

  #matchingPolicy(
    call: PreparedCall,
    now: number,
  ): CompiledExactPolicy | undefined {
    if (
      call.safety !== "action" ||
      (call.actionKind !== "create" && call.actionKind !== "update") ||
      (call.cardinality?.kind !== "single" &&
        call.cardinality?.kind !== "bounded")
    ) {
      return undefined;
    }
    return this.#policies.find((policy) =>
      matchesExactPolicy(policy, call, now),
    );
  }

  #mintReceipt(
    call: PreparedCall,
    credential: CredentialAuthorizationBinding,
    path: "per-call" | "exact-policy",
    policyDigest: Sha256 | undefined,
    expiresAt: number,
  ): AuthorizedActionDecision {
    const now = this.#now();
    this.#prune(now);
    if (now >= expiresAt || this.#receipts.size >= this.#limits.receipts) {
      throw deniedError("Authorization receipt capacity is exhausted");
    }
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const token = hexRandom(this.#randomBytes);
      const authorizationId = Object.freeze(
        Object.create(null) as object,
      ) as AuthorizationId;
      let collision = false;
      for (const existing of this.#receipts.values()) {
        if (existing.randomId === token) {
          collision = true;
          break;
        }
      }
      if (collision) continue;
      const decision = Object.freeze({
        status: "authorized",
        callDigest: call.preparedCallDigest,
        credentialBindingDigest: credential.bindingDigest,
        path,
        authorizationId,
        ...(policyDigest === undefined ? {} : { policyDigest }),
      }) as AuthorizedActionDecision;
      const receipt = Object.freeze({
        randomId: token,
        decision,
        callDigest: decision.callDigest,
        credentialBindingDigest: decision.credentialBindingDigest,
        path,
        ...(policyDigest === undefined ? {} : { policyDigest }),
        expiresAt,
      });
      this.#receipts.set(authorizationId, receipt);
      this.#decisions.set(decision, receipt);
      return decision;
    }
    throw deniedError("Authorization identifier collision");
  }

  #activationKey(policyDigest: Sha256, bindingDigest: Sha256): string {
    return `${policyDigest}\0${bindingDigest}`;
  }

  #prune(now: number): void {
    for (const [id, pending] of this.#pending) {
      if (now >= pending.expiresAt) this.#pending.delete(id);
    }
    for (const [id, receipt] of this.#receipts) {
      if (now >= receipt.expiresAt) {
        this.#receipts.delete(id);
        this.#decisions.delete(receipt.decision);
      }
    }
    for (const [key, activation] of this.#activations) {
      if (now >= activation.expiresAt) this.#activations.delete(key);
    }
  }
}

export function createDenyActionAuthorizer(): ActionAuthorizer {
  return Object.freeze({
    async authorize(): Promise<AuthorizationDecision> {
      return deny("Action authorization is disabled");
    },
    async consume(): Promise<void> {
      throw deniedError("Action authorization is disabled");
    },
  });
}

export function createClientElicitationActionAuthorizer(
  options: ClientElicitationAuthorizerOptions,
): StatefulActionAuthorizer {
  return new LedgerActionAuthorizer(options);
}

export function createExactPolicyActionAuthorizer(
  options: ExactPolicyAuthorizerOptions,
): StatefulActionAuthorizer {
  return new LedgerActionAuthorizer(options, options.templates);
}
