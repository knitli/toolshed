import {
  createRequestStateCodec,
  type ServerContext,
} from "@modelcontextprotocol/server";
import type { Sha256, VerifiedActionRequestState } from "../runtime/types.ts";

const digestPattern = /^[0-9a-f]{64}$/;
const idPattern = /^[0-9a-f]{32}$/;

export interface PendingRequestStatePayload {
  readonly version: 1;
  readonly pendingId: string;
  readonly callDigest: Sha256;
  readonly credentialBindingDigest: Sha256;
  readonly expiresAt: number;
}

function decodePayload(value: unknown): PendingRequestStatePayload {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("malformed");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error("malformed");
  }
  const keys = Reflect.ownKeys(value);
  const expected = [
    "callDigest",
    "credentialBindingDigest",
    "expiresAt",
    "pendingId",
    "version",
  ];
  if (
    keys.some((key) => typeof key !== "string") ||
    (keys as string[]).sort().join(",") !== expected.join(",")
  ) {
    throw new Error("malformed");
  }
  const payload: Record<string, unknown> = Object.create(null);
  for (const key of keys as string[]) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable
    ) {
      throw new Error("malformed");
    }
    payload[key] = descriptor.value;
  }
  if (
    payload.version !== 1 ||
    typeof payload.pendingId !== "string" ||
    !idPattern.test(payload.pendingId) ||
    typeof payload.callDigest !== "string" ||
    !digestPattern.test(payload.callDigest) ||
    typeof payload.credentialBindingDigest !== "string" ||
    !digestPattern.test(payload.credentialBindingDigest) ||
    typeof payload.expiresAt !== "number" ||
    !Number.isSafeInteger(payload.expiresAt)
  ) {
    throw new Error("malformed");
  }
  return Object.freeze({
    version: 1,
    pendingId: payload.pendingId,
    callDigest: payload.callDigest as Sha256,
    credentialBindingDigest: payload.credentialBindingDigest as Sha256,
    expiresAt: payload.expiresAt,
  });
}

export function createVerifiedRequestStateCodec(options: {
  readonly key: Uint8Array;
  readonly now: () => number;
  readonly isPending: (payload: PendingRequestStatePayload) => boolean;
}) {
  if (!(options.key instanceof Uint8Array) || options.key.byteLength < 32) {
    throw new RangeError("HMAC key is too short");
  }
  const codec = createRequestStateCodec<PendingRequestStatePayload>({
    key: new Uint8Array(options.key),
    ttlSeconds: 120,
  });
  const registered = new WeakMap<
    VerifiedActionRequestState,
    PendingRequestStatePayload
  >();

  return Object.freeze({
    async mint(payload: PendingRequestStatePayload): Promise<string> {
      return codec.mint(decodePayload(payload));
    },
    async verify(
      state: string,
      context?: ServerContext,
    ): Promise<VerifiedActionRequestState> {
      const decoded = decodePayload(
        await codec.verify(state, context as ServerContext),
      );
      if (options.now() >= decoded.expiresAt || !options.isPending(decoded)) {
        throw new Error("expired");
      }
      const capability = Object.freeze({}) as VerifiedActionRequestState;
      registered.set(capability, decoded);
      return capability;
    },
    read(
      capability: VerifiedActionRequestState,
    ): PendingRequestStatePayload | undefined {
      return registered.get(capability);
    },
  });
}
