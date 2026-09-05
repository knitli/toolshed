import { expect, test } from "bun:test";
import type {
  Sha256,
  VerifiedActionRequestState,
} from "../src/runtime/types.ts";
import {
  createVerifiedRequestStateCodec,
  type PendingRequestStatePayload,
} from "../src/stdio/request-state.ts";

function fixture(key = new Uint8Array(32).fill(1)) {
  let now = 1_000;
  let pending = true;
  const payload: PendingRequestStatePayload = {
    version: 1,
    pendingId: "a".repeat(32),
    callDigest: "b".repeat(64) as Sha256,
    credentialBindingDigest: "c".repeat(64) as Sha256,
    expiresAt: 2_000,
  };
  const codec = createVerifiedRequestStateCodec({
    key,
    now: () => now,
    isPending: (candidate) =>
      pending && candidate.pendingId === payload.pendingId,
  });
  return {
    codec,
    payload,
    expire: () => {
      now = payload.expiresAt;
    },
    consume: () => {
      pending = false;
    },
  };
}

test("request-state HMAC rejects a modified authenticated body", async () => {
  const { codec, payload } = fixture();
  const state = await codec.mint(payload);
  const separator = state.lastIndexOf(".");
  const index = separator - 1;
  const tampered =
    state.slice(0, index) +
    (state[index] === "A" ? "B" : "A") +
    state.slice(index + 1);
  await expect(codec.verify(tampered)).rejects.toThrow();
  expect(codec.read(await codec.verify(state))).toEqual(payload);
});

test("a fresh process key rejects state signed before restart", async () => {
  const original = fixture();
  const restarted = fixture(new Uint8Array(32).fill(2));
  const state = await original.codec.mint(original.payload);
  await expect(restarted.codec.verify(state)).rejects.toThrow();
});

test("ledger expiry applies even while the SDK wall-clock envelope remains valid", async () => {
  const current = fixture();
  const state = await current.codec.mint(current.payload);
  current.expire();
  await expect(current.codec.verify(state)).rejects.toThrow("expired");
});

test("capabilities require exact identity and registration in this codec", async () => {
  const original = fixture();
  const other = fixture();
  const state = await original.codec.mint(original.payload);
  const capability = await original.codec.verify(state);
  expect(Object.isFrozen(capability)).toBe(true);
  expect(original.codec.read(capability)).toEqual(original.payload);
  expect(
    original.codec.read({ ...capability } as VerifiedActionRequestState),
  ).toBeUndefined();
  expect(
    original.codec.read(
      original.payload as unknown as VerifiedActionRequestState,
    ),
  ).toBeUndefined();
  expect(other.codec.read(capability)).toBeUndefined();
});

test("verification rechecks the pending ledger after an earlier successful verification", async () => {
  const current = fixture();
  const state = await current.codec.mint(current.payload);
  await current.codec.verify(state);
  current.consume();
  await expect(current.codec.verify(state)).rejects.toThrow("expired");
});

test("expiry during asynchronous signature verification cannot register a capability", async () => {
  const current = fixture();
  const state = await current.codec.mint(current.payload);
  const verification = current.codec.verify(state);
  current.expire();
  await expect(verification).rejects.toThrow("expired");
});

test("pending consumption during asynchronous verification rejects the state", async () => {
  const current = fixture();
  const state = await current.codec.mint(current.payload);
  const verification = current.codec.verify(state);
  current.consume();
  await expect(verification).rejects.toThrow("expired");
});
