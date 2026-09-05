import { describe, expect, test } from "bun:test";
import {
  digestCredentialAuthorizationBinding,
  snapshotCredentialAuthorizationBinding,
} from "../src/runtime/credential-binding.ts";
import type {
  CredentialAuthorizationBinding,
  PreparedCall,
  Sha256,
} from "../src/runtime/types.ts";

const digestA = "a".repeat(64) as Sha256;
const digestB = "b".repeat(64) as Sha256;
const digestC = "c".repeat(64) as Sha256;

type BindingPayload = Omit<CredentialAuthorizationBinding, "bindingDigest">;

function payload(overrides: Partial<BindingPayload> = {}): BindingPayload {
  return {
    profileId: "profile",
    profileDigest: digestA,
    grantId: "grant_0123456789abcdef",
    audience: "https://api.example.test",
    scopes: ["write", "read"],
    slotsDigest: digestB,
    ...overrides,
  };
}

async function binding(
  overrides: Partial<BindingPayload> = {},
): Promise<CredentialAuthorizationBinding> {
  const value = payload(overrides);
  return {
    ...value,
    bindingDigest: await digestCredentialAuthorizationBinding(value),
  };
}

function callCommitments(
  overrides: Partial<
    Pick<
      PreparedCall,
      "credentialProfileId" | "credentialProfileDigest" | "reservedSlotsDigest"
    >
  > = {},
): Pick<
  PreparedCall,
  "credentialProfileId" | "credentialProfileDigest" | "reservedSlotsDigest"
> {
  return {
    credentialProfileId: "profile",
    credentialProfileDigest: digestA,
    reservedSlotsDigest: digestB,
    ...overrides,
  };
}

async function expectInvalid(value: unknown): Promise<void> {
  await expect(
    digestCredentialAuthorizationBinding(value as BindingPayload),
  ).rejects.toMatchObject({
    code: "AUTH_PROFILE_INVALID",
    message: "Credential binding is invalid",
  });
}

describe("credential authorization binding", () => {
  test("canonicalizes scope order and returns a detached frozen snapshot", async () => {
    const first = payload({ scopes: ["write", "read"] });
    const second = payload({ scopes: ["read", "write"] });
    expect(await digestCredentialAuthorizationBinding(first)).toBe(
      await digestCredentialAuthorizationBinding(second),
    );

    const owned = await snapshotCredentialAuthorizationBinding(
      await binding(),
      callCommitments(),
    );
    expect(owned.scopes).toEqual(["read", "write"]);
    expect(Object.isFrozen(owned)).toBe(true);
    expect(Object.isFrozen(owned.scopes)).toBe(true);
  });

  test("snapshots binding and call commitments before the digest await", async () => {
    const input = await binding();
    const expectedDigest = input.bindingDigest;
    const commitments = callCommitments();
    const pending = snapshotCredentialAuthorizationBinding(input, commitments);

    (input as unknown as { profileId: string }).profileId = "changed";
    commitments.credentialProfileId = "changed";
    commitments.credentialProfileDigest = digestC;
    commitments.reservedSlotsDigest = digestC;

    const owned = await pending;
    expect(owned.profileId).toBe("profile");
    expect(owned.bindingDigest).toBe(expectedDigest);
  });

  test("rejects altered digests and each prepared-call commitment mismatch", async () => {
    const valid = await binding();
    await expect(
      snapshotCredentialAuthorizationBinding({
        ...valid,
        bindingDigest: digestC,
      }),
    ).rejects.toMatchObject({ code: "AUTH_PROFILE_INVALID" });

    for (const mismatch of [
      { credentialProfileId: "other" },
      { credentialProfileDigest: digestC },
      { reservedSlotsDigest: digestC },
    ]) {
      await expect(
        snapshotCredentialAuthorizationBinding(
          valid,
          callCommitments(mismatch),
        ),
      ).rejects.toMatchObject({
        code: "AUTH_PROFILE_INVALID",
        message: "Credential binding does not match the prepared call",
      });
    }
  });

  test("rejects unknown fields, accessors, proxies, and duplicate scopes", async () => {
    await expectInvalid({ ...payload(), tokenHash: digestC });
    await expectInvalid(payload({ scopes: ["read", "read"] }));

    let getterCalls = 0;
    const accessor = Object.defineProperty(payload(), "profileId", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return "profile";
      },
    });
    await expectInvalid(accessor);
    expect(getterCalls).toBe(0);

    await expectInvalid(
      new Proxy(payload(), {
        ownKeys() {
          throw new Error("must not escape");
        },
      }),
    );
  });

  test("enforces identifiers, text controls, collection, and byte limits", async () => {
    const cases: unknown[] = [
      payload({ profileId: "../profile" }),
      payload({ profileId: "x".repeat(129) }),
      payload({ grantId: "short" }),
      payload({ profileDigest: "A".repeat(64) as Sha256 }),
      payload({ audience: "bad\naudience" }),
      payload({ scopes: ["has space"] }),
      payload({ scopes: Array.from({ length: 65 }, (_, i) => `scope${i}`) }),
      payload({ audience: "x".repeat(16_384) }),
    ];
    for (const value of cases) await expectInvalid(value);
  });
});
