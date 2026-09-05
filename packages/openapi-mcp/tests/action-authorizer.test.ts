import { describe, expect, test } from "bun:test";
import { digestCredentialAuthorizationBinding } from "../src/runtime/credential-binding.ts";
import { createPreparedCall } from "../src/runtime/prepared-call.ts";
import type {
  AuthorizationContext,
  CredentialAuthorizationBinding,
  PreparedCall,
  Sha256,
  VerifiedActionRequestState,
} from "../src/runtime/types.ts";
import {
  createClientElicitationActionAuthorizer,
  createDenyActionAuthorizer,
  createExactPolicyActionAuthorizer,
} from "../src/stdio/authorizer.ts";
import {
  compileExactPolicy,
  type ExactPolicyTemplate,
} from "../src/stdio/exact-policy.ts";
import { createVerifiedRequestStateCodec } from "../src/stdio/request-state.ts";

const digestA = "a".repeat(64) as Sha256;
const digestB = "b".repeat(64) as Sha256;
const digestC = "c".repeat(64) as Sha256;

async function call(
  overrides: Partial<PreparedCall> = {},
): Promise<PreparedCall> {
  return createPreparedCall({
    version: 2,
    pageToken: null,
    catalogId: "catalog" as PreparedCall["catalogId"],
    releaseId: "release" as PreparedCall["releaseId"],
    operationId: "operation:api:createWidget",
    operationDigest: digestB,
    manifestDigest: digestA,
    credentialProfileId: "profile",
    credentialProfileDigest: digestC,
    reservedSlotsDigest: digestA,
    method: "POST",
    origin: "https://api.example.test",
    relativeUrl: "/widgets",
    headers: {},
    body: null,
    normalizedArguments: { body: { count: 2 } },
    safety: "action",
    actionKind: "create",
    cardinality: { kind: "single" },
    ...overrides,
  });
}

async function binding(
  overrides: Partial<CredentialAuthorizationBinding> = {},
): Promise<CredentialAuthorizationBinding> {
  const value = {
    profileId: "profile",
    profileDigest: digestC,
    grantId: "grant_identifier_1",
    audience: "https://api.example.test",
    scopes: ["widgets.write"],
    slotsDigest: digestA,
    ...overrides,
  };
  const { bindingDigest: _ignored, ...payload } =
    value as CredentialAuthorizationBinding;
  return Object.freeze({
    ...payload,
    scopes: Object.freeze([...payload.scopes]),
    bindingDigest: await digestCredentialAuthorizationBinding(payload),
  });
}

function accepted(): Record<string, unknown> {
  return { confirm: { action: "accept", content: { confirm: true } } };
}

function acceptedActivation(): Record<string, unknown> {
  return {
    confirm: {
      action: "accept",
      content: { confirm: true, activatePolicy: true },
    },
  };
}

function deterministicRandom() {
  let next = 0;
  return (size: number): Uint8Array => {
    const bytes = new Uint8Array(size);
    bytes.fill(++next);
    return bytes;
  };
}

async function resumeContext(
  authorizer: ReturnType<typeof createClientElicitationActionAuthorizer>,
  requestState: string,
  inputResponses: unknown = accepted(),
): Promise<AuthorizationContext> {
  return {
    kind: "resume",
    requestState: await authorizer.requestStateVerifier(requestState),
    inputResponses,
  };
}

describe("action authorizers", () => {
  test("default authorizer denies authorize and consume", async () => {
    const authorizer = createDenyActionAuthorizer();
    const prepared = await call();
    const credential = await binding();
    expect(
      await authorizer.authorize(prepared, credential, { kind: "initial" }),
    ).toEqual({
      status: "denied",
      reason: "Action authorization is disabled",
    });
    await expect(
      authorizer.consume({} as never, prepared, credential),
    ).rejects.toMatchObject({ code: "ACTION_DENIED" });
  });

  test("uses a two-entry confirmation and atomically consumes its receipt", async () => {
    const authorizer = createClientElicitationActionAuthorizer({
      elicitationAvailable: () => true,
      randomBytes: deterministicRandom(),
    });
    const prepared = await call();
    const credential = await binding();
    const first = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    expect(first.status).toBe("input-required");
    if (first.status !== "input-required")
      throw new Error("expected input-required");

    const decision = await authorizer.authorize(
      prepared,
      credential,
      await resumeContext(authorizer, first.requestState),
    );
    expect(decision).toMatchObject({
      status: "authorized",
      path: "per-call",
      callDigest: prepared.preparedCallDigest,
      credentialBindingDigest: credential.bindingDigest,
    });
    if (decision.status !== "authorized")
      throw new Error("expected authorized");
    expect(Object.isFrozen(decision)).toBe(true);
    expect(Object.isFrozen(decision.authorizationId)).toBe(true);
    await expect(
      authorizer.consume(decision, prepared, credential),
    ).resolves.toBeUndefined();
    await expect(
      authorizer.consume(decision, prepared, credential),
    ).rejects.toMatchObject({
      code: "ACTION_DENIED",
    });
  });

  test("replay, decline, malformed acceptance, and opaque-state forgery deny", async () => {
    const authorizer = createClientElicitationActionAuthorizer({
      elicitationAvailable: () => true,
      randomBytes: deterministicRandom(),
    });
    const prepared = await call();
    const credential = await binding();
    const first = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    if (first.status !== "input-required")
      throw new Error("expected input-required");
    const context = await resumeContext(authorizer, first.requestState);
    expect(
      (await authorizer.authorize(prepared, credential, context)).status,
    ).toBe("authorized");
    expect(
      (await authorizer.authorize(prepared, credential, context)).status,
    ).toBe("denied");

    const declined = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    if (declined.status !== "input-required")
      throw new Error("expected input-required");
    expect(
      (
        await authorizer.authorize(
          prepared,
          credential,
          await resumeContext(authorizer, declined.requestState, {
            confirm: { action: "decline" },
          }),
        )
      ).status,
    ).toBe("denied");

    const malformed = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    if (malformed.status !== "input-required")
      throw new Error("expected input-required");
    expect(
      (
        await authorizer.authorize(
          prepared,
          credential,
          await resumeContext(authorizer, malformed.requestState, {
            confirm: { action: "accept", content: { confirm: "yes" } },
          }),
        )
      ).status,
    ).toBe("denied");

    expect(
      (
        await authorizer.authorize(prepared, credential, {
          kind: "resume",
          requestState: Object.freeze({}) as VerifiedActionRequestState,
          inputResponses: accepted(),
        })
      ).status,
    ).toBe("denied");
  });

  test("cancel is a terminal denial that consumes pending state", async () => {
    const authorizer = createClientElicitationActionAuthorizer({
      elicitationAvailable: () => true,
      randomBytes: deterministicRandom(),
    });
    const prepared = await call();
    const credential = await binding();
    const first = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    if (first.status !== "input-required") throw new Error();
    const state = await authorizer.requestStateVerifier(first.requestState);
    expect(
      (
        await authorizer.authorize(prepared, credential, {
          kind: "resume",
          requestState: state,
          inputResponses: { confirm: { action: "cancel" } },
        })
      ).status,
    ).toBe("denied");
    expect(
      (
        await authorizer.authorize(prepared, credential, {
          kind: "resume",
          requestState: state,
          inputResponses: accepted(),
        })
      ).status,
    ).toBe("denied");
  });

  test("a stale verified state cannot delete a reused pending identifier", async () => {
    let now = 1_000;
    const authorizer = createClientElicitationActionAuthorizer({
      elicitationAvailable: () => true,
      now: () => now,
      randomBytes: (size) => new Uint8Array(size).fill(9),
      limits: { pending: 1 },
    });
    const prepared = await call();
    const credential = await binding();
    const stale = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    if (stale.status !== "input-required") throw new Error();
    const staleCapability = await authorizer.requestStateVerifier(
      stale.requestState,
    );
    now += 120_000;
    expect(
      (await authorizer.authorize(prepared, credential, { kind: "initial" }))
        .status,
    ).toBe("input-required");
    expect(
      (
        await authorizer.authorize(
          { ...prepared, normalizedArguments: { changed: true } },
          credential,
          {
            kind: "resume",
            requestState: staleCapability,
            inputResponses: accepted(),
          },
        )
      ).status,
    ).toBe("denied");
    expect(
      (await authorizer.authorize(prepared, credential, { kind: "initial" }))
        .status,
    ).toBe("denied");
  });

  test("changed call or credential across entries consumes pending state and denies", async () => {
    const authorizer = createClientElicitationActionAuthorizer({
      elicitationAvailable: () => true,
      randomBytes: deterministicRandom(),
    });
    const original = await call();
    const changed = await call({ normalizedArguments: { body: { count: 3 } } });
    const credential = await binding();
    const first = await authorizer.authorize(original, credential, {
      kind: "initial",
    });
    if (first.status !== "input-required")
      throw new Error("expected input-required");
    const context = await resumeContext(authorizer, first.requestState);
    expect(
      (await authorizer.authorize(changed, credential, context)).status,
    ).toBe("denied");
    expect(
      (await authorizer.authorize(original, credential, context)).status,
    ).toBe("denied");

    const second = await authorizer.authorize(original, credential, {
      kind: "initial",
    });
    if (second.status !== "input-required")
      throw new Error("expected input-required");
    const changedCredential = await binding({ grantId: "different_grant_1" });
    const credentialContext = await resumeContext(
      authorizer,
      second.requestState,
    );
    expect(
      (
        await authorizer.authorize(
          original,
          changedCredential,
          credentialContext,
        )
      ).status,
    ).toBe("denied");
    expect(
      (await authorizer.authorize(original, credential, credentialContext))
        .status,
    ).toBe("denied");
  });

  test("rejects divergent descriptor and getter views before reserving authorization state", async () => {
    let elicitationChecks = 0;
    const authorizer = createClientElicitationActionAuthorizer({
      elicitationAvailable: () => {
        elicitationChecks += 1;
        return true;
      },
      randomBytes: deterministicRandom(),
      limits: { pending: 1 },
    });
    const prepared = await call();
    const alternateProfileDigest = "d".repeat(64) as Sha256;
    const alternateSlotsDigest = "e".repeat(64) as Sha256;
    const alternateCredential = await binding({
      profileId: "alternate-profile",
      profileDigest: alternateProfileDigest,
      slotsDigest: alternateSlotsDigest,
    });
    const divergent = new Proxy(
      { ...prepared },
      {
        get(target, property, receiver) {
          if (property === "credentialProfileId") return "alternate-profile";
          if (property === "credentialProfileDigest")
            return alternateProfileDigest;
          if (property === "reservedSlotsDigest") return alternateSlotsDigest;
          return Reflect.get(target, property, receiver);
        },
      },
    );

    expect(
      (
        await authorizer.authorize(divergent, alternateCredential, {
          kind: "initial",
        })
      ).status,
    ).toBe("denied");
    expect(elicitationChecks).toBe(0);
    expect(
      (
        await authorizer.authorize(prepared, await binding(), {
          kind: "initial",
        })
      ).status,
    ).toBe("input-required");
    expect(elicitationChecks).toBe(1);

    const policyAuthorizer = createExactPolicyActionAuthorizer({
      templates: [await compileExactPolicy(policyTemplate(prepared))],
      elicitationAvailable: () => true,
      randomBytes: deterministicRandom(),
    });
    expect(
      (
        await policyAuthorizer.authorize(divergent, alternateCredential, {
          kind: "initial",
        })
      ).status,
    ).toBe("denied");
    expect(
      (
        await policyAuthorizer.authorize(prepared, await binding(), {
          kind: "initial",
        })
      ).status,
    ).toBe("input-required");
  });

  test("ledger clock expiration and tampered HMAC state deny", async () => {
    let now = 1_000;
    const authorizer = createClientElicitationActionAuthorizer({
      elicitationAvailable: () => true,
      now: () => now,
      randomBytes: deterministicRandom(),
    });
    const prepared = await call();
    const credential = await binding();
    const first = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    if (first.status !== "input-required")
      throw new Error("expected input-required");
    const macStart = first.requestState.lastIndexOf(".") + 1;
    const replacement = first.requestState[macStart] === "A" ? "B" : "A";
    await expect(
      authorizer.requestStateVerifier(
        `${first.requestState.slice(0, macStart)}${replacement}${first.requestState.slice(macStart + 1)}`,
      ),
    ).rejects.toThrow();
    now += 120_000;
    await expect(
      authorizer.requestStateVerifier(first.requestState),
    ).rejects.toThrow();
  });

  test("pending capacity rejects without evicting a live confirmation", async () => {
    const authorizer = createClientElicitationActionAuthorizer({
      elicitationAvailable: () => true,
      randomBytes: deterministicRandom(),
      limits: { pending: 1 },
    });
    const prepared = await call();
    const credential = await binding();
    const first = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    expect(first.status).toBe("input-required");
    expect(
      (await authorizer.authorize(prepared, credential, { kind: "initial" }))
        .status,
    ).toBe("denied");
    if (first.status !== "input-required")
      throw new Error("expected input-required");
    expect(
      (
        await authorizer.authorize(
          prepared,
          credential,
          await resumeContext(authorizer, first.requestState),
        )
      ).status,
    ).toBe("authorized");
  });

  test("missing elicitation capability denies without minting state", async () => {
    const authorizer = createClientElicitationActionAuthorizer({
      elicitationAvailable: () => false,
    });
    expect(
      (
        await authorizer.authorize(await call(), await binding(), {
          kind: "initial",
        })
      ).status,
    ).toBe("denied");
  });

  test("expired entries are pruned before pending and receipt capacity checks", async () => {
    let now = 1_000;
    const authorizer = createClientElicitationActionAuthorizer({
      elicitationAvailable: () => true,
      now: () => now,
      randomBytes: deterministicRandom(),
      limits: { pending: 1, receipts: 1 },
    });
    const prepared = await call();
    const credential = await binding();
    const abandoned = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    expect(abandoned.status).toBe("input-required");
    now += 120_000;
    const first = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    if (first.status !== "input-required")
      throw new Error("expected input-required");
    const staleReceipt = await authorizer.authorize(
      prepared,
      credential,
      await resumeContext(authorizer, first.requestState),
    );
    expect(staleReceipt.status).toBe("authorized");
    now += 120_000;
    const next = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    if (next.status !== "input-required")
      throw new Error("expected input-required");
    expect(
      (
        await authorizer.authorize(
          prepared,
          credential,
          await resumeContext(authorizer, next.requestState),
        )
      ).status,
    ).toBe("authorized");
  });

  test("receipt exhaustion preserves an accepted pending confirmation", async () => {
    const authorizer = createClientElicitationActionAuthorizer({
      elicitationAvailable: () => true,
      randomBytes: deterministicRandom(),
      limits: { receipts: 1 },
    });
    const prepared = await call();
    const credential = await binding();
    const first = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    if (first.status !== "input-required") throw new Error();
    const occupying = await authorizer.authorize(
      prepared,
      credential,
      await resumeContext(authorizer, first.requestState),
    );
    if (occupying.status !== "authorized") throw new Error();
    const second = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    if (second.status !== "input-required") throw new Error();
    const state = await authorizer.requestStateVerifier(second.requestState);
    const context = {
      kind: "resume",
      requestState: state,
      inputResponses: accepted(),
    } as const;
    expect(
      (await authorizer.authorize(prepared, credential, context)).status,
    ).toBe("denied");
    await authorizer.consume(occupying, prepared, credential);
    expect(
      (await authorizer.authorize(prepared, credential, context)).status,
    ).toBe("authorized");
  });

  test("lower-only limits and repeated random collisions fail closed", async () => {
    expect(() =>
      createClientElicitationActionAuthorizer({
        elicitationAvailable: () => true,
        limits: { pending: 257 },
      }),
    ).toThrow(RangeError);
    expect(() =>
      createClientElicitationActionAuthorizer({
        elicitationAvailable: () => true,
        limits: { receipts: 0 },
      }),
    ).toThrow(RangeError);
    const authorizer = createClientElicitationActionAuthorizer({
      elicitationAvailable: () => true,
      randomBytes: (size) => new Uint8Array(size).fill(7),
    });
    const prepared = await call();
    const credential = await binding();
    expect(
      (await authorizer.authorize(prepared, credential, { kind: "initial" }))
        .status,
    ).toBe("input-required");
    expect(
      (await authorizer.authorize(prepared, credential, { kind: "initial" }))
        .status,
    ).toBe("denied");
  });

  test("burns accessor-bearing responses without invoking accessors", async () => {
    const authorizer = createClientElicitationActionAuthorizer({
      elicitationAvailable: () => true,
      randomBytes: deterministicRandom(),
    });
    const prepared = await call();
    const credential = await binding();
    const first = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    if (first.status !== "input-required")
      throw new Error("expected input-required");
    const state = await authorizer.requestStateVerifier(first.requestState);
    let invoked = false;
    const hostile: Record<string, unknown> = {};
    Object.defineProperty(hostile, "confirm", {
      enumerable: true,
      get() {
        invoked = true;
        return { action: "accept", content: { confirm: true } };
      },
    });
    expect(
      (
        await authorizer.authorize(prepared, credential, {
          kind: "resume",
          requestState: state,
          inputResponses: hostile,
        })
      ).status,
    ).toBe("denied");
    expect(invoked).toBe(false);
    expect(
      (
        await authorizer.authorize(prepared, credential, {
          kind: "resume",
          requestState: state,
          inputResponses: accepted(),
        })
      ).status,
    ).toBe("denied");
  });

  test("rejects accessor-bearing or open authorization contexts without invoking accessors", async () => {
    const authorizer = createClientElicitationActionAuthorizer({
      elicitationAvailable: () => true,
    });
    let invoked = false;
    const hostile = {} as AuthorizationContext;
    Object.defineProperty(hostile, "kind", {
      enumerable: true,
      get() {
        invoked = true;
        return "initial";
      },
    });
    expect(
      (await authorizer.authorize(await call(), await binding(), hostile))
        .status,
    ).toBe("denied");
    expect(invoked).toBe(false);
    expect(
      (
        await authorizer.authorize(await call(), await binding(), {
          kind: "initial",
          extra: true,
        } as never)
      ).status,
    ).toBe("denied");
  });

  test("request-state codec rejects non-byte and short HMAC keys", () => {
    const options = {
      now: () => 0,
      isPending: () => false,
    };
    expect(() =>
      createVerifiedRequestStateCodec({
        ...options,
        key: { byteLength: 32 } as Uint8Array,
      }),
    ).toThrow(RangeError);
    expect(() =>
      createVerifiedRequestStateCodec({
        ...options,
        key: new Uint8Array(31),
      }),
    ).toThrow(RangeError);
  });

  test.each(["call", "credential"] as const)(
    "consume rejects a receipt presented with a changed %s",
    async (changedTuple) => {
      const authorizer = createClientElicitationActionAuthorizer({
        elicitationAvailable: () => true,
        randomBytes: deterministicRandom(),
      });
      const prepared = await call();
      const credential = await binding();
      const first = await authorizer.authorize(prepared, credential, {
        kind: "initial",
      });
      if (first.status !== "input-required")
        throw new Error("expected input-required");
      const decision = await authorizer.authorize(
        prepared,
        credential,
        await resumeContext(authorizer, first.requestState),
      );
      if (decision.status !== "authorized")
        throw new Error("expected authorized");
      const consumedCall =
        changedTuple === "call"
          ? await call({ normalizedArguments: { body: { count: 3 } } })
          : prepared;
      const consumedCredential =
        changedTuple === "credential"
          ? await binding({ grantId: "different_grant_1" })
          : credential;
      await expect(
        authorizer.consume(decision, consumedCall, consumedCredential),
      ).rejects.toMatchObject({ code: "ACTION_DENIED" });
    },
  );

  test("only one concurrent consume succeeds and copied decisions are rejected", async () => {
    const authorizer = createClientElicitationActionAuthorizer({
      elicitationAvailable: () => true,
      randomBytes: deterministicRandom(),
    });
    const prepared = await call();
    const credential = await binding();
    const first = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    if (first.status !== "input-required")
      throw new Error("expected input-required");
    const decision = await authorizer.authorize(
      prepared,
      credential,
      await resumeContext(authorizer, first.requestState),
    );
    if (decision.status !== "authorized")
      throw new Error("expected authorized");
    await expect(
      authorizer.consume({ ...decision }, prepared, credential),
    ).rejects.toMatchObject({ code: "ACTION_DENIED" });
    const results = await Promise.allSettled([
      authorizer.consume(decision, prepared, credential),
      authorizer.consume(decision, prepared, credential),
    ]);
    expect(
      results.filter((result) => result.status === "fulfilled"),
    ).toHaveLength(1);
    expect(
      results.filter((result) => result.status === "rejected"),
    ).toHaveLength(1);
  });
});

function policyTemplate(prepared: PreparedCall): ExactPolicyTemplate {
  return {
    version: 1,
    catalogId: prepared.catalogId,
    releaseId: prepared.releaseId,
    manifestDigest: prepared.manifestDigest,
    operationId: prepared.operationId,
    operationDigest: prepared.operationDigest,
    credentialProfileDigest: prepared.credentialProfileDigest,
    actionKind: "create",
    cardinality: "single",
    maxAffected: 1,
    expiresAt: 20_000,
    arguments: {
      kind: "object",
      properties: {
        body: {
          kind: "object",
          properties: { count: { kind: "number", min: 1, max: 3 } },
        },
      },
    },
  };
}

describe("exact policy authorizer", () => {
  test("policy activation requires a separate explicit affirmative", async () => {
    const prepared = await call();
    const credential = await binding();
    const authorizer = createExactPolicyActionAuthorizer({
      templates: [await compileExactPolicy(policyTemplate(prepared))],
      elicitationAvailable: () => true,
      now: () => 1_000,
      randomBytes: deterministicRandom(),
    });
    const first = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    if (first.status !== "input-required") throw new Error();
    expect(
      (
        await authorizer.authorize(prepared, credential, {
          kind: "resume",
          requestState: await authorizer.requestStateVerifier(
            first.requestState,
          ),
          inputResponses: accepted(),
        })
      ).status,
    ).toBe("denied");
    const second = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    if (second.status !== "input-required") throw new Error();
    expect(
      (
        await authorizer.authorize(prepared, credential, {
          kind: "resume",
          requestState: await authorizer.requestStateVerifier(
            second.requestState,
          ),
          inputResponses: acceptedActivation(),
        })
      ).status,
    ).toBe("authorized");
  });

  test("requires explicit first-use activation then mints distinct single-use receipts", async () => {
    let now = 1_000;
    const prepared = await call();
    const credential = await binding();
    const policy = await compileExactPolicy(policyTemplate(prepared));
    const authorizer = createExactPolicyActionAuthorizer({
      templates: [policy],
      elicitationAvailable: () => true,
      now: () => now,
      randomBytes: deterministicRandom(),
    });
    const first = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    expect(first.status).toBe("input-required");
    if (first.status !== "input-required")
      throw new Error("expected activation confirmation");
    expect(first.presentation.policyActivation).toMatchObject({
      policyDigest: policy.policyDigest,
      expiresAt: 20_000,
    });
    const activated = await authorizer.authorize(prepared, credential, {
      kind: "resume",
      requestState: await authorizer.requestStateVerifier(first.requestState),
      inputResponses: acceptedActivation(),
    });
    expect(activated).toMatchObject({
      status: "authorized",
      path: "exact-policy",
      policyDigest: policy.policyDigest,
    });
    const next = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    expect(next).toMatchObject({ status: "authorized", path: "exact-policy" });
    if (activated.status !== "authorized" || next.status !== "authorized")
      throw new Error();
    expect(next.authorizationId).not.toBe(activated.authorizationId);
    await authorizer.consume(activated, prepared, credential);
    const consumed = await Promise.allSettled([
      authorizer.consume(next, prepared, credential),
      authorizer.consume(next, prepared, credential),
    ]);
    expect(
      consumed.filter((result) => result.status === "fulfilled"),
    ).toHaveLength(1);
    expect(
      consumed.filter((result) => result.status === "rejected"),
    ).toHaveLength(1);
    now = 20_000;
    expect(
      (await authorizer.authorize(prepared, credential, { kind: "initial" }))
        .status,
    ).toBe("input-required");
  });

  test.each([
    "delete",
    "communicate",
    "authority",
    "transaction",
    "execute",
    "unknown",
  ] as const)("%s never policy-auto-approves", async (actionKind) => {
    const base = await call();
    const policy = await compileExactPolicy(policyTemplate(base));
    const authorizer = createExactPolicyActionAuthorizer({
      templates: [policy],
      elicitationAvailable: () => false,
    });
    const unsafe = await call({ actionKind });
    expect(
      (await authorizer.authorize(unsafe, await binding(), { kind: "initial" }))
        .status,
    ).toBe("denied");
  });

  test.each([
    { kind: "unbounded" } as const,
    { kind: "unknown" } as const,
    { kind: "bounded", maxAffected: 2 } as const,
  ])(
    "$kind cardinality cannot use a single-item policy",
    async (cardinality) => {
      const base = await call();
      const authorizer = createExactPolicyActionAuthorizer({
        templates: [await compileExactPolicy(policyTemplate(base))],
        elicitationAvailable: () => false,
      });
      const changed = await call({ cardinality });
      expect(
        (
          await authorizer.authorize(changed, await binding(), {
            kind: "initial",
          })
        ).status,
      ).toBe("denied");
    },
  );

  test("a valid update policy activates and then authorizes matching calls", async () => {
    const prepared = await call({ actionKind: "update", method: "PATCH" });
    const policy = await compileExactPolicy({
      ...policyTemplate(prepared),
      actionKind: "update",
    });
    const credential = await binding();
    const authorizer = createExactPolicyActionAuthorizer({
      templates: [policy],
      elicitationAvailable: () => true,
      now: () => 1_000,
      randomBytes: deterministicRandom(),
    });
    const first = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    if (first.status !== "input-required") throw new Error();
    expect(
      (
        await authorizer.authorize(prepared, credential, {
          kind: "resume",
          requestState: await authorizer.requestStateVerifier(
            first.requestState,
          ),
          inputResponses: acceptedActivation(),
        })
      ).status,
    ).toBe("authorized");
    expect(
      (await authorizer.authorize(prepared, credential, { kind: "initial" }))
        .status,
    ).toBe("authorized");
  });

  test("policy receipts expire at the activation/template boundary", async () => {
    let now = 1_000;
    const prepared = await call();
    const policy = await compileExactPolicy({
      ...policyTemplate(prepared),
      expiresAt: 1_050,
    });
    const credential = await binding();
    const authorizer = createExactPolicyActionAuthorizer({
      templates: [policy],
      elicitationAvailable: () => true,
      now: () => now,
      randomBytes: deterministicRandom(),
    });
    const first = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    if (first.status !== "input-required") throw new Error();
    const activationReceipt = await authorizer.authorize(prepared, credential, {
      kind: "resume",
      requestState: await authorizer.requestStateVerifier(first.requestState),
      inputResponses: acceptedActivation(),
    });
    if (activationReceipt.status !== "authorized") throw new Error();
    const activeReceipt = await authorizer.authorize(prepared, credential, {
      kind: "initial",
    });
    if (activeReceipt.status !== "authorized") throw new Error();
    now = 1_049;
    await expect(
      authorizer.consume(activationReceipt, prepared, credential),
    ).resolves.toBeUndefined();
    now = 1_050;
    await expect(
      authorizer.consume(activeReceipt, prepared, credential),
    ).rejects.toMatchObject({ code: "ACTION_DENIED" });
  });

  test("a restart or live grant change requires a fresh explicit activation", async () => {
    const prepared = await call();
    const policy = await compileExactPolicy({
      ...policyTemplate(prepared),
      expiresAt: 2_000_000,
    });
    const firstCredential = await binding();
    const authorizer = createExactPolicyActionAuthorizer({
      templates: [policy],
      elicitationAvailable: () => true,
      now: () => 1_000,
      randomBytes: deterministicRandom(),
    });
    const first = await authorizer.authorize(prepared, firstCredential, {
      kind: "initial",
    });
    if (first.status !== "input-required") throw new Error();
    expect(
      (
        await authorizer.authorize(prepared, firstCredential, {
          kind: "resume",
          requestState: await authorizer.requestStateVerifier(
            first.requestState,
          ),
          inputResponses: acceptedActivation(),
        })
      ).status,
    ).toBe("authorized");
    expect(
      (
        await authorizer.authorize(
          prepared,
          await binding({ grantId: "another_live_grant" }),
          { kind: "initial" },
        )
      ).status,
    ).toBe("input-required");
    expect(
      (
        await authorizer.authorize(
          prepared,
          await binding({ audience: "https://other.example.test" }),
          { kind: "initial" },
        )
      ).status,
    ).toBe("input-required");
    expect(
      (
        await authorizer.authorize(
          prepared,
          await binding({ scopes: ["widgets.admin"] }),
          { kind: "initial" },
        )
      ).status,
    ).toBe("input-required");
    const restarted = createExactPolicyActionAuthorizer({
      templates: [policy],
      elicitationAvailable: () => true,
      now: () => 1_000,
      randomBytes: deterministicRandom(),
    });
    expect(
      (
        await restarted.authorize(prepared, firstCredential, {
          kind: "initial",
        })
      ).status,
    ).toBe("input-required");
  });

  test("activation capacity failure preserves pending and inserts no activation", async () => {
    const prepared = await call();
    const policy = await compileExactPolicy({
      ...policyTemplate(prepared),
      expiresAt: 2_000_000,
    });
    const authorizer = createExactPolicyActionAuthorizer({
      templates: [policy],
      elicitationAvailable: () => true,
      now: () => 1_000,
      randomBytes: deterministicRandom(),
      limits: { activations: 1 },
    });
    const firstCredential = await binding();
    const first = await authorizer.authorize(prepared, firstCredential, {
      kind: "initial",
    });
    if (first.status !== "input-required") throw new Error();
    const firstDecision = await authorizer.authorize(
      prepared,
      firstCredential,
      {
        kind: "resume",
        requestState: await authorizer.requestStateVerifier(first.requestState),
        inputResponses: acceptedActivation(),
      },
    );
    if (firstDecision.status !== "authorized") throw new Error();
    await authorizer.consume(firstDecision, prepared, firstCredential);

    const secondCredential = await binding({ grantId: "second_live_grant_" });
    const second = await authorizer.authorize(prepared, secondCredential, {
      kind: "initial",
    });
    if (second.status !== "input-required") throw new Error();
    const state = await authorizer.requestStateVerifier(second.requestState);
    const context = {
      kind: "resume",
      requestState: state,
      inputResponses: acceptedActivation(),
    } as const;
    expect(
      (await authorizer.authorize(prepared, secondCredential, context)).status,
    ).toBe("denied");
    await expect(
      authorizer.requestStateVerifier(second.requestState),
    ).resolves.toBeObject();
    expect(
      (
        await authorizer.authorize(prepared, secondCredential, {
          kind: "initial",
        })
      ).status,
    ).toBe("input-required");
  });
});
