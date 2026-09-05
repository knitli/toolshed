import { describe, expect, test } from "bun:test";
import { digestCredentialAuthorizationBinding } from "../src/runtime/credential-binding.ts";
import {
  createPreparedCall,
  type PreparedCallInput,
} from "../src/runtime/prepared-call.ts";
import type {
  ActionAuthorizer,
  AuthorizationId,
  AuthorizedActionDecision,
  CredentialAuthorizationBinding,
  PreparedCall,
  Sha256,
} from "../src/runtime/types.ts";
import { createActionAuthorizationBoundary } from "../src/stdio/action-broker.ts";
import { createClientElicitationActionAuthorizer } from "../src/stdio/authorizer.ts";

const digest = (character: string) => character.repeat(64) as Sha256;

async function call(): Promise<PreparedCall> {
  return await createPreparedCall({
    version: 2,
    catalogId: "tiny" as PreparedCall["catalogId"],
    releaseId: "release-1" as PreparedCall["releaseId"],
    operationId: "operation:tiny:deletePet",
    operationDigest: digest("a"),
    manifestDigest: digest("b"),
    credentialProfileId: "operator",
    credentialProfileDigest: digest("c"),
    reservedSlotsDigest: digest("d"),
    method: "DELETE",
    origin: "https://api.example.test",
    relativeUrl: "/pets/7",
    headers: {},
    body: null,
    normalizedArguments: { path: { id: "7" } },
    safety: "action",
    actionKind: "delete",
    cardinality: { kind: "single" },
  } satisfies PreparedCallInput);
}

async function binding(): Promise<CredentialAuthorizationBinding> {
  const payload = {
    profileId: "operator",
    profileDigest: digest("c"),
    grantId: "grant_1234567890abcdef",
    audience: "https://api.example.test",
    scopes: ["pets:write"],
    slotsDigest: digest("d"),
  } as const;
  return Object.freeze({
    ...payload,
    bindingDigest: await digestCredentialAuthorizationBinding(payload),
  });
}

function decision(
  prepared: PreparedCall,
  credential: CredentialAuthorizationBinding,
): AuthorizedActionDecision {
  return {
    status: "authorized",
    callDigest: prepared.preparedCallDigest,
    credentialBindingDigest: credential.bindingDigest,
    path: "per-call",
    authorizationId: Object.freeze({}) as AuthorizationId,
  };
}

function authorizer(consume: ActionAuthorizer["consume"]): ActionAuthorizer {
  return {
    async authorize() {
      return { status: "denied", reason: "not used" };
    },
    consume,
  };
}

function expectDenied(action: () => unknown): void {
  expect(action).toThrow(expect.objectContaining({ code: "ACTION_DENIED" }));
}

describe("private action authorization boundary", () => {
  test("calls the configured authorizer before issuing a single-use permit", async () => {
    const prepared = await call();
    const credential = await binding();
    const frozenDecision = Object.freeze(decision(prepared, credential));
    let consumed = 0;
    let receivedDecision: AuthorizedActionDecision | undefined;
    const boundary = createActionAuthorizationBoundary(
      authorizer(async (received) => {
        consumed += 1;
        receivedDecision = received;
      }),
    );

    const permit = await boundary.broker.consume(
      frozenDecision,
      prepared,
      credential,
    );
    expect(consumed).toBe(1);
    expect(receivedDecision).toBe(frozenDecision);
    boundary.permits.consume(
      permit,
      prepared.preparedCallDigest,
      credential.bindingDigest,
    );
    expectDenied(() =>
      boundary.permits.consume(
        permit,
        prepared.preparedCallDigest,
        credential.bindingDigest,
      ),
    );
  });

  test("consumes a built-in authorizer decision through the snapshotting broker", async () => {
    let randomByte = 0;
    const configured = createClientElicitationActionAuthorizer({
      elicitationAvailable: () => true,
      randomBytes(size) {
        const bytes = new Uint8Array(size);
        bytes.fill(++randomByte);
        return bytes;
      },
    });
    const prepared = await call();
    const credential = await binding();
    const first = await configured.authorize(prepared, credential, {
      kind: "initial",
    });
    if (first.status !== "input-required") {
      throw new Error("expected input-required decision");
    }
    const authorized = await configured.authorize(prepared, credential, {
      kind: "resume",
      requestState: await configured.requestStateVerifier(first.requestState),
      inputResponses: {
        confirm: { action: "accept", content: { confirm: true } },
      },
    });
    if (authorized.status !== "authorized") {
      throw new Error("expected authorized decision");
    }
    const boundary = createActionAuthorizationBoundary(configured);

    const permit = await boundary.broker.consume(
      authorized,
      prepared,
      credential,
    );
    boundary.permits.consume(
      permit,
      prepared.preparedCallDigest,
      credential.bindingDigest,
    );
  });

  test("does not issue a permit when the configured authorizer rejects consumption", async () => {
    const prepared = await call();
    const credential = await binding();
    const boundary = createActionAuthorizationBoundary(
      authorizer(async () => {
        throw new Error("private authorizer detail");
      }),
    );

    await expect(
      boundary.broker.consume(
        decision(prepared, credential),
        prepared,
        credential,
      ),
    ).rejects.toMatchObject({ code: "ACTION_DENIED" });
  });

  test("rejects a decision for another call or credential before authorizer consumption", async () => {
    const prepared = await call();
    const credential = await binding();
    let consumes = 0;
    const boundary = createActionAuthorizationBoundary(
      authorizer(async () => {
        consumes += 1;
      }),
    );

    await expect(
      boundary.broker.consume(
        { ...decision(prepared, credential), callDigest: digest("e") },
        prepared,
        credential,
      ),
    ).rejects.toMatchObject({ code: "ACTION_DENIED" });
    await expect(
      boundary.broker.consume(
        {
          ...decision(prepared, credential),
          credentialBindingDigest: digest("f"),
        },
        prepared,
        credential,
      ),
    ).rejects.toMatchObject({ code: "ACTION_DENIED" });
    expect(consumes).toBe(0);
  });

  test("snapshots the exact decision before awaiting external code", async () => {
    const prepared = await call();
    const credential = await binding();
    const mutable = decision(prepared, credential) as {
      -readonly [Key in keyof AuthorizedActionDecision]: AuthorizedActionDecision[Key];
    };
    let release!: () => void;
    const waiting = new Promise<void>((resolve) => {
      release = resolve;
    });
    let observed: AuthorizedActionDecision | undefined;
    const boundary = createActionAuthorizationBoundary(
      authorizer(async (received) => {
        observed = received;
        await waiting;
      }),
    );

    const pending = boundary.broker.consume(mutable, prepared, credential);
    mutable.path = "exact-policy";
    mutable.callDigest = digest("e");
    release();
    const permit = await pending;

    expect(observed).toMatchObject({
      path: "per-call",
      callDigest: prepared.preparedCallDigest,
    });
    expect(Object.isFrozen(observed)).toBe(true);
    boundary.permits.consume(
      permit,
      prepared.preparedCallDigest,
      credential.bindingDigest,
    );
  });

  test("rejects frozen accessor-bearing and extra-field decisions without invoking consume", async () => {
    const prepared = await call();
    const credential = await binding();
    let accesses = 0;
    let consumes = 0;
    const accessorBearing = Object.freeze({
      status: "authorized",
      get callDigest() {
        accesses += 1;
        return prepared.preparedCallDigest;
      },
      credentialBindingDigest: credential.bindingDigest,
      path: "per-call",
      authorizationId: Object.freeze({}) as AuthorizationId,
    }) as unknown as AuthorizedActionDecision;
    const extraField = Object.freeze({
      ...decision(prepared, credential),
      unexpected: true,
    }) as unknown as AuthorizedActionDecision;
    const boundary = createActionAuthorizationBoundary(
      authorizer(async () => {
        consumes += 1;
      }),
    );

    for (const malformed of [accessorBearing, extraField]) {
      await expect(
        boundary.broker.consume(malformed, prepared, credential),
      ).rejects.toMatchObject({ code: "ACTION_DENIED" });
    }
    expect(accesses).toBe(0);
    expect(consumes).toBe(0);
  });

  test("rejects malformed authorization paths and policy digest combinations", async () => {
    const prepared = await call();
    const credential = await binding();
    let consumes = 0;
    const valid = decision(prepared, credential);
    const malformed = [
      { ...valid, path: "other" },
      { ...valid, policyDigest: digest("e") },
      { ...valid, path: "exact-policy" },
      { ...valid, path: "exact-policy", policyDigest: "invalid" },
    ] as unknown as AuthorizedActionDecision[];
    const boundary = createActionAuthorizationBoundary(
      authorizer(async () => {
        consumes += 1;
      }),
    );

    for (const candidate of malformed) {
      await expect(
        boundary.broker.consume(candidate, prepared, credential),
      ).rejects.toMatchObject({ code: "ACTION_DENIED" });
    }
    expect(consumes).toBe(0);
  });

  test("rejects forged, copied, foreign, mismatched, and concurrently reused permits", async () => {
    const prepared = await call();
    const credential = await binding();
    const first = createActionAuthorizationBoundary(authorizer(async () => {}));
    const second = createActionAuthorizationBoundary(
      authorizer(async () => {}),
    );
    const permit = await first.broker.consume(
      decision(prepared, credential),
      prepared,
      credential,
    );

    expectDenied(() =>
      first.permits.consume(
        Object.freeze({}) as typeof permit,
        prepared.preparedCallDigest,
        credential.bindingDigest,
      ),
    );
    expectDenied(() =>
      first.permits.consume(
        { ...permit },
        prepared.preparedCallDigest,
        credential.bindingDigest,
      ),
    );
    expectDenied(() =>
      second.permits.consume(
        permit,
        prepared.preparedCallDigest,
        credential.bindingDigest,
      ),
    );
    expectDenied(() =>
      first.permits.consume(permit, digest("f"), credential.bindingDigest),
    );
    expectDenied(() =>
      first.permits.consume(permit, prepared.preparedCallDigest, digest("e")),
    );

    const results = await Promise.allSettled([
      Promise.resolve().then(() =>
        first.permits.consume(
          permit,
          prepared.preparedCallDigest,
          credential.bindingDigest,
        ),
      ),
      Promise.resolve().then(() =>
        first.permits.consume(
          permit,
          prepared.preparedCallDigest,
          credential.bindingDigest,
        ),
      ),
    ]);
    expect(
      results.filter((result) => result.status === "fulfilled"),
    ).toHaveLength(1);
    expect(
      results.filter((result) => result.status === "rejected"),
    ).toHaveLength(1);
  });

  test("expires unconsumed permits after 120 seconds", async () => {
    const prepared = await call();
    const credential = await binding();
    let now = 1_000;
    const boundary = createActionAuthorizationBoundary(
      authorizer(async () => {}),
      { now: () => now },
    );
    const permit = await boundary.broker.consume(
      decision(prepared, credential),
      prepared,
      credential,
    );
    now += 120_000;

    expectDenied(() =>
      boundary.permits.consume(
        permit,
        prepared.preparedCallDigest,
        credential.bindingDigest,
      ),
    );
  });

  test("fails closed when the permit clock becomes non-finite", async () => {
    const prepared = await call();
    const credential = await binding();
    let now = 1_000;
    const boundary = createActionAuthorizationBoundary(
      authorizer(async () => {}),
      { now: () => now },
    );
    const permit = await boundary.broker.consume(
      decision(prepared, credential),
      prepared,
      credential,
    );
    now = Number.NaN;

    expectDenied(() =>
      boundary.permits.consume(
        permit,
        prepared.preparedCallDigest,
        credential.bindingDigest,
      ),
    );
  });
});
