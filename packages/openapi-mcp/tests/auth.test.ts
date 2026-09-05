import { describe, expect, test } from "bun:test";
import { request } from "node:http";

import { sha256 } from "../src/runtime/digest.ts";
import type {
  CredentialSlotContext,
  LocalAuthProfile,
  Sha256,
} from "../src/runtime/types.ts";
import {
  createCredentialProvider,
  digestCredentialProfile,
  type LocalCredentialProvider,
  MemorySecretStore,
} from "../src/sqlite/auth.ts";

const origin = "https://api.example.test";
const digest = "a".repeat(64) as Sha256;

function context(
  overrides: Partial<CredentialSlotContext> = {},
): CredentialSlotContext {
  return {
    catalogId: "catalog" as CredentialSlotContext["catalogId"],
    releaseId: "release" as CredentialSlotContext["releaseId"],
    operationId: "operation:tiny:list" as CredentialSlotContext["operationId"],
    operationDigest: digest,
    manifestDigest: digest,
    method: "GET",
    origin,
    ...overrides,
  };
}

function bearerProfile(
  overrides: Partial<LocalAuthProfile> = {},
): LocalAuthProfile {
  return {
    profileId: "tiny",
    revision: 1,
    allowedOrigins: [origin],
    auth: { type: "bearer-env", env: "API_TOKEN" },
    audience: origin,
    scopes: ["widgets.read"],
    ...overrides,
  };
}

function oauthProfile(
  overrides: Partial<LocalAuthProfile> = {},
): LocalAuthProfile {
  return {
    profileId: "oauth-tiny",
    revision: 2,
    allowedOrigins: [origin],
    auth: {
      type: "oauth2-pkce",
      authorizationEndpoint: "https://identity.example.test/authorize",
      tokenEndpoint: "https://identity.example.test/token",
      clientId: "public-client",
      scopes: ["widgets.read", "widgets.write"],
      resource: "urn:example:widgets",
    },
    audience: "widgets-api-v2",
    ...overrides,
  };
}

function deterministicRandom(): (size: number) => Uint8Array {
  let value = 0;
  return (size) => {
    value += 1;
    return new Uint8Array(size).fill(value);
  };
}

function requiredQuery(url: URL, name: string): string {
  const value = url.searchParams.get(name);
  if (value === null) throw new Error(`missing ${name}`);
  return value;
}

async function ready(provider: LocalCredentialProvider) {
  const result = await provider.resolve();
  expect(result.status).toBe("ready");
  if (result.status !== "ready") throw new Error("credential not ready");
  return result.snapshot;
}

function callbackRequest(
  callback: string,
  options: { method?: string; host?: string } = {},
): Promise<{ status: number; body: string }> {
  const url = new URL(callback);
  return new Promise((resolve, reject) => {
    const outgoing = request(
      {
        hostname: url.hostname,
        port: url.port,
        path: `${url.pathname}${url.search}`,
        method: options.method ?? "GET",
        headers: options.host === undefined ? {} : { host: options.host },
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
        response.on("end", () =>
          resolve({
            status: response.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
          }),
        );
      },
    );
    outgoing.on("error", reject);
    outgoing.end();
  });
}

describe("local authentication", () => {
  test("MemorySecretStore keeps secrets only in its own process object", async () => {
    const store = new MemorySecretStore();
    await store.set("oauth:tiny", "refresh-secret");
    expect(await store.get("oauth:tiny")).toBe("refresh-secret");
    expect(await new MemorySecretStore().get("oauth:tiny")).toBeNull();
  });

  test("prepares canonical non-secret bindings without reading env or secrets", async () => {
    let envReads = 0;
    let secretReads = 0;
    const environment = Object.defineProperty({}, "API_TOKEN", {
      get() {
        envReads += 1;
        return "operator-secret";
      },
    }) as Record<string, string>;
    const first = await createCredentialProvider(bearerProfile(), {
      manifestOrigins: [origin],
      environment,
      secretStore: {
        async get() {
          secretReads += 1;
          return null;
        },
        async set() {},
        async delete() {},
      },
      randomBytes: deterministicRandom(),
    });
    const second = await createCredentialProvider(bearerProfile(), {
      manifestOrigins: [origin],
      environment: { API_TOKEN: "different-secret" },
      randomBytes: deterministicRandom(),
    });
    const firstPrepared = await first.bindingResolver.resolve(context());
    const secondPrepared = await second.bindingResolver.resolve(context());
    expect(envReads).toBe(0);
    expect(secretReads).toBe(0);
    expect(firstPrepared).toEqual(secondPrepared);
    expect(firstPrepared.slots).toEqual([
      { placement: "header", name: "authorization" },
    ]);
    expect(
      await sha256("knitli.openapi-mcp.credential-slots.v1", [
        { placement: "header", name: "authorization" },
      ]),
    ).toBe((await ready(first)).binding.slotsDigest);
    expect((await ready(first)).binding.profileDigest).toBe(
      firstPrepared.profileDigest,
    );
    expect(JSON.stringify(firstPrepared)).not.toContain("API_TOKEN");
    expect(JSON.stringify(firstPrepared)).not.toContain("operator-secret");
    await expect(
      first.bindingResolver.resolve(
        context({ origin: "https://other.example.test" }),
      ),
    ).rejects.toMatchObject({ code: "DESTINATION_DENIED" });
  });

  test("rotates immutable environment bindings on secret change and forget", async () => {
    const environment: Record<string, string | undefined> = {
      API_TOKEN: undefined,
    };
    const provider = await createCredentialProvider(bearerProfile(), {
      manifestOrigins: [origin],
      environment,
      randomBytes: deterministicRandom(),
    });
    await expect(provider.resolve()).rejects.toMatchObject({
      code: "AUTH_REQUIRED",
      message: "Credential is not available",
      details: {},
    });
    environment.API_TOKEN = "operator-secret";
    const first = await ready(provider);
    const stable = await ready(provider);
    environment.API_TOKEN = "replacement-secret";
    const rotated = await ready(provider);
    await provider.forget();
    const afterForget = await ready(provider);
    expect(first.credential).toEqual({
      type: "bearer",
      token: "operator-secret",
    });
    expect(first.binding.grantId).toBe(stable.binding.grantId);
    expect(rotated.binding.grantId).not.toBe(first.binding.grantId);
    expect(afterForget.binding.grantId).not.toBe(rotated.binding.grantId);
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.credential)).toBe(true);
    expect(Object.isFrozen(first.binding)).toBe(true);
    expect(Object.isFrozen(first.binding.scopes)).toBe(true);
    expect(JSON.stringify(first.binding)).not.toContain("operator-secret");
  });

  test("supports header and query API keys without injecting them in preparation", async () => {
    for (const placement of ["header", "query"] as const) {
      const expectedName = placement === "header" ? "x-api-key" : "X-Api-Key";
      const provider = await createCredentialProvider(
        bearerProfile({
          auth: {
            type: "api-key-env",
            env: "API_KEY",
            placement,
            name: "X-Api-Key",
          },
        }),
        {
          manifestOrigins: [origin],
          environment: { API_KEY: "api-secret" },
          randomBytes: deterministicRandom(),
        },
      );
      expect((await provider.bindingResolver.resolve(context())).slots).toEqual(
        [{ placement, name: expectedName }],
      );
      expect(await ready(provider)).toMatchObject({
        credential: {
          type: "api-key",
          placement,
          name: expectedName,
          value: "api-secret",
        },
      });
    }
  });

  test("rejects malformed profiles, unsafe headers, and empty origin intersections", async () => {
    const invalid: LocalAuthProfile[] = [
      bearerProfile({ profileId: "../tiny" }),
      bearerProfile({ revision: 0 }),
      bearerProfile({ allowedOrigins: ["http://api.example.test"] }),
      bearerProfile({ allowedOrigins: [origin, origin] }),
      bearerProfile({ auth: { type: "bearer-env", env: "BAD-NAME" } }),
      bearerProfile({
        auth: {
          type: "api-key-env",
          env: "API_KEY",
          placement: "header",
          name: "Authorization",
        },
      }),
      bearerProfile({
        auth: {
          type: "api-key-env",
          env: "API_KEY",
          placement: "header",
          name: "Cookie",
        },
      }),
      bearerProfile({
        auth: {
          type: "api-key-env",
          env: "API_KEY",
          placement: "header",
          name: "X-Forwarded-Evil",
        },
      }),
      oauthProfile({ scopes: ["ambiguous"] }),
      oauthProfile({
        auth: {
          type: "oauth2-pkce",
          authorizationEndpoint: "http://identity.example.test/authorize",
          tokenEndpoint: "https://identity.example.test/token",
          clientId: "client",
          scopes: [],
        },
      }),
    ];
    for (const profile of invalid) {
      await expect(
        createCredentialProvider(profile, { manifestOrigins: [origin] }),
      ).rejects.toMatchObject({
        code: "AUTH_PROFILE_INVALID",
        message: "Authentication profile is invalid",
        details: {},
      });
    }
    await expect(
      createCredentialProvider(bearerProfile(), {
        manifestOrigins: ["https://other.example.test"],
      }),
    ).rejects.toMatchObject({ code: "AUTH_PROFILE_INVALID" });
  });

  test("profile digest commits non-secret settings and is deterministic", async () => {
    const base = bearerProfile();
    expect(await digestCredentialProfile(base)).toBe(
      await digestCredentialProfile(base),
    );
    const pending = digestCredentialProfile(base);
    (base as { revision: number }).revision = 99;
    (base.auth as { env: string }).env = "CHANGED_AFTER_CALL";
    expect(await pending).toBe(await digestCredentialProfile(bearerProfile()));
    expect(await digestCredentialProfile({ ...base, revision: 2 })).not.toBe(
      await digestCredentialProfile(bearerProfile()),
    );
  });

  test("runs one shared S256 flow and invalid callbacks do not consume it", async () => {
    const tokenCalls: Array<{ url: string; init?: RequestInit }> = [];
    const provider = await createCredentialProvider(oauthProfile(), {
      manifestOrigins: [origin],
      fetch: async (input, init) => {
        tokenCalls.push({ url: String(input), init });
        return Response.json({
          access_token: "access-secret",
          refresh_token: "refresh-secret",
          token_type: "Bearer",
          expires_in: 60,
          scope: "widgets.read",
          id_token: "provider-subject-secret",
        });
      },
      randomBytes: deterministicRandom(),
    });
    const [first, concurrent] = await Promise.all([
      provider.resolve(),
      provider.resolve(),
    ]);
    expect(concurrent).toEqual(first);
    if (first.status !== "auth-required")
      throw new Error("authorization not required");
    const authorizationUrl = new URL(first.authorizationUrl);
    expect(authorizationUrl.origin + authorizationUrl.pathname).toBe(
      "https://identity.example.test/authorize",
    );
    expect(authorizationUrl.searchParams.get("code_challenge_method")).toBe(
      "S256",
    );
    expect(
      authorizationUrl.searchParams.get("state")?.length,
    ).toBeGreaterThanOrEqual(43);
    const redirect = requiredQuery(authorizationUrl, "redirect_uri");
    expect(new URL(redirect).hostname).toBe("127.0.0.1");
    expect(new URL(redirect).pathname).toBe("/oauth/callback");
    expect(new URL(redirect).port).not.toBe("");
    expect(
      await callbackRequest(`${redirect}?state=wrong&code=super-secret-code`),
    ).toEqual({ status: 400, body: "OAuth callback rejected" });
    expect(
      await callbackRequest(`${redirect}?state=wrong&state=again&code=secret`),
    ).toEqual({ status: 400, body: "OAuth callback rejected" });
    expect(
      await callbackRequest(
        `${redirect}?state=${authorizationUrl.searchParams.get("state")}&code=a&code=b`,
      ),
    ).toEqual({ status: 400, body: "OAuth callback rejected" });
    const excessiveExtensions = new URL(redirect);
    excessiveExtensions.searchParams.set(
      "state",
      requiredQuery(authorizationUrl, "state"),
    );
    excessiveExtensions.searchParams.set("code", "bounded-code");
    for (let index = 0; index < 64; index += 1) {
      excessiveExtensions.searchParams.set(`extension_${index}`, "value");
    }
    expect(await callbackRequest(excessiveExtensions.toString())).toEqual({
      status: 400,
      body: "OAuth callback rejected",
    });
    expect(
      await callbackRequest(
        `${redirect}?state=${authorizationUrl.searchParams.get("state")}&code=authorization-secret&iss=https%3A%2F%2Fidentity.example.test&session_state=opaque-extension`,
      ),
    ).toEqual({ status: 200, body: "Authorization complete" });
    expect(tokenCalls).toHaveLength(1);
    expect(tokenCalls[0]?.url).toBe("https://identity.example.test/token");
    expect(tokenCalls[0]?.init?.redirect).toBe("manual");
    const body = new URLSearchParams(String(tokenCalls[0]?.init?.body));
    expect(body.get("grant_type")).toBe("authorization_code");
    expect(body.get("code")).toBe("authorization-secret");
    expect(body.get("redirect_uri")).toBe(redirect);
    const verifier = requiredQuery(
      new URL(`https://local.test/?${body.toString()}`),
      "code_verifier",
    );
    expect(verifier.length).toBeGreaterThanOrEqual(43);
    const challenge = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(verifier),
    );
    expect(Buffer.from(challenge).toString("base64url")).toBe(
      authorizationUrl.searchParams.get("code_challenge"),
    );
    const snapshot = await ready(provider);
    expect(snapshot.credential).toEqual({
      type: "bearer",
      token: "access-secret",
    });
    expect(snapshot.binding.audience).toBe("widgets-api-v2");
    expect(snapshot.binding.scopes).toEqual(["widgets.read"]);
    expect(JSON.stringify(snapshot.binding)).not.toContain(
      "provider-subject-secret",
    );
    expect(JSON.stringify(snapshot.binding)).not.toContain("access-secret");
    const replay = await callbackRequest(
      `${redirect}?state=${authorizationUrl.searchParams.get("state")}&code=again`,
    ).catch(() => null);
    expect(replay?.status).not.toBe(200);
    await provider.close();
  });

  test("coalesces resolve while an accepted callback token exchange is pending", async () => {
    let releaseToken!: () => void;
    let tokenStarted!: () => void;
    let tokenCalls = 0;
    const gate = new Promise<void>((resolve) => {
      releaseToken = resolve;
    });
    const started = new Promise<void>((resolve) => {
      tokenStarted = resolve;
    });
    const provider = await createCredentialProvider(oauthProfile(), {
      manifestOrigins: [origin],
      randomBytes: deterministicRandom(),
      fetch: async () => {
        tokenCalls += 1;
        tokenStarted();
        await gate;
        return Response.json({
          access_token: "coalesced-access",
          refresh_token: "coalesced-refresh",
          token_type: "Bearer",
        });
      },
    });
    const required = await provider.resolve();
    if (required.status !== "auth-required")
      throw new Error("authorization not required");
    const authorization = new URL(required.authorizationUrl);
    const callback = callbackRequest(
      `${requiredQuery(authorization, "redirect_uri")}?state=${authorization.searchParams.get("state")}&code=coalesced-code`,
    );
    await started;
    const [duringA, duringB] = await Promise.all([
      provider.resolve(),
      provider.resolve(),
    ]);
    expect(duringA).toEqual(required);
    expect(duringB).toEqual(required);
    expect(tokenCalls).toBe(1);
    releaseToken();
    expect(await callback).toEqual({
      status: 200,
      body: "Authorization complete",
    });
    expect((await ready(provider)).credential).toEqual({
      type: "bearer",
      token: "coalesced-access",
    });
    await provider.close();
  });

  test("accepts bounded error extensions but consumes the valid-state callback", async () => {
    let tokenCalls = 0;
    const provider = await createCredentialProvider(oauthProfile(), {
      manifestOrigins: [origin],
      randomBytes: deterministicRandom(),
      fetch: async () => {
        tokenCalls += 1;
        return Response.json({});
      },
    });
    const required = await provider.resolve();
    if (required.status !== "auth-required")
      throw new Error("authorization not required");
    const authorization = new URL(required.authorizationUrl);
    const result = await callbackRequest(
      `${requiredQuery(authorization, "redirect_uri")}?state=${authorization.searchParams.get("state")}&error=access_denied&error_description=provider-secret-detail&error_uri=https%3A%2F%2Fidentity.example.test%2Ferrors%2F1&iss=https%3A%2F%2Fidentity.example.test`,
    );
    expect(result).toEqual({ status: 400, body: "Authorization failed" });
    expect(JSON.stringify(result)).not.toContain("provider-secret-detail");
    expect(tokenCalls).toBe(0);
    const replacement = await provider.resolve();
    expect(replacement.status).toBe("auth-required");
    if (replacement.status !== "auth-required")
      throw new Error("authorization not required");
    expect(replacement.authorizationUrl).not.toBe(required.authorizationUrl);
    await provider.close();
  });

  test("refreshes once concurrently, retains grant, and narrows scopes", async () => {
    let now = 1_000;
    let calls = 0;
    let releaseRefresh!: () => void;
    const refreshGate = new Promise<void>((resolve) => {
      releaseRefresh = resolve;
    });
    const provider = await createCredentialProvider(oauthProfile(), {
      manifestOrigins: [origin],
      now: () => now,
      randomBytes: deterministicRandom(),
      fetch: async (_input, init) => {
        calls += 1;
        if (
          new URLSearchParams(String(init?.body)).get("grant_type") ===
          "refresh_token"
        ) {
          await refreshGate;
          return Response.json({
            access_token: "refreshed-secret",
            token_type: "Bearer",
            expires_in: 60,
          });
        }
        return Response.json({
          access_token: "initial-secret",
          refresh_token: "refresh-secret",
          token_type: "Bearer",
          expires_in: 1,
          scope: "widgets.read",
        });
      },
    });
    const required = await provider.resolve();
    if (required.status !== "auth-required")
      throw new Error("authorization not required");
    const authorize = new URL(required.authorizationUrl);
    await callbackRequest(
      `${authorize.searchParams.get("redirect_uri")}?state=${authorize.searchParams.get("state")}&code=code-secret`,
    );
    const initial = await ready(provider);
    now += 2_000;
    const refreshingA = provider.resolve();
    const refreshingB = provider.resolve();
    while (calls < 2) await Bun.sleep(1);
    expect(calls).toBe(2);
    releaseRefresh();
    const [refreshedA, refreshedB] = await Promise.all([
      refreshingA,
      refreshingB,
    ]);
    expect(refreshedA).toEqual(refreshedB);
    if (refreshedA.status !== "ready") throw new Error("refresh failed");
    expect(refreshedA.snapshot.binding.grantId).toBe(initial.binding.grantId);
    expect(refreshedA.snapshot.binding.scopes).toEqual(["widgets.read"]);
    expect(refreshedA.snapshot.credential).toEqual({
      type: "bearer",
      token: "refreshed-secret",
    });
    await provider.close();
  });

  test("forget prevents a late token response from resurrecting credentials", async () => {
    let release!: () => void;
    let started!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tokenStarted = new Promise<void>((resolve) => {
      started = resolve;
    });
    const provider = await createCredentialProvider(oauthProfile(), {
      manifestOrigins: [origin],
      randomBytes: deterministicRandom(),
      fetch: async () => {
        started();
        await gate;
        return Response.json({
          access_token: "late-secret",
          refresh_token: "late-refresh",
          token_type: "Bearer",
        });
      },
    });
    const required = await provider.resolve();
    if (required.status !== "auth-required")
      throw new Error("authorization not required");
    const authorize = new URL(required.authorizationUrl);
    const callback = callbackRequest(
      `${authorize.searchParams.get("redirect_uri")}?state=${authorize.searchParams.get("state")}&code=callback-secret`,
    );
    await tokenStarted;
    await provider.forget();
    release();
    const result = await callback;
    expect(result.status).not.toBe(200);
    expect(JSON.stringify(result)).not.toContain("late-secret");
    expect((await provider.resolve()).status).toBe("auth-required");
    await provider.close();
  });

  test("forget and close clean token writes that finish after lifecycle cancellation", async () => {
    for (const lifecycle of ["forget", "close"] as const) {
      const values = new Map<string, string>();
      let releaseSet!: () => void;
      let setStarted!: () => void;
      const setGate = new Promise<void>((resolve) => {
        releaseSet = resolve;
      });
      const started = new Promise<void>((resolve) => {
        setStarted = resolve;
      });
      const provider = await createCredentialProvider(oauthProfile(), {
        manifestOrigins: [origin],
        randomBytes: deterministicRandom(),
        secretStore: {
          async get(key) {
            return values.get(key) ?? null;
          },
          async set(key, value) {
            if (key.endsWith(":access")) {
              setStarted();
              await setGate;
            }
            values.set(key, value);
          },
          async delete(key) {
            values.delete(key);
          },
        },
        fetch: async () =>
          Response.json({
            access_token: "late-access",
            refresh_token: "late-refresh",
            token_type: "Bearer",
          }),
      });
      const required = await provider.resolve();
      if (required.status !== "auth-required")
        throw new Error("authorization not required");
      const authorization = new URL(required.authorizationUrl);
      const callback = callbackRequest(
        `${authorization.searchParams.get("redirect_uri")}?state=${authorization.searchParams.get("state")}&code=secret-code`,
      );
      await started;
      await provider[lifecycle]();
      releaseSet();
      expect((await callback).status).not.toBe(200);
      expect(values.size).toBe(0);
      if (lifecycle === "forget") await provider.close();
    }
  });

  test("obsolete refresh cleanup cannot reset completed replacement grant metadata", async () => {
    const values = new Map<string, string>();
    let now = 1_000;
    let pauseNextDelete = false;
    let releaseDelete!: () => void;
    let deleteStarted!: () => void;
    const deleteGate = new Promise<void>((resolve) => {
      releaseDelete = resolve;
    });
    const firstDelete = new Promise<void>((resolve) => {
      deleteStarted = resolve;
    });
    const provider = await createCredentialProvider(oauthProfile(), {
      manifestOrigins: [origin],
      now: () => now,
      randomBytes: deterministicRandom(),
      secretStore: {
        async get(key) {
          return values.get(key) ?? null;
        },
        async set(key, value) {
          values.set(key, value);
        },
        async delete(key) {
          if (pauseNextDelete) {
            pauseNextDelete = false;
            deleteStarted();
            await deleteGate;
          }
          values.delete(key);
        },
      },
      fetch: async (_input, init) => {
        const body = new URLSearchParams(String(init?.body));
        if (body.get("grant_type") === "refresh_token") {
          return Response.json(
            { error: "invalid_grant", error_description: "provider-secret" },
            { status: 400 },
          );
        }
        const replacement = body.get("code") === "replacement-code";
        return Response.json({
          access_token: replacement ? "replacement-access" : "initial-access",
          refresh_token: replacement
            ? "replacement-refresh"
            : "initial-refresh",
          token_type: "Bearer",
          expires_in: replacement ? 60 : 1,
        });
      },
    });

    const initialRequired = await provider.resolve();
    if (initialRequired.status !== "auth-required")
      throw new Error("authorization not required");
    const initialAuthorization = new URL(initialRequired.authorizationUrl);
    expect(
      await callbackRequest(
        `${requiredQuery(initialAuthorization, "redirect_uri")}?state=${initialAuthorization.searchParams.get("state")}&code=initial-code`,
      ),
    ).toMatchObject({ status: 200 });
    const initial = await ready(provider);
    now += 2_000;
    pauseNextDelete = true;
    const obsoleteRefresh = provider.resolve();
    await firstDelete;

    await provider.forget();
    const replacementRequired = await provider.resolve();
    if (replacementRequired.status !== "auth-required")
      throw new Error("authorization not required");
    const replacementAuthorization = new URL(
      replacementRequired.authorizationUrl,
    );
    expect(
      await callbackRequest(
        `${requiredQuery(replacementAuthorization, "redirect_uri")}?state=${replacementAuthorization.searchParams.get("state")}&code=replacement-code`,
      ),
    ).toMatchObject({ status: 200 });
    const replacement = await ready(provider);
    expect(replacement.binding.grantId).not.toBe(initial.binding.grantId);

    releaseDelete();
    await expect(obsoleteRefresh).rejects.toMatchObject({
      code: "AUTH_REQUIRED",
      message: "Authorization was cancelled",
    });
    expect((await ready(provider)).credential).toEqual({
      type: "bearer",
      token: "replacement-access",
    });
    await provider.close();
  });

  test("stale generation cleanup cannot erase a completed replacement login", async () => {
    const values = new Map<string, string>();
    let releaseFirstSet!: () => void;
    let firstSetStarted!: () => void;
    let blockFirstAccessSet = true;
    const firstSetGate = new Promise<void>((resolve) => {
      releaseFirstSet = resolve;
    });
    const firstSet = new Promise<void>((resolve) => {
      firstSetStarted = resolve;
    });
    const provider = await createCredentialProvider(oauthProfile(), {
      manifestOrigins: [origin],
      randomBytes: deterministicRandom(),
      secretStore: {
        async get(key) {
          return values.get(key) ?? null;
        },
        async set(key, value) {
          if (key.endsWith(":access") && blockFirstAccessSet) {
            blockFirstAccessSet = false;
            firstSetStarted();
            await firstSetGate;
          }
          values.set(key, value);
        },
        async delete(key) {
          values.delete(key);
        },
      },
      fetch: async (_input, init) => {
        const code = new URLSearchParams(String(init?.body)).get("code");
        return Response.json({
          access_token:
            code === "replacement-code"
              ? "replacement-access"
              : "obsolete-access",
          refresh_token:
            code === "replacement-code"
              ? "replacement-refresh"
              : "obsolete-refresh",
          token_type: "Bearer",
        });
      },
    });

    const obsoleteRequired = await provider.resolve();
    if (obsoleteRequired.status !== "auth-required")
      throw new Error("authorization not required");
    const obsoleteAuthorization = new URL(obsoleteRequired.authorizationUrl);
    const obsoleteCallback = callbackRequest(
      `${requiredQuery(obsoleteAuthorization, "redirect_uri")}?state=${obsoleteAuthorization.searchParams.get("state")}&code=obsolete-code`,
    );
    await firstSet;
    await provider.forget();

    const replacementRequired = await provider.resolve();
    if (replacementRequired.status !== "auth-required")
      throw new Error("authorization not required");
    const replacementAuthorization = new URL(
      replacementRequired.authorizationUrl,
    );
    expect(
      await callbackRequest(
        `${requiredQuery(replacementAuthorization, "redirect_uri")}?state=${replacementAuthorization.searchParams.get("state")}&code=replacement-code`,
      ),
    ).toEqual({ status: 200, body: "Authorization complete" });
    expect([...values.values()]).toContain("replacement-access");

    releaseFirstSet();
    expect((await obsoleteCallback).status).not.toBe(200);
    expect((await ready(provider)).credential).toEqual({
      type: "bearer",
      token: "replacement-access",
    });
    expect([...values.values()]).not.toContain("obsolete-access");
    await provider.close();
  });

  test("redacts redirects, extra scopes, malformed and oversized token bodies", async () => {
    const responses = [
      new Response(null, {
        status: 302,
        headers: { location: "https://evil.test" },
      }),
      Response.json({
        access_token: "secret",
        token_type: "Bearer",
        scope: "admin",
      }),
      new Response('{"access_token":"secret","access_token":"duplicate"}'),
      new Response(
        JSON.stringify({
          access_token: "x".repeat(1024),
          token_type: "Bearer",
        }),
      ),
    ];
    for (const response of responses) {
      const provider = await createCredentialProvider(oauthProfile(), {
        manifestOrigins: [origin],
        randomBytes: deterministicRandom(),
        maxTokenResponseBytes: 256,
        fetch: async () => response,
      });
      const required = await provider.resolve();
      if (required.status !== "auth-required")
        throw new Error("authorization not required");
      const authorize = new URL(required.authorizationUrl);
      const result = await callbackRequest(
        `${authorize.searchParams.get("redirect_uri")}?state=${authorize.searchParams.get("state")}&code=secret-code`,
      );
      expect(result).toEqual({ status: 502, body: "Authorization failed" });
      expect(JSON.stringify(result)).not.toContain("secret-code");
      await provider.close();
    }
  });

  test("expires listeners and rejects wrong method, path, host, and large targets", async () => {
    const expiring = await createCredentialProvider(oauthProfile(), {
      manifestOrigins: [origin],
      randomBytes: deterministicRandom(),
      authorizationDeadlineMs: 10,
      fetch: async () => Response.json({}),
    });
    const required = await expiring.resolve();
    if (required.status !== "auth-required")
      throw new Error("authorization not required");
    const authorize = new URL(required.authorizationUrl);
    await Bun.sleep(25);
    const expired = await callbackRequest(
      `${authorize.searchParams.get("redirect_uri")}?state=${authorize.searchParams.get("state")}&code=secret`,
    ).catch(() => null);
    expect(expired?.status).not.toBe(200);
    await expiring.close();

    const provider = await createCredentialProvider(oauthProfile(), {
      manifestOrigins: [origin],
      randomBytes: deterministicRandom(),
      fetch: async () =>
        Response.json({ access_token: "unused", token_type: "Bearer" }),
    });
    const pending = await provider.resolve();
    if (pending.status !== "auth-required")
      throw new Error("authorization not required");
    const auth = new URL(pending.authorizationUrl);
    const redirect = requiredQuery(auth, "redirect_uri");
    const state = auth.searchParams.get("state");
    expect(
      await callbackRequest(`${redirect}?state=${state}&code=secret`, {
        method: "POST",
      }),
    ).toEqual({ status: 400, body: "OAuth callback rejected" });
    expect(
      await callbackRequest(
        `${new URL(redirect).origin}/wrong?state=${state}&code=secret`,
      ),
    ).toEqual({ status: 400, body: "OAuth callback rejected" });
    expect(
      await callbackRequest(`${redirect}?state=${state}&code=secret`, {
        host: "localhost",
      }),
    ).toEqual({ status: 400, body: "OAuth callback rejected" });
    expect(
      await callbackRequest(`${redirect}?state=wrong&code=${"s".repeat(5000)}`),
    ).toEqual({ status: 400, body: "OAuth callback rejected" });
    await provider.close();
  });
});
