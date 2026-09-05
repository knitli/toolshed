import { expect, test } from "bun:test";
import { DEFAULT_RUNTIME_LIMITS } from "../src/runtime/versions.ts";
import {
  authorizer,
  credential,
  prepared,
  profile,
} from "./helpers/dispatch-fixtures.ts";

const transportModule = await import("../src/sqlite/guarded-fetch.ts").catch(
  () => ({}),
);

test("paired local dispatch boundary is available", () => {
  expect(typeof transportModule.createLocalDispatchBoundary).toBe("function");
});

test("opaque continuation codec authenticates all state, rejects tamper, expires and bounds its registry", async () => {
  let now = Date.now();
  const pair = boundary({ now: () => now, tokenCapacity: 1, tokenTtlMs: 1000 });
  const call = await prepared();
  const state = {
    catalogId: call.catalogId,
    releaseId: call.releaseId,
    manifestDigest: call.manifestDigest,
    operationId: call.operationId,
    inputDigest: call.inputDigest,
    origin: call.origin,
    nextRelativeUrl: "/widgets?cursor=private",
    expiresAt: new Date(now + 1000).toISOString(),
    pageCount: 1,
    cumulativeBytes: 20,
  };
  const token = await pair.paginationTokenCodec.encode(state);
  expect(token).not.toContain("private");
  expect(
    Buffer.from(token.split(".")[2], "base64url").toString(),
  ).not.toContain("widgets");
  expect(await pair.paginationTokenCodec.decode(token)).toEqual(state);
  state.nextRelativeUrl = "/mutated";
  expect((await pair.paginationTokenCodec.decode(token)).nextRelativeUrl).toBe(
    "/widgets?cursor=private",
  );
  for (const forged of [
    token.slice(0, -1),
    `${token}a`,
    token.replace(/.$/, token.endsWith("a") ? "b" : "a"),
  ])
    await expect(
      pair.paginationTokenCodec.decode(forged),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
  await expect(
    boundary().paginationTokenCodec.decode(token),
  ).rejects.toMatchObject({ code: "INPUT_INVALID" });
  const newer = await pair.paginationTokenCodec.encode(state);
  await expect(pair.paginationTokenCodec.decode(token)).rejects.toMatchObject({
    code: "INPUT_INVALID",
  });
  now += 1000;
  await expect(pair.paginationTokenCodec.decode(newer)).rejects.toMatchObject({
    code: "INPUT_INVALID",
  });
});

function boundary(extra = {}) {
  let lookups = 0;
  const auth = authorizer();
  const pair = transportModule.createLocalDispatchBoundary(auth, {
    profile,
    allowsManifestOrigin: async (context) =>
      context.catalogId === "fixture" &&
      context.releaseId === "release" &&
      context.manifestDigest === "b".repeat(64) &&
      context.origin === "https://api.example.test",
    lookup: async () => {
      lookups++;
      return [{ address: "8.8.8.8", family: 4 }];
    },
    ...extra,
  });
  return { ...pair, auth, lookups: () => lookups };
}

// Expanding body bytes into JSON nodes must fail these valid-envelope cases;
// omitting raw body content from the fingerprint must fail the tamper check.
for (const size of [110_000, DEFAULT_RUNTIME_LIMITS.maxArgumentsBytes - 32]) {
  test(`dispatch fingerprint admits a ${size}-byte body and detects same-length tampering`, async () => {
    const pair = boundary();
    try {
      const text = "z".repeat(size);
      const call = await prepared({
        body: new TextEncoder().encode(text),
        normalizedArguments: { body: text },
      });
      const snapshot = await credential();
      const plan = await pair.transport.prepareDispatch(call, snapshot);
      expect(() =>
        pair.transport.verifyPlan(plan, call, snapshot.binding),
      ).not.toThrow();
      const copiedBody = new Uint8Array(call.body ?? []);
      expect(() =>
        pair.transport.verifyPlan(
          plan,
          { ...call, body: copiedBody },
          snapshot.binding,
        ),
      ).not.toThrow();
      copiedBody[size - 1] ^= 1;
      // Keep the original public digest: verification must inspect actual bytes.
      expect(() =>
        pair.transport.verifyPlan(
          plan,
          { ...call, body: copiedBody },
          snapshot.binding,
        ),
      ).toThrow();
    } finally {
      await pair.close();
    }
  });
}

test("dispatch fingerprint distinguishes absent and zero-byte bodies", async () => {
  const pair = boundary();
  try {
    const snapshot = await credential();
    for (const body of [null, new Uint8Array()]) {
      const call = await prepared({ body });
      const plan = await pair.transport.prepareDispatch(call, snapshot);
      const substituted = body === null ? new Uint8Array() : null;
      expect(() =>
        pair.transport.verifyPlan(plan, call, snapshot.binding),
      ).not.toThrow();
      expect(() =>
        pair.transport.verifyPlan(
          plan,
          { ...call, body: substituted },
          snapshot.binding,
        ),
      ).toThrow();
    }
  } finally {
    await pair.close();
  }
});

test("dispatch fingerprint preserves the independent normalized-argument node budget", async () => {
  const pair = boundary();
  try {
    const values = new Array<number>(99_990).fill(0);
    const call = await prepared({
      body: new Uint8Array(),
      normalizedArguments: { values },
    });
    const snapshot = await credential();
    const plan = await pair.transport.prepareDispatch(call, snapshot);
    expect(() =>
      pair.transport.verifyPlan(plan, call, snapshot.binding),
    ).not.toThrow();
    values[values.length - 1] = 1;
    expect(() =>
      pair.transport.verifyPlan(
        plan,
        { ...call, normalizedArguments: { values } },
        snapshot.binding,
      ),
    ).toThrow();
  } finally {
    await pair.close();
  }
});

test("manifest policy is mandatory, literal true, digest-bound and checked before DNS", async () => {
  expect(() => boundary({ allowsManifestOrigin: undefined })).toThrow();
  const snapshot = await credential();
  for (const allowsManifestOrigin of [
    async () => false,
    async () => "true",
    async () => {
      throw new Error("private policy detail");
    },
  ]) {
    const pair = boundary({ allowsManifestOrigin });
    await expect(
      pair.transport.prepareDispatch(await prepared(), snapshot),
    ).rejects.toMatchObject({ code: "DESTINATION_DENIED" });
    expect(pair.lookups()).toBe(0);
  }
  const pair = boundary();
  await expect(
    pair.transport.prepareDispatch(
      await prepared({ manifestDigest: "f".repeat(64) }),
      snapshot,
    ),
  ).rejects.toMatchObject({ code: "DESTINATION_DENIED" });
  expect(pair.lookups()).toBe(0);
});

test("close invalidates unused plans and interrupts pending manifest and DNS preflight", async () => {
  const pair = boundary();
  const call = await prepared();
  const snapshot = await credential();
  const plan = await pair.transport.prepareDispatch(call, snapshot);
  await pair.close();
  expect(() =>
    pair.transport.verifyPlan(plan, call, snapshot.binding),
  ).toThrow();
  await expect(
    pair.transport.prepareDispatch(call, snapshot),
  ).rejects.toMatchObject({ code: "ACTION_DENIED" });
  await expect(
    pair.paginationTokenCodec.decode("page.v1.invalid.invalid"),
  ).rejects.toMatchObject({ code: "ACTION_DENIED" });
  for (const option of ["allowsManifestOrigin", "lookup"]) {
    let entered: () => void;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const pendingPair = boundary({
      [option]: () => {
        entered();
        return new Promise(() => {});
      },
    });
    const pending = pendingPair.transport.prepareDispatch(call, snapshot);
    const observed = pending.catch((error) => error);
    await started;
    await pendingPair.close();
    expect(await observed).toBeInstanceOf(Error);
  }
}, 1000);

test("factory bounds only reduce defaults and never accept invalid values", () => {
  for (const patch of [
    { planTtlMs: 30_001 },
    { tokenTtlMs: 120_001 },
    { tokenCapacity: 1025 },
    { planTtlMs: 0 },
    { tokenTtlMs: NaN },
    { tokenCapacity: 1.5 },
    { limits: { requestDeadlineMs: 30_001 } },
    { limits: { maxResponseBytes: 8 * 1024 * 1024 + 1 } },
    { limits: { maxRedirects: 4 } },
    { limits: { maxPages: 11 } },
    { limits: { maxPaginationBytes: 16 * 1024 * 1024 + 1 } },
  ])
    expect(() => boundary(patch)).toThrow();
});

test("read dispatch rejects forged read safety on a POST", async () => {
  const pair = boundary();
  const call = await prepared({
    safety: "read",
    actionKind: null,
    cardinality: null,
  });
  const plan = await pair.transport.prepareDispatch(call, await credential());
  await expect(pair.transport.dispatchRead(plan)).rejects.toMatchObject({
    code: "ACTION_DENIED",
  });
});

test("GET and HEAD bodies fail explicitly before DNS or request construction", async () => {
  const pair = boundary();
  for (const method of ["GET", "HEAD"] as const) {
    const call = await prepared({
      method,
      safety: "read",
      actionKind: null,
      cardinality: null,
    });
    await expect(
      pair.transport.prepareDispatch(call, await credential()),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
  }
  expect(pair.lookups()).toBe(0);
});

test("DNS preflight timeout cannot retain an unbounded pending attempt", async () => {
  const guard = new guardModule.NodeDestinationGuard({
    allowedOrigins: profile.allowedOrigins,
    ttlMs: 20,
    lookup: () => new Promise(() => {}),
  });
  await expect(
    guard.authorize(new URL("https://api.example.test/x")),
  ).rejects.toMatchObject({ code: "DESTINATION_DENIED" });
}, 200);

test("preflight detaches secrets and rejects forged profile, binding and credential slots before DNS", async () => {
  const pair = boundary();
  const call = await prepared();
  const snapshot = await credential();
  const plan = await pair.transport.prepareDispatch(call, snapshot);
  expect(Object.isFrozen(plan)).toBe(true);
  expect(Reflect.ownKeys(plan)).toEqual([]);
  pair.transport.verifyPlan(plan, call, snapshot.binding);
  const before = pair.lookups();
  const substitutions = [
    await credential({ profileDigest: "f".repeat(64) }),
    {
      ...snapshot,
      binding: { ...snapshot.binding, grantId: "forged_grant_1234" },
    },
    {
      ...snapshot,
      credential: {
        type: "api-key",
        placement: "query",
        name: "api_key",
        value: "secret",
      },
    },
    {
      ...snapshot,
      credential: { type: "bearer", token: "secret\r\ninjected: yes" },
    },
  ];
  for (const substitution of substitutions)
    await expect(
      pair.transport.prepareDispatch(call, substitution),
    ).rejects.toMatchObject({ code: "AUTH_PROFILE_INVALID" });
  expect(pair.lookups()).toBe(before);
  const changedGrant = await credential({ grantId: "different_grant_123" });
  expect(() =>
    pair.transport.verifyPlan(plan, call, changedGrant.binding),
  ).toThrow();
  expect(() =>
    pair.transport.verifyPlan(
      plan,
      { ...call, relativeUrl: "/evil" },
      snapshot.binding,
    ),
  ).toThrow();
  expect(() =>
    pair.transport.verifyPlan({ ...plan }, call, snapshot.binding),
  ).toThrow();
});

test("registered plans reject expiry, owner substitution and read/action confusion", async () => {
  let now = 100;
  const pair = boundary({ now: () => now });
  const call = await prepared();
  const snapshot = await credential();
  const plan = await pair.transport.prepareDispatch(call, snapshot);
  await expect(pair.transport.dispatchRead(plan)).rejects.toMatchObject({
    code: "ACTION_DENIED",
  });
  await expect(pair.transport.dispatchAction(call, {})).rejects.toMatchObject({
    code: "ACTION_DENIED",
  });
  await expect(
    boundary().transport.dispatchAction(plan, {}),
  ).rejects.toMatchObject({ code: "ACTION_DENIED" });
  const read = await prepared({
    method: "GET",
    body: null,
    safety: "read",
    actionKind: null,
    cardinality: null,
  });
  const readPlan = await pair.transport.prepareDispatch(read, snapshot);
  await expect(
    pair.transport.dispatchAction(readPlan, {}),
  ).rejects.toMatchObject({ code: "ACTION_DENIED" });
  now = 30_100;
  expect(() =>
    pair.transport.verifyPlan(plan, call, snapshot.binding),
  ).toThrow();
  await expect(pair.transport.dispatchRead(readPlan)).rejects.toMatchObject({
    code: "ACTION_DENIED",
  });
});

test("action structural and copied permits are denied without spending the real permit", async () => {
  const pair = boundary();
  const call = await prepared();
  const snapshot = await credential();
  const plan = await pair.transport.prepareDispatch(call, snapshot);
  const decision = await pair.auth.authorize(call, snapshot.binding, {
    kind: "initial",
  });
  const permit = await pair.broker.consume(decision, call, snapshot.binding);
  for (const forged of [
    {},
    { ...permit },
    {
      callDigest: call.preparedCallDigest,
      credentialBindingDigest: snapshot.binding.bindingDigest,
    },
  ])
    await expect(
      pair.transport.dispatchAction(plan, forged),
    ).rejects.toMatchObject({ code: "ACTION_DENIED" });
  pair.transport.verifyPlan(plan, call, snapshot.binding);
});

// Regression targets: permitting a reserved address or trusting only the first
// DNS answer must turn these destination denials into an observable success.
const guardModule = await import("../src/sqlite/destination-guard.ts").catch(
  () => ({}),
);

test("local destination guard is available", () => {
  expect(typeof guardModule.NodeDestinationGuard).toBe("function");
});

const deniedAddresses = [
  "0.0.0.0",
  "0.1.2.3",
  "10.1.2.3",
  "100.64.0.1",
  "127.0.0.1",
  "169.254.169.254",
  "172.16.0.1",
  "172.31.255.255",
  "192.0.0.1",
  "192.0.2.1",
  "192.88.99.1",
  "192.168.0.1",
  "198.18.0.1",
  "198.19.255.255",
  "198.51.100.1",
  "203.0.113.1",
  "224.0.0.1",
  "240.0.0.1",
  "255.255.255.255",
  "::",
  "::1",
  "::ffff:127.0.0.1",
  "::ffff:a01:203",
  "64:ff9b::a00:1",
  "64:ff9b:1::1",
  "100::1",
  "2001::1",
  "2001:db8::1",
  "2002::1",
  "3fff::1",
  "fc00::1",
  "fdff::1",
  "fe80::1",
  "ff02::1",
  "::8.8.8.8",
];

for (const address of deniedAddresses)
  test(`rejects non-public address ${address}`, async () => {
    const guard = new guardModule.NodeDestinationGuard({
      allowedOrigins: ["https://api.example.test"],
      lookup: async () => [{ address, family: address.includes(":") ? 6 : 4 }],
    });
    await expect(
      guard.authorize(new URL("https://api.example.test/x")),
    ).rejects.toMatchObject({ code: "DESTINATION_DENIED" });
  });

test("rejects mixed public and private DNS answers", async () => {
  const guard = new guardModule.NodeDestinationGuard({
    allowedOrigins: ["https://api.example.test"],
    lookup: async () => [
      { address: "8.8.8.8", family: 4 },
      { address: "::1", family: 6 },
    ],
  });
  await expect(
    guard.authorize(new URL("https://api.example.test/x")),
  ).rejects.toMatchObject({ code: "DESTINATION_DENIED" });
});

test("exact HTTPS origin policy rejects mismatches before DNS", async () => {
  let lookups = 0;
  const guard = new guardModule.NodeDestinationGuard({
    allowedOrigins: ["https://api.example.test"],
    lookup: async () => {
      lookups++;
      return [{ address: "8.8.8.8", family: 4 }];
    },
  });
  for (const value of [
    "http://api.example.test/x",
    "https://evil.test/x",
    "https://api.example.test:444/x",
    "https://user:secret@api.example.test/x",
  ]) {
    await expect(guard.authorize(new URL(value))).rejects.toMatchObject({
      code: "DESTINATION_DENIED",
    });
  }
  expect(lookups).toBe(0);
});

test("approved DNS lookup pins addresses, validates hostname and expires", async () => {
  let now = 100;
  let lookups = 0;
  const guard = new guardModule.NodeDestinationGuard({
    allowedOrigins: ["https://api.example.test"],
    now: () => now,
    lookup: async () => {
      lookups++;
      return [{ address: lookups === 1 ? "8.8.8.8" : "127.0.0.1", family: 4 }];
    },
  });
  const approved = await guard.authorize(new URL("https://api.example.test/x"));
  const lookup = (hostname: string, all = false) =>
    new Promise((resolve, reject) => {
      approved.lookup(hostname, { all }, (error, address) =>
        error ? reject(error) : resolve(address),
      );
    });
  expect(await lookup("api.example.test")).toBe("8.8.8.8");
  expect(await lookup("api.example.test", true)).toEqual([
    { address: "8.8.8.8", family: 4 },
  ]);
  expect(lookups).toBe(1);
  await expect(lookup("evil.test")).rejects.toMatchObject({
    code: "DESTINATION_DENIED",
  });
  now = 30_100;
  await expect(lookup("api.example.test")).rejects.toMatchObject({
    code: "DESTINATION_DENIED",
  });
  await expect(
    guard.authorize(new URL("https://api.example.test/x")),
  ).rejects.toMatchObject({ code: "DESTINATION_DENIED" });
});
