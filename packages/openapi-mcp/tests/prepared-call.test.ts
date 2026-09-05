import { expect, test } from "bun:test";
import {
  createPreparedCall,
  digestBytes,
  digestPreparedCall,
  verifyPreparedCall,
} from "../src/runtime/prepared-call.ts";
import { serializeArguments } from "../src/runtime/serialize.ts";
import type {
  OperationRecordV4,
  PreparedCall,
  SchemaRecordV4,
  TypedSchemaId,
} from "../src/runtime/types.ts";

const digest = "a".repeat(64) as PreparedCall["operationDigest"];

async function call(
  overrides: Partial<PreparedCall> = {},
): Promise<PreparedCall> {
  return await createPreparedCall({
    version: 2,
    pageToken: null,
    catalogId: "tiny" as PreparedCall["catalogId"],
    releaseId: "release-1" as PreparedCall["releaseId"],
    operationId: "operation:tiny:createWidget",
    operationDigest: digest,
    manifestDigest: "b".repeat(64) as PreparedCall["manifestDigest"],
    credentialProfileId: "tiny-user",
    credentialProfileDigest: "d".repeat(
      64,
    ) as PreparedCall["credentialProfileDigest"],
    reservedSlotsDigest: "c".repeat(64) as PreparedCall["reservedSlotsDigest"],
    method: "POST",
    origin: "https://api.example.test",
    relativeUrl: "/widgets?view=full",
    headers: { accept: "application/json", "x-trace": "trace-1" },
    body: new Uint8Array([1, 2, 3]),
    normalizedArguments: { body: { name: "Ada" } },
    safety: "action",
    actionKind: "create",
    cardinality: { kind: "single" },
    ...overrides,
  });
}

test("hashes raw body bytes with ordinary SHA-256", async () => {
  expect(await digestBytes(new TextEncoder().encode("abc"))).toBe(
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});

test("creates a frozen credential-free call whose digest binds body and inputs", async () => {
  const sourceBody = new Uint8Array([1, 2, 3]);
  const prepared = await call({ body: sourceBody });
  sourceBody[0] = 9;

  expect(Object.isFrozen(prepared)).toBe(true);
  expect(Object.isFrozen(prepared.headers)).toBe(true);
  expect(Object.isFrozen(prepared.normalizedArguments)).toBe(true);
  expect([...(prepared.body ?? [])]).toEqual([1, 2, 3]);
  const exposedBody = prepared.body;
  expect(exposedBody).not.toBeNull();
  exposedBody[0] = 9;
  expect([...(prepared.body ?? [])]).toEqual([1, 2, 3]);
  expect(JSON.stringify(prepared)).not.toMatch(
    /authorization|"token"|secret|grant|subject/i,
  );
  await expect(verifyPreparedCall(prepared)).resolves.toBeUndefined();

  const changedBody = {
    ...prepared,
    body: new Uint8Array([1, 2, 4]),
  };
  await expect(digestPreparedCall(changedBody)).resolves.not.toBe(
    prepared.preparedCallDigest,
  );
  await expect(verifyPreparedCall(changedBody)).rejects.toMatchObject({
    code: "INPUT_INVALID",
  });
});

test("omits the self digest from canonical preparation input", async () => {
  const prepared = await call();
  await expect(
    digestPreparedCall({
      ...prepared,
      preparedCallDigest: "c".repeat(64) as PreparedCall["preparedCallDigest"],
    }),
  ).resolves.toBe(prepared.preparedCallDigest);
});

test("rejects mutations of every integrity-bound public field", async () => {
  const prepared = await call();
  const mutations: readonly Partial<PreparedCall>[] = [
    { version: 1 as never },
    { catalogId: "other" as PreparedCall["catalogId"] },
    { releaseId: "release-2" as PreparedCall["releaseId"] },
    { operationId: "operation:tiny:other" },
    { operationDigest: "c".repeat(64) as PreparedCall["operationDigest"] },
    { manifestDigest: "d".repeat(64) as PreparedCall["manifestDigest"] },
    { credentialProfileId: "other-profile" },
    {
      credentialProfileDigest: "f".repeat(
        64,
      ) as PreparedCall["credentialProfileDigest"],
    },
    {
      reservedSlotsDigest: "e".repeat(
        64,
      ) as PreparedCall["reservedSlotsDigest"],
    },
    { method: "PUT" },
    { origin: "https://other.example.test" },
    { relativeUrl: "/other" },
    { headers: { accept: "text/plain" } },
    { body: null },
    { normalizedArguments: { body: { name: "Grace" } } },
    { safety: "read", actionKind: null, cardinality: null },
    { actionKind: "update" },
    { cardinality: { kind: "bounded", maxAffected: 2 } },
    { inputDigest: "e".repeat(64) as PreparedCall["inputDigest"] },
    {
      preparedCallDigest: "f".repeat(64) as PreparedCall["preparedCallDigest"],
    },
  ];

  for (const mutation of mutations) {
    await expect(
      verifyPreparedCall({ ...prepared, ...mutation }),
    ).rejects.toMatchObject({
      code: "INPUT_INVALID",
    });
  }
});

test("rejects hostile shape and transport values", async () => {
  const prepared = await call();
  const accessor = Object.defineProperties(
    {},
    {
      ...Object.getOwnPropertyDescriptors(prepared),
      origin: {
        enumerable: true,
        get() {
          throw new Error("origin getter must not run");
        },
      },
    },
  );
  const cases: readonly unknown[] = [
    { ...prepared, extra: true },
    accessor,
    { ...prepared, credentialProfileId: "unstable/profile" },
    { ...prepared, credentialProfileDigest: "A".repeat(64) },
    { ...prepared, origin: "http://api.example.test" },
    { ...prepared, origin: "https://user@api.example.test" },
    { ...prepared, relativeUrl: "//attacker.example/path" },
    { ...prepared, relativeUrl: "/safe#fragment" },
    { ...prepared, headers: { authorization: "Bearer secret" } },
    { ...prepared, headers: { "x-trace": "ok\r\nInjected: yes" } },
    { ...prepared, body: new Uint8Array(256 * 1024 + 1) },
    { ...prepared, cardinality: { kind: "bounded", maxAffected: 0 } },
  ];
  for (const candidate of cases) {
    await expect(
      verifyPreparedCall(candidate as PreparedCall),
    ).rejects.toMatchObject({
      code: "INPUT_INVALID",
    });
  }
});

test("accepts HTAB in a header field value", async () => {
  const prepared = await call({ headers: { "x-trace": "part-one\tpart-two" } });

  expect(prepared.headers["x-trace"]).toBe("part-one\tpart-two");
  await expect(verifyPreparedCall({ ...prepared })).resolves.toBeUndefined();
});

test("rejects every other C0 control and DEL in a header field value", async () => {
  const prepared = await call();
  const forbiddenCodePoints = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x7f,
  ] as const;

  for (const codePoint of forbiddenCodePoints) {
    const headers = {
      "x-trace": `before${String.fromCharCode(codePoint)}after`,
    };
    await expect(call({ headers })).rejects.toMatchObject({
      code: "INPUT_INVALID",
    });
    await expect(
      verifyPreparedCall({
        ...prepared,
        headers,
      }),
    ).rejects.toMatchObject({ code: "INPUT_INVALID" });
  }
});

test("normalizes root and nested proxy traps to a stable input error", async () => {
  const prepared = await call();
  const trap = () => {
    throw new Error("attacker-controlled trap text");
  };
  const cases: readonly unknown[] = [
    new Proxy(prepared, { ownKeys: trap }),
    { ...prepared, headers: new Proxy({}, { getPrototypeOf: trap }) },
    {
      ...prepared,
      cardinality: new Proxy({ kind: "single" }, { ownKeys: trap }),
    },
    {
      ...prepared,
      normalizedArguments: new Proxy({}, { ownKeys: trap }),
    },
  ];
  for (const candidate of cases) {
    await expect(
      verifyPreparedCall(candidate as PreparedCall),
    ).rejects.toMatchObject({
      code: "INPUT_INVALID",
      message: "Prepared call is invalid",
    });
  }
});

test("accepts ordinary declared token-like headers from serialization through verification", async () => {
  const schemaId = "schema:tiny:header-text" as TypedSchemaId;
  const schema: SchemaRecordV4 = {
    id: schemaId,
    schema: { type: "string" },
  };
  const operation: OperationRecordV4 = {
    id: "operation:tiny:updateWidget",
    api: "tiny",
    operationId: "updateWidget",
    method: "PATCH",
    path: "/widgets",
    origin: "https://api.example.test",
    summary: null,
    tags: [],
    deprecated: false,
    parameters: [
      "Api-Key",
      "Authentication",
      "X-Auth",
      "X-Bearer-Token",
      "X-Credential",
      "X-Password",
      "X-Secret",
      "X-Session-Token",
      "X-Token",
    ].map((name) => ({
      name,
      in: "header" as const,
      required: true,
      deprecated: false,
      style: "simple" as const,
      explode: false,
      allowReserved: false,
      value: { kind: "schema" as const, schemaId },
    })),
    requestBody: null,
    schemaIds: [schemaId],
    advisory: {},
  };
  const serialized = serializeArguments(
    operation,
    new Map([[schemaId, schema]]),
    {
      headers: {
        "Api-Key": "display-key",
        Authentication: "domain-authentication",
        "X-Auth": "domain-auth",
        "X-Bearer-Token": "domain-bearer-token",
        "X-Credential": "domain-credential",
        "X-Password": "domain-password",
        "X-Secret": "domain-secret",
        "X-Session-Token": "domain-session-token",
        "X-Token": "workflow-token",
      },
    },
  );
  const prepared = await createPreparedCall({
    version: 2,
    pageToken: null,
    catalogId: "tiny" as PreparedCall["catalogId"],
    releaseId: "release-1" as PreparedCall["releaseId"],
    operationId: operation.id,
    operationDigest: digest,
    manifestDigest: "b".repeat(64) as PreparedCall["manifestDigest"],
    credentialProfileId: "tiny-user",
    credentialProfileDigest: "d".repeat(
      64,
    ) as PreparedCall["credentialProfileDigest"],
    reservedSlotsDigest: "c".repeat(64) as PreparedCall["reservedSlotsDigest"],
    method: operation.method,
    origin: operation.origin,
    relativeUrl: serialized.relativeUrl,
    headers: serialized.headers,
    body: serialized.body,
    normalizedArguments: serialized.normalizedArguments,
    safety: "action",
    actionKind: "update",
    cardinality: { kind: "single" },
  });

  expect(prepared.headers).toEqual({
    accept: "application/json",
    "api-key": "display-key",
    authentication: "domain-authentication",
    "x-auth": "domain-auth",
    "x-bearer-token": "domain-bearer-token",
    "x-credential": "domain-credential",
    "x-password": "domain-password",
    "x-secret": "domain-secret",
    "x-session-token": "domain-session-token",
    "x-token": "workflow-token",
  });
  await expect(verifyPreparedCall(prepared)).resolves.toBeUndefined();
  const copied = { ...prepared };
  await expect(verifyPreparedCall(copied)).resolves.toBeUndefined();
  await expect(digestPreparedCall(copied)).resolves.toBe(
    prepared.preparedCallDigest,
  );
});

test.each([
  "host",
  "connection",
  "content-length",
  "set-cookie",
  "keep-alive",
  "proxy-authenticate",
  "www-authenticate",
  "te",
  "transfer-encoding",
  "trailer",
  "upgrade",
  "via",
  "forwarded",
  "x-forwarded-for",
  "x-auth-token",
  "authorization",
  "cookie",
  "proxy-authorization",
  "x-api-key",
  "cf-access-client-id",
  "cf-connecting-ip",
  "cf-connecting-ipv6",
  "cf-pseudo-ipv4",
  "cloudfront-viewer-address",
  "fastly-client-ip",
  "fly-client-ip",
  "true-client-ip",
  "x-azure-clientip",
  "x-client-id",
  "x-client-ip",
  "x-client-secret",
  "x-cluster-client-ip",
  "x-envoy-external-address",
  "x-appengine-user-ip",
  "x-provider-id",
  "x-real-ip",
  "x-amz-security-token",
  "x-aws-principal",
  "x-goog-authenticated-user-email",
  "x-ms-client-principal",
  "x-original-forwarded-for",
  "sec-fetch-site",
  "proxy-connection",
])(
  "rejects forbidden transport or provider-identity header %s",
  async (name) => {
    await expect(call({ headers: { [name]: "value" } })).rejects.toMatchObject({
      code: "INPUT_INVALID",
    });
  },
);

test("does not reject an ordinary declared non-credential header by name heuristics", async () => {
  const prepared = await call({ headers: { "x-workflow-tokenizer": "v1" } });
  await expect(verifyPreparedCall(prepared)).resolves.toBeUndefined();
});

test.each([
  "x-amz-copy-source",
  "x-amz-meta-color",
  "x-amz-checksum-sha256",
  "x-goog-meta-color",
  "x-ms-blob-type",
])("accepts non-credential provider header %s", async (name) => {
  const prepared = await call({ headers: { [name]: "value" } });
  await expect(verifyPreparedCall(prepared)).resolves.toBeUndefined();
});

test("verifies and digests a copied owned call through the strict untrusted path", async () => {
  const prepared = await call();
  const copied = { ...prepared };
  await expect(verifyPreparedCall(copied)).resolves.toBeUndefined();
  await expect(digestPreparedCall(copied)).resolves.toBe(
    prepared.preparedCallDigest,
  );
});
