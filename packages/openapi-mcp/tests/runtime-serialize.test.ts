import { expect, test } from "bun:test";
import { serializeArguments } from "../src/runtime/serialize.ts";
import type {
  OperationRecordV4,
  SchemaRecordV4,
  TypedSchemaId,
} from "../src/runtime/types.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function schema(name: string, value: SchemaRecordV4["schema"]): SchemaRecordV4 {
  return { id: `schema:tiny:${name}`, schema: value };
}

function schemas(
  ...records: readonly SchemaRecordV4[]
): ReadonlyMap<TypedSchemaId, Readonly<SchemaRecordV4>> {
  return new Map(records.map((record) => [record.id, record]));
}

function operation(
  overrides: Partial<OperationRecordV4> = {},
): OperationRecordV4 {
  return {
    id: "operation:tiny:getWidget",
    api: "tiny",
    operationId: "getWidget",
    method: "GET",
    path: "/widgets/{id}",
    origin: "https://api.example.test",
    summary: null,
    deprecated: false,
    parameters: [],
    requestBody: null,
    schemaIds: [],
    tags: [],
    advisory: {},
    ...overrides,
  };
}

function parameter(
  name: string,
  location: "path" | "query" | "header" | "cookie",
  schemaId: TypedSchemaId,
  overrides: Partial<OperationRecordV4["parameters"][number]> = {},
): OperationRecordV4["parameters"][number] {
  return {
    name,
    in: location,
    required: location === "path",
    deprecated: false,
    style: location === "query" ? "form" : "simple",
    explode: location === "query",
    allowReserved: false,
    value: { kind: "schema", schemaId },
    ...overrides,
  };
}

test("serializes declared path, query, and header parameters deterministically", () => {
  const id = schema("id", { type: "string", minLength: 1 });
  const tags = schema("tags", {
    type: "array",
    items: { type: "string" },
    minItems: 1,
    maxItems: 3,
  });
  const trace = schema("trace", { type: "string" });
  const result = serializeArguments(
    operation({
      parameters: [
        parameter("id", "path", id.id),
        parameter("tag", "query", tags.id),
        parameter("X-Trace", "header", trace.id),
      ],
      schemaIds: [id.id, tags.id, trace.id].sort(),
    }),
    schemas(id, tags, trace),
    {
      path: { id: "a/b c" },
      query: { tag: ["blue", "a&b"] },
      headers: { "x-trace": "trace-7" },
    },
  );

  expect(result.relativeUrl).toBe("/widgets/a%2Fb%20c?tag=blue&tag=a%26b");
  expect(result.headers).toEqual({
    accept: "application/json",
    "x-trace": "trace-7",
  });
  expect(result.body).toBeNull();
  expect(result.normalizedArguments).toEqual({
    headers: { "X-Trace": "trace-7" },
    path: { id: "a/b c" },
    query: { tag: ["blue", "a&b"] },
  });
});

test("serializes supported style and explode combinations", () => {
  const text = schema("text", { type: "string" });
  const array = schema("array", {
    type: "array",
    items: { type: "string" },
  });
  const object = schema("object", {
    type: "object",
    properties: { a: { type: "string" }, z: { type: "string" } },
    additionalProperties: false,
  });
  const result = serializeArguments(
    operation({
      path: "/items/{matrix}/{label}",
      parameters: [
        parameter("matrix", "path", text.id, {
          style: "matrix",
          explode: true,
        }),
        parameter("label", "path", text.id, {
          style: "label",
          explode: true,
        }),
        parameter("coords", "query", array.id, {
          style: "pipeDelimited",
          explode: false,
        }),
        parameter("filter", "query", object.id, {
          style: "deepObject",
          explode: true,
        }),
        parameter("X-Options", "header", text.id, {
          style: "simple",
          explode: true,
        }),
      ],
      schemaIds: [array.id, object.id, text.id],
    }),
    schemas(array, object, text),
    {
      path: { matrix: "m", label: "x" },
      query: {
        coords: ["10", "20"],
        filter: { z: "last", a: "first" },
      },
      headers: { "X-Options": "a=first,z=last" },
    },
  );

  expect(result.relativeUrl).toBe(
    "/items/;matrix=m/.x?coords=10%7C20&filter%5Ba%5D=first&filter%5Bz%5D=last",
  );
  expect(result.headers["x-options"]).toBe("a=first,z=last");
});

test("validates schemas, refs, bounds, enums, nullability, and composition", () => {
  const branchA = schema("branch-a", {
    type: "object",
    required: ["kind", "value"],
    properties: {
      kind: { const: "a" },
      value: { type: "integer", minimum: 1, maximum: 4 },
    },
    additionalProperties: false,
  });
  const branchB = schema("branch-b", {
    type: "object",
    required: ["kind", "value"],
    properties: {
      kind: { const: "b" },
      value: { type: "string", enum: ["ok"] },
    },
    additionalProperties: false,
  });
  const root = schema("root", {
    oneOf: [{ $ref: branchA.id }, { $ref: branchB.id }],
    discriminator: {
      propertyName: "kind",
      mapping: { a: branchA.id, b: branchB.id },
    },
  });
  const nullable = schema("nullable", { type: "string", nullable: true });
  const op = operation({
    path: "/validate",
    parameters: [
      parameter("choice", "query", root.id),
      parameter("note", "query", nullable.id),
    ],
    schemaIds: [nullable.id, root.id],
  });
  const closure = schemas(root, branchA, branchB, nullable);

  expect(
    serializeArguments(op, closure, {
      query: { choice: { kind: "a", value: 4 }, note: null },
    }).relativeUrl,
  ).toBe("/validate?kind=a&value=4&note=null");
  expect(() =>
    serializeArguments(op, closure, {
      query: { choice: { kind: "a", value: 5 } },
    }),
  ).toThrow(expect.objectContaining({ code: "INPUT_INVALID" }));
});

test("validates multipleOf using exact finite-number decimal semantics", () => {
  const integerStep = schema("integer-step", { type: "number", multipleOf: 1 });
  const decimalStep = schema("decimal-step", {
    type: "number",
    multipleOf: 0.1,
  });
  const op = operation({
    path: "/validate",
    parameters: [
      parameter("integer", "query", integerStep.id),
      parameter("decimal", "query", decimalStep.id),
    ],
    schemaIds: [decimalStep.id, integerStep.id],
  });
  const closure = schemas(integerStep, decimalStep);

  expect(
    serializeArguments(op, closure, {
      query: { integer: 2, decimal: 0.3 },
    }).relativeUrl,
  ).toBe("/validate?integer=2&decimal=0.3");
  expect(() =>
    serializeArguments(op, closure, {
      query: { integer: 1.00000000001, decimal: 0.3 },
    }),
  ).toThrow(expect.objectContaining({ code: "INPUT_INVALID" }));
  expect(() =>
    serializeArguments(op, closure, {
      query: { integer: 2, decimal: 0.30000000000000004 },
    }),
  ).toThrow(expect.objectContaining({ code: "INPUT_INVALID" }));
});

test("validates finite inputs through recursive schema references", () => {
  const node = schema("node", {
    anyOf: [
      { type: "null" },
      {
        type: "object",
        required: ["next"],
        properties: { next: { $ref: "schema:tiny:node" } },
        additionalProperties: false,
      },
    ],
  });
  const result = serializeArguments(
    operation({
      method: "POST",
      path: "/nodes",
      requestBody: {
        required: true,
        content: [
          {
            mediaType: "application/json" as never,
            schemaId: node.id,
            encoding: [],
          },
        ],
      },
      schemaIds: [node.id],
    }),
    schemas(node),
    { body: { next: { next: null } } },
  );
  expect(decoder.decode(result.body ?? encoder.encode("missing"))).toBe(
    '{"next":{"next":null}}',
  );
});

test("bounds schema branch evaluation work", () => {
  const expensive = schema("expensive", {
    anyOf: [
      ...Array.from({ length: 32 }, (_, index) => ({ const: index })),
      { type: "string" },
    ],
  });
  expect(() =>
    serializeArguments(
      operation({
        path: "/validate",
        parameters: [parameter("value", "query", expensive.id)],
        schemaIds: [expensive.id],
      }),
      schemas(expensive),
      { query: { value: "ok" } },
      { limits: { maxArgumentsBytes: 24 } },
    ),
  ).toThrow(expect.objectContaining({ code: "INPUT_INVALID", details: {} }));
});

test("charges enum member comparisons to the shared validation budget", () => {
  const value = "target-123456789";
  const expensive = schema("expensive-enum", {
    enum: [
      ...Array.from(
        { length: 32 },
        (_, index) => `member-${index.toString().padStart(10, "0")}`,
      ),
      value,
    ],
  });
  expect(() =>
    serializeArguments(
      operation({
        path: "/validate",
        parameters: [parameter("value", "query", expensive.id)],
        schemaIds: [expensive.id],
      }),
      schemas(expensive),
      { query: { value } },
      { limits: { maxArgumentsBytes: 64 } },
    ),
  ).toThrow(expect.objectContaining({ code: "INPUT_INVALID", details: {} }));
});

test("handles self-referential anyOf without rejecting a valid branch", () => {
  const self = schema("self-any-of", {
    anyOf: [
      { $ref: "schema:tiny:self-any-of" },
      { $ref: "schema:tiny:self-any-of" },
      { type: "string" },
    ],
  });
  expect(
    serializeArguments(
      operation({
        path: "/validate",
        parameters: [parameter("value", "query", self.id)],
        schemaIds: [self.id],
      }),
      schemas(self),
      { query: { value: "ok" } },
    ).relativeUrl,
  ).toBe("/validate?value=ok");
});

test("handles mutually-referential oneOf without rejecting a valid branch", () => {
  const left = schema("left-one-of", {
    oneOf: [{ $ref: "schema:tiny:right-one-of" }, { type: "string" }],
  });
  const right = schema("right-one-of", {
    oneOf: [{ $ref: "schema:tiny:left-one-of" }, { type: "number" }],
  });
  expect(
    serializeArguments(
      operation({
        path: "/validate",
        parameters: [parameter("value", "query", left.id)],
        schemaIds: [left.id, right.id],
      }),
      schemas(left, right),
      { query: { value: "ok" } },
    ).relativeUrl,
  ).toBe("/validate?value=ok");
});

test("allows a reference to be reused sequentially for the same value", () => {
  const text = schema("reusable-text", { type: "string", minLength: 1 });
  const root = schema("reusable-root", {
    allOf: [{ $ref: text.id }, { $ref: text.id }],
  });
  expect(
    serializeArguments(
      operation({
        path: "/validate",
        parameters: [parameter("value", "query", root.id)],
        schemaIds: [root.id, text.id],
      }),
      schemas(root, text),
      { query: { value: "ok" } },
    ).relativeUrl,
  ).toBe("/validate?value=ok");
});

test("rejects ambiguous oneOf and unsupported discriminators", () => {
  const ambiguous = schema("ambiguous", {
    oneOf: [{ type: "string" }, { enum: ["same"] }],
  });
  const unsupported = schema("unsupported", {
    oneOf: [{ type: "string" }],
    discriminator: { propertyName: "kind" },
  });

  for (const candidate of [ambiguous, unsupported]) {
    expect(() =>
      serializeArguments(
        operation({
          path: "/validate",
          parameters: [parameter("value", "query", candidate.id)],
          schemaIds: [candidate.id],
        }),
        schemas(candidate),
        { query: { value: "same" } },
      ),
    ).toThrow(expect.objectContaining({ code: "INPUT_INVALID" }));
  }
});

test("rejects unknown, missing, cookie, credential, transport, and CRLF inputs", () => {
  const text = schema("text", { type: "string" });
  const cases: Array<readonly [OperationRecordV4, unknown]> = [
    [operation({ path: "/fixed" }), { query: { unknown: "x" } }],
    [
      operation({
        parameters: [parameter("id", "path", text.id)],
        schemaIds: [text.id],
      }),
      {},
    ],
    [
      operation({
        path: "/fixed",
        parameters: [parameter("session", "cookie", text.id)],
        schemaIds: [text.id],
      }),
      {},
    ],
    [
      operation({
        path: "/fixed",
        parameters: [parameter("Authorization", "header", text.id)],
        schemaIds: [text.id],
      }),
      { headers: { authorization: "Bearer secret" } },
    ],
    [
      operation({
        path: "/fixed",
        parameters: [parameter("X-Forwarded-Host", "header", text.id)],
        schemaIds: [text.id],
      }),
      { headers: { "x-forwarded-host": "evil.test" } },
    ],
    [
      operation({
        path: "/fixed",
        parameters: [parameter("X-Safe", "header", text.id)],
        schemaIds: [text.id],
      }),
      { headers: { "x-safe": "ok\r\ninjected: yes" } },
    ],
  ];

  for (const [op, input] of cases) {
    expect(() => serializeArguments(op, schemas(text), input)).toThrow(
      expect.objectContaining({ code: "INPUT_INVALID" }),
    );
  }
});

test.each(
  [...Array.from({ length: 32 }, (_, code) => code), 0x7f]
    .filter((code) => code !== 0x09)
    .map((code) => [code.toString(16).padStart(4, "0"), code] as const),
)(
  "rejects HTTP header control U+%s before emitting the serialized value",
  (_label, code) => {
    const text = schema("controlled-header", { type: "string" });
    const op = operation({
      path: "/fixed",
      parameters: [parameter("X-Safe", "header", text.id)],
      schemaIds: [text.id],
    });

    expect(() =>
      serializeArguments(op, schemas(text), {
        headers: { "X-Safe": `before${String.fromCharCode(code)}after` },
      }),
    ).toThrow(expect.objectContaining({ code: "INPUT_INVALID" }));
  },
);

test("allows horizontal tab and ordinary field content in serialized headers", () => {
  const text = schema("allowed-header-content", { type: "string" });
  const result = serializeArguments(
    operation({
      path: "/fixed",
      parameters: [parameter("X-Safe", "header", text.id)],
      schemaIds: [text.id],
    }),
    schemas(text),
    { headers: { "X-Safe": "one\ttwo !~" } },
  );

  expect(result.headers["x-safe"]).toBe("one\ttwo !~");
});

test.each([
  "Forwarded",
  "fOrWaRdEd",
  "CF-Connecting-IP",
  "CF-Connecting-IPv6",
  "CF-Pseudo-IPv4",
  "True-Client-IP",
  "Fastly-Client-IP",
  "Fly-Client-IP",
  "CloudFront-Viewer-Address",
  "X-Appengine-User-IP",
  "X-Azure-ClientIP",
  "X-Client-IP",
  "X-Cluster-Client-IP",
  "X-Envoy-External-Address",
  "X-Provider-Id",
  "CF-Access-Authenticated-User-Email",
  "X-Amz-Security-Token",
  "X-Auth-Request-User",
  "X-Aws-Principal",
  "X-Goog-Authenticated-User-Email",
  "X-Ms-Client-Principal",
])("rejects provider-controlled forwarding or identity header %s", (name) => {
  const text = schema("provider-header", { type: "string" });
  expect(() =>
    serializeArguments(
      operation({
        path: "/fixed",
        parameters: [parameter(name, "header", text.id)],
        schemaIds: [text.id],
      }),
      schemas(text),
      { headers: { [name]: "provider-controlled" } },
    ),
  ).toThrow(expect.objectContaining({ code: "INPUT_INVALID" }));
});

test.each([
  "X-Amz-Copy-Source",
  "X-Amz-Meta-Color",
  "X-Amz-Checksum-Sha256",
  "X-Goog-Meta-Color",
  "X-Ms-Blob-Type",
])("allows declared non-credential provider header %s", (name) => {
  const text = schema("provider-data-header", { type: "string" });
  const result = serializeArguments(
    operation({
      path: "/fixed",
      parameters: [parameter(name, "header", text.id)],
      schemaIds: [text.id],
    }),
    schemas(text),
    { headers: { [name]: "value" } },
  );
  expect(result.headers[name.toLowerCase()]).toBe("value");
});

test("allows schema-declared semantic key, password, token, and body data without reserved slots", () => {
  const text = schema("text", { type: "string" });
  const body = schema("semantic-body", {
    type: "object",
    required: ["password", "token"],
    properties: {
      password: { type: "string" },
      token: { type: "string" },
    },
    additionalProperties: false,
  });
  const result = serializeArguments(
    operation({
      method: "POST",
      path: "/semantic",
      parameters: [
        parameter("api_key", "query", text.id),
        parameter("pageToken", "query", text.id),
        parameter("key", "query", text.id),
        parameter("Api-Key", "header", text.id),
      ],
      requestBody: {
        required: true,
        content: [
          {
            mediaType: "application/json" as never,
            schemaId: body.id,
            encoding: [],
          },
        ],
      },
      schemaIds: [body.id, text.id],
    }),
    schemas(text, body),
    {
      query: {
        api_key: "display-key",
        pageToken: "Bearer semantic-marker",
        key: "ordinary-key",
      },
      headers: { "Api-Key": "not-a-host-credential" },
      body: { password: "user-selected", token: "domain-token" },
    },
  );

  expect(result.relativeUrl).toBe(
    "/semantic?api_key=display-key&pageToken=Bearer%20semantic-marker&key=ordinary-key",
  );
  expect(result.headers["api-key"]).toBe("not-a-host-credential");
  expect(result.normalizedArguments.body).toEqual({
    password: "user-selected",
    token: "domain-token",
  });
});

test("rejects exact reserved credential-slot collisions after wire serialization", () => {
  const text = schema("text", { type: "string" });
  const object = schema("slot-object", {
    type: "object",
    properties: { q: { type: "string" } },
    additionalProperties: false,
  });
  const direct = operation({
    path: "/search",
    parameters: [parameter("api_key", "query", text.id)],
    schemaIds: [text.id],
  });
  expect(() =>
    serializeArguments(
      direct,
      schemas(text),
      { query: { api_key: "ordinary" } },
      {
        reservedCredentialSlots: [{ placement: "query", name: "api_key" }],
      },
    ),
  ).toThrow(expect.objectContaining({ code: "INPUT_INVALID" }));

  const exploded = operation({
    path: "/search",
    parameters: [
      parameter("filter", "query", object.id, {
        style: "form",
        explode: true,
      }),
    ],
    schemaIds: [object.id],
  });
  expect(() =>
    serializeArguments(
      exploded,
      schemas(object),
      { query: { filter: { q: "nested" } } },
      { reservedCredentialSlots: [{ placement: "query", name: "q" }] },
    ),
  ).toThrow(expect.objectContaining({ code: "INPUT_INVALID" }));

  const deep = operation({
    path: "/search",
    parameters: [
      parameter("filter", "query", object.id, {
        style: "deepObject",
        explode: true,
      }),
    ],
    schemaIds: [object.id],
  });
  expect(() =>
    serializeArguments(
      deep,
      schemas(object),
      { query: { filter: { q: "nested" } } },
      {
        reservedCredentialSlots: [{ placement: "query", name: "filter[q]" }],
      },
    ),
  ).toThrow(expect.objectContaining({ code: "INPUT_INVALID" }));
  expect(
    serializeArguments(
      deep,
      schemas(object),
      { query: { filter: { q: "nested" } } },
      {
        reservedCredentialSlots: [{ placement: "query", name: "filter[z]" }],
      },
    ).relativeUrl,
  ).toBe("/search?filter%5Bq%5D=nested");
});

test("rejects reserved header slots case-insensitively against declared and emitted headers", () => {
  const text = schema("text", { type: "string" });
  expect(() =>
    serializeArguments(
      operation({
        path: "/fixed",
        parameters: [parameter("X-Service-Key", "header", text.id)],
        schemaIds: [text.id],
      }),
      schemas(text),
      {},
      {
        reservedCredentialSlots: [
          { placement: "header", name: "x-service-key" },
        ],
      },
    ),
  ).toThrow(expect.objectContaining({ code: "INPUT_INVALID" }));

  expect(() =>
    serializeArguments(
      operation({ path: "/fixed" }),
      schemas(),
      {},
      {
        reservedCredentialSlots: [{ placement: "header", name: "Accept" }],
      },
    ),
  ).toThrow(expect.objectContaining({ code: "INPUT_INVALID" }));
});

test("validates exact bounded host-owned credential-slot options without reading accessors", () => {
  let reads = 0;
  const accessor = Object.defineProperty({}, "reservedCredentialSlots", {
    enumerable: true,
    get() {
      reads += 1;
      return [];
    },
  });
  expect(() =>
    serializeArguments(
      operation({ path: "/fixed" }),
      schemas(),
      {},
      accessor as never,
    ),
  ).toThrow(expect.objectContaining({ code: "INPUT_INVALID" }));
  expect(reads).toBe(0);

  const invalidOptions: unknown[] = [
    { unexpected: true },
    { reservedCredentialSlots: [{ placement: "cookie", name: "session" }] },
    {
      reservedCredentialSlots: [
        { placement: "header", name: "X-Key" },
        { placement: "header", name: "x-key" },
      ],
    },
    {
      reservedCredentialSlots: Array.from({ length: 65 }, (_, index) => ({
        placement: "query",
        name: `slot-${index}`,
      })),
    },
  ];
  for (const options of invalidOptions) {
    expect(() =>
      serializeArguments(
        operation({ path: "/fixed" }),
        schemas(),
        {},
        options as never,
      ),
    ).toThrow(expect.objectContaining({ code: "INPUT_INVALID" }));
  }

  expect(() =>
    serializeArguments(operation({ path: "/fixed" }), schemas(), {
      reservedCredentialSlots: [{ placement: "query", name: "q" }],
    }),
  ).toThrow(expect.objectContaining({ code: "INPUT_INVALID" }));
});

test("rejects collisions between final encoded query wire keys", () => {
  const text = schema("text", { type: "string" });
  const object = schema("object", {
    type: "object",
    properties: { q: { type: "string" } },
    additionalProperties: false,
  });
  const formCollision = operation({
    path: "/search",
    parameters: [
      parameter("filter", "query", object.id, {
        style: "form",
        explode: true,
      }),
      parameter("q", "query", text.id),
    ],
    schemaIds: [object.id, text.id],
  });
  expect(() =>
    serializeArguments(formCollision, schemas(text, object), {
      query: { filter: { q: "nested" }, q: "direct" },
    }),
  ).toThrow(expect.objectContaining({ code: "INPUT_INVALID" }));

  const deepObjectCollision = operation({
    path: "/search",
    parameters: [
      parameter("filter[q]", "query", text.id),
      parameter("filter", "query", object.id, {
        style: "deepObject",
        explode: true,
      }),
    ],
    schemaIds: [object.id, text.id],
  });
  expect(() =>
    serializeArguments(deepObjectCollision, schemas(text, object), {
      query: { "filter[q]": "direct", filter: { q: "nested" } },
    }),
  ).toThrow(expect.objectContaining({ code: "INPUT_INVALID" }));
});

test("takes an exact own-data detached snapshot before validation", () => {
  let reads = 0;
  const accessor = Object.defineProperty({}, "query", {
    enumerable: true,
    get() {
      reads += 1;
      return {};
    },
  });
  expect(() =>
    serializeArguments(operation({ path: "/fixed" }), schemas(), accessor),
  ).toThrow(expect.objectContaining({ code: "INPUT_INVALID" }));
  expect(reads).toBe(0);

  const inherited = Object.create({ query: {} });
  expect(() =>
    serializeArguments(operation({ path: "/fixed" }), schemas(), inherited),
  ).toThrow(expect.objectContaining({ code: "INPUT_INVALID" }));
});

test("enforces maxArgumentsBytes without exposing partial output", () => {
  const text = schema("text", { type: "string" });
  expect(() =>
    serializeArguments(
      operation({
        path: "/fixed",
        parameters: [parameter("q", "query", text.id)],
        schemaIds: [text.id],
      }),
      schemas(text),
      { query: { q: "x".repeat(100) } },
      { limits: { maxArgumentsBytes: 32 } },
    ),
  ).toThrow(expect.objectContaining({ code: "INPUT_INVALID", details: {} }));
});

test("emits canonical JSON body bytes and generated representation headers", () => {
  const body = schema("body", {
    type: "object",
    required: ["name"],
    properties: {
      name: { type: "string", minLength: 1, maxLength: 20 },
      count: { type: "integer", minimum: 0 },
    },
    additionalProperties: false,
  });
  const result = serializeArguments(
    operation({
      method: "POST",
      path: "/widgets",
      requestBody: {
        required: true,
        content: [
          {
            mediaType: "application/json" as never,
            schemaId: body.id,
            encoding: [],
          },
        ],
      },
      schemaIds: [body.id],
    }),
    schemas(body),
    { body: { name: "Ada", count: 2 } },
  );

  expect(result.headers).toEqual({
    accept: "application/json",
    "content-type": "application/json",
  });
  expect(decoder.decode(result.body ?? encoder.encode("missing"))).toBe(
    '{"count":2,"name":"Ada"}',
  );
  expect(result.normalizedArguments).toEqual({
    body: { count: 2, name: "Ada" },
  });
});

test("returns deeply immutable normalized arguments and defensive body copies", () => {
  const body = schema("immutable-body", {
    type: "object",
    required: ["items"],
    properties: {
      items: {
        type: "array",
        items: {
          type: "object",
          required: ["name"],
          properties: { name: { type: "string" } },
          additionalProperties: false,
        },
      },
    },
    additionalProperties: false,
  });
  const result = serializeArguments(
    operation({
      method: "POST",
      path: "/widgets",
      requestBody: {
        required: true,
        content: [
          {
            mediaType: "application/json" as never,
            schemaId: body.id,
            encoding: [],
          },
        ],
      },
      schemaIds: [body.id],
    }),
    schemas(body),
    { body: { items: [{ name: "Ada" }] } },
  );

  const normalizedBody = result.normalizedArguments.body as {
    items: Array<{ name: string }>;
  };
  expect(Object.isFrozen(result.normalizedArguments)).toBe(true);
  expect(Object.isFrozen(normalizedBody)).toBe(true);
  expect(Object.isFrozen(normalizedBody.items)).toBe(true);
  expect(Object.isFrozen(normalizedBody.items[0])).toBe(true);

  const firstRead = result.body;
  expect(firstRead).not.toBeNull();
  if (firstRead !== null) firstRead[0] = 0;
  expect(decoder.decode(result.body ?? encoder.encode("missing"))).toBe(
    '{"items":[{"name":"Ada"}]}',
  );
  expect(result.body).not.toBe(result.body);
});

test("rejects unsupported parameter content, body media, encoding, and unsafe paths", () => {
  const text = schema("text", { type: "string" });
  const patterned = schema("patterned", { type: "string", pattern: "^ok$" });
  const body = schema("body", { type: "object" });
  const cases: Array<readonly [OperationRecordV4, unknown]> = [
    [
      operation({
        path: "/fixed",
        parameters: [
          {
            ...parameter("q", "query", text.id),
            value: {
              kind: "content",
              mediaType: "application/json" as never,
              schemaId: text.id,
            },
          },
        ],
        schemaIds: [text.id],
      }),
      { query: { q: "x" } },
    ],
    [
      operation({
        method: "POST",
        path: "/fixed",
        requestBody: {
          required: true,
          content: [
            {
              mediaType: "text/plain" as never,
              schemaId: body.id,
              encoding: [],
            },
          ],
        },
        schemaIds: [body.id],
      }),
      { body: {} },
    ],
    [
      operation({
        method: "POST",
        path: "/fixed",
        requestBody: {
          required: true,
          content: [
            {
              mediaType: "application/json" as never,
              schemaId: body.id,
              encoding: [
                {
                  property: "x",
                  contentType: null,
                  style: null,
                  explode: null,
                  allowReserved: false,
                  headers: [],
                },
              ],
            },
          ],
        },
        schemaIds: [body.id],
      }),
      { body: {} },
    ],
    [operation({ path: "//evil.test/steal" }), {}],
    [operation({ path: "/\\evil.test/steal" }), {}],
    [
      operation({
        path: "/fixed",
        parameters: [parameter("Bad Name", "header", text.id)],
        schemaIds: [text.id],
      }),
      { headers: { "Bad Name": "x" } },
    ],
    [
      operation({
        path: "/fixed",
        parameters: [parameter("q", "query", patterned.id)],
        schemaIds: [patterned.id],
      }),
      { query: { q: "ok" } },
    ],
    [
      operation({
        path: "/fixed",
        parameters: [parameter("q", "query", text.id, { allowReserved: true })],
        schemaIds: [text.id],
      }),
      { query: { q: "a/b" } },
    ],
  ];

  for (const [op, input] of cases) {
    expect(() =>
      serializeArguments(op, schemas(text, body, patterned), input),
    ).toThrow(expect.objectContaining({ code: "INPUT_INVALID" }));
  }
});
