import { expect, test } from "bun:test";
import { countKeys, sliceSpec } from "../src/slice.ts";

const spec = {
  openapi: "3.0.1",
  info: { title: "Fixture", version: "1" },
  servers: [{ url: "https://api.example.com/v1.0" }],
  paths: {
    "/me/messages": {
      parameters: [{ $ref: "#/components/parameters/top" }],
      get: {
        tags: ["me.message"],
        operationId: "me.ListMessages",
        responses: {
          "200": { $ref: "#/components/responses/messageCollection" },
        },
      },
      post: {
        tags: ["me.message"],
        operationId: "me.CreateMessages",
        requestBody: {
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/message" },
            },
          },
        },
        responses: { "201": { description: "ok" } },
      },
    },
    "/me/sendMail": {
      post: {
        tags: ["me.Actions"],
        operationId: "me.sendMail",
        requestBody: {
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  message: { $ref: "#/components/schemas/message" },
                },
              },
            },
          },
        },
        responses: { "204": { description: "ok" } },
      },
    },
    "/drives": {
      get: {
        tags: ["drives.drive"],
        operationId: "drives.ListDrive",
        responses: { "200": { description: "ok" } },
      },
    },
  },
  components: {
    parameters: {
      top: { name: "$top", in: "query", schema: { type: "integer" } },
    },
    responses: {
      messageCollection: {
        description: "ok",
        content: {
          "application/json": {
            schema: {
              type: "array",
              items: { $ref: "#/components/schemas/message" },
            },
          },
        },
      },
    },
    schemas: {
      message: {
        allOf: [
          { $ref: "#/components/schemas/entity" },
          {
            type: "object",
            properties: { body: { $ref: "#/components/schemas/itemBody" } },
          },
        ],
      },
      entity: {
        type: "object",
        properties: { id: { type: "string" } },
        discriminator: {
          propertyName: "@odata.type",
          mapping: { "#microsoft.graph.drive": "#/components/schemas/drive" },
        },
      },
      itemBody: { type: "object", properties: { content: { type: "string" } } },
      drive: { type: "object" },
      unrelated: { type: "object" },
    },
  },
};

test("keeps operations by tag or by operation id, drops empty path items, and prunes unreachable components", () => {
  const sliced = sliceSpec(spec, {
    tags: ["me.message"],
    operations: ["me.sendMail"],
  }) as {
    paths: Record<string, object>;
    components: Record<string, Record<string, unknown>>;
  };
  expect(Object.keys(sliced.paths).toSorted()).toEqual([
    "/me/messages",
    "/me/sendMail",
  ]);
  expect(Object.keys(sliced.paths["/me/messages"]).toSorted()).toEqual([
    "get",
    "parameters",
    "post",
  ]);
  expect(Object.keys(sliced.components.schemas).toSorted()).toEqual([
    "entity",
    "itemBody",
    "message",
  ]);
  expect(Object.keys(sliced.components.parameters)).toEqual(["top"]);
  expect(Object.keys(sliced.components.responses)).toEqual([
    "messageCollection",
  ]);
  // discriminator mappings are strings, not $ref keys: they do not pull `drive` in.
  expect("drive" in sliced.components.schemas).toEqual(false);
});

test("rewrites the server URL to its bare origin because the compiler rejects a path", () => {
  const sliced = sliceSpec(spec, { tags: ["drives.drive"], operations: [] });
  expect(sliced.servers).toEqual([{ url: "https://api.example.com" }]);
});

test("a selection matching nothing is an error, not an empty release", () => {
  expect(() => sliceSpec(spec, { tags: ["nope"], operations: [] })).toThrow(
    /selected no operations/,
  );
});

test("countKeys counts every object key so the caller can compare against the compiler's maxDocumentKeys", () => {
  expect(countKeys({ a: { b: 1, c: [{ d: 2 }] } })).toEqual(4);
});

test("throws listing selectors that matched nothing, even when another selector did match", () => {
  expect(() =>
    sliceSpec(spec, { tags: ["me.message"], operations: ["nope"] }),
  ).toThrow(/nope/);
  expect(() =>
    sliceSpec(spec, { tags: ["me.message", "also-nope"], operations: [] }),
  ).toThrow(/also-nope/);
});

test("preserves path-item extras like servers and summary alongside kept methods", () => {
  const withPathServers = {
    ...spec,
    paths: {
      ...spec.paths,
      "/me/sendMail": {
        ...spec.paths["/me/sendMail"],
        summary: "Send mail",
        servers: [{ url: "https://graph.microsoft.com/beta" }],
      },
    },
  };
  const sliced = sliceSpec(withPathServers, {
    tags: [],
    operations: ["me.sendMail"],
  }) as { paths: Record<string, Record<string, unknown>> };
  expect(sliced.paths["/me/sendMail"].summary).toEqual("Send mail");
  expect(sliced.paths["/me/sendMail"].servers).toEqual([
    { url: "https://graph.microsoft.com/beta" },
  ]);
});

test("decodes JSON-pointer escapes in $ref component names", () => {
  const escaped = {
    openapi: "3.0.1",
    info: { title: "Escaped", version: "1" },
    servers: [{ url: "https://api.example.com" }],
    paths: {
      "/x": {
        get: {
          tags: ["x"],
          operationId: "x.get",
          responses: {
            "200": {
              description: "ok",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/a~1b" },
                },
              },
            },
          },
        },
      },
    },
    components: { schemas: { "a/b": { type: "object" } } },
  };
  const sliced = sliceSpec(escaped, { tags: ["x"], operations: [] }) as {
    components: { schemas: Record<string, unknown> };
  };
  expect(Object.keys(sliced.components.schemas)).toEqual(["a/b"]);
});

test("keeps security schemes referenced by root or operation security requirements", () => {
  const withSecurity = {
    ...spec,
    security: [{ apiKey: [] }],
    components: {
      ...spec.components,
      securitySchemes: {
        apiKey: { type: "apiKey", name: "x-api-key", in: "header" },
        unused: { type: "apiKey", name: "unused", in: "header" },
      },
    },
  };
  const sliced = sliceSpec(withSecurity, {
    tags: ["drives.drive"],
    operations: [],
  }) as { components: { securitySchemes: Record<string, unknown> } };
  expect(Object.keys(sliced.components.securitySchemes)).toEqual(["apiKey"]);
});

test("prunes discriminator.mapping entries whose target is outside the kept closure", () => {
  const sliced = sliceSpec(spec, {
    tags: ["me.message"],
    operations: ["me.sendMail"],
  }) as {
    components: {
      schemas: {
        entity: { discriminator: { mapping: Record<string, string> } };
      };
    };
  };
  // `drive` is pruned (not `$ref`-reachable), so the mapping entry pointing at it goes too.
  expect(sliced.components.schemas.entity.discriminator.mapping).toEqual({});
});
