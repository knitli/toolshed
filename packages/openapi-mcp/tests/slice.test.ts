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
