import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import {
  type CompileReleaseOptions,
  compileRelease,
  DEFAULT_COMPILER_LIMITS,
} from "../src/compiler.ts";
import { generateKeypair } from "../src/sign.ts";

const roots: string[] = [];
const SOURCE_URI = "https://schemas.example.test/openapi.json";

async function temporaryRoot(): Promise<string> {
  const root = join(
    import.meta.dir,
    `../.tmp/schema-semantics-${crypto.randomUUID()}`,
  );
  await mkdir(root, { recursive: true });
  roots.push(root);
  return root;
}

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

function documentWithSchemas(schemas: Record<string, unknown>) {
  return {
    openapi: "3.1.0",
    info: { title: "Schema semantics", version: "1" },
    servers: [{ url: "https://api.example.test" }],
    paths: {},
    components: { schemas },
  };
}

async function compileDocument(
  root: string,
  name: string,
  document: Record<string, unknown>,
  extra: Partial<CompileReleaseOptions> = {},
) {
  const specPath = join(root, `${name}.json`);
  await writeFile(specPath, JSON.stringify(document));
  const options: CompileReleaseOptions = {
    specPath,
    sourceUri: SOURCE_URI,
    sourceRevision: "schema-semantics-fixture",
    catalogId: "tiny",
    releaseId: name,
    generation: 1,
    issuer: "test-issuer",
    keyId: "test-key",
    policyId: "test-policy",
    allowedOrigins: ["https://api.example.test"],
    outDir: root,
    privateKeyPem: generateKeypair().privateKeyPem,
    ...extra,
  };
  return compileRelease(options);
}

interface TestSchema {
  readonly [key: string]: unknown;
  readonly type?: string;
  readonly $ref?: string;
  readonly properties?: Readonly<Record<string, TestSchema>>;
  readonly $defs?: Readonly<Record<string, TestSchema>>;
  readonly allOf?: readonly TestSchema[];
  readonly not?: TestSchema;
  readonly example?: unknown;
  readonly discriminator?: unknown;
}

type SchemaRecord = { readonly id: string; readonly schema: TestSchema };

function readSchemaRecords(path: string): Map<string, SchemaRecord> {
  const database = new DatabaseSync(path, { readOnly: true });
  try {
    const rows = database
      .prepare("SELECT record_id, record_json FROM schemas")
      .all() as Array<{ record_id: string; record_json: string }>;
    return new Map(
      rows.map((row) => [row.record_id, JSON.parse(row.record_json)]),
    );
  } finally {
    database.close();
  }
}

function record(
  records: ReadonlyMap<string, SchemaRecord>,
  id: string,
): SchemaRecord {
  const value = records.get(id);
  if (!value) throw new Error(`missing schema record ${id}`);
  return value;
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

describe("OpenAPI 3.1 schema resource semantics", () => {
  test("materializes boolean component, parameter, and request-body root schemas", async () => {
    const root = await temporaryRoot();
    const compiled = await compileDocument(root, "boolean-schema-roots", {
      ...documentWithSchemas({
        AllowsEverything: true,
        RejectsEverything: false,
      }),
      paths: {
        "/boolean": {
          get: {
            operationId: "getBoolean",
            parameters: [{ name: "allowed", in: "query", schema: true }],
            responses: { "200": { description: "ok" } },
          },
          post: {
            operationId: "postBoolean",
            requestBody: {
              content: { "application/json": { schema: false } },
            },
            responses: { "200": { description: "ok" } },
          },
        },
      },
    });

    const records = readSchemaRecords(compiled.paths.sqlite);
    expect(
      record(records, "schema:tiny:#/components/schemas/AllowsEverything")
        .schema,
    ).toBe(true);
    expect(
      record(records, "schema:tiny:#/components/schemas/RejectsEverything")
        .schema,
    ).toBe(false);
    const database = new DatabaseSync(compiled.paths.sqlite, {
      readOnly: true,
    });
    try {
      const getOperation = JSON.parse(
        (
          database
            .prepare(
              "SELECT record_json FROM operations WHERE operation_id = ?",
            )
            .get("getBoolean") as { record_json: string }
        ).record_json,
      ) as { parameters: Array<{ value: { schemaId: string } }> };
      const postOperation = JSON.parse(
        (
          database
            .prepare(
              "SELECT record_json FROM operations WHERE operation_id = ?",
            )
            .get("postBoolean") as { record_json: string }
        ).record_json,
      ) as { requestBody: { content: Array<{ schemaId: string }> } };
      expect(
        record(records, getOperation.parameters[0].value.schemaId).schema,
      ).toBe(true);
      expect(
        record(records, postOperation.requestBody.content[0].schemaId).schema,
      ).toBe(false);
    } finally {
      database.close();
    }
  });

  test("resolves a local fragment from the active $id resource root", async () => {
    const root = await temporaryRoot();
    const compiled = await compileDocument(root, "local-id-fragment", {
      ...documentWithSchemas({
        Scoped: {
          $id: "embedded/scoped.json",
          $defs: { child: { type: "integer" } },
          properties: { value: { $ref: "#/$defs/child" } },
        },
      }),
      $defs: { child: { type: "string" } },
    });

    const records = readSchemaRecords(compiled.paths.sqlite);
    const scoped = record(records, "schema:tiny:#/components/schemas/Scoped");
    const childId = scoped.schema.properties?.value?.$ref;
    expect(typeof childId).toBe("string");
    if (typeof childId !== "string") throw new Error("missing child reference");
    expect(record(records, childId).schema.type).toBe("integer");
  });

  test("keeps nested $id scope from leaking into its sibling", async () => {
    const root = await temporaryRoot();
    const parentLeaf = JSON.stringify({ type: "string" });
    const nestedLeaf = JSON.stringify({ type: "integer" });
    await writeFile(join(root, "parent-leaf.json"), parentLeaf);
    await writeFile(join(root, "nested-leaf.json"), nestedLeaf);
    const referenceMapPath = join(root, "reference-map.json");
    await writeFile(
      referenceMapPath,
      JSON.stringify({
        version: 1,
        entries: [
          {
            uri: "bundles/leaf.json",
            file: "parent-leaf.json",
            sha256: digest(parentLeaf),
          },
          {
            uri: "bundles/nested/leaf.json",
            file: "nested-leaf.json",
            sha256: digest(nestedLeaf),
          },
        ],
      }),
    );
    const compiled = await compileDocument(
      root,
      "nested-id-scope",
      documentWithSchemas({
        Bundle: {
          $id: "bundles/root.json",
          $defs: {
            nested: {
              $id: "nested/",
              properties: { value: { $ref: "leaf.json" } },
            },
            sibling: {
              properties: { value: { $ref: "leaf.json" } },
            },
          },
        },
      }),
      { referenceRoot: root, referenceMapPath },
    );

    const records = readSchemaRecords(compiled.paths.sqlite);
    const bundle = record(records, "schema:tiny:#/components/schemas/Bundle");
    const nestedId = bundle.schema.$defs?.nested?.properties?.value?.$ref;
    const siblingId = bundle.schema.$defs?.sibling?.properties?.value?.$ref;
    expect(typeof nestedId).toBe("string");
    expect(typeof siblingId).toBe("string");
    if (typeof nestedId !== "string" || typeof siblingId !== "string")
      throw new Error("missing scoped leaf reference");
    expect(record(records, nestedId).schema.type).toBe("integer");
    expect(record(records, siblingId).schema.type).toBe("string");
  });

  test("inherits an enclosing local resource when a pointer lands below its $id", async () => {
    const root = await temporaryRoot();
    const compiled = await compileDocument(root, "local-pointer-below-id", {
      ...documentWithSchemas({
        Consumer: {
          $ref: "#/components/schemas/Container/properties/value",
        },
        Container: {
          $id: "resources/container.json",
          $defs: { leaf: { type: "integer" } },
          properties: { value: { $ref: "#/$defs/leaf" } },
        },
      }),
      $defs: { leaf: { type: "string" } },
    });

    const records = readSchemaRecords(compiled.paths.sqlite);
    const consumer = record(
      records,
      "schema:tiny:#/components/schemas/Consumer",
    );
    const valueId = consumer.schema.$ref;
    expect(typeof valueId).toBe("string");
    if (typeof valueId !== "string") throw new Error("missing value reference");
    const leafId = record(records, valueId).schema.$ref;
    expect(typeof leafId).toBe("string");
    if (typeof leafId !== "string") throw new Error("missing leaf reference");
    expect(record(records, leafId).schema.type).toBe("integer");
  });

  test("inherits an enclosing external resource when a pointer lands below its $id", async () => {
    const root = await temporaryRoot();
    const external = JSON.stringify({
      $defs: {
        leaf: { type: "string" },
        container: {
          $id: "declared/container.json",
          $defs: { leaf: { type: "integer" } },
          properties: { value: { $ref: "#/$defs/leaf" } },
        },
      },
    });
    await writeFile(join(root, "external.json"), external);
    const referenceMapPath = join(root, "external-map.json");
    await writeFile(
      referenceMapPath,
      JSON.stringify({
        version: 1,
        entries: [
          {
            uri: "external.json",
            file: "external.json",
            sha256: digest(external),
          },
        ],
      }),
    );
    const compiled = await compileDocument(
      root,
      "external-pointer-below-id",
      documentWithSchemas({
        Consumer: {
          $ref: "external.json#/$defs/container/properties/value",
        },
      }),
      { referenceRoot: root, referenceMapPath },
    );

    const records = readSchemaRecords(compiled.paths.sqlite);
    const consumer = record(
      records,
      "schema:tiny:#/components/schemas/Consumer",
    );
    const valueId = consumer.schema.$ref;
    expect(typeof valueId).toBe("string");
    if (typeof valueId !== "string") throw new Error("missing value reference");
    const leafId = record(records, valueId).schema.$ref;
    expect(typeof leafId).toBe("string");
    if (typeof leafId !== "string") throw new Error("missing leaf reference");
    expect(record(records, leafId).schema.type).toBe("integer");
  });

  test("pre-indexes operation schema resources before component materialization", async () => {
    const root = await temporaryRoot();
    const targetUri = "https://schemas.example.test/operation-target.json";
    const compiled = await compileDocument(
      root,
      "operation-resource-preindex",
      {
        ...documentWithSchemas({ Consumer: { $ref: targetUri } }),
        paths: {
          "/items": {
            get: {
              operationId: "listItems",
              parameters: [
                {
                  name: "limit",
                  in: "query",
                  schema: { $id: targetUri, type: "integer" },
                },
              ],
              responses: { "200": { description: "ok" } },
            },
          },
        },
      },
    );

    const records = readSchemaRecords(compiled.paths.sqlite);
    const targetId = record(
      records,
      "schema:tiny:#/components/schemas/Consumer",
    ).schema.$ref;
    expect(typeof targetId).toBe("string");
    if (typeof targetId !== "string")
      throw new Error("missing target reference");
    expect(record(records, targetId).schema.type).toBe("integer");
  });

  test("does not index $id resources through a Path Item reference", async () => {
    const root = await temporaryRoot();
    const targetUri = "https://schemas.example.test/path-item.json";
    await expect(
      compileDocument(root, "path-item-is-not-schema", {
        ...documentWithSchemas({ Consumer: { $ref: targetUri } }),
        properties: {
          foo: {
            $id: targetUri,
            get: {
              operationId: "listItems",
              responses: { "200": { description: "ok" } },
            },
          },
        },
        paths: { "/items": { $ref: "#/properties/foo" } },
      }),
    ).rejects.toThrow("external reference is absent from the reference map");
  });

  test("pre-indexes content, request-body, and encoding-header schema roots", async () => {
    const root = await temporaryRoot();
    const uris = {
      parameter: "https://schemas.example.test/parameter-content.json",
      body: "https://schemas.example.test/request-body.json",
      header: "https://schemas.example.test/encoding-header.json",
      headerContent:
        "https://schemas.example.test/encoding-header-content.json",
    };
    const compiled = await compileDocument(root, "all-operation-schema-roots", {
      ...documentWithSchemas({
        ParameterConsumer: { $ref: uris.parameter },
        BodyConsumer: { $ref: uris.body },
        HeaderConsumer: { $ref: uris.header },
        HeaderContentConsumer: { $ref: uris.headerContent },
      }),
      paths: {
        "/upload": {
          post: {
            operationId: "upload",
            parameters: [
              {
                name: "filter",
                in: "query",
                content: {
                  "application/json": {
                    schema: { $id: uris.parameter, type: "integer" },
                  },
                },
              },
            ],
            requestBody: {
              content: {
                "multipart/form-data": {
                  schema: {
                    $id: uris.body,
                    type: "object",
                    properties: { file: { type: "string" } },
                  },
                  encoding: {
                    file: {
                      headers: {
                        "X-Direct": {
                          schema: { $id: uris.header, type: "boolean" },
                        },
                        "X-Content": {
                          content: {
                            "application/json": {
                              schema: {
                                $id: uris.headerContent,
                                type: "number",
                              },
                            },
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
            responses: { "200": { description: "ok" } },
          },
        },
      },
    });

    const records = readSchemaRecords(compiled.paths.sqlite);
    for (const [consumer, type] of [
      ["ParameterConsumer", "integer"],
      ["BodyConsumer", "object"],
      ["HeaderConsumer", "boolean"],
      ["HeaderContentConsumer", "number"],
    ] as const) {
      const targetId = record(
        records,
        `schema:tiny:#/components/schemas/${consumer}`,
      ).schema.$ref;
      expect(typeof targetId).toBe("string");
      if (typeof targetId !== "string")
        throw new Error(`missing ${consumer} target reference`);
      expect(record(records, targetId).schema.type).toBe(type);
    }
  });

  test("rejects duplicate resource IDs across component and operation roots", async () => {
    const root = await temporaryRoot();
    const shared = "https://schemas.example.test/duplicate-root.json";
    await expect(
      compileDocument(root, "duplicate-operation-resource", {
        ...documentWithSchemas({
          Component: { $id: shared, type: "string" },
        }),
        paths: {
          "/items": {
            get: {
              operationId: "listDuplicateItems",
              parameters: [
                {
                  name: "limit",
                  in: "query",
                  schema: { $id: shared, type: "integer" },
                },
              ],
              responses: { "200": { description: "ok" } },
            },
          },
        },
      }),
    ).rejects.toThrow("duplicates an embedded resource URI");
  });

  test("pre-indexes mapped schema closures before resolving declared resource IDs", async () => {
    const root = await temporaryRoot();
    const external = JSON.stringify({
      $id: "https://schemas.example.test/declared/external.json",
      type: "integer",
    });
    await writeFile(join(root, "mapped.json"), external);
    const referenceMapPath = join(root, "closure-map.json");
    await writeFile(
      referenceMapPath,
      JSON.stringify({
        version: 1,
        entries: [
          {
            uri: "mapped.json",
            file: "mapped.json",
            sha256: digest(external),
          },
        ],
      }),
    );
    const compiled = await compileDocument(
      root,
      "external-resource-closure",
      documentWithSchemas({
        Consumer: {
          $ref: "https://schemas.example.test/declared/external.json",
        },
        Loader: { $ref: "mapped.json" },
      }),
      { referenceRoot: root, referenceMapPath },
    );

    const records = readSchemaRecords(compiled.paths.sqlite);
    const consumerTarget = record(
      records,
      "schema:tiny:#/components/schemas/Consumer",
    ).schema.$ref;
    const loaderTarget = record(
      records,
      "schema:tiny:#/components/schemas/Loader",
    ).schema.$ref;
    expect(consumerTarget).toBe(loaderTarget);
  });

  test("pre-indexes deferred resource edges with a linear attempt budget", async () => {
    const root = await temporaryRoot();
    const count = 32;
    const aliases = Array.from(
      { length: count + 1 },
      (_, index) => `https://schemas.example.test/alias-${index}.json`,
    );
    const loaders = Array.from(
      { length: count + 1 },
      (_, index) => `https://schemas.example.test/loader-${index}.json`,
    );
    const documents = loaders.map((_, index) =>
      JSON.stringify(
        index === 0
          ? {
              $id: aliases[0],
              allOf: [
                ...aliases.slice(1).map(($ref) => ({ $ref })),
                { $ref: loaders[1] },
              ],
            }
          : index < count
            ? { $id: aliases[index], $ref: loaders[index + 1] }
            : { $id: aliases[index], type: "string" },
      ),
    );
    const referenceMapPath = join(root, "linear-worklist-map.json");
    await Promise.all(
      documents.map((document, index) =>
        writeFile(join(root, `loader-${index}.json`), document),
      ),
    );
    await writeFile(
      referenceMapPath,
      JSON.stringify({
        version: 1,
        entries: loaders.map((uri, index) => ({
          uri,
          file: `loader-${index}.json`,
          sha256: digest(documents[index]),
        })),
      }),
    );
    let attempts = 0;
    const NativeURL = globalThis.URL;
    globalThis.URL = class extends NativeURL {
      constructor(url: string | URL, base?: string | URL) {
        if (String(url).includes("/alias-")) attempts += 1;
        super(url, base);
      }
    };
    let compiled: Awaited<ReturnType<typeof compileDocument>>;
    try {
      compiled = await compileDocument(
        root,
        "linear-deferred-resource-worklist",
        documentWithSchemas({ Loader: { $ref: loaders[0] } }),
        { referenceMapPath, referenceRoot: root },
      );
    } finally {
      globalThis.URL = NativeURL;
    }
    expect(readSchemaRecords(compiled.paths.sqlite).size).toBeGreaterThan(
      count,
    );
    expect(attempts).toBeLessThanOrEqual(13 * count);
  });

  test.each([
    [64, true],
    [65, false],
  ] as const)(
    "bounds retained schema reference work at the derived limit: %i refs",
    async (referenceCount, accepted) => {
      const root = await temporaryRoot();
      const result = compileDocument(
        root,
        `reference-work-${referenceCount}`,
        documentWithSchemas({
          Fanout: {
            allOf: Array.from({ length: referenceCount }, () => ({
              $ref: "#/components/schemas/Fanout",
            })),
          },
        }),
        {
          limits: { ...DEFAULT_COMPILER_LIMITS, maxSchemas: 1 },
        },
      );
      if (accepted) await expect(result).resolves.toBeDefined();
      else
        await expect(result).rejects.toThrow(
          "schema reference work exceeds limit",
        );
    },
  );

  test("canonicalizes URI-fragment aliases to one physical materialization", async () => {
    const root = await temporaryRoot();
    const compiled = await compileDocument(
      root,
      "pointer-aliases",
      documentWithSchemas({
        First: {
          $ref: "#/components/schemas/Container/$defs/Inner",
        },
        Second: {
          $ref: "#%2Fcomponents%2Fschemas%2FContainer%2F%24defs%2F%49nner",
        },
        Container: { $defs: { Inner: { type: "integer" } } },
      }),
    );

    const records = readSchemaRecords(compiled.paths.sqlite);
    const first = record(records, "schema:tiny:#/components/schemas/First")
      .schema.$ref;
    const second = record(records, "schema:tiny:#/components/schemas/Second")
      .schema.$ref;
    expect(first).toBe(second);
    expect(
      [...records.keys()].filter((id) => id.includes("__openapi_mcp_v4_")),
    ).toHaveLength(1);
  });

  test("resolves a pre-indexed embedded resource without a map entry", async () => {
    const root = await temporaryRoot();
    const targetUri = "https://schemas.example.test/resources/target.json";
    const compiled = await compileDocument(
      root,
      "direct-embedded-resource",
      documentWithSchemas({
        User: { $ref: targetUri },
        Target: { $id: targetUri, type: "integer" },
      }),
    );

    const records = readSchemaRecords(compiled.paths.sqlite);
    expect(
      record(records, "schema:tiny:#/components/schemas/User").schema.$ref,
    ).toBe("schema:tiny:#/components/schemas/Target");
  });

  test("rejects conflicting embedded resource identifiers", async () => {
    const root = await temporaryRoot();
    await expect(
      compileDocument(
        root,
        "duplicate-embedded-id",
        documentWithSchemas({
          First: { $id: "shared.json", type: "string" },
          Second: { $id: "shared.json", type: "integer" },
        }),
      ),
    ).rejects.toThrow("duplicates an embedded resource URI");
  });

  test("does not let $id authorize an unpinned external document", async () => {
    const root = await temporaryRoot();
    await compileDocument(
      root,
      "absent-external-map",
      documentWithSchemas({
        Scoped: {
          $id: "bundles/root.json",
          properties: { value: { $ref: "unmapped.json" } },
        },
      }),
    ).then(
      () => {
        throw new Error("expected an unpinned external reference to fail");
      },
      (error: unknown) => {
        expect(error).toBeInstanceOf(Error);
      },
    );
  });

  test("preserves opaque annotation data and walks only schema locations", async () => {
    const root = await temporaryRoot();
    const literal = {
      $ref: "https://unmapped.example.test/literal.json",
      $id: "https://unmapped.example.test/not-a-resource.json",
    };
    const compiled = await compileDocument(
      root,
      "schema-keywords",
      documentWithSchemas({
        Annotated: {
          example: literal,
          "x-literal": { nested: literal },
          discriminator: { mapping: { literal } },
          properties: {
            $ref: { type: "string" },
            real: { $ref: "#/components/schemas/Child" },
          },
          allOf: [{ $ref: "#/components/schemas/Child" }],
          not: { $ref: "#/components/schemas/Child" },
          $defs: { real: { $ref: "#/components/schemas/Child" } },
        },
        Child: { type: "integer" },
      }),
    );

    const records = readSchemaRecords(compiled.paths.sqlite);
    const schema = record(
      records,
      "schema:tiny:#/components/schemas/Annotated",
    ).schema;
    const childId = "schema:tiny:#/components/schemas/Child";
    expect(schema.example).toEqual(literal);
    expect(schema["x-literal"]).toEqual({ nested: literal });
    expect(schema.discriminator).toEqual({ mapping: { literal } });
    expect(schema.properties?.$ref).toEqual({ type: "string" });
    expect(schema.properties?.real?.$ref).toBe(childId);
    expect(schema.allOf?.[0]?.$ref).toBe(childId);
    expect(schema.not?.$ref).toBe(childId);
    expect(schema.$defs?.real?.$ref).toBe(childId);
  });
});
