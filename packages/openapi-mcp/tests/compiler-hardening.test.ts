import { afterEach, describe, expect, test } from "bun:test";
import {
  link,
  mkdir,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  type CompileReleaseOptions,
  type CompilerLimits,
  compileRelease,
  DEFAULT_COMPILER_LIMITS,
  discardCompiledRelease,
  loadSpecV4,
  resolveLocalPointer,
} from "../src/compiler.ts";
import { readFileBoundedV4 } from "../src/release/load-v4.ts";
import { loadReferenceMap } from "../src/release/reference-map.ts";
import { parseTypedRecordId } from "../src/runtime/references.ts";
import { generateKeypair } from "../src/sign.ts";

const roots: string[] = [];

async function temporaryRoot(): Promise<string> {
  const root = fileURLToPath(
    new URL(
      `../../../../.tmp/compiler-hardening-${crypto.randomUUID()}/`,
      import.meta.url,
    ),
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

function limits(overrides: Partial<CompilerLimits>): CompilerLimits {
  return { ...DEFAULT_COMPILER_LIMITS, ...overrides };
}

async function write(
  root: string,
  name: string,
  contents: string,
): Promise<string> {
  const path = join(root, name);
  await writeFile(path, contents);
  return path;
}

async function runChildWithDeadline(
  script: string,
  deadlineMs = 750,
): Promise<{ kind: "exit"; code: number } | { kind: "timeout" }> {
  const child = Bun.spawn([process.execPath, "-e", script], {
    stdout: "pipe",
    stderr: "pipe",
  });
  const outcome = await Promise.race([
    child.exited.then((code) => ({ kind: "exit" as const, code })),
    Bun.sleep(deadlineMs).then(() => ({ kind: "timeout" as const })),
  ]);
  if (outcome.kind === "timeout") {
    child.kill();
    await child.exited;
  }
  return outcome;
}

function reachableErrorText(error: unknown): string {
  const seen = new WeakSet<object>();
  const texts: string[] = [];
  const visit = (value: unknown): void => {
    if (typeof value === "string") {
      texts.push(value);
      return;
    }
    if ((typeof value !== "object" && typeof value !== "function") || !value)
      return;
    if (seen.has(value)) return;
    seen.add(value);
    for (const key of Reflect.ownKeys(value)) {
      texts.push(String(key));
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor && "value" in descriptor) visit(descriptor.value);
    }
  };
  visit(error);
  return texts.join("\n");
}

function minimalDocument(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    openapi: "3.1.0",
    info: { title: "Tiny", version: "1" },
    servers: [{ url: "https://api.example.test" }],
    paths: {},
    ...overrides,
  };
}

function releaseOptions(root: string, specPath: string): CompileReleaseOptions {
  const { privateKeyPem } = generateKeypair();
  return {
    specPath,
    sourceLabel: "graph-v1",
    sourceRevision: "abc123",
    catalogId: "tiny",
    releaseId: "release-1",
    generation: 1,
    issuer: "test-issuer",
    keyId: "test-key",
    policyId: "test-policy",
    allowedOrigins: ["https://api.example.test"],
    outDir: root,
    privateKeyPem,
  };
}

describe("strict v4 loading", () => {
  test("bounds permissions datasets at the effective source-byte limit", async () => {
    const root = await temporaryRoot();
    const specPath = await write(
      root,
      "permissions-boundary-spec.json",
      JSON.stringify(minimalDocument()),
    );
    const maxSourceBytes = 4_096;
    const dataset = JSON.stringify({ permissions: {} });
    const exact = `${dataset}${" ".repeat(maxSourceBytes - Buffer.byteLength(dataset))}`;
    const exactPath = await write(root, "permissions-exact.json", exact);
    const accepted = await compileRelease({
      ...releaseOptions(root, specPath),
      permissionsPath: exactPath,
      limits: limits({ maxSourceBytes }),
    });
    await discardCompiledRelease(accepted);

    const oversizedPath = await write(
      root,
      "permissions-oversized.json",
      `${exact} `,
    );
    await expect(
      compileRelease({
        ...releaseOptions(root, specPath),
        releaseId: "release-oversized-permissions",
        permissionsPath: oversizedPath,
        limits: limits({ maxSourceBytes }),
      }),
    ).rejects.toThrow("permissions dataset exceeds byte limit");

    const invalidUtf8Path = join(root, "permissions-invalid-utf8.json");
    await writeFile(invalidUtf8Path, new Uint8Array([0x7b, 0x7d, 0xff]));
    await expect(
      compileRelease({
        ...releaseOptions(root, specPath),
        releaseId: "release-invalid-permissions-utf8",
        permissionsPath: invalidUtf8Path,
        limits: limits({ maxSourceBytes }),
      }),
    ).rejects.toThrow("permissions dataset is not valid UTF-8");
  });

  test("rejects a permissions FIFO without waiting for a writer", async () => {
    const root = await temporaryRoot();
    const specPath = await write(
      root,
      "permissions-fifo-spec.json",
      JSON.stringify(minimalDocument()),
    );
    const fifo = join(root, "permissions.json");
    const mkfifo = Bun.spawn(["mkfifo", fifo]);
    expect(await mkfifo.exited).toBe(0);
    const modulePath = fileURLToPath(
      new URL("../src/compiler.ts", import.meta.url),
    );
    const options = {
      ...releaseOptions(root, specPath),
      permissionsPath: fifo,
    };
    const script = `
      const compiler = await import(${JSON.stringify(modulePath)});
      try {
        await compiler.compileRelease(${JSON.stringify(options)});
        process.exit(2);
      } catch (error) {
        process.exit(error instanceof Error && error.message === "permissions dataset could not be read" ? 0 : 3);
      }
    `;
    expect(await runChildWithDeadline(script)).toEqual({
      kind: "exit",
      code: 0,
    });
  });

  test("bounds regular source reads before unbounded allocation", async () => {
    const root = await temporaryRoot();
    const regular = await write(root, "bounded.bin", "x".repeat(65));
    await expect(readFileBoundedV4(regular, 64, "test source")).rejects.toThrow(
      /byte|size|limit/i,
    );
    await expect(
      readFileBoundedV4(regular, 65, "test source"),
    ).resolves.toHaveLength(65);

    const symlinkPath = join(root, "bounded-link.bin");
    await symlink(regular, symlinkPath);
    await expect(
      readFileBoundedV4(symlinkPath, 65, "test source"),
    ).rejects.toThrow(/symbolic|no.?follow|unsafe/i);
  });

  test("rejects root FIFOs without blocking for a writer or EOF", async () => {
    const root = await temporaryRoot();
    const modulePath = fileURLToPath(
      new URL("../src/compiler.ts", import.meta.url),
    );
    for (const api of ["loadSpecV4", "compileRelease"] as const) {
      for (const mode of ["no-writer", "writer-kept-open"] as const) {
        const fifo = join(root, `${api}-${mode}.json`);
        const mkfifo = Bun.spawn(["mkfifo", fifo]);
        expect(await mkfifo.exited).toBe(0);
        const writer =
          mode === "writer-kept-open"
            ? Bun.spawn([
                "/bin/sh",
                "-c",
                '{ printf %s "$2"; sleep 10; } > "$1"',
                "writer",
                fifo,
                JSON.stringify(minimalDocument()),
              ])
            : undefined;
        try {
          const compileOptions = releaseOptions(root, fifo);
          const script = `
          const compiler = await import(${JSON.stringify(modulePath)});
          try {
            if (${JSON.stringify(api)} === "loadSpecV4") {
              await compiler.loadSpecV4(${JSON.stringify(fifo)});
            } else {
              await compiler.compileRelease(${JSON.stringify(compileOptions)});
            }
            process.exit(2);
          } catch (error) {
            process.exit(error instanceof Error && error.message === "source document could not be read" ? 0 : 3);
          }
        `;
          expect(await runChildWithDeadline(script)).toEqual({
            kind: "exit",
            code: 0,
          });
        } finally {
          writer?.kill();
          if (writer) await writer.exited;
        }
      }
    }
  });

  test("public read errors recursively redact source and reference paths", async () => {
    const root = await temporaryRoot();
    const missingSpec = join(root, "private-spec-canary.json");
    const missingMap = join(root, "private-map-canary.json");
    const missingPermissions = join(root, "private-permissions-canary.json");
    const readableSpec = await write(
      root,
      "readable-spec.json",
      JSON.stringify(minimalDocument()),
    );
    const cases: Array<readonly [Promise<unknown>, string]> = [
      [loadSpecV4(missingSpec), "source document could not be read"],
      [
        compileRelease(releaseOptions(root, missingSpec)),
        "source document could not be read",
      ],
      [
        loadReferenceMap(
          missingMap,
          "urn:openapi-source:test",
          DEFAULT_COMPILER_LIMITS,
        ),
        "reference map could not be read",
      ],
      [
        compileRelease({
          ...releaseOptions(root, readableSpec),
          permissionsPath: missingPermissions,
        }),
        "permissions dataset could not be read",
      ],
    ];
    for (const [operation, message] of cases) {
      const error = await operation.catch((reason) => reason);
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe(message);
      const reachable = reachableErrorText(error);
      expect(reachable).not.toContain(root);
      expect(reachable).not.toContain("private-spec-canary");
      expect(reachable).not.toContain("private-map-canary");
      expect(reachable).not.toContain("private-permissions-canary");
    }

    const referenced = JSON.stringify({ type: "string" });
    const referencedTarget = await write(
      root,
      "private-reference-target-canary.json",
      referenced,
    );
    const referencedLink = join(root, "private-reference-link-canary.json");
    await symlink(referencedTarget, referencedLink);
    const map = await write(
      root,
      "reference-map.json",
      JSON.stringify({
        version: 1,
        entries: [
          {
            uri: "private.json",
            file: "private-reference-link-canary.json",
            sha256: new Bun.CryptoHasher("sha256")
              .update(referenced)
              .digest("hex"),
          },
        ],
      }),
    );
    const spec = await write(
      root,
      "reference-spec.json",
      JSON.stringify(
        minimalDocument({
          components: { schemas: { Private: { $ref: "private.json" } } },
        }),
      ),
    );
    const referenceError = await compileRelease({
      ...releaseOptions(root, spec),
      referenceMapPath: map,
      referenceRoot: root,
    }).catch((reason) => reason);
    expect(referenceError).toBeInstanceOf(Error);
    expect((referenceError as Error).message).toBe(
      "referenced document could not be read",
    );
    const reachableReference = reachableErrorText(referenceError);
    expect(reachableReference).not.toContain(root);
    expect(reachableReference).not.toContain("private-reference-link-canary");
    expect(reachableReference).not.toContain("private-reference-target-canary");
  });

  test("uses the exact frozen compiler defaults", () => {
    expect(DEFAULT_COMPILER_LIMITS).toEqual({
      maxSourceBytes: 128 * 1024 * 1024,
      maxReferencedDocuments: 1_024,
      maxPaths: 100_000,
      maxOperations: 100_000,
      maxSchemas: 50_000,
      maxParametersPerOperation: 256,
      maxPropertiesPerSchema: 10_000,
      maxStringBytes: 1 * 1024 * 1024,
      maxRefLength: 2_048,
      maxJsonDepth: 64,
      maxRecordBytes: 1 * 1024 * 1024,
      maxYamlAliasExpansions: 100,
      maxDocumentNodes: 1_000_000,
      maxDocumentKeys: 250_000,
    });
  });

  test("accepts the exact byte, depth, node, and key boundary and rejects one over", async () => {
    const root = await temporaryRoot();
    const path = await write(
      root,
      "spec.json",
      JSON.stringify(minimalDocument()),
    );
    const byteLength = (await Bun.file(path).arrayBuffer()).byteLength;
    await expect(
      loadSpecV4(path, limits({ maxSourceBytes: byteLength })),
    ).resolves.toBeDefined();
    await expect(
      loadSpecV4(path, limits({ maxSourceBytes: byteLength - 1 })),
    ).rejects.toThrow(/source bytes/i);

    const nested = await write(
      root,
      "nested.json",
      '{"openapi":"3.1.0","paths":{},"x":{"y":1}}',
    );
    await expect(
      loadSpecV4(nested, limits({ maxJsonDepth: 2 })),
    ).resolves.toBeDefined();
    await expect(
      loadSpecV4(nested, limits({ maxJsonDepth: 1 })),
    ).rejects.toThrow(/depth/i);
    await expect(
      loadSpecV4(nested, limits({ maxDocumentNodes: 5 })),
    ).resolves.toBeDefined();
    await expect(
      loadSpecV4(nested, limits({ maxDocumentNodes: 4 })),
    ).rejects.toThrow(/node/i);
    await expect(
      loadSpecV4(nested, limits({ maxDocumentKeys: 4 })),
    ).resolves.toBeDefined();
    await expect(
      loadSpecV4(nested, limits({ maxDocumentKeys: 3 })),
    ).rejects.toThrow(/key/i);
  });

  test("rejects duplicate and prototype keys with JSON/YAML parity", async () => {
    const root = await temporaryRoot();
    for (const [name, body] of [
      ["duplicate.json", '{"openapi":"3.1.0","paths":{},"paths":{}}'],
      ["duplicate.yaml", "openapi: 3.1.0\npaths: {}\npaths: {}\n"],
      ["prototype.json", '{"openapi":"3.1.0","paths":{},"constructor":{}}'],
      ["prototype.yaml", "openapi: 3.1.0\npaths: {}\n__proto__: {}\n"],
    ] as const) {
      const path = await write(root, name, body);
      await expect(loadSpecV4(path)).rejects.toThrow(
        /duplicate|unique|forbidden/i,
      );
    }
  });

  test("bounds YAML aliases and rejects unsupported media and OpenAPI versions", async () => {
    const root = await temporaryRoot();
    const aliases = await write(
      root,
      "aliases.yaml",
      "openapi: 3.1.0\npaths: {}\nx: &x { value: 1 }\ny: *x\n",
    );
    await expect(
      loadSpecV4(aliases, limits({ maxYamlAliasExpansions: 2 })),
    ).resolves.toBeDefined();
    await expect(
      loadSpecV4(aliases, limits({ maxYamlAliasExpansions: 1 })),
    ).rejects.toThrow(/alias/i);
    const text = await write(
      root,
      "spec.txt",
      JSON.stringify(minimalDocument()),
    );
    await expect(loadSpecV4(text)).rejects.toThrow(/media|extension/i);
    for (const version of ["2.0", "4.0.0"]) {
      const path = await write(
        root,
        `v${version}.json`,
        JSON.stringify(minimalDocument({ openapi: version })),
      );
      await expect(loadSpecV4(path)).rejects.toThrow(/OpenAPI version/i);
    }
  });

  test("uses the caller-effective YAML alias expansion limit during conversion", async () => {
    const root = await temporaryRoot();
    const aliases = Array.from(
      { length: 101 },
      (_, index) => `alias${index}: *shared`,
    ).join("\n");
    const path = await write(
      root,
      "caller-alias-limit.yaml",
      `openapi: 3.1.0\npaths: {}\nshared: &shared { value: 1 }\n${aliases}\n`,
    );

    await expect(
      loadSpecV4(path, limits({ maxYamlAliasExpansions: 102 })),
    ).resolves.toBeDefined();
    await expect(
      loadSpecV4(path, limits({ maxYamlAliasExpansions: 101 })),
    ).rejects.toThrow(/alias|resource exhaustion/i);
  });
});

describe("safe local pointers", () => {
  test("accepts only the frozen synthetic schema namespace outside authored grammar", () => {
    const synthetic = `schema:tiny:#/components/schemas/__openapi_mcp_v4_${"a".repeat(64)}`;
    expect(parseTypedRecordId(synthetic)).toBe(synthetic);
    for (const invalid of [
      "schema:tiny:#/components/schemas/_private",
      `schema:tiny:#/components/schemas/__openapi_mcp_v4_${"A".repeat(64)}`,
      `schema:tiny:#/components/schemas/__openapi_mcp_v4_${"a".repeat(63)}`,
    ])
      expect(() => parseTypedRecordId(invalid)).toThrow(/schema segment/i);
  });

  test("decodes URI and RFC6901 escapes once and never traverses a prototype", () => {
    const doc = Object.assign(Object.create(null), {
      $defs: { Foo: { type: "integer" } },
      components: { schemas: { "a/b~c": { type: "string" }, "%2F": 2 } },
    });
    expect(resolveLocalPointer(doc, "#/components/schemas/a~1b~0c")).toEqual({
      type: "string",
    });
    expect(resolveLocalPointer(doc, "#/components/schemas/%252F")).toBe(2);
    for (const alias of ["#/$defs/Foo", "#/%24defs/%46oo", "#%2F%24defs%2FFoo"])
      expect(resolveLocalPointer(doc, alias)).toEqual({ type: "integer" });
    expect(() => resolveLocalPointer(doc, "#/constructor/prototype")).toThrow(
      /forbidden/i,
    );
    expect(() => resolveLocalPointer(doc, "#/components/~2bad")).toThrow(
      /escape/i,
    );
    for (const invalid of ["#named-anchor", "#%66oo", "#/%", "#/%7E2"])
      expect(() => resolveLocalPointer(doc, invalid)).toThrow(
        /fragment|escape/i,
      );
  });

  test("requires canonical array indices", () => {
    const doc = Object.assign(Object.create(null), { list: ["zero", "one"] });
    expect(resolveLocalPointer(doc, "#/list/0")).toBe("zero");
    for (const pointer of ["#/list/00", "#/list/+1", "#/list/-1", "#/list/2"]) {
      expect(() => resolveLocalPointer(doc, pointer)).toThrow(
        /array index|not found/i,
      );
    }
  });
});

describe("compiler contract limits and provenance", () => {
  test("reads a regular root source once and binds records and provenance to those bytes", async () => {
    const root = await temporaryRoot();
    const spec = join(root, "swapped.json");
    const makeDocument = (operationId: string) =>
      JSON.stringify(
        minimalDocument({
          paths: {
            "/probe": {
              get: {
                operationId,
                responses: { "204": { description: "ok" } },
              },
            },
          },
        }),
      );
    const external = JSON.stringify({ type: "string" });
    const firstDocument = minimalDocument({
      paths: {
        "/probe": {
          get: {
            operationId: "firstRead",
            responses: { "204": { description: "ok" } },
          },
        },
      },
      components: {
        schemas: { External: { $ref: "other.json" } },
      },
    });
    const first = JSON.stringify(firstDocument);
    const second = makeDocument("secondRead");
    await writeFile(spec, first);
    const map = await write(
      root,
      "snapshot-map.json",
      JSON.stringify({
        version: 1,
        entries: [
          {
            uri: "other.json",
            file: "unused.json",
            sha256: new Bun.CryptoHasher("sha256")
              .update(external)
              .digest("hex"),
          },
        ],
      }),
    );

    let compiled: Awaited<ReturnType<typeof compileRelease>> | undefined;
    try {
      compiled = await compileRelease({
        ...releaseOptions(root, spec),
        referenceMapPath: map,
        referenceResolver: {
          async resolve() {
            await writeFile(spec, second);
            return {
              bytes: new TextEncoder().encode(external),
              mediaType: "json",
            };
          },
        },
      });
      expect(compiled.manifest.source.contentSha256).toBe(
        new Bun.CryptoHasher("sha256").update(first).digest("hex"),
      );
      expect(Object.keys(compiled.manifest.records)).toContain(
        "operation:tiny:firstRead",
      );
      expect(Object.keys(compiled.manifest.records)).not.toContain(
        "operation:tiny:secondRead",
      );
    } finally {
      if (compiled) await discardCompiledRelease(compiled);
    }
  });

  test("validates provenance before reading the local source and canonicalizes HTTPS", async () => {
    const root = await temporaryRoot();
    const missing = join(root, "secret", "missing.json");
    const base = releaseOptions(root, missing);
    await expect(
      compileRelease({ ...base, sourceLabel: ".." }),
    ).rejects.toThrow(/source label/i);
    await expect(
      compileRelease({
        ...base,
        sourceUri: "https://user:pass@example.test/spec?token=x",
        sourceLabel: undefined,
      }),
    ).rejects.toThrow(/source URI/i);

    const spec = await write(
      root,
      "spec.json",
      JSON.stringify(minimalDocument()),
    );
    const compiled = await compileRelease({
      ...releaseOptions(root, spec),
      sourceLabel: undefined,
      sourceUri: "HTTPS://API.EXAMPLE.TEST:443/a/../spec%7e.json",
    });
    expect(compiled.manifest.source.uri).toBe(
      "https://api.example.test/spec~.json",
    );
    expect(JSON.stringify(compiled.manifest)).not.toContain(
      await realpath(root),
    );
    await discardCompiledRelease(compiled);
  });

  test("rejects non-root-relative or non-normalized OpenAPI path keys", async () => {
    const root = await temporaryRoot();
    for (const [name, path] of [
      ["absolute", "https://evil.example/escape"],
      ["authority", "//evil.example/escape"],
      ["backslash", "/safe\\escape"],
      ["query", "/safe?escape=1"],
      ["fragment", "/safe#escape"],
      ["dot-segment", "/safe/../escape"],
      ["control", "/safe\u0000escape"],
      ["malformed-template", "/safe/{id"],
      ["duplicate-template", "/safe/{id}/{id}"],
    ] as const) {
      const parameters = path.includes("{id")
        ? [
            {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "string" },
            },
          ]
        : [];
      const spec = await write(
        root,
        `${name}.json`,
        JSON.stringify(
          minimalDocument({
            paths: {
              [path]: {
                get: {
                  operationId: name,
                  parameters,
                  responses: { "204": { description: "ok" } },
                },
              },
            },
          }),
        ),
      );
      await expect(compileRelease(releaseOptions(root, spec))).rejects.toThrow(
        /path|request-target|template|normalized/i,
      );
    }
  });

  test("enforces exact and one-over structural operation/schema limits", async () => {
    const root = await temporaryRoot();
    const operation = {
      operationId: "getThing",
      parameters: [{ name: "q", in: "query", schema: { type: "string" } }],
      responses: { "200": { description: "ok" } },
    };
    const document = minimalDocument({
      paths: { "/things": { get: operation } },
      components: {
        schemas: {
          Thing: { type: "object", properties: { id: { type: "string" } } },
        },
      },
    });
    const spec = await write(root, "spec.json", JSON.stringify(document));
    for (const [field, exact] of [
      ["maxPaths", 1],
      ["maxOperations", 1],
      ["maxSchemas", 2],
      ["maxParametersPerOperation", 1],
      ["maxPropertiesPerSchema", 1],
    ] as const) {
      const ok = await compileRelease({
        ...releaseOptions(root, spec),
        limits: limits({ [field]: exact }),
      });
      await discardCompiledRelease(ok);
      await expect(
        compileRelease({
          ...releaseOptions(root, spec),
          limits: limits({ [field]: exact - 1 }),
        }),
      ).rejects.toThrow(new RegExp(field.replace(/^max/, ""), "i"));
    }
  });

  test("rejects oversized strings, refs, records, bad IDs, and server overrides", async () => {
    const root = await temporaryRoot();
    const cases: Array<
      [string, Record<string, unknown>, Partial<CompilerLimits>, RegExp]
    > = [
      [
        "string",
        minimalDocument({ info: { title: "xx", version: "1" } }),
        { maxStringBytes: 1 },
        /string/i,
      ],
      [
        "ref",
        minimalDocument({
          components: { schemas: { A: { $ref: "#/components/schemas/B" } } },
        }),
        { maxRefLength: 3 },
        /ref/i,
      ],
      [
        "record",
        minimalDocument({
          components: {
            schemas: { A: { type: "string", description: "large" } },
          },
        }),
        { maxRecordBytes: 20 },
        /record/i,
      ],
      [
        "id",
        minimalDocument({
          paths: { "/x": { get: { operationId: "bad:id", responses: {} } } },
        }),
        {},
        /operation.*invalid/i,
      ],
      [
        "path-server",
        minimalDocument({
          paths: {
            "/x": {
              servers: [{ url: "https://other.test" }],
              get: { operationId: "x", responses: {} },
            },
          },
        }),
        {},
        /server.*override/i,
      ],
      [
        "op-server",
        minimalDocument({
          paths: {
            "/x": {
              get: {
                operationId: "x",
                servers: [{ url: "https://other.test" }],
                responses: {},
              },
            },
          },
        }),
        {},
        /server.*override/i,
      ],
    ];
    for (const [name, document, limitOverrides, error] of cases) {
      const spec = await write(root, `${name}.json`, JSON.stringify(document));
      await expect(
        compileRelease({
          ...releaseOptions(root, spec),
          limits: limits(limitOverrides),
        }),
      ).rejects.toThrow(error);
    }
  });

  test("extracts operations from a local Path Item reference", async () => {
    const root = await temporaryRoot();
    const spec = await write(
      root,
      "local-path-item.json",
      JSON.stringify(
        minimalDocument({
          paths: {
            "/widgets": {
              $ref: "#/components/pathItems/Widgets",
            },
          },
          components: {
            pathItems: {
              Widgets: {
                get: {
                  operationId: "listWidgets",
                  responses: { "200": { description: "ok" } },
                },
              },
            },
          },
        }),
      ),
    );
    const compiled = await compileRelease(releaseOptions(root, spec));
    try {
      expect(Object.keys(compiled.manifest.records)).toContain(
        "operation:tiny:listWidgets",
      );
    } finally {
      await discardCompiledRelease(compiled);
    }
  });

  test("uses the resolved Path Item document for path parameters", async () => {
    const root = await temporaryRoot();
    const pathItemDocument = JSON.stringify({
      items: {
        parameters: [{ $ref: "#/parameters/tenant" }],
        get: {
          operationId: "listExternalWidgets",
          responses: { "200": { description: "ok" } },
        },
      },
      parameters: {
        tenant: {
          name: "tenant",
          in: "query",
          schema: { type: "string" },
        },
      },
    });
    await write(root, "path-items.json", pathItemDocument);
    const spec = await write(
      root,
      "mapped-path-item.json",
      JSON.stringify(
        minimalDocument({
          paths: { "/widgets": { $ref: "path-items.json#/items" } },
        }),
      ),
    );
    const map = await write(
      root,
      "path-items-map.json",
      JSON.stringify({
        version: 1,
        entries: [
          {
            uri: "path-items.json",
            file: "path-items.json",
            sha256: new Bun.CryptoHasher("sha256")
              .update(pathItemDocument)
              .digest("hex"),
          },
        ],
      }),
    );
    const compiled = await compileRelease({
      ...releaseOptions(root, spec),
      referenceRoot: root,
      referenceMapPath: map,
    });
    try {
      expect(Object.keys(compiled.manifest.records)).toContain(
        "operation:tiny:listExternalWidgets",
      );
    } finally {
      await discardCompiledRelease(compiled);
    }
  });

  test("requires mapped, digest-bound, contained references and permits safe cycles", async () => {
    const root = await temporaryRoot();
    const refs = join(root, "refs");
    await mkdir(refs);
    const external =
      '{"components":{"schemas":{"Other":{"type":"object","properties":{"self":{"$ref":"#/components/schemas/Other"}}}}}}';
    await write(refs, "other.json", external);
    const digest = new Bun.CryptoHasher("sha256")
      .update(external)
      .digest("hex");
    const spec = await write(
      root,
      "spec.json",
      JSON.stringify(
        minimalDocument({
          components: {
            schemas: { Root: { $ref: "other.json#/components/schemas/Other" } },
          },
        }),
      ),
    );
    const map = await write(
      root,
      "map.json",
      JSON.stringify({
        version: 1,
        entries: [{ uri: "other.json", file: "other.json", sha256: digest }],
      }),
    );
    const base = {
      ...releaseOptions(root, spec),
      referenceRoot: refs,
      referenceMapPath: map,
    };
    const compiled = await compileRelease(base);
    await discardCompiledRelease(compiled);
    const aggregateBytes =
      (await readFile(spec)).byteLength + Buffer.byteLength(external);
    const exactAggregate = await compileRelease({
      ...base,
      limits: limits({ maxSourceBytes: aggregateBytes }),
    });
    await discardCompiledRelease(exactAggregate);
    await expect(
      compileRelease({
        ...base,
        limits: limits({ maxSourceBytes: aggregateBytes - 1 }),
      }),
    ).rejects.toThrow(/aggregate source bytes/i);
    await expect(
      compileRelease({
        ...base,
        limits: limits({ maxReferencedDocuments: 0 }),
      }),
    ).rejects.toThrow(/referenced document count/i);
    await writeFile(
      map,
      JSON.stringify({
        version: 1,
        entries: [
          { uri: "other.json", file: "other.json", sha256: "0".repeat(64) },
        ],
      }),
    );
    await expect(compileRelease(base)).rejects.toThrow(/digest/i);
    await writeFile(
      map,
      JSON.stringify({
        version: 1,
        entries: [
          { uri: "other.json", file: "other.json", sha256: digest },
          { uri: "other%2Ejson", file: "other.json", sha256: digest },
        ],
      }),
    );
    await expect(compileRelease(base)).rejects.toThrow(/duplicate normalized/i);
    await writeFile(
      map,
      JSON.stringify({
        version: 1,
        entries: [
          { uri: "other.json?token=x", file: "other.json", sha256: digest },
        ],
      }),
    );
    await expect(compileRelease(base)).rejects.toThrow(/URI|query/i);
    await writeFile(
      map,
      JSON.stringify({
        version: 1,
        entries: [
          { uri: "other.json", file: "../outside.json", sha256: digest },
        ],
      }),
    );
    await expect(compileRelease(base)).rejects.toThrow(
      /contained|relative|travers/i,
    );
    await writeFile(map, JSON.stringify({ version: 1, entries: [] }));
    await expect(compileRelease(base)).rejects.toThrow(/reference map/i);

    await write(refs, "other.txt", external);
    await writeFile(
      map,
      JSON.stringify({
        version: 1,
        entries: [{ uri: "other.json", file: "other.txt", sha256: digest }],
      }),
    );
    await expect(compileRelease(base)).rejects.toThrow(/media type/i);

    await symlink("other.json", join(refs, "inside-link.json"));
    await writeFile(
      map,
      JSON.stringify({
        version: 1,
        entries: [
          { uri: "other.json", file: "inside-link.json", sha256: digest },
        ],
      }),
    );
    await expect(compileRelease(base)).rejects.toThrow(
      /referenced document.*read/i,
    );

    await link(join(refs, "other.json"), join(refs, "hard-link.json"));
    await writeFile(
      map,
      JSON.stringify({
        version: 1,
        entries: [
          { uri: "other.json", file: "hard-link.json", sha256: digest },
        ],
      }),
    );
    await expect(compileRelease(base)).rejects.toThrow(
      /referenced document.*read/i,
    );

    const outside = await write(root, "outside.json", external);
    await symlink(outside, join(refs, "escape.json"));
    await writeFile(
      map,
      JSON.stringify({
        version: 1,
        entries: [{ uri: "other.json", file: "escape.json", sha256: digest }],
      }),
    );
    await expect(compileRelease(base)).rejects.toThrow(/root|symlink|contain/i);
  });

  test("accepts reference depth 64 and rejects depth 65", async () => {
    const root = await temporaryRoot();
    const refs = join(root, "depth-refs");
    await mkdir(refs);
    const entries: Array<{ uri: string; file: string; sha256: string }> = [];
    for (let index = 0; index < 64; index += 1) {
      const body =
        index === 63 ? '{"type":"string"}' : `{"$ref":"d${index + 1}.json#"}`;
      await write(refs, `d${index}.json`, body);
      entries.push({
        uri: `d${index}.json`,
        file: `d${index}.json`,
        sha256: new Bun.CryptoHasher("sha256").update(body).digest("hex"),
      });
    }
    const spec = await write(
      root,
      "depth.json",
      JSON.stringify(
        minimalDocument({
          components: { schemas: { Root: { $ref: "d0.json#" } } },
        }),
      ),
    );
    const map = await write(
      root,
      "depth-map.json",
      JSON.stringify({ version: 1, entries: entries.slice(0, 64) }),
    );
    const exact = await compileRelease({
      ...releaseOptions(root, spec),
      referenceRoot: refs,
      referenceMapPath: map,
    });
    await discardCompiledRelease(exact);
    const sixtyFifth = '{"type":"string"}';
    await write(refs, "d64.json", sixtyFifth);
    const extendedSixtyFourth = '{"$ref":"d64.json#"}';
    await writeFile(join(refs, "d63.json"), extendedSixtyFourth);
    entries[63] = {
      uri: "d63.json",
      file: "d63.json",
      sha256: new Bun.CryptoHasher("sha256")
        .update(extendedSixtyFourth)
        .digest("hex"),
    };
    entries.push({
      uri: "d64.json",
      file: "d64.json",
      sha256: new Bun.CryptoHasher("sha256").update(sixtyFifth).digest("hex"),
    });
    await writeFile(map, JSON.stringify({ version: 1, entries }));
    await expect(
      compileRelease({
        ...releaseOptions(root, spec),
        referenceRoot: refs,
        referenceMapPath: map,
      }),
    ).rejects.toThrow(/reference depth/i);
  });

  test("accepts local reference depth 64 and rejects depth 65", async () => {
    const root = await temporaryRoot();
    const documentWithReferenceHops = (
      hops: number,
    ): Record<string, unknown> => {
      const schemas: Record<string, unknown> = {};
      for (let index = 0; index <= hops; index += 1) {
        schemas[`S${index}`] =
          index === hops
            ? { type: "string" }
            : { $ref: `#/components/schemas/S${index + 1}` };
      }
      return minimalDocument({ components: { schemas } });
    };
    const exactSpec = await write(
      root,
      "local-depth-64.json",
      JSON.stringify(documentWithReferenceHops(64)),
    );
    const exact = await compileRelease({
      ...releaseOptions(root, exactSpec),
      limits: limits({ maxJsonDepth: 64 }),
    });
    await discardCompiledRelease(exact);

    const overSpec = await write(
      root,
      "local-depth-65.json",
      JSON.stringify(documentWithReferenceHops(65)),
    );
    await expect(
      compileRelease({
        ...releaseOptions(root, overSpec),
        limits: limits({ maxJsonDepth: 64 }),
      }),
    ).rejects.toThrow(/reference depth/i);
  });
});
