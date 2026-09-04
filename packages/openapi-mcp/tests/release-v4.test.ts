import { afterEach, describe, expect, test } from "bun:test";
import { createPublicKey } from "node:crypto";
import {
  appendFile,
  mkdir,
  open,
  readdir,
  readFile,
  rename,
  rm,
  stat,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { basename, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import {
  type CompileReleaseOptions,
  compileRelease,
  discardCompiledRelease,
  publishRelease,
} from "../src/compiler.ts";
import {
  type ConstructionCheckpoint,
  compileReleaseWithCheckpoint,
} from "../src/release/compile-release.ts";
import { buildManifestEnvelopeV4 } from "../src/release/manifest-builder.ts";
import {
  pathIdentityFromStats,
  publishReleaseWithCheckpoint,
  samePathIdentity,
} from "../src/release/publish.ts";
import type {
  CatalogId,
  GenerationState,
  GenerationStore,
  OperationRecordV4,
  Sha256,
} from "../src/runtime/index.ts";
import {
  admitManifest,
  canonicalJson,
  sha256,
  verifyStoredRecord,
} from "../src/runtime/index.ts";
import {
  MAX_OPERATION_TAG_BYTES,
  MAX_OPERATION_TAG_BYTES_TOTAL,
  MAX_OPERATION_TAGS,
} from "../src/runtime/versions.ts";
import { generateKeypair } from "../src/sign.ts";

const roots: string[] = [];
async function temporaryRoot(): Promise<string> {
  const root = fileURLToPath(
    new URL(
      `../../../../.tmp/release-v4-${crypto.randomUUID()}/`,
      import.meta.url,
    ),
  );
  await mkdir(root, { recursive: true });
  roots.push(root);
  return root;
}
afterEach(async () =>
  Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  ),
);

test("path identity rejects inode reuse with a new birth time", () => {
  const original = { dev: 17n, ino: 23n, birthtimeNs: 41n };
  const replacement = { ...original, birthtimeNs: 43n };

  expect(samePathIdentity(original, original)).toBe(true);
  expect(samePathIdentity(original, replacement)).toBe(false);
  expect(() => pathIdentityFromStats({ ...original, birthtimeNs: 0n })).toThrow(
    "path identity requires a nonzero birthtimeNs",
  );
});

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

const SPEC = {
  openapi: "3.1.0",
  info: { title: "Tiny", version: "1" },
  servers: [{ url: "https://api.example.test" }],
  paths: {
    "/things/{id}": {
      parameters: [
        { name: "id", in: "path", required: true, schema: { type: "string" } },
      ],
      post: {
        operationId: "updateThing",
        summary: "Update a thing",
        parameters: [{ name: "q", in: "query", schema: { type: "integer" } }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/Thing" },
            },
          },
        },
        responses: { "200": { description: "ok" } },
      },
    },
  },
  components: {
    schemas: {
      Thing: { type: "object", properties: { id: { type: "string" } } },
    },
  },
};

async function fixture(root: string, releaseId = "release-1") {
  const specPath = join(root, `${releaseId}.json`);
  await writeFile(specPath, JSON.stringify(SPEC));
  const { privateKeyPem, publicKeyPem } = generateKeypair();
  const options: CompileReleaseOptions = {
    specPath,
    sourceLabel: "fixture-v1",
    sourceRevision: "abc123",
    catalogId: "tiny",
    releaseId,
    generation: 1,
    issuer: "test-issuer",
    keyId: "test-key",
    policyId: "test-policy",
    allowedOrigins: ["https://api.example.test"],
    outDir: root,
    privateKeyPem,
  };
  return {
    compiled: await compileRelease(options),
    privateKeyPem,
    publicKeyPem,
  };
}

async function constructionOptions(
  root: string,
  releaseId = "release-1",
): Promise<CompileReleaseOptions> {
  const specPath = join(root, `${releaseId}.json`);
  await writeFile(specPath, JSON.stringify(SPEC));
  return {
    specPath,
    sourceLabel: "fixture-v1",
    sourceRevision: "abc123",
    catalogId: "tiny",
    releaseId,
    generation: 1,
    issuer: "test-issuer",
    keyId: "test-key",
    policyId: "test-policy",
    allowedOrigins: ["https://api.example.test"],
    outDir: root,
    privateKeyPem: generateKeypair().privateKeyPem,
  };
}

class MemoryGenerationStore implements GenerationStore {
  state: GenerationState | null = null;
  async get(): Promise<GenerationState | null> {
    return this.state;
  }
  async accept(
    _catalog: CatalogId,
    _issuer: string,
    transition: { expectedRevision: number | null; next: GenerationState },
  ): Promise<GenerationState | null> {
    if ((this.state?.revision ?? null) !== transition.expectedRevision)
      return null;
    this.state = structuredClone(transition.next);
    return structuredClone(this.state);
  }
}

describe("immutable v4 construction", () => {
  test("resolves nested schema refs against a physical document's declared $id base", async () => {
    const root = await temporaryRoot();
    const options = await constructionOptions(root, "scoped-id");
    const specPath = join(root, "scoped-id.json");
    const physical = JSON.stringify({
      Thing: {
        $id: "declared/base.json",
        type: "object",
        properties: { child: { $ref: "child.json" } },
      },
    });
    const child = JSON.stringify({ type: "integer" });
    await writeFile(
      specPath,
      JSON.stringify({
        ...SPEC,
        paths: {
          "/scoped": {
            get: {
              operationId: "getScoped",
              parameters: [
                {
                  name: "value",
                  in: "query",
                  schema: { $ref: "#/components/schemas/FromPhysical" },
                },
              ],
              responses: { "200": { description: "ok" } },
            },
          },
        },
        components: {
          schemas: { FromPhysical: { $ref: "physical.json#/Thing" } },
        },
      }),
    );
    await writeFile(join(root, "physical.json"), physical);
    await writeFile(join(root, "child.json"), child);
    const mapPath = join(root, "references.json");
    await writeFile(
      mapPath,
      JSON.stringify({
        version: 1,
        entries: [
          {
            uri: "physical.json",
            file: "physical.json",
            sha256: new Bun.CryptoHasher("sha256")
              .update(physical)
              .digest("hex"),
          },
          {
            uri: "declared/child.json",
            file: "child.json",
            sha256: new Bun.CryptoHasher("sha256").update(child).digest("hex"),
          },
        ],
      }),
    );

    const compiled = await compileRelease({
      ...options,
      specPath,
      referenceRoot: root,
      referenceMapPath: mapPath,
    });
    const database = new DatabaseSync(compiled.paths.sqlite, {
      readOnly: true,
    });
    try {
      const rows = database
        .prepare("SELECT record_id, record_json FROM schemas")
        .all() as Array<{ record_id: string; record_json: string }>;
      const fromPhysical = JSON.parse(
        rows.find(
          (row) =>
            row.record_id === "schema:tiny:#/components/schemas/FromPhysical",
        )?.record_json ?? "null",
      ) as { schema: { $ref: string } };
      const physicalSchema = JSON.parse(
        rows.find((row) => row.record_id === fromPhysical.schema.$ref)
          ?.record_json ?? "null",
      ) as { schema: { properties: { child: { $ref: string } } } };
      const childSchema = JSON.parse(
        rows.find(
          (row) =>
            row.record_id === physicalSchema.schema.properties.child.$ref,
        )?.record_json ?? "null",
      ) as { schema: { type: string } };

      expect(childSchema.schema.type).toBe("integer");
      expect(
        compiled.manifest.records[physicalSchema.schema.properties.child.$ref],
      ).toBeDefined();
    } finally {
      database.close();
    }
    await discardCompiledRelease(compiled);
  });

  test("preserves JSON annotations as data while rewriting real child schemas", async () => {
    const root = await temporaryRoot();
    const options = await constructionOptions(root, "annotations");
    await writeFile(
      options.specPath,
      JSON.stringify({
        ...SPEC,
        components: {
          schemas: {
            Annotated: {
              type: "object",
              default: { $ref: "literal-default" },
              examples: [{ $ref: "literal-example" }],
              const: { $ref: "literal-const" },
              enum: [{ $ref: "literal-enum" }],
              properties: { real: { $ref: "#/components/schemas/Child" } },
            },
            Child: { type: "integer" },
            Thing: { type: "string" },
          },
        },
      }),
    );

    const compiled = await compileRelease(options);
    const database = new DatabaseSync(compiled.paths.sqlite, {
      readOnly: true,
    });
    try {
      const row = database
        .prepare("SELECT record_json FROM schemas WHERE record_id = ?")
        .get("schema:tiny:#/components/schemas/Annotated") as {
        record_json: string;
      };
      const schema = JSON.parse(row.record_json).schema as Record<
        string,
        unknown
      >;
      expect(schema.default).toEqual({ $ref: "literal-default" });
      expect(schema.examples).toEqual([{ $ref: "literal-example" }]);
      expect(schema.const).toEqual({ $ref: "literal-const" });
      expect(schema.enum).toEqual([{ $ref: "literal-enum" }]);
      expect((schema.properties as { real: { $ref: string } }).real.$ref).toBe(
        "schema:tiny:#/components/schemas/Child",
      );
    } finally {
      database.close();
    }
    await discardCompiledRelease(compiled);
  });

  test("truncates operation summaries without splitting an astral character", async () => {
    const root = await temporaryRoot();
    const options = await constructionOptions(root, "astral-summary");
    await writeFile(
      options.specPath,
      JSON.stringify({
        ...SPEC,
        paths: {
          "/summary": {
            get: {
              operationId: "getSummary",
              summary: `${"a".repeat(599)}😀tail`,
              responses: { "200": { description: "ok" } },
            },
          },
        },
      }),
    );
    const compiled = await compileRelease(options);
    const database = new DatabaseSync(compiled.paths.sqlite, {
      readOnly: true,
    });
    try {
      const row = database
        .prepare("SELECT summary FROM operations WHERE operation_id = ?")
        .get("getSummary") as { summary: string };
      expect(row.summary).toBe("a".repeat(599));
      expect(row.summary.length).toBeLessThanOrEqual(600);
    } finally {
      database.close();
    }
    await discardCompiledRelease(compiled);
  });

  test("signs source-order operation tags", async () => {
    const root = await temporaryRoot();
    const options = await constructionOptions(root, "signed-tags");
    await writeFile(
      options.specPath,
      JSON.stringify({
        ...SPEC,
        paths: {
          "/tags": {
            get: {
              operationId: "getTagged",
              tags: ["refund", "billing"],
              responses: { "200": { description: "ok" } },
            },
          },
        },
      }),
    );
    const compiled = await compileRelease(options);
    const database = new DatabaseSync(compiled.paths.sqlite, {
      readOnly: true,
    });
    try {
      const row = database
        .prepare("SELECT record_json FROM operations WHERE operation_id = ?")
        .get("getTagged") as { record_json: string };
      expect((JSON.parse(row.record_json) as OperationRecordV4).tags).toEqual([
        "refund",
        "billing",
      ]);
    } finally {
      database.close();
    }
    await discardCompiledRelease(compiled);
  });

  test("rejects malformed and one-over operation tags before signing", async () => {
    const cases: readonly [string, unknown][] = [
      ["non-array", "refund"],
      ["duplicate", ["refund", "refund"]],
      [
        "count one-over",
        Array.from(
          { length: MAX_OPERATION_TAGS + 1 },
          (_, index) => `tag-${index}`,
        ),
      ],
      [
        "UTF-8 bytes one-over",
        ["😀".repeat(Math.floor(MAX_OPERATION_TAG_BYTES / 4) + 1)],
      ],
      [
        "aggregate UTF-8 bytes one-over",
        [
          ...Array.from(
            {
              length: MAX_OPERATION_TAG_BYTES_TOTAL / MAX_OPERATION_TAG_BYTES,
            },
            (_, index) =>
              `${index.toString().padStart(3, "0")}${"a".repeat(MAX_OPERATION_TAG_BYTES - 3)}`,
          ),
          "z",
        ],
      ],
    ];

    for (const [index, [_name, tags]] of cases.entries()) {
      const root = await temporaryRoot();
      const options = await constructionOptions(root, `invalid-tags-${index}`);
      await writeFile(
        options.specPath,
        JSON.stringify({
          ...SPEC,
          paths: {
            "/tags": {
              get: {
                operationId: "getTagged",
                tags,
                responses: { "200": { description: "ok" } },
              },
            },
          },
        }),
      );
      await expect(compileRelease(options)).rejects.toThrow(
        "operation tags are invalid",
      );
    }
  });

  test("bounds emitted SQLite reread when its inode grows after capped stat", async () => {
    const root = await temporaryRoot();
    const probePath = join(root, "file-handle-probe");
    await writeFile(probePath, "probe");
    const probe = await open(probePath, "r");
    const prototype = Object.getPrototypeOf(probe) as {
      readFile: (...args: unknown[]) => Promise<unknown>;
    };
    await probe.close();
    const originalReadFile = prototype.readFile;
    let unboundedReadFileCalls = 0;
    prototype.readFile = function (...args: unknown[]): Promise<unknown> {
      unboundedReadFileCalls += 1;
      return Reflect.apply(originalReadFile, this, args) as Promise<unknown>;
    };
    const options = await constructionOptions(root);
    let stage = "";
    let error: unknown;
    try {
      error = await compileReleaseWithCheckpoint(
        options,
        async (checkpoint, paths) => {
          if (checkpoint !== "before-sqlite-snapshot-read") return;
          stage = paths.directory;
          await appendFile(paths.sqlite, Buffer.alloc(1024 * 1024, 0x61));
        },
      ).catch((reason) => reason);
    } finally {
      prototype.readFile = originalReadFile;
    }
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toBe(
      "emitted SQLite could not be reopened safely",
    );
    expect(unboundedReadFileCalls).toBe(0);
    expect(stage).not.toBe("");
    await expect(stat(stage)).rejects.toThrow();
  });

  test("rejects emitted SQLite corruption before self-admission", async () => {
    const root = await temporaryRoot();
    const options = await constructionOptions(root);
    let stage = "";
    await expect(
      compileReleaseWithCheckpoint(options, async (checkpoint, paths) => {
        if (checkpoint !== "after-sqlite-emitted") return;
        stage = paths.directory;
        const database = new DatabaseSync(paths.sqlite);
        try {
          database
            .prepare("UPDATE operations SET record_json = '{' LIMIT 1")
            .run();
        } finally {
          database.close();
        }
      }),
    ).rejects.toThrow(/reread|digest|record/i);
    expect(stage).not.toBe("");
    await expect(stat(stage)).rejects.toThrow();
  });

  test("fails closed when the stage parent is substituted before every leaf transition", async () => {
    for (const checkpoint of [
      "before-sqlite-created",
      "before-signature-created",
      "before-manifest-created",
    ] as const satisfies readonly ConstructionCheckpoint[]) {
      const root = await temporaryRoot();
      const options = await constructionOptions(root);
      const attacker = join(root, `attacker-${checkpoint}`);
      const sentinel = join(attacker, "sentinel.txt");
      let ownedStage = "";
      const error = await compileReleaseWithCheckpoint(
        options,
        async (current, paths) => {
          if (current !== checkpoint) return;
          ownedStage = `${paths.directory}.owned`;
          await rename(paths.directory, ownedStage);
          await mkdir(attacker);
          await writeFile(sentinel, "preserve-me");
          await symlink(attacker, paths.directory);
        },
      ).catch((reason) => reason);
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toMatch(/stage directory identity/i);
      expect(await readFile(sentinel, "utf8")).toBe("preserve-me");
      expect(await readdir(attacker)).toEqual(["sentinel.txt"]);
      expect(ownedStage).not.toBe("");
      expect((await stat(ownedStage)).isDirectory()).toBe(true);
    }
  });

  test("compile-error cleanup preserves a substituted stage parent and sentinel", async () => {
    const root = await temporaryRoot();
    const options = await constructionOptions(root);
    const attacker = join(root, "attacker-cleanup");
    const sentinel = join(attacker, "sentinel.txt");
    let ownedStage = "";
    const error = await compileReleaseWithCheckpoint(
      options,
      async (checkpoint, paths) => {
        if (checkpoint !== "before-sqlite-created") return;
        ownedStage = `${paths.directory}.owned`;
        await rename(paths.directory, ownedStage);
        await mkdir(attacker);
        await writeFile(sentinel, "preserve-me");
        await symlink(attacker, paths.directory);
        throw new Error("injected construction failure");
      },
    ).catch((reason) => reason);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toBe("injected construction failure");
    expect(await readFile(sentinel, "utf8")).toBe("preserve-me");
    expect(await readdir(attacker)).toEqual(["sentinel.txt"]);
    expect((await stat(ownedStage)).isDirectory()).toBe(true);
  });

  test("post-open parent and leaf substitution never receives release content", async () => {
    const cases = [
      ["after-sqlite-opened", "sqlite"],
      ["after-signature-opened", "signature"],
      ["after-manifest-opened", "manifest"],
    ] as const satisfies ReadonlyArray<
      readonly [ConstructionCheckpoint, "sqlite" | "signature" | "manifest"]
    >;
    for (const [checkpoint, kind] of cases) {
      for (const substitution of ["parent", "leaf"] as const) {
        const root = await temporaryRoot();
        const options = await constructionOptions(root);
        const attacker = join(root, `attacker-${checkpoint}-${substitution}`);
        const sentinel = join(attacker, "sentinel.txt");
        let replacement = "";
        let openedLeaf = "";
        const error = await compileReleaseWithCheckpoint(
          options,
          async (current, paths) => {
            if (current !== checkpoint) return;
            if (substitution === "parent") {
              const ownedStage = `${paths.directory}.owned`;
              await rename(paths.directory, ownedStage);
              await mkdir(attacker);
              await writeFile(sentinel, "preserve-parent");
              await symlink(attacker, paths.directory);
              replacement = sentinel;
              openedLeaf = join(ownedStage, basename(paths[kind]));
              return;
            }
            const leaf = paths[kind];
            openedLeaf = `${leaf}.owned`;
            await rename(leaf, openedLeaf);
            await writeFile(leaf, "preserve-leaf");
            replacement = leaf;
          },
        ).catch((reason) => reason);
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toMatch(/stage.*identity/i);
        expect(await readFile(replacement, "utf8")).toMatch(/^preserve-/);
        expect((await stat(openedLeaf)).size).toBe(0);
      }
    }
  });

  test("emits the exact lower-case transport schema and canonical logical rows", async () => {
    const root = await temporaryRoot();
    const { compiled } = await fixture(root);
    const db = new DatabaseSync(compiled.paths.sqlite);
    try {
      const tables = db
        .prepare(
          "SELECT name, sql FROM sqlite_master WHERE type IN ('table','index') ORDER BY name",
        )
        .all() as Array<{ name: string; sql: string }>;
      for (const name of [
        "operations",
        "operations_fts",
        "operations_release_api",
        "release_metadata",
        "schemas",
      ]) {
        expect(tables.map((row) => row.name)).toContain(name);
      }
      expect(
        (
          db.prepare("PRAGMA table_info(operations)").all() as Array<{
            name: string;
          }>
        ).map((column) => column.name),
      ).toEqual([
        "catalog_id",
        "release_id",
        "record_id",
        "record_json",
        "logical_digest",
        "api",
        "operation_id",
        "summary",
        "path",
        "search_text",
      ]);
      expect(
        (
          db.prepare("PRAGMA table_info(schemas)").all() as Array<{
            name: string;
          }>
        ).map((column) => column.name),
      ).toEqual([
        "catalog_id",
        "release_id",
        "record_id",
        "record_json",
        "logical_digest",
      ]);
      expect(
        tables.find((row) => row.name === "operations_fts")?.sql,
      ).toContain("USING fts5(");
      const rows = db
        .prepare(
          "SELECT record_id, record_json, logical_digest FROM operations UNION ALL SELECT record_id, record_json, logical_digest FROM schemas ORDER BY record_id",
        )
        .all() as Array<{
        record_id: string;
        record_json: string;
        logical_digest: string;
      }>;
      for (const row of rows) {
        expect(row.record_json).toBe(
          canonicalJson(JSON.parse(row.record_json)),
        );
        const domain = row.record_id.startsWith("operation:")
          ? "knitli.openapi-mcp.operation-record.v4"
          : "knitli.openapi-mcp.schema-record.v4";
        expect(row.logical_digest).toBe(
          await sha256(domain, JSON.parse(row.record_json)),
        );
        expect(
          compiled.manifest.records[
            row.record_id as keyof typeof compiled.manifest.records
          ],
        ).toBe(row.logical_digest);
      }
      const operationRow = rows.find((row) =>
        row.record_id.startsWith("operation:"),
      );
      expect(operationRow).toBeDefined();
      const operation = JSON.parse(operationRow?.record_json ?? "null");
      expect(operation).not.toHaveProperty("searchText");
      expect(
        operation.parameters.map((parameter: { in: string }) => parameter.in),
      ).toEqual(["path", "query"]);
      expect(operation.parameters[0]).toMatchObject({
        name: "id",
        in: "path",
        required: true,
        deprecated: false,
        style: "simple",
        explode: false,
        allowReserved: false,
        value: { kind: "schema" },
      });
      expect(operation.parameters[0].value.schemaId).toBe(
        "schema:tiny:#/components/schemas/__openapi_mcp_v4_415dea5a6fe0e7dc63d687d25fe24e8e92668946a11f4dce177f1586361f0367",
      );
      expect(operation.parameters[1]).toMatchObject({
        name: "q",
        in: "query",
        required: false,
        deprecated: false,
        style: "form",
        explode: true,
        allowReserved: false,
        value: { kind: "schema" },
      });
      expect(operation.parameters[1].value.schemaId).toBe(
        "schema:tiny:#/components/schemas/__openapi_mcp_v4_6fc2c15cdfaba67896f4ee035a510751c3a7be1dc5353dd19b6b12663233cbc8",
      );
      expect(operation.requestBody).toEqual({
        required: true,
        content: [
          {
            mediaType: "application/json",
            schemaId: "schema:tiny:#/components/schemas/Thing",
            encoding: [],
          },
        ],
      });
      expect(operation.schemaIds).toEqual(
        [
          ...operation.parameters.map(
            (parameter: { value: { schemaId: string } }) =>
              parameter.value.schemaId,
          ),
          operation.requestBody.content[0].schemaId,
        ].sort(),
      );
      db.exec("UPDATE operations SET search_text = 'poisoned discovery only'");
      const unchanged = db
        .prepare("SELECT logical_digest FROM operations")
        .get() as { logical_digest: string };
      expect(unchanged.logical_digest).toBe(
        compiled.manifest.records[operation.id],
      );
    } finally {
      db.close();
    }
    await discardCompiledRelease(compiled);
  });

  test("the canonical signature self-admits and every D1-shaped row verifies", async () => {
    const root = await temporaryRoot();
    const { compiled, publicKeyPem } = await fixture(root);
    expect(compiled.envelope.manifestJson).toBe(
      canonicalJson(compiled.manifest),
    );
    expect(compiled.envelope.signature.algorithm).toBe("Ed25519");
    const publicKey = createPublicKey(publicKeyPem)
      .export({ type: "spki", format: "der" })
      .toString("base64url");
    const admitted = await admitManifest(
      compiled.envelope,
      {
        releaseKeys: [{ issuer: "test-issuer", keyId: "test-key", publicKey }],
        rollbackKeys: [],
      },
      new MemoryGenerationStore(),
    );
    const db = new DatabaseSync(compiled.paths.sqlite, { readOnly: true });
    const rows = db
      .prepare(
        "SELECT record_id, logical_digest, record_json FROM operations UNION ALL SELECT record_id, logical_digest, record_json FROM schemas",
      )
      .all() as Array<{
      record_id: string;
      logical_digest: string;
      record_json: string;
    }>;
    db.close();
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      await expect(
        verifyStoredRecord(admitted, {
          id: row.record_id,
          logicalDigest: row.logical_digest,
          record: JSON.parse(row.record_json),
        } as never),
      ).resolves.toBeDefined();
    }
    await discardCompiledRelease(compiled);
  });

  test("cleans a compiler-owned stage when explicitly discarded and refuses reuse", async () => {
    const root = await temporaryRoot();
    const { compiled } = await fixture(root);
    await discardCompiledRelease(compiled);
    await expect(stat(compiled.paths.directory)).rejects.toThrow();
    await expect(discardCompiledRelease(compiled)).rejects.toThrow(/consumed/i);
    await expect(publishRelease(compiled, { directory: root })).rejects.toThrow(
      /consumed/i,
    );
  });

  test("publication revalidates staged content and consumes a substituted stage", async () => {
    const root = await temporaryRoot();
    const target = join(root, "published");
    await mkdir(target);
    const { compiled } = await fixture(root);
    await writeFile(
      compiled.paths.manifest,
      `${compiled.envelope.manifestJson}\n`,
    );
    await expect(
      publishRelease(compiled, { directory: target }),
    ).rejects.toThrow(/staged content was modified/i);
    await expect(stat(compiled.paths.directory)).rejects.toThrow();
    expect(await readdir(target)).toEqual([]);
  });

  test("rejects persistently oversized staged content without unbounded reads", async () => {
    const root = await temporaryRoot();
    const target = join(root, "published");
    await mkdir(target);
    const { compiled } = await fixture(root);
    const probePath = join(root, "publication-file-handle-probe");
    await writeFile(probePath, "probe");
    const probe = await open(probePath, "r");
    const prototype = Object.getPrototypeOf(probe) as {
      readFile: (...args: unknown[]) => Promise<unknown>;
    };
    await probe.close();
    const originalReadFile = prototype.readFile;
    let unboundedReadFileCalls = 0;
    prototype.readFile = function (...args: unknown[]): Promise<unknown> {
      unboundedReadFileCalls += 1;
      return Reflect.apply(originalReadFile, this, args) as Promise<unknown>;
    };
    try {
      await appendFile(compiled.paths.sqlite, Buffer.alloc(1024 * 1024, 0x61));
      await expect(
        publishRelease(compiled, { directory: target }),
      ).rejects.toThrow(/size|modified/i);
      expect(unboundedReadFileCalls).toBe(0);
    } finally {
      prototype.readFile = originalReadFile;
    }
    await expect(stat(compiled.paths.directory)).rejects.toThrow();
    expect(await readdir(target)).toEqual([]);
  });

  test("bounds staged hashing when the owned inode grows after capped stat", async () => {
    const root = await temporaryRoot();
    const target = join(root, "published");
    await mkdir(target);
    const { compiled } = await fixture(root);
    const probePath = join(root, "publication-growth-file-handle-probe");
    await writeFile(probePath, "probe");
    const probe = await open(probePath, "r");
    const prototype = Object.getPrototypeOf(probe) as {
      readFile: (...args: unknown[]) => Promise<unknown>;
    };
    await probe.close();
    const originalReadFile = prototype.readFile;
    let unboundedReadFileCalls = 0;
    prototype.readFile = function (...args: unknown[]): Promise<unknown> {
      unboundedReadFileCalls += 1;
      return Reflect.apply(originalReadFile, this, args) as Promise<unknown>;
    };
    try {
      await expect(
        publishReleaseWithCheckpoint(
          compiled,
          { directory: target },
          async (checkpoint) => {
            if ((checkpoint as string) !== "before-sqlite-validation-read")
              return;
            await appendFile(
              compiled.paths.sqlite,
              Buffer.alloc(1024 * 1024, 0x62),
            );
          },
        ),
      ).rejects.toThrow(
        "compiled release staged content was modified: exceeds recorded size",
      );
      expect(unboundedReadFileCalls).toBe(0);
    } finally {
      prototype.readFile = originalReadFile;
    }
    await expect(stat(compiled.paths.directory)).rejects.toThrow();
    expect(await readdir(target)).toEqual([]);
  });

  test("rejects a staged FIFO substitution without waiting for a writer", async () => {
    const root = await temporaryRoot();
    const target = join(root, "published");
    await mkdir(target);
    const options = await constructionOptions(root);
    const compilerModule = fileURLToPath(
      new URL("../src/compiler.ts", import.meta.url),
    );
    const publishModule = fileURLToPath(
      new URL("../src/release/publish.ts", import.meta.url),
    );
    const script = `
      const compiler = await import(${JSON.stringify(compilerModule)});
      const publisher = await import(${JSON.stringify(publishModule)});
      const fs = await import("node:fs/promises");
      const compiled = await compiler.compileRelease(${JSON.stringify(options)});
      try {
        await publisher.publishReleaseWithCheckpoint(
          compiled,
          { directory: ${JSON.stringify(target)} },
          async (checkpoint) => {
            if (checkpoint !== "before-sqlite-validation-open") return;
            await fs.unlink(compiled.paths.sqlite);
            const mkfifo = Bun.spawn(["mkfifo", compiled.paths.sqlite]);
            if (await mkfifo.exited !== 0) process.exit(4);
          },
        );
        process.exit(2);
      } catch (error) {
        process.exit(error instanceof Error && /staged file|identity|modified/.test(error.message) ? 0 : 3);
      }
    `;
    expect(await runChildWithDeadline(script)).toEqual({
      kind: "exit",
      code: 0,
    });
    expect(await readdir(target)).toEqual([]);
  });
});

describe("runtime operation record invariants", () => {
  test("rejects path-template and normalized path-parameter disagreement", async () => {
    const root = await temporaryRoot();
    const { compiled, privateKeyPem, publicKeyPem } = await fixture(root);
    const db = new DatabaseSync(compiled.paths.sqlite, { readOnly: true });
    const stored = db
      .prepare(
        "SELECT record_id, record_json FROM operations WHERE operation_id = ?",
      )
      .get("updateThing") as { record_id: string; record_json: string };
    db.close();
    const valid = JSON.parse(stored.record_json) as OperationRecordV4;
    const cases: Array<readonly [string, OperationRecordV4]> = [
      [
        "missing",
        {
          ...valid,
          parameters: valid.parameters.filter((item) => item.in !== "path"),
        },
      ],
      [
        "extra",
        {
          ...valid,
          path: "/things",
        },
      ],
      [
        "duplicate template",
        {
          ...valid,
          path: "/things/{id}/{id}",
        },
      ],
      [
        "malformed template",
        {
          ...valid,
          path: "/things/{id",
        },
      ],
      ["absolute URL", { ...valid, path: "https://evil.example/{id}" }],
      ["network authority", { ...valid, path: "//evil.example/{id}" }],
      ["backslash", { ...valid, path: "/things\\{id}" }],
      ["query", { ...valid, path: "/things/{id}?escape=1" }],
      ["fragment", { ...valid, path: "/things/{id}#escape" }],
      ["dot segment", { ...valid, path: "/safe/../things/{id}" }],
      ["control", { ...valid, path: "/things/{id}\u0000" }],
    ];

    const publicKey = createPublicKey(publicKeyPem)
      .export({ type: "spki", format: "der" })
      .toString("base64url");
    for (const [name, record] of cases) {
      const digest = (await sha256(
        "knitli.openapi-mcp.operation-record.v4",
        record,
      )) as Sha256;
      const manifest = {
        ...compiled.manifest,
        records: { ...compiled.manifest.records, [record.id]: digest },
      };
      const admitted = await admitManifest(
        buildManifestEnvelopeV4(manifest, privateKeyPem),
        {
          releaseKeys: [
            { issuer: "test-issuer", keyId: "test-key", publicKey },
          ],
          rollbackKeys: [],
        },
        new MemoryGenerationStore(),
      );
      await expect(
        verifyStoredRecord(admitted, {
          id: record.id,
          logicalDigest: digest,
          record,
        }),
        name,
      ).rejects.toMatchObject({ code: "RECORD_DIGEST_MISMATCH" });
    }
    await discardCompiledRelease(compiled);
  });
});

describe("manifest-last publication", () => {
  test("publishes payload, signature, and manifest in order while observers see no early manifest", async () => {
    const root = await temporaryRoot();
    const target = join(root, "published");
    await mkdir(target);
    const { compiled } = await fixture(root);
    const checkpoints: string[] = [];
    await publishReleaseWithCheckpoint(
      compiled,
      { directory: target },
      async (checkpoint) => {
        checkpoints.push(checkpoint);
        const names = await readdir(target);
        if (checkpoint !== "manifest-published")
          expect(names).not.toContain("release-1.manifest.json");
      },
    );
    expect(checkpoints).toEqual([
      "before-sqlite-validation-open",
      "before-sqlite-validation-read",
      "before-signature-validation-open",
      "before-signature-validation-read",
      "before-manifest-validation-open",
      "before-manifest-validation-read",
      "payload-published",
      "signature-published",
      "manifest-published",
    ]);
    expect((await readdir(target)).sort()).toEqual([
      "release-1.manifest.json",
      "release-1.manifest.sig",
      "release-1.sqlite",
    ]);
    await expect(stat(compiled.paths.directory)).rejects.toThrow();
  });

  test("refuses existing targets and concurrent publishers without overwrite", async () => {
    const root = await temporaryRoot();
    const target = join(root, "published");
    await mkdir(target);
    await writeFile(join(target, "release-1.sqlite"), "existing");
    const { compiled } = await fixture(root);
    await expect(
      publishRelease(compiled, { directory: target }),
    ).rejects.toThrow(/exists/i);
    expect(await readFile(join(target, "release-1.sqlite"), "utf8")).toBe(
      "existing",
    );
    await expect(stat(compiled.paths.directory)).rejects.toThrow();

    const first = await fixture(root, "release-2");
    const second = await fixture(root, "release-2");
    const results = await Promise.allSettled([
      publishRelease(first.compiled, { directory: target }),
      publishRelease(second.compiled, { directory: target }),
    ]);
    expect(
      results.filter((result) => result.status === "fulfilled"),
    ).toHaveLength(1);
    expect(
      results.filter((result) => result.status === "rejected"),
    ).toHaveLength(1);
  });

  test("handled pre-manifest failure leaves no admissible release and preserves older releases", async () => {
    const root = await temporaryRoot();
    const target = join(root, "published");
    await mkdir(target);
    await writeFile(join(target, "older.manifest.json"), "older");
    const { compiled } = await fixture(root);
    await expect(
      publishReleaseWithCheckpoint(
        compiled,
        { directory: target },
        async (checkpoint) => {
          if (checkpoint === "signature-published")
            throw new Error("simulated failure");
        },
      ),
    ).rejects.toThrow("simulated failure");
    expect(await readFile(join(target, "older.manifest.json"), "utf8")).toBe(
      "older",
    );
    expect(await readdir(target)).not.toContain("release-1.manifest.json");
    expect(await readdir(target)).not.toContain("release-1.sqlite");
    expect(await readdir(target)).not.toContain("release-1.manifest.sig");
    expect(await readdir(target)).not.toContain(".release-1.publish.lock");
    await expect(stat(compiled.paths.directory)).rejects.toThrow();
  });

  test("atomically refuses a target inserted after publication begins", async () => {
    const root = await temporaryRoot();
    const target = join(root, "published");
    await mkdir(target);
    const { compiled } = await fixture(root);
    const sentinel = "do-not-overwrite";
    const signature = join(target, "release-1.manifest.sig");

    await expect(
      publishReleaseWithCheckpoint(
        compiled,
        { directory: target },
        async (at) => {
          if (at === "payload-published") {
            await writeFile(signature, sentinel, { flag: "wx" });
          }
        },
      ),
    ).rejects.toThrow(/exists|publish/i);
    expect(await readFile(signature, "utf8")).toBe(sentinel);
    expect(await readdir(target)).not.toContain("release-1.manifest.json");
  });

  test("fails closed when its lock is lost while another publisher completes", async () => {
    const root = await temporaryRoot();
    const target = join(root, "published");
    await mkdir(target);
    const first = await fixture(root, "release-2");
    const second = await fixture(root, "release-2");
    const lock = join(target, ".release-2.publish.lock");
    const payload = join(target, "release-2.sqlite");

    const firstResult = publishReleaseWithCheckpoint(
      first.compiled,
      { directory: target },
      async (at) => {
        if (at === "payload-published") {
          await unlink(lock);
          await unlink(payload);
          await publishRelease(second.compiled, { directory: target });
        }
      },
    );
    await expect(firstResult).rejects.toThrow(/lock|identity|ownership/i);
    expect(
      await readFile(join(target, "release-2.manifest.json"), "utf8"),
    ).toBe(second.compiled.envelope.manifestJson);
  });

  test("rejects a payload replacement after signature before manifest visibility", async () => {
    const root = await temporaryRoot();
    const target = join(root, "published");
    await mkdir(target);
    const { compiled } = await fixture(root);
    const payload = join(target, "release-1.sqlite");
    const manifest = join(target, "release-1.manifest.json");
    const sentinel = "replacement-payload-sentinel";
    await expect(
      publishReleaseWithCheckpoint(
        compiled,
        { directory: target },
        async (checkpoint) => {
          if (checkpoint !== "signature-published") return;
          await unlink(payload);
          await writeFile(payload, sentinel);
        },
      ),
    ).rejects.toThrow(/published target.*identity|ownership/i);
    expect(await readFile(payload, "utf8")).toBe(sentinel);
    await expect(stat(manifest)).rejects.toThrow();
  });

  test("rejects target-directory replacement without writing into the substitute", async () => {
    const root = await temporaryRoot();
    const target = join(root, "published");
    const ownedTarget = join(root, "published-owned");
    await mkdir(target);
    const { compiled } = await fixture(root);
    const sentinel = join(target, "sentinel.txt");
    await expect(
      publishReleaseWithCheckpoint(
        compiled,
        { directory: target },
        async (checkpoint) => {
          if (checkpoint !== "payload-published") return;
          await rename(target, ownedTarget);
          await mkdir(target);
          await writeFile(sentinel, "preserve-target");
        },
      ),
    ).rejects.toThrow(/target directory.*identity|ownership/i);
    expect(await readFile(sentinel, "utf8")).toBe("preserve-target");
    expect(await readdir(target)).toEqual(["sentinel.txt"]);
    expect(await stat(join(ownedTarget, "release-1.sqlite"))).toBeDefined();
    await expect(
      stat(join(ownedTarget, "release-1.manifest.json")),
    ).rejects.toThrow();
  });

  test("cleanup preserves a substituted published target", async () => {
    const root = await temporaryRoot();
    const target = join(root, "published");
    await mkdir(target);
    const { compiled } = await fixture(root);
    const payload = join(target, "release-1.sqlite");
    const sentinel = "replacement-payload";

    await expect(
      publishReleaseWithCheckpoint(
        compiled,
        { directory: target },
        async (at) => {
          if (at === "payload-published") {
            await unlink(payload);
            await writeFile(payload, sentinel, { flag: "wx" });
            throw new Error("forced failure after substitution");
          }
        },
      ),
    ).rejects.toThrow("forced failure after substitution");
    expect(await readFile(payload, "utf8")).toBe(sentinel);
  });

  test("discard preserves a substituted stage directory", async () => {
    const root = await temporaryRoot();
    const { compiled } = await fixture(root);
    const directory = compiled.paths.directory;
    await rm(directory, { recursive: true });
    await mkdir(directory);
    const sentinel = join(directory, "unowned.txt");
    await writeFile(sentinel, "replacement-directory");

    await discardCompiledRelease(compiled);
    expect(await readFile(sentinel, "utf8")).toBe("replacement-directory");
  });

  test("discard preserves a substituted stage file", async () => {
    const root = await temporaryRoot();
    const { compiled } = await fixture(root);
    const sentinel = "replacement-manifest";
    await unlink(compiled.paths.manifest);
    await writeFile(compiled.paths.manifest, sentinel, { flag: "wx" });

    await discardCompiledRelease(compiled);
    expect(await readFile(compiled.paths.manifest, "utf8")).toBe(sentinel);
  });

  test("publication preserves a substituted pending stage file", async () => {
    const root = await temporaryRoot();
    const target = join(root, "published");
    await mkdir(target);
    const { compiled } = await fixture(root);
    const sentinel = "replacement-stage-signature";

    await expect(
      publishReleaseWithCheckpoint(
        compiled,
        { directory: target },
        async (at) => {
          if (at === "payload-published") {
            await unlink(compiled.paths.signature);
            await writeFile(compiled.paths.signature, sentinel, { flag: "wx" });
          }
        },
      ),
    ).rejects.toThrow(/identity|ownership|staged/i);
    expect(await readFile(compiled.paths.signature, "utf8")).toBe(sentinel);
    expect(await readdir(target)).not.toContain("release-1.manifest.json");
  });

  test("publication preserves a substituted stage directory", async () => {
    const root = await temporaryRoot();
    const target = join(root, "published");
    await mkdir(target);
    const { compiled } = await fixture(root);
    const moved = `${compiled.paths.directory}.owned-moved`;
    const sentinel = join(compiled.paths.directory, "unowned.txt");

    await expect(
      publishReleaseWithCheckpoint(
        compiled,
        { directory: target },
        async (at) => {
          if (at === "payload-published") {
            await rename(compiled.paths.directory, moved);
            await mkdir(compiled.paths.directory);
            await writeFile(sentinel, "replacement-directory");
          }
        },
      ),
    ).rejects.toThrow();
    expect(await readFile(sentinel, "utf8")).toBe("replacement-directory");
    expect(await readdir(target)).not.toContain("release-1.manifest.json");
  });

  test("partial crash residue fails closed without deleting either file", async () => {
    const root = await temporaryRoot();
    const target = join(root, "published");
    await mkdir(target);
    const payload = join(target, "release-1.sqlite");
    const signature = join(target, "release-1.manifest.sig");
    await writeFile(payload, "partial-payload");
    await writeFile(signature, "partial-signature");
    const { compiled } = await fixture(root);

    await expect(
      publishRelease(compiled, { directory: target }),
    ).rejects.toThrow(/exists/i);
    expect(await readFile(payload, "utf8")).toBe("partial-payload");
    expect(await readFile(signature, "utf8")).toBe("partial-signature");
    expect(await readdir(target)).not.toContain("release-1.manifest.json");
  });

  test("a crash-residue lock fails closed and is never reclaimed", async () => {
    const root = await temporaryRoot();
    const target = join(root, "published");
    await mkdir(target);
    await writeFile(join(target, ".release-1.publish.lock"), "", {
      mode: 0o600,
    });
    const { compiled } = await fixture(root);
    await expect(
      publishRelease(compiled, { directory: target }),
    ).rejects.toThrow(/lock|progress/i);
    expect(
      (await stat(join(target, ".release-1.publish.lock"))).mode & 0o777,
    ).toBe(0o600);
    await expect(stat(compiled.paths.directory)).rejects.toThrow();
  });
});
