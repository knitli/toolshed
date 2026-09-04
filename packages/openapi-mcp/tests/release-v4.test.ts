import { afterEach, describe, expect, test } from "bun:test";
import { createPublicKey } from "node:crypto";
import {
  mkdir,
  readdir,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import {
  type CompileReleaseOptions,
  compileRelease,
  discardCompiledRelease,
  publishRelease,
} from "../src/compiler.ts";
import { publishReleaseWithCheckpoint } from "../src/release/publish.ts";
import type {
  CatalogId,
  GenerationState,
  GenerationStore,
} from "../src/runtime/index.ts";
import {
  admitManifest,
  canonicalJson,
  sha256,
  verifyStoredRecord,
} from "../src/runtime/index.ts";
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
  return { compiled: await compileRelease(options), publicKeyPem };
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
