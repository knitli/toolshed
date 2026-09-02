import { Database } from "bun:sqlite";
import { unlinkSync } from "node:fs";
import { loadSpec } from "./load";
import { extractOperations } from "./operations";
import {
  applyPermissions,
  buildPermissionIndex,
  type PermissionsDataset,
} from "./permissions";
import { createSchema, FORMAT_VERSION } from "./schema";
import { extractSchemas } from "./schemas";

export interface CompileOptions {
  specPath: string;
  api: string;
  outPath: string;
  permissionsPath?: string;
}

export interface CompileResult {
  operations: number;
  schemas: number;
  mapped: number;
}

const COMPILER_VERSION = "0.1.0";

export async function compile(
  options: CompileOptions,
): Promise<CompileResult> {
  const doc = await loadSpec(options.specPath);
  const operations = extractOperations(doc, options.api);
  const schemas = extractSchemas(doc, options.api);

  if (options.permissionsPath) {
    const dataset = (await Bun.file(
      options.permissionsPath,
    ).json()) as PermissionsDataset;
    applyPermissions(operations, buildPermissionIndex(dataset));
  } else {
    // Still recompute risk so unmapped writes land on `high`.
    applyPermissions(operations, { byMethod: new Map(), privilege: new Map() });
  }

  try {
    unlinkSync(options.outPath);
  } catch {
    // No previous artifact; nothing to remove.
  }

  const db = new Database(options.outPath, { create: true });
  try {
    createSchema(db);
    db.run("BEGIN");

    const insertOp = db.prepare(
      `INSERT INTO operations
       (qualified_id, api, operation_id, method, path, safety, risk,
        operation_type, pageable, deprecated, permissions, perm_confidence,
        privilege_level, summary, tags, params_json, body_ref, server_url)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    );
    for (const op of operations) {
      insertOp.run(
        op.qualifiedId, op.api, op.operationId, op.method, op.path,
        op.safety, op.risk, op.operationType,
        op.pageable ? 1 : 0, op.deprecated ? 1 : 0,
        op.permissions ? JSON.stringify(op.permissions) : null,
        op.permConfidence, op.privilegeLevel, op.summary, op.tags,
        op.paramsJson, op.bodyRef, op.serverUrl,
      );
    }

    const insertSchema = db.prepare(
      "INSERT INTO schemas (api, name, json) VALUES (?,?,?)",
    );
    for (const s of schemas) insertSchema.run(s.api, s.name, s.json);

    // External-content fts5: populate from the base table after loading it.
    db.run(
      `INSERT INTO operations_fts (rowid, qualified_id, operation_id, summary, path, tags, api)
       SELECT rowid, qualified_id, operation_id, summary, path, tags, api FROM operations`,
    );

    // Global keys plus per-api namespaced provenance. `apis` is a JSON array so
    // a second mount can append to it without rewriting anything.
    const insertMeta = db.prepare(
      "INSERT OR REPLACE INTO meta (key, value) VALUES (?,?)",
    );
    for (const [key, value] of Object.entries({
      format_version: String(FORMAT_VERSION),
      compiler_version: COMPILER_VERSION,
      apis: JSON.stringify([options.api]),
      [`${options.api}.source_path`]: options.specPath,
      [`${options.api}.compiled_at`]: new Date().toISOString(),
    })) {
      insertMeta.run(key, value);
    }

    db.run("COMMIT");
  } catch (err) {
    db.run("ROLLBACK");
    throw err;
  } finally {
    db.close();
  }

  return {
    operations: operations.length,
    schemas: schemas.length,
    mapped: operations.filter((o) => o.permissions !== null).length,
  };
}
