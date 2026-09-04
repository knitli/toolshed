import { existsSync, renameSync, unlinkSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import { loadSpec } from "./load.ts";
import { extractOperations } from "./operations.ts";
import {
  applyPermissions,
  buildPermissionIndex,
  type PermissionsDataset,
} from "./permissions.ts";
import { createSchema, LEGACY_FORMAT_VERSION } from "./schema.ts";
import { extractSchemas } from "./schemas.ts";

export interface CompileOptions {
  specPath: string;
  api: string;
  outPath: string;
  permissionsPath?: string;
  /** Mount into an existing artifact instead of replacing it. */
  append?: boolean;
}

export interface CompileResult {
  operations: number;
  schemas: number;
  mapped: number;
}

const COMPILER_VERSION = "0.1.0";

export async function compile(options: CompileOptions): Promise<CompileResult> {
  const doc = await loadSpec(options.specPath);
  const operations = extractOperations(doc, options.api);
  const schemas = extractSchemas(doc, options.api);

  if (options.permissionsPath) {
    const dataset = JSON.parse(
      await readFile(options.permissionsPath, "utf8"),
    ) as PermissionsDataset;
    applyPermissions(operations, buildPermissionIndex(dataset));
  } else {
    // Still recompute risk so unmapped writes land on `high`.
    applyPermissions(operations, { byMethod: new Map(), privilege: new Map() });
  }

  const exists = existsSync(options.outPath);
  if (options.append && !exists) {
    throw new Error(`${options.outPath} does not exist; cannot append`);
  }
  // A fresh compile builds into a sibling and renames over the target only
  // after a clean close. Replacing in place would destroy a valid artifact the
  // instant anything downstream failed — rollback can only empty the new
  // database, it cannot bring the old one back. Append has nothing to protect:
  // it mutates the existing artifact under its own transaction.
  const buildPath = options.append
    ? options.outPath
    : `${options.outPath}.building`;
  if (!options.append) {
    try {
      unlinkSync(buildPath);
    } catch {
      // No leftover build file from an interrupted run.
    }
  }

  let existingApis: string[] = [];
  let committed = false;
  const db = new DatabaseSync(buildPath);
  try {
    db.exec("BEGIN");
    if (options.append) {
      const version = (
        db
          .prepare("SELECT value FROM meta WHERE key = ?")
          .get("format_version") as { value: string } | undefined
      )?.value;
      if (version !== String(LEGACY_FORMAT_VERSION)) {
        throw new Error(
          `format_version mismatch: artifact is ${version}, compiler is ${LEGACY_FORMAT_VERSION}`,
        );
      }
      const mounted = JSON.parse(
        (
          db.prepare("SELECT value FROM meta WHERE key = ?").get("apis") as
            | { value: string }
            | undefined
        )?.value ?? "[]",
      ) as string[];
      if (mounted.includes(options.api)) {
        throw new Error(`api "${options.api}" is already mounted`);
      }
      existingApis = mounted;
    } else {
      createSchema(db);
    }

    const insertOp = db.prepare(
      `INSERT INTO operations
       (qualified_id, api, operation_id, method, path, safety, risk,
        operation_type, pageable, deprecated, permissions, perm_confidence,
        privilege_level, summary, tags, params_json, search_text, body_ref,
        body_schema, body_media_type, server_url)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    );
    for (const op of operations) {
      insertOp.run(
        op.qualifiedId,
        op.api,
        op.operationId,
        op.method,
        op.path,
        op.safety,
        op.risk,
        op.operationType,
        op.pageable ? 1 : 0,
        op.deprecated ? 1 : 0,
        op.permissions ? JSON.stringify(op.permissions) : null,
        op.permConfidence,
        op.privilegeLevel,
        op.summary,
        op.tags,
        op.paramsJson,
        op.searchText,
        op.bodyRef,
        op.bodySchemaJson,
        op.bodyMediaType,
        op.serverUrl,
      );
    }

    const insertSchema = db.prepare(
      "INSERT INTO schemas (api, name, json) VALUES (?,?,?)",
    );
    for (const s of schemas) insertSchema.run(s.api, s.name, s.json);

    // External-content fts5: populate from the base table after loading it.
    // Appending only indexes the newly mounted api's rows — the first
    // mount's rows are already indexed and must not be touched again.
    if (options.append) {
      db.prepare(
        `INSERT INTO operations_fts (rowid, qualified_id, operation_id, summary, path, tags, api, search_text)
         SELECT rowid, qualified_id, operation_id, summary, path, tags, api, search_text
         FROM operations WHERE api = ?`,
      ).run(options.api);
    } else {
      db.exec(
        `INSERT INTO operations_fts (rowid, qualified_id, operation_id, summary, path, tags, api, search_text)
         SELECT rowid, qualified_id, operation_id, summary, path, tags, api, search_text FROM operations`,
      );
    }

    // Global keys plus per-api namespaced provenance. `apis` is a JSON array so
    // a second mount can append to it without rewriting anything.
    const insertMeta = db.prepare(
      "INSERT OR REPLACE INTO meta (key, value) VALUES (?,?)",
    );
    for (const [key, value] of Object.entries({
      format_version: String(LEGACY_FORMAT_VERSION),
      compiler_version: COMPILER_VERSION,
      apis: JSON.stringify([...existingApis, options.api]),
      [`${options.api}.source_path`]: options.specPath,
      [`${options.api}.compiled_at`]: new Date().toISOString(),
    })) {
      insertMeta.run(key, value);
    }

    db.exec("COMMIT");
    committed = true;
  } catch (err) {
    try {
      db.exec("ROLLBACK");
    } catch {
      // No active transaction (e.g. BEGIN itself failed) — the original
      // error is what matters; don't let a rollback failure mask it.
    }
    throw err;
  } finally {
    db.close();
    // Cleared only after the handle is closed, so this is safe on platforms
    // that refuse to unlink an open file.
    if (!committed && buildPath !== options.outPath) {
      try {
        unlinkSync(buildPath);
      } catch {
        // Never created, or already gone.
      }
    }
  }

  if (buildPath !== options.outPath) renameSync(buildPath, options.outPath);

  return {
    operations: operations.length,
    schemas: schemas.length,
    mapped: operations.filter((o) => o.permissions !== null).length,
  };
}
