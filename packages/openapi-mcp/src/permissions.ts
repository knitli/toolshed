import { riskFor } from "./safety.ts";
import type { OperationRecord, PermConfidence } from "./types.ts";

export interface PermissionsDataset {
  permissions: Record<
    string,
    {
      schemes?: Record<string, { privilegeLevel?: number }>;
      pathSets?: Array<{ methods?: string[]; paths?: Record<string, unknown> }>;
    }
  >;
}

export interface PermissionMatch {
  permissions: string[];
  privilegeLevel: number | null;
  confidence: PermConfidence;
}

export interface PermissionIndex {
  /** method -> normalised path -> permission names */
  byMethod: Map<string, Map<string, Set<string>>>;
  privilege: Map<string, number>;
}

/** Parameter names differ between the two Microsoft datasets; erase them. */
function normalise(path: string): string {
  return path
    .replace(/\{[^}]*\}/g, "{}")
    .replace(/\/+$/, "")
    .toLowerCase();
}

const ODATA_SUFFIX = /\/(\$count|\$ref|\$value|microsoft\.graph\.[a-z0-9.]+)$/;

export function buildPermissionIndex(
  dataset: PermissionsDataset,
): PermissionIndex {
  const byMethod = new Map<string, Map<string, Set<string>>>();
  const privilege = new Map<string, number>();

  for (const [name, body] of Object.entries(dataset.permissions ?? {})) {
    const level = body.schemes?.DelegatedWork?.privilegeLevel;
    if (typeof level === "number") privilege.set(name, level);

    for (const set of body.pathSets ?? []) {
      for (const method of set.methods ?? []) {
        const key = method.toUpperCase();
        let table = byMethod.get(key);
        if (!table) {
          table = new Map();
          byMethod.set(key, table);
        }
        for (const path of Object.keys(set.paths ?? {})) {
          const n = normalise(path);
          let names = table.get(n);
          if (!names) {
            names = new Set();
            table.set(n, names);
          }
          names.add(name);
        }
      }
    }
  }
  return { byMethod, privilege };
}

function finish(
  index: PermissionIndex,
  names: Set<string>,
  confidence: PermConfidence,
): PermissionMatch {
  const permissions = [...names].sort();
  // Several permissions can authorise one operation; the strictest bounds risk.
  const levels = permissions
    .map((p) => index.privilege.get(p))
    .filter((l): l is number => typeof l === "number");
  return {
    permissions,
    privilegeLevel: levels.length ? Math.max(...levels) : null,
    confidence,
  };
}

/**
 * Three strategies in order: exact, OData-suffix-stripped, then longest
 * prefix. Prefix matches are a heuristic and are marked as such — a child
 * path can require a broader permission than its parent.
 */
export function lookupPermissions(
  index: PermissionIndex,
  path: string,
  method: string,
): PermissionMatch | null {
  const table = index.byMethod.get(method.toUpperCase());
  if (!table) return null;

  const exact = normalise(path);
  const hitExact = table.get(exact);
  if (hitExact) return finish(index, hitExact, "exact");

  const stripped = exact.replace(ODATA_SUFFIX, "");
  if (stripped !== exact) {
    const hitSuffix = table.get(stripped);
    if (hitSuffix) return finish(index, hitSuffix, "suffix");
  }

  const parts = stripped.split("/");
  for (let i = parts.length - 1; i > 1; i--) {
    const hitPrefix = table.get(parts.slice(0, i).join("/"));
    if (hitPrefix) return finish(index, hitPrefix, "prefix");
  }
  return null;
}

/** Annotates records in place and recomputes risk now that privilege is known. */
export function applyPermissions(
  ops: OperationRecord[],
  index: PermissionIndex,
): void {
  for (const op of ops) {
    const match = lookupPermissions(index, op.path, op.method);
    if (match) {
      op.permissions = match.permissions;
      op.permConfidence = match.confidence;
      op.privilegeLevel = match.privilegeLevel;
    }
    op.risk = riskFor(op.safety, op.privilegeLevel, op.path);
  }
}
