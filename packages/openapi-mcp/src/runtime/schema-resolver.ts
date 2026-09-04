import { OpenApiMcpError } from "./errors.ts";
import type { AdmittedManifest } from "./manifest.ts";
import { parseTypedRecordId } from "./references.ts";
import { schemaChildKind } from "./schema-keywords.ts";
import { canonicalJson } from "./strict-json.ts";
import type {
  CatalogStore,
  JsonSchemaV4,
  SchemaRecordV4,
  TypedSchemaId,
} from "./types.ts";
import { verifyStoredRecord } from "./verify-record.ts";
import {
  DEFAULT_RUNTIME_LIMITS,
  type RuntimeLimits,
  resolveRuntimeLimits,
} from "./versions.ts";

function resolutionLimit(message: string): OpenApiMcpError {
  return new OpenApiMcpError("SCHEMA_RESOLUTION_LIMIT", message);
}

function schemaLookupUnavailable(): OpenApiMcpError {
  return new OpenApiMcpError("UPSTREAM_ERROR", "Schema lookup is unavailable", {
    retryable: true,
  });
}

function schemaReference(value: unknown): TypedSchemaId {
  try {
    if (typeof value !== "string") throw new Error();
    const parsed = parseTypedRecordId(value);
    if (!parsed.startsWith("schema:")) throw new Error();
    return parsed as TypedSchemaId;
  } catch {
    throw new OpenApiMcpError(
      "RECORD_DIGEST_MISMATCH",
      "Verified schema contains an invalid local reference",
    );
  }
}

/** Collect references only from positions that JSON Schema defines as schemas. */
function collectReferences(schema: JsonSchemaV4): readonly TypedSchemaId[] {
  if (typeof schema === "boolean") return [];
  const found = new Set<TypedSchemaId>();
  const stack: JsonSchemaV4[] = [schema];
  while (stack.length > 0) {
    const current = stack.pop();
    if (typeof current === "boolean" || current === undefined) continue;
    if (Object.hasOwn(current, "$ref")) {
      found.add(schemaReference(current.$ref));
    }
    for (const [key, child] of Object.entries(current)) {
      const kind = schemaChildKind(key);
      if (kind === "single") {
        stack.push(child as JsonSchemaV4);
      } else if (kind === "array") {
        for (const entry of child as JsonSchemaV4[]) stack.push(entry);
      } else if (kind === "map") {
        for (const entry of Object.values(
          child as Record<string, JsonSchemaV4>,
        )) {
          stack.push(entry);
        }
      }
    }
  }
  return [...found].sort();
}

function snapshotRows(value: unknown, maximum: number): readonly unknown[] {
  try {
    if (!Array.isArray(value)) throw new Error();
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    if (
      lengthDescriptor === undefined ||
      !("value" in lengthDescriptor) ||
      !Number.isSafeInteger(lengthDescriptor.value) ||
      lengthDescriptor.value < 0 ||
      lengthDescriptor.value > maximum
    )
      throw new Error();
    const length = lengthDescriptor.value as number;
    const keys = Reflect.ownKeys(value);
    if (
      keys.length !== length + 1 ||
      keys.some(
        (key) =>
          typeof key !== "string" ||
          (key !== "length" && !/^(0|[1-9][0-9]*)$/.test(key)),
      )
    )
      throw new Error();
    const snapshot: unknown[] = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        !descriptor.enumerable
      )
        throw new Error();
      snapshot.push(descriptor.value);
    }
    return snapshot;
  } catch {
    throw new OpenApiMcpError(
      "RECORD_NOT_ADMITTED",
      "Schema lookup result is invalid",
    );
  }
}

class ImmutableSchemaMap
  implements ReadonlyMap<TypedSchemaId, Readonly<SchemaRecordV4>>
{
  readonly #records: ReadonlyMap<TypedSchemaId, Readonly<SchemaRecordV4>>;

  constructor(records: ReadonlyMap<TypedSchemaId, Readonly<SchemaRecordV4>>) {
    this.#records = new Map(records);
    Object.freeze(this);
  }

  get size(): number {
    return this.#records.size;
  }

  get(key: TypedSchemaId): Readonly<SchemaRecordV4> | undefined {
    return this.#records.get(key);
  }

  has(key: TypedSchemaId): boolean {
    return this.#records.has(key);
  }

  entries(): MapIterator<[TypedSchemaId, Readonly<SchemaRecordV4>]> {
    return this.#records.entries();
  }

  keys(): MapIterator<TypedSchemaId> {
    return this.#records.keys();
  }

  values(): MapIterator<Readonly<SchemaRecordV4>> {
    return this.#records.values();
  }

  forEach(
    callbackfn: (
      value: Readonly<SchemaRecordV4>,
      key: TypedSchemaId,
      map: ReadonlyMap<TypedSchemaId, Readonly<SchemaRecordV4>>,
    ) => void,
    thisArg?: unknown,
  ): void {
    for (const [key, value] of this.#records) {
      callbackfn.call(thisArg, value, key, this);
    }
  }

  [Symbol.iterator](): MapIterator<[TypedSchemaId, Readonly<SchemaRecordV4>]> {
    return this.entries();
  }

  get [Symbol.toStringTag](): string {
    return "ImmutableSchemaMap";
  }
}

function snapshotRoots(
  value: TypedSchemaId | readonly TypedSchemaId[],
  maximum: number,
): readonly TypedSchemaId[] {
  try {
    if (typeof value === "string") return [value as TypedSchemaId];
    if (
      !Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Array.prototype
    )
      throw new Error();
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    if (
      lengthDescriptor === undefined ||
      !("value" in lengthDescriptor) ||
      !Number.isSafeInteger(lengthDescriptor.value) ||
      lengthDescriptor.value < 0 ||
      lengthDescriptor.value > maximum
    )
      throw new Error();
    const length = lengthDescriptor.value as number;
    const ownKeys = Reflect.ownKeys(value);
    if (
      ownKeys.length !== length + 1 ||
      ownKeys.some(
        (key) =>
          typeof key !== "string" ||
          (key !== "length" && !/^(0|[1-9][0-9]*)$/.test(key)),
      )
    )
      throw new Error();
    const snapshot: TypedSchemaId[] = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        typeof descriptor.value !== "string"
      )
        throw new Error();
      snapshot.push(descriptor.value as TypedSchemaId);
    }
    return snapshot;
  } catch {
    throw resolutionLimit("Schema root list is invalid or exceeds its limit");
  }
}

/**
 * Load and verify a schema graph one breadth-first frontier at a time.
 * No result escapes until the complete requested closure has passed all checks.
 */
export async function resolveSchemaClosure(
  store: CatalogStore,
  admitted: AdmittedManifest,
  roots: TypedSchemaId | readonly TypedSchemaId[],
  limitOverrides: RuntimeLimits = DEFAULT_RUNTIME_LIMITS,
): Promise<ReadonlyMap<TypedSchemaId, Readonly<SchemaRecordV4>>> {
  const limits = resolveRuntimeLimits(limitOverrides);
  const rootLimit = Math.min(
    limits.maxManifestRecords,
    limits.maxSchemaClosureBytes,
  );
  let frontier = [...new Set(snapshotRoots(roots, rootLimit))].sort();
  const visited = new Set<TypedSchemaId>();
  const resolved = new Map<TypedSchemaId, Readonly<SchemaRecordV4>>();
  let aggregateBytes = 0;
  let hop = 0;

  while (frontier.length > 0) {
    if (hop > limits.maxSchemaRefHops) {
      throw resolutionLimit("Schema reference hop limit exceeded");
    }
    for (const id of frontier) {
      let parsed: string;
      try {
        parsed = parseTypedRecordId(id);
      } catch {
        throw new OpenApiMcpError(
          "RECORD_NOT_ADMITTED",
          "Schema reference is not admitted",
        );
      }
      if (
        !parsed.startsWith("schema:") ||
        !Object.hasOwn(admitted.manifest.records, id)
      ) {
        throw new OpenApiMcpError(
          "RECORD_NOT_ADMITTED",
          "Schema reference is not admitted",
        );
      }
    }

    const next = new Set<TypedSchemaId>();
    let offset = 0;
    while (offset < frontier.length) {
      const remainingBytes = limits.maxSchemaClosureBytes - aggregateBytes;
      if (remainingBytes <= 0) {
        throw resolutionLimit("Schema closure byte limit exceeded");
      }
      const chunkSize = Math.max(
        1,
        Math.min(
          frontier.length - offset,
          Math.floor(remainingBytes / limits.maxRecordBytes),
        ),
      );
      const chunk = frontier.slice(offset, offset + chunkSize);
      let rowResult: unknown;
      try {
        rowResult = await store.getSchemas(
          admitted.manifest.catalogId,
          admitted.manifest.releaseId,
          chunk,
        );
      } catch {
        throw schemaLookupUnavailable();
      }
      const rows = snapshotRows(rowResult, chunk.length);
      const verifiedRows = await Promise.all(
        rows.map((row) =>
          verifyStoredRecord(
            admitted,
            row as Parameters<typeof verifyStoredRecord>[1],
            limits,
          ),
        ),
      );
      const byId = new Map(
        verifiedRows.map((record) => [record.id as TypedSchemaId, record]),
      );
      if (
        byId.size !== chunk.length ||
        verifiedRows.length !== chunk.length ||
        chunk.some((id) => !byId.has(id))
      ) {
        throw new OpenApiMcpError(
          "RECORD_NOT_ADMITTED",
          "A required schema record is missing or ambiguous",
        );
      }
      for (const id of chunk) {
        const verified = byId.get(id) as Readonly<SchemaRecordV4>;
        if (!verified.id.startsWith("schema:")) {
          throw new OpenApiMcpError(
            "RECORD_DIGEST_MISMATCH",
            "Schema lookup returned a non-schema record",
          );
        }
        aggregateBytes += new TextEncoder().encode(
          canonicalJson(verified),
        ).length;
        if (aggregateBytes > limits.maxSchemaClosureBytes) {
          throw resolutionLimit("Schema closure byte limit exceeded");
        }
        resolved.set(id, verified);
        visited.add(id);
        for (const reference of collectReferences(verified.schema)) {
          if (!visited.has(reference)) next.add(reference);
        }
      }
      offset += chunk.length;
    }
    frontier = [...next].sort();
    hop += 1;
  }

  return new ImmutableSchemaMap(resolved);
}
