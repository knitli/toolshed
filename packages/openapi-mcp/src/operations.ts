import type { OpenApiDoc, OpenApiOperation } from "./load.ts";
import { classifySafety, riskFor } from "./safety.ts";
import type { OperationRecord } from "./types.ts";

/** The gatekeeper caps rendered descriptions at 600 characters. */
export const MAX_SUMMARY = 600;

/**
 * Splits identifier-style text into lowercase words for fts indexing.
 * fts5's unicode61 tokenizer already folds case but treats `sendMail` as one
 * token, so `MATCH 'send mail'` misses it — this widens the indexed text with
 * a word-split shadow so both the joined and split forms are searchable.
 * Splits camelCase boundaries (including acronym runs: `getURLValue` →
 * `get url value`), `. / _ - { }` separators, and whitespace, then
 * lowercases and collapses runs of whitespace. Deduping words is not required.
 */
export function splitWords(text: string): string {
  return text
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[._/\-{}\s]+/)
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

const HTTP_METHODS = new Set([
  "get",
  "post",
  "put",
  "patch",
  "delete",
  "head",
  "options",
]);

interface ParamRecord {
  name: string;
  in: string;
  required: boolean;
  schema: unknown;
}

const FORBIDDEN_POINTER_KEYS = new Set([
  "__proto__",
  "prototype",
  "constructor",
]);

/**
 * Canonicalize the URI-fragment representation of an RFC 6901 pointer.
 *
 * The returned value is an internal, already URI-decoded physical address. It
 * must not be fed through URI decoding a second time.
 */
export function canonicalLocalPointer(ref: string): string {
  if (ref === "") return "#";
  if (!ref.startsWith("#"))
    throw new Error("local reference must be a JSON Pointer fragment");
  let pointer: string;
  try {
    pointer = decodeURIComponent(ref.slice(1));
  } catch {
    throw new Error("JSON Pointer contains an invalid URI escape");
  }
  if (pointer === "") return "#";
  if (!pointer.startsWith("/"))
    throw new Error("local reference must be a JSON Pointer fragment");
  const tokens = pointer.slice(1).split("/");
  for (const rawToken of tokens) {
    if (/(?:~(?:[^01]|$))/.test(rawToken))
      throw new Error("JSON Pointer contains an invalid ~ escape");
    const token = rawToken.replace(/~1/g, "/").replace(/~0/g, "~");
    if (FORBIDDEN_POINTER_KEYS.has(token))
      throw new Error("JSON Pointer contains a forbidden prototype key");
  }
  return `#/${tokens.join("/")}`;
}

/** Resolve an already canonicalized physical JSON Pointer address. */
export function resolveCanonicalPointer(
  doc: unknown,
  pointer: string,
): unknown {
  if (pointer === "#") return doc;
  if (!pointer.startsWith("#/"))
    throw new Error("canonical pointer must be a JSON Pointer fragment");
  let node: unknown = doc;
  for (const rawToken of pointer.slice(2).split("/")) {
    if (/(?:~(?:[^01]|$))/.test(rawToken)) {
      throw new Error("JSON Pointer contains an invalid ~ escape");
    }
    const token = rawToken.replace(/~1/g, "/").replace(/~0/g, "~");
    if (FORBIDDEN_POINTER_KEYS.has(token)) {
      throw new Error("JSON Pointer contains a forbidden prototype key");
    }
    if (Array.isArray(node)) {
      if (!/^(?:0|[1-9][0-9]*)$/.test(token)) {
        throw new Error("JSON Pointer array index is not canonical");
      }
      const index = Number(token);
      if (
        !Number.isSafeInteger(index) ||
        index >= node.length ||
        !Object.hasOwn(node, index)
      ) {
        throw new Error("JSON Pointer array index was not found");
      }
      node = node[index];
      continue;
    }
    if (
      typeof node !== "object" ||
      node === null ||
      !Object.hasOwn(node, token)
    ) {
      throw new Error("JSON Pointer target was not found");
    }
    const descriptor = Object.getOwnPropertyDescriptor(node, token);
    if (descriptor === undefined || !("value" in descriptor)) {
      throw new Error("JSON Pointer target is not an own data property");
    }
    node = descriptor.value;
  }
  return node;
}

/** Resolve a URI-decoded, one-pass RFC 6901 fragment through own properties only. */
export function resolveLocalPointer(doc: unknown, ref: string): unknown {
  return resolveCanonicalPointer(doc, canonicalLocalPointer(ref));
}

function collectParams(
  doc: OpenApiDoc,
  pathItem: Record<string, unknown>,
  op: OpenApiOperation,
): ParamRecord[] {
  const raw = [
    ...((pathItem.parameters as unknown[]) ?? []),
    ...((op.parameters as unknown[]) ?? []),
  ];
  // OpenAPI identifies a parameter by `(name, in)` and lets the operation
  // override the path item's. Operation entries come second, so a plain
  // last-write-wins keyed insert gives exactly that precedence — whereas
  // concatenating would emit both and leave the caller two conflicting
  // schemas for one parameter.
  const out = new Map<string, ParamRecord>();
  for (const entry of raw) {
    const p = (
      typeof entry === "object" && entry !== null && "$ref" in entry
        ? resolveLocalPointer(doc, (entry as { $ref: string }).$ref)
        : entry
    ) as Record<string, unknown> | undefined;
    if (!p || typeof p.name !== "string") continue;
    const where = typeof p.in === "string" ? p.in : "query";
    out.set(`${where}:${p.name}`, {
      name: p.name,
      in: where,
      required: p.required === true,
      schema: p.schema ?? { type: "string" },
    });
  }
  return [...out.values()];
}

interface BodyContract {
  ref: string | null;
  schemaJson: string | null;
  mediaType: string | null;
}

const NO_BODY: BodyContract = { ref: null, schemaJson: null, mediaType: null };

/**
 * Captures an operation's request-body contract. A `$ref` is kept as a ref and
 * resolved lazily from the schema store, which is the whole point of the thin
 * artifact. Anything else — an inline schema, or a body under a non-JSON media
 * type — is stored verbatim instead of dropped: a write whose body contract is
 * missing is either unusable or, worse, executable with no validation at all.
 */
function bodyOf(op: OpenApiOperation): BodyContract {
  const rb = op.requestBody as Record<string, unknown> | undefined;
  if (!rb) return NO_BODY;
  if (typeof rb.$ref === "string") {
    return { ref: rb.$ref, schemaJson: null, mediaType: null };
  }

  const content = rb.content as
    | Record<string, { schema?: unknown }>
    | undefined;
  if (!content) return NO_BODY;
  // Prefer JSON, but fall back to whatever the operation actually declares —
  // the media type travels with the schema so the server can set Content-Type.
  const mediaType =
    "application/json" in content
      ? "application/json"
      : Object.keys(content)[0];
  if (mediaType === undefined) return NO_BODY;
  const schema = content[mediaType]?.schema;
  if (schema === undefined) return NO_BODY;

  const ref = (schema as { $ref?: unknown }).$ref;
  return typeof ref === "string"
    ? { ref, schemaJson: null, mediaType }
    : { ref: null, schemaJson: JSON.stringify(schema), mediaType };
}

/** Extracts one thin record per operation. `$ref`s are stored, never resolved. */
export function extractOperations(
  doc: OpenApiDoc,
  api: string,
): OperationRecord[] {
  const serverUrl = doc.servers?.[0]?.url ?? "";
  if (!serverUrl) throw new Error("document declares no servers[0].url");

  const seen = new Set<string>();
  const records: OperationRecord[] = [];

  for (const [path, pathItem] of Object.entries(doc.paths)) {
    if (pathItem.servers !== undefined) {
      throw new Error(
        `${path}: path-item-level "servers" overrides are not supported`,
      );
    }
    for (const [method, op] of Object.entries(pathItem)) {
      if (!HTTP_METHODS.has(method)) continue;
      if (op.servers !== undefined) {
        throw new Error(
          `${method.toUpperCase()} ${path}: operation-level "servers" overrides are not supported`,
        );
      }

      const operationId = op.operationId;
      if (typeof operationId !== "string" || operationId.length === 0) {
        throw new Error(`${method.toUpperCase()} ${path}: missing operationId`);
      }
      const qualifiedId = `${api}:${operationId}`;
      if (seen.has(qualifiedId)) {
        throw new Error(`duplicate operationId: ${operationId}`);
      }
      seen.add(qualifiedId);

      const upper = method.toUpperCase();
      const body = bodyOf(op);
      const safety = classifySafety(upper, path, operationId, api);
      const summary = (op.summary ?? op.description ?? null)?.slice(
        0,
        MAX_SUMMARY,
      );

      records.push({
        qualifiedId,
        api,
        operationId,
        method: upper,
        path,
        safety,
        risk: riskFor(safety, null, path),
        operationType:
          typeof op["x-ms-docs-operation-type"] === "string"
            ? (op["x-ms-docs-operation-type"] as string)
            : null,
        pageable: op["x-ms-pageable"] !== undefined,
        deprecated: op.deprecated === true,
        permissions: null,
        permConfidence: null,
        privilegeLevel: null,
        summary: summary ?? null,
        tags: Array.isArray(op.tags) ? op.tags.join(" ") : null,
        paramsJson: JSON.stringify(collectParams(doc, pathItem, op)),
        searchText: `${splitWords(operationId)} ${splitWords(path)}`,
        bodyRef: body.ref,
        bodySchemaJson: body.schemaJson,
        bodyMediaType: body.mediaType,
        serverUrl,
      });
    }
  }
  return records;
}
