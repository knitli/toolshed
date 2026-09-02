import type { OpenApiDoc, OpenApiOperation } from "./load";
import { classifySafety, riskFor } from "./safety";
import type { OperationRecord } from "./types";

/** The gatekeeper caps rendered descriptions at 600 characters. */
export const MAX_SUMMARY = 600;

const HTTP_METHODS = new Set([
  "get", "post", "put", "patch", "delete", "head", "options",
]);

interface ParamRecord {
  name: string;
  in: string;
  required: boolean;
  schema: unknown;
}

function resolveLocal(doc: OpenApiDoc, ref: string): unknown {
  let node: unknown = doc;
  for (const part of ref.replace(/^#\//, "").split("/")) {
    if (typeof node !== "object" || node === null) return undefined;
    node = (node as Record<string, unknown>)[part];
  }
  return node;
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
  const out: ParamRecord[] = [];
  for (const entry of raw) {
    const p = (
      typeof entry === "object" && entry !== null && "$ref" in entry
        ? resolveLocal(doc, (entry as { $ref: string }).$ref)
        : entry
    ) as Record<string, unknown> | undefined;
    if (!p || typeof p.name !== "string") continue;
    out.push({
      name: p.name,
      in: typeof p.in === "string" ? p.in : "query",
      required: p.required === true,
      schema: p.schema ?? { type: "string" },
    });
  }
  return out;
}

function bodyRefOf(op: OpenApiOperation): string | null {
  const rb = op.requestBody as Record<string, unknown> | undefined;
  if (!rb) return null;
  if (typeof rb.$ref === "string") return rb.$ref;
  const content = rb.content as Record<string, { schema?: unknown }> | undefined;
  const schema = content?.["application/json"]?.schema as
    | { $ref?: string }
    | undefined;
  return typeof schema?.$ref === "string" ? schema.$ref : null;
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
      const safety = classifySafety(upper, path, operationId);
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
        bodyRef: bodyRefOf(op),
        serverUrl,
      });
    }
  }
  return records;
}
