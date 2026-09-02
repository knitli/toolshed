import { readFile } from "node:fs/promises";

export interface OpenApiOperation {
  operationId?: string;
  summary?: string;
  description?: string;
  tags?: string[];
  deprecated?: boolean;
  parameters?: unknown[];
  requestBody?: unknown;
  [key: string]: unknown;
}

export interface OpenApiDoc {
  openapi: string;
  servers?: Array<{ url: string }>;
  paths: Record<string, Record<string, OpenApiOperation>>;
  components?: {
    schemas?: Record<string, unknown>;
    parameters?: Record<string, unknown>;
    responses?: Record<string, unknown>;
  };
  [key: string]: unknown;
}

/**
 * Reads an OpenAPI 3.x document from disk. Under Bun, YAML is parsed with
 * Bun's native parser, which handles the 44 MB Microsoft Graph document in
 * ~0.5s. Under Node, it falls back to the `yaml` package, which takes ~12.6s
 * on the same document — acceptable for a compile step, and JSON specs skip
 * YAML parsing entirely either way.
 */
export async function loadSpec(path: string): Promise<OpenApiDoc> {
  const text = await readFile(path, "utf8");
  const doc = (
    path.endsWith(".json")
      ? JSON.parse(text)
      : typeof Bun !== "undefined"
        ? Bun.YAML.parse(text)
        : (await import("yaml")).parse(text)
  ) as OpenApiDoc;

  if (!doc || typeof doc !== "object" || typeof doc.paths !== "object") {
    throw new Error(`${path}: not an OpenAPI document (no "paths" object)`);
  }
  return doc;
}
