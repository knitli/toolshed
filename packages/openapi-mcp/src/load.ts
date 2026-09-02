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
 * Reads an OpenAPI 3.x document from disk. YAML is parsed with Bun's native
 * parser, which handles the 44 MB Microsoft Graph document in well under a
 * second — do not add a JS YAML dependency.
 */
export async function loadSpec(path: string): Promise<OpenApiDoc> {
  const text = await Bun.file(path).text();
  const doc = (
    path.endsWith(".json") ? JSON.parse(text) : Bun.YAML.parse(text)
  ) as OpenApiDoc;

  if (!doc || typeof doc !== "object" || typeof doc.paths !== "object") {
    throw new Error(`${path}: not an OpenAPI document (no "paths" object)`);
  }
  return doc;
}
