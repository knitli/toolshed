import type { OpenApiDoc } from "./load.ts";
import type { SchemaRecord } from "./types.ts";

/**
 * Stores each component schema exactly as written, with `$ref`s intact.
 * Resolution happens at request time against one operation's closure;
 * eager dereferencing of Microsoft Graph exceeds 342 MB and, resolved per
 * `$ref` hop rather than per nesting level, does not terminate at all.
 */
export function extractSchemas(doc: OpenApiDoc, api: string): SchemaRecord[] {
  const schemas = doc.components?.schemas;
  if (!schemas) return [];
  return Object.entries(schemas).map(([name, value]) => ({
    api,
    name: `#/components/schemas/${name}`,
    json: JSON.stringify(value),
  }));
}
