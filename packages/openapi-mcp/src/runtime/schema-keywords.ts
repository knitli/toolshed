export type SchemaChildKind = "single" | "map" | "array" | null;

const singular = new Set([
  "additionalProperties",
  "contains",
  "contentSchema",
  "else",
  "if",
  "items",
  "not",
  "propertyNames",
  "then",
  "unevaluatedItems",
  "unevaluatedProperties",
]);
const maps = new Set([
  "$defs",
  "definitions",
  "dependentSchemas",
  "patternProperties",
  "properties",
]);
const arrays = new Set(["allOf", "anyOf", "oneOf", "prefixItems"]);

export function schemaChildKind(key: string): SchemaChildKind {
  if (singular.has(key)) return "single";
  if (maps.has(key)) return "map";
  if (arrays.has(key)) return "array";
  return null;
}
