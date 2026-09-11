// Slice an OpenAPI 3.x document down to the operations a deployment will expose, prune the
// components nothing left references, and rewrite `servers` to the bare origin `compile-release`
// requires. This is what lets a document far beyond `maxDocumentKeys` (Microsoft Graph's full
// v1.0, served from `/v1.0`) be compiled as one catalog per deployment.
//
// OpenAPI 3.1 `webhooks` are deliberately left untouched: they are not part of `paths` and are
// spread through as-is, dangling refs and all, same as any other top-level key. Graph is 3.0 and
// has none.

export const HTTP_METHODS = [
  "get",
  "put",
  "post",
  "delete",
  "options",
  "head",
  "patch",
  "trace",
] as const;
type Json = Record<string, unknown>;

/** Which operations survive: any of these tags, or any of these operation ids. */
export interface SliceSelection {
  readonly tags: readonly string[];
  readonly operations: readonly string[];
}

/** Number of object keys in a JSON value; compare with the compiler's `maxDocumentKeys` (250,000). */
export function countKeys(value: unknown): number {
  if (Array.isArray(value))
    return value.reduce((sum: number, item) => sum + countKeys(item), 0);
  if (value && typeof value === "object") {
    return Object.entries(value).reduce(
      (sum, [, item]) => sum + 1 + countKeys(item),
      0,
    );
  }
  return 0;
}

function collectRefs(value: unknown, into: Set<string>): void {
  if (Array.isArray(value)) {
    for (const item of value) collectRefs(item, into);
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value)) {
    if (
      key === "$ref" &&
      typeof item === "string" &&
      item.startsWith("#/components/")
    )
      into.add(item);
    else collectRefs(item, into);
  }
}

/** A `$ref` path segment is a URI-fragment-encoded JSON pointer token: decode `%xx`, then `~1`
 * (`/`) and `~0` (`~`), in that order, so a component named e.g. `a/b` round-trips. */
function decodeRefSegment(raw: string): string {
  return decodeURIComponent(raw).replaceAll("~1", "/").replaceAll("~0", "~");
}

function refParts(ref: string): { kind: string; name: string } | undefined {
  const [, , kind, name] = ref.split("/");
  if (kind === undefined || name === undefined) return undefined;
  return { kind, name: decodeRefSegment(name) };
}

function securitySchemeNames(requirements: unknown, into: Set<string>): void {
  if (!Array.isArray(requirements)) return;
  for (const requirement of requirements) {
    if (!requirement || typeof requirement !== "object") continue;
    for (const name of Object.keys(requirement)) into.add(name);
  }
}

/** Walks `document.paths`, keeping only operations matching `selection`, and reports which
 * selectors actually matched something (an unmatched selector is the caller's problem, not
 * this function's — checked by `sliceSpec`). */
function selectOperations(
  document: Json,
  selection: SliceSelection,
): { paths: Json; keptOperations: Json[] } {
  const tags = new Set(selection.tags);
  const operations = new Set(selection.operations);
  const matchedTags = new Set<string>();
  const matchedOperations = new Set<string>();
  const keptOperations: Json[] = [];
  const paths: Json = {};
  for (const [path, item] of Object.entries((document.paths ?? {}) as Json)) {
    const source = item as Json;
    const target: Json = { ...source };
    let keptAny = false;
    for (const method of HTTP_METHODS) {
      const operation = source[method] as Json | undefined;
      if (!operation) continue;
      const operationTags = Array.isArray(operation.tags)
        ? (operation.tags as string[])
        : [];
      const matchingTags = operationTags.filter((tag) => tags.has(tag));
      const operationId = operation.operationId as string | undefined;
      const matchesOperation =
        operationId !== undefined && operations.has(operationId);
      if (matchingTags.length === 0 && !matchesOperation) {
        delete target[method];
        continue;
      }
      for (const tag of matchingTags) matchedTags.add(tag);
      if (matchesOperation && operationId !== undefined)
        matchedOperations.add(operationId);
      keptAny = true;
      keptOperations.push(operation);
    }
    if (!keptAny) continue;
    paths[path] = target;
  }
  if (matchedTags.size === 0 && matchedOperations.size === 0)
    throw new Error("The selection selected no operations.");

  const unmatched = [
    ...[...tags].filter((tag) => !matchedTags.has(tag)),
    ...[...operations].filter((id) => !matchedOperations.has(id)),
  ];
  if (unmatched.length > 0)
    throw new Error(`Selection matched nothing for: ${unmatched.join(", ")}`);

  return { paths, keptOperations };
}

/** Transitive closure over `$ref` keys only, starting from the kept paths. Discriminator
 * mappings are plain strings and are followed separately (`pruneDiscriminatorMapping`), so a
 * pruned mapping target can be dropped instead of resolved. */
function resolveReachableRefs(
  paths: Json,
  components: Record<string, Json>,
): Set<string> {
  const reachable = new Set<string>();
  const pending = new Set<string>();
  collectRefs(paths, pending);
  while (pending.size) {
    const ref = pending.values().next().value as string;
    pending.delete(ref);
    if (reachable.has(ref)) continue;
    reachable.add(ref);
    const parts = refParts(ref);
    const component =
      parts !== undefined ? components[parts.kind]?.[parts.name] : undefined;
    if (component === undefined)
      throw new Error(`Unresolvable reference ${ref}`);
    const next = new Set<string>();
    collectRefs(component, next);
    for (const item of next) if (!reachable.has(item)) pending.add(item);
  }
  return reachable;
}

/** Security schemes are referenced by name in `security` requirements, not by `$ref`, so the
 * closure in `resolveReachableRefs` never finds them; collect the names the kept operations (or
 * the root, when an operation has no override) actually use. */
function collectUsedSecuritySchemes(
  document: Json,
  keptOperations: readonly Json[],
): Set<string> {
  const usedSchemes = new Set<string>();
  securitySchemeNames(document.security, usedSchemes);
  for (const operation of keptOperations)
    securitySchemeNames(operation.security, usedSchemes);
  return usedSchemes;
}

function buildPrunedComponents(
  components: Record<string, Json>,
  reachable: ReadonlySet<string>,
  usedSchemes: ReadonlySet<string>,
): Record<string, Json> {
  const prunedComponents: Record<string, Json> = {};
  for (const ref of reachable) {
    const parts = refParts(ref);
    if (parts === undefined) continue;
    const bucket = components[parts.kind];
    if (bucket === undefined) continue;
    let component = bucket[parts.name];
    if (
      parts.kind === "schemas" &&
      component &&
      typeof component === "object"
    ) {
      component = pruneDiscriminatorMapping(component as Json, reachable);
    }
    const target = prunedComponents[parts.kind] ?? {};
    target[parts.name] = component;
    prunedComponents[parts.kind] = target;
  }
  if (usedSchemes.size > 0) {
    const schemes = components.securitySchemes ?? {};
    const target: Json = {};
    for (const name of usedSchemes)
      if (name in schemes) target[name] = schemes[name];
    if (Object.keys(target).length > 0)
      prunedComponents.securitySchemes = target;
  }
  return prunedComponents;
}

/** Pure: returns a new document containing only the selected operations and what they reference. */
export function sliceSpec(document: Json, selection: SliceSelection): Json {
  const { paths, keptOperations } = selectOperations(document, selection);
  const components = (document.components ?? {}) as Record<string, Json>;
  const reachable = resolveReachableRefs(paths, components);
  const usedSchemes = collectUsedSecuritySchemes(document, keptOperations);
  const prunedComponents = buildPrunedComponents(
    components,
    reachable,
    usedSchemes,
  );

  const server = (document.servers as { url: string }[] | undefined)?.[0]?.url;
  if (!server) throw new Error("The document names no server.");
  return {
    ...document,
    servers: [{ url: new URL(server).origin }],
    paths,
    components: prunedComponents,
  };
}

/** Drops `discriminator.mapping` entries whose target is not in the kept closure, on a shallow
 * copy — the schema itself is left aliased to the source document when there is nothing to prune. */
function pruneDiscriminatorMapping(
  schema: Json,
  reachable: ReadonlySet<string>,
): Json {
  const discriminator = schema.discriminator as Json | undefined;
  const mapping = discriminator?.mapping as Record<string, string> | undefined;
  if (!discriminator || !mapping) return schema;
  const prunedMapping: Record<string, string> = {};
  for (const [key, target] of Object.entries(mapping))
    if (reachable.has(target)) prunedMapping[key] = target;
  if (Object.keys(prunedMapping).length === Object.keys(mapping).length)
    return schema;
  return {
    ...schema,
    discriminator: { ...discriminator, mapping: prunedMapping },
  };
}
