// Slice an OpenAPI 3.x document down to the operations a deployment will expose, prune the
// components nothing left references, and rewrite `servers` to the bare origin `compile-release`
// requires. This is what lets a document far beyond `maxDocumentKeys` (Microsoft Graph's full
// v1.0, served from `/v1.0`) be compiled as one catalog per deployment.

const METHODS = [
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

/** Pure: returns a new document containing only the selected operations and what they reference. */
export function sliceSpec(document: Json, selection: SliceSelection): Json {
  const tags = new Set(selection.tags);
  const operations = new Set(selection.operations);
  const paths: Json = {};
  let kept = 0;
  for (const [path, item] of Object.entries((document.paths ?? {}) as Json)) {
    const source = item as Json;
    const target: Json = {};
    for (const method of METHODS) {
      const operation = source[method] as Json | undefined;
      if (!operation) continue;
      const operationTags = Array.isArray(operation.tags)
        ? (operation.tags as string[])
        : [];
      if (
        operationTags.some((tag) => tags.has(tag)) ||
        operations.has(operation.operationId as string)
      ) {
        target[method] = operation;
        kept++;
      }
    }
    if (Object.keys(target).length === 0) continue;
    if (source.parameters !== undefined) target.parameters = source.parameters;
    paths[path] = target;
  }
  if (kept === 0) throw new Error("The selection selected no operations.");

  // Transitive closure over `$ref` keys only. Discriminator mappings are plain strings and are
  // deliberately not followed: Graph's `entity` maps to every subtype.
  const components = (document.components ?? {}) as Record<string, Json>;
  const reachable = new Set<string>();
  const pending = new Set<string>();
  collectRefs(paths, pending);
  while (pending.size) {
    const ref = pending.values().next().value as string;
    pending.delete(ref);
    if (reachable.has(ref)) continue;
    reachable.add(ref);
    const [, , kind, name] = ref.split("/");
    const component =
      kind !== undefined && name !== undefined
        ? components[kind]?.[name]
        : undefined;
    if (component === undefined)
      throw new Error(`Unresolvable reference ${ref}`);
    const next = new Set<string>();
    collectRefs(component, next);
    for (const item of next) if (!reachable.has(item)) pending.add(item);
  }
  const prunedComponents: Record<string, Json> = {};
  for (const ref of reachable) {
    const [, , kind, name] = ref.split("/");
    if (kind === undefined || name === undefined) continue;
    const bucket = components[kind];
    if (bucket === undefined) continue;
    const target = prunedComponents[kind] ?? {};
    target[name] = bucket[name];
    prunedComponents[kind] = target;
  }

  const server = (document.servers as { url: string }[] | undefined)?.[0]?.url;
  if (!server) throw new Error("The document names no server.");
  return {
    ...document,
    servers: [{ url: new URL(server).origin }],
    paths,
    components: prunedComponents,
  };
}
