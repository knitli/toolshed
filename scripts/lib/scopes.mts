/**
 * Validate shared.scopeAliases and materialize a routing table.
 *
 * Canonical scopes are plugin names, any extra non-plugin workspace scopes,
 * and "marketplace". Extra scopes appear in commitlint's scope-enum but get
 * no release config — they are not plugins.
 */
export function buildScopeRouting(
  pluginNames: string[],
  rawAliases: Record<string, unknown> | undefined,
  extraScopes: string[] = [],
): { aliasesByScope: Record<string, string[]>; allScopes: string[] } {
  const pluginSet = new Set(pluginNames);
  for (const extra of extraScopes) {
    if (pluginSet.has(extra) || extra === "marketplace") {
      throw new Error(
        `ERROR: extraScope "${extra}" collides with a plugin name or "marketplace".`,
      );
    }
  }

  const canonicals = [...pluginNames, ...extraScopes, "marketplace"];
  const canonicalSet = new Set(canonicals);
  const aliasesByScope: Record<string, string[]> = Object.fromEntries(
    canonicals.map((c) => [c, [] as string[]]),
  );
  const seenAliases: string[] = [];
  const seenAliasSet = new Set<string>();

  if (rawAliases !== undefined && rawAliases !== null) {
    if (typeof rawAliases !== "object" || Array.isArray(rawAliases)) {
      throw new Error("ERROR: shared.scopeAliases must be an object.");
    }
    for (const [canonical, aliases] of Object.entries(rawAliases)) {
      if (!canonicalSet.has(canonical)) {
        throw new Error(
          `ERROR: shared.scopeAliases key "${canonical}" is not a canonical scope. ` +
            `Expected one of: ${canonicals.join(", ")}.`,
        );
      }
      if (!Array.isArray(aliases)) {
        throw new Error(
          `ERROR: shared.scopeAliases["${canonical}"] must be an array of strings.`,
        );
      }
      for (const alias of aliases) {
        if (typeof alias !== "string" || alias.length === 0) {
          throw new Error(
            `ERROR: shared.scopeAliases["${canonical}"] contains an invalid alias.`,
          );
        }
        if (canonicalSet.has(alias)) {
          throw new Error(
            `ERROR: alias "${alias}" (under "${canonical}") collides with a canonical scope name.`,
          );
        }
        if (seenAliasSet.has(alias)) {
          throw new Error(
            `ERROR: alias "${alias}" is defined more than once in shared.scopeAliases.`,
          );
        }
        seenAliasSet.add(alias);
        seenAliases.push(alias);
        aliasesByScope[canonical].push(alias);
      }
    }
  }

  return { aliasesByScope, allScopes: [...canonicals, ...seenAliases] };
}
