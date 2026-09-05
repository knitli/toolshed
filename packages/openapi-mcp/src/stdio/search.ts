import { OpenApiMcpError } from "../runtime/errors.ts";
import {
  createRuntimeWithCandidateLookup,
  type OpenApiRuntimeOptions,
} from "../runtime/runtime.ts";
import type {
  CandidateRef,
  CatalogStore,
  OpenApiRuntime,
} from "../runtime/types.ts";
import { resolveRuntimeLimits } from "../runtime/versions.ts";

export interface StdioSearchCatalog {
  readonly catalogId: string;
  readonly releaseId: string;
  readonly apiNamespaces: readonly string[];
  readonly store: CatalogStore;
}

/** One semantic search, including one shared proof/work/byte budget across catalogs. */
export function createStdioSearchRuntime(
  catalogs: readonly StdioSearchCatalog[],
  options: Omit<OpenApiRuntimeOptions, "store">,
): Pick<OpenApiRuntime, "search"> {
  const ordered = [...catalogs].sort((a, b) => {
    const left = `${a.catalogId}\0${a.releaseId}`;
    const right = `${b.catalogId}\0${b.releaseId}`;
    return left < right ? -1 : left > right ? 1 : 0;
  });
  const limits = resolveRuntimeLimits(options.limits);
  const stores = new Map(
    ordered.map((entry) => [
      `${entry.catalogId}\0${entry.releaseId}`,
      entry.store,
    ]),
  );
  const storeFor = (catalogId: string, releaseId: string) => {
    const store = stores.get(`${catalogId}\0${releaseId}`);
    if (!store) throw new OpenApiMcpError("RECORD_NOT_ADMITTED");
    return store;
  };
  return {
    async search(input) {
      const matching = ordered.filter(
        (entry) =>
          input.api === undefined || entry.apiNamespaces.includes(input.api),
      );
      const store: CatalogStore = {
        getManifest: (catalog, release) =>
          storeFor(catalog, release).getManifest(catalog, release),
        getOperation: (catalog, release, id) =>
          storeFor(catalog, release).getOperation(catalog, release, id),
        getSchemas: (catalog, release, ids) =>
          storeFor(catalog, release).getSchemas(catalog, release, ids),
        async searchCandidates() {
          throw new OpenApiMcpError("UPSTREAM_ERROR");
        },
      };
      return createRuntimeWithCandidateLookup(
        { ...options, limits, store },
        async (query, tryChargeSource) => {
          const batches: (readonly CandidateRef[])[] = [];
          let remaining = query.limit;
          let limited = false;
          // Source calls share the proof budget, including queries with no matches.
          // One total candidate allowance bounds hydration across all sources.
          // FTS ranks are local; interleave equal local ranks in stable catalog order.
          for (const [index, entry] of matching.entries()) {
            if (remaining === 0) break;
            if (!tryChargeSource()) {
              limited = true;
              break;
            }
            const limit = Math.min(
              limits.maxSearchResults,
              Math.ceil(remaining / (matching.length - index)),
            );
            const rows = await entry.store.searchCandidates({
              ...query,
              limit,
            });
            if (
              rows.length > limit ||
              rows.some(
                (row) =>
                  row.catalogId !== entry.catalogId ||
                  row.releaseId !== entry.releaseId,
              )
            )
              throw new OpenApiMcpError("RECORD_NOT_ADMITTED");
            remaining -= rows.length;
            batches.push(rows);
          }
          const candidates: CandidateRef[] = [];
          for (let rank = 0; candidates.length < query.limit; rank++) {
            let found = false;
            for (const batch of batches) {
              const candidate = batch[rank];
              if (candidate) {
                candidates.push(candidate);
                found = true;
              }
            }
            if (!found) break;
          }
          return { candidates, limited };
        },
      ).search(input);
    },
  };
}
