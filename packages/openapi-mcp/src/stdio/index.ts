import {
  type StdioServerHandle,
  serveStdio,
} from "@modelcontextprotocol/server/stdio";
import type { AuthenticatedManifest } from "../runtime/manifest.ts";
import {
  admitExecutableRelease,
  createOpenApiRuntime,
  verifyExecutableRelease,
} from "../runtime/runtime.ts";
import type { CatalogId, ReleaseId } from "../runtime/types.ts";
import { resolveRuntimeLimits } from "../runtime/versions.ts";
import {
  createCredentialProvider,
  type LocalCredentialProvider,
} from "../sqlite/auth.ts";
import { SqliteCatalogStore } from "../sqlite/catalog-store.ts";
import { FileGenerationStore } from "../sqlite/generation-store.ts";
import { createLocalDispatchBoundary } from "../sqlite/guarded-fetch.ts";
import { type OpenApiStdioConfig, parseOpenApiStdioConfig } from "./config.ts";
import { compileExactPolicy } from "./exact-policy.ts";
import { createStdioSearchRuntime } from "./search.ts";
import {
  createOpenApiMcpServer,
  createStdioActionAuthorizer,
  type OpenApiServerRoute,
} from "./server.ts";

export { type OpenApiStdioConfig, parseOpenApiStdioConfig } from "./config.ts";
export {
  createOpenApiMcpServer,
  type OpenApiMcpServerOptions,
} from "./server.ts";

/** Owns process-local credentials/catalogs independently of disposable SDK probes. */
export async function serveOpenApiStdio(
  input: OpenApiStdioConfig,
): Promise<StdioServerHandle> {
  const config = parseOpenApiStdioConfig(input);
  const stores: SqliteCatalogStore[] = [];
  const providers: LocalCredentialProvider[] = [];
  const boundaries: ReturnType<typeof createLocalDispatchBoundary>[] = [];
  let sdk: StdioServerHandle | undefined;
  let closing: Promise<void> | undefined;
  const onTerminate = () => {
    void close().catch(() => {
      process.stderr.write("OpenAPI stdio cleanup failed\n");
      process.exitCode = 1;
    });
  };
  const close = (): Promise<void> =>
    (closing ??= (async () => {
      process.off("SIGTERM", onTerminate);
      process.off("SIGINT", onTerminate);
      process.stdin.off("end", onTerminate);
      const results = await Promise.allSettled([
        ...boundaries.map((entry) => entry.close()),
        ...providers.map((entry) => entry.close()),
        ...(sdk ? [sdk.close()] : []),
      ]);
      for (const store of stores) store.close();
      if (results.some((entry) => entry.status === "rejected"))
        throw new Error("OpenAPI stdio cleanup failed");
    })());
  try {
    const generations = new FileGenerationStore(config.generationStatePath);
    const limits = resolveRuntimeLimits(config.limits);
    const admitted: {
      config: OpenApiStdioConfig["catalogs"][number];
      store: SqliteCatalogStore;
      verified: AuthenticatedManifest;
    }[] = [];
    for (const entry of config.catalogs) {
      const store = new SqliteCatalogStore(entry.path, { limits });
      stores.push(store);
      const verified = await verifyExecutableRelease(
        { store, trust: config.trust, generations, limits },
        entry.catalogId as CatalogId,
        entry.releaseId as ReleaseId,
      );
      if (
        verified.manifest.catalogId !== entry.catalogId ||
        verified.manifest.releaseId !== entry.releaseId
      )
        throw new Error("Catalog identity mismatch");
      admitted.push({ config: entry, store, verified });
    }
    const templates = await Promise.all(
      (config.exactPolicies ?? []).map((entry) => compileExactPolicy(entry)),
    );
    // Reject invalid releases and policies before advancing any catalog.
    // GenerationStore provides per-catalog CAS, not a cross-catalog transaction.
    for (const entry of admitted)
      await admitExecutableRelease(
        { store: entry.store, trust: config.trust, generations, limits },
        entry.verified,
      );
    const authorizer = createStdioActionAuthorizer(templates);
    const routes: OpenApiServerRoute[] = [];
    for (const profile of config.profiles) {
      const catalogs = admitted.filter(
        (entry) => entry.config.profileId === profile.profileId,
      );
      if (!catalogs.length) continue;
      const credentials = await createCredentialProvider(profile, {
        manifestOrigins: [
          ...new Set(
            catalogs.flatMap((entry) => entry.verified.manifest.allowedOrigins),
          ),
        ],
      });
      providers.push(credentials);
      const boundary = createLocalDispatchBoundary(authorizer, {
        profile,
        limits,
        async allowsManifestOrigin(context) {
          const entry = catalogs.find(
            (entry) =>
              entry.verified.manifest.catalogId === context.catalogId &&
              entry.verified.manifest.releaseId === context.releaseId &&
              entry.verified.manifestDigest === context.manifestDigest,
          );
          if (
            !entry ||
            !config.allowedOrigins.includes(context.origin) ||
            !entry.verified.manifest.allowedOrigins.includes(context.origin)
          )
            return false;
          try {
            const current = await generations.get(
              entry.verified.manifest.catalogId,
              entry.verified.manifest.issuer,
            );
            return (
              current?.activeGeneration ===
                entry.verified.manifest.generation &&
              current.activeManifestDigest === entry.verified.manifestDigest
            );
          } catch {
            return false;
          }
        },
      });
      boundaries.push(boundary);
      for (const entry of catalogs)
        routes.push({
          catalogId: entry.config.catalogId,
          releaseId: entry.config.releaseId,
          apiNamespaces: [
            ...new Set(
              Object.keys(entry.verified.manifest.records)
                .filter((id) => id.startsWith("operation:"))
                .map((id) => id.split(":")[1] as string),
            ),
          ],
          credentials,
          boundary,
          runtime: createOpenApiRuntime({
            store: entry.store,
            trust: config.trust,
            generations,
            destinationPolicy: {
              async allows(origin) {
                return (
                  config.allowedOrigins.includes(origin) &&
                  profile.allowedOrigins.includes(origin)
                );
              },
            },
            credentialBinding: credentials.bindingResolver,
            paginationTokenCodec: boundary.paginationTokenCodec,
            limits,
          }),
        });
    }
    sdk = serveStdio(
      () =>
        createOpenApiMcpServer({
          routes,
          searchRuntime: createStdioSearchRuntime(
            admitted.map((entry) => ({
              catalogId: entry.config.catalogId,
              releaseId: entry.config.releaseId,
              apiNamespaces:
                routes.find(
                  (route) => route.catalogId === entry.config.catalogId,
                )?.apiNamespaces ?? [],
              store: entry.store,
            })),
            { trust: config.trust, generations, limits },
          ),
          limits,
          authorizer,
          maxSearchResults: limits.maxSearchResults,
          defaultSearchResults: limits.defaultSearchResults,
        }),
      {
        onerror() {
          process.stderr.write("OpenAPI stdio protocol error\n");
        },
      },
    );
    process.once("SIGTERM", onTerminate);
    process.once("SIGINT", onTerminate);
    process.stdin.once("end", onTerminate);
    return Object.freeze({ close });
  } catch {
    await close().catch(() => {});
    throw new Error("OpenAPI stdio startup failed");
  }
}
