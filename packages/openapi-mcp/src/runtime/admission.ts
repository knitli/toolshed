import type { AdmittedManifest } from "./manifest.ts";
import {
  admitExecutableRelease,
  type OpenApiRuntimeOptions,
  verifyExecutableRelease,
} from "./runtime.ts";
import type { CatalogId, ReleaseId } from "./types.ts";

/** Verify the complete release inventory before atomically admitting its generation.
 * Storage must preserve immutable release identities; later runtime reads still
 * verify records because this check cannot guarantee future storage availability.
 */
export async function admitCatalogRelease(
  options: OpenApiRuntimeOptions,
  catalogId: CatalogId,
  releaseId: ReleaseId,
): Promise<AdmittedManifest> {
  const preflight = await verifyExecutableRelease(
    options,
    catalogId,
    releaseId,
  );
  return admitExecutableRelease(options, preflight);
}
