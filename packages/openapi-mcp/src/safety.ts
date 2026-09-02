import type { Risk, Safety } from "./types";

const READ_METHODS = new Set(["GET", "HEAD"]);

/**
 * Operation-id suffixes that are POSTs by protocol but reads by semantics,
 * keyed by the API they were derived from. Scoping is load-bearing, not
 * tidiness: `preview` and `query` are generic enough that another mounted API
 * will have a genuinely mutating `POST .../query`, and a global list would
 * classify it `read` — reachable through the no-approval read tool. An API
 * with no entry here gets no overrides, so mutating methods stay `write`.
 *
 * This table is engine code, not artifact data: the server recomputes safety
 * at load and honours a stored `read` on a mutating method only if the same
 * `(api, suffix)` pair appears here.
 */
export const READ_OVERRIDES: Record<string, readonly string[]> = {
  graph: [
    "getByIds",
    "getMemberGroups",
    "getMemberObjects",
    "checkMemberGroups",
    "checkMemberObjects",
    "getAvailableExtensionProperties",
    "findMeetingTimes",
    "getSchedule",
    "translateExchangeIds",
    "preview",
    "query",
  ],
};

/** A batch endpoint bundles arbitrary sub-request methods, so it is never a read. */
export function isBatch(path: string): boolean {
  return path === "/$batch" || path.endsWith("/$batch");
}

/**
 * Classifies an operation as read or write. Method is the default; the
 * API's own override list corrects semantically-read POSTs. `$batch` always
 * wins, and an unrecognised API never gets an override.
 */
export function classifySafety(
  method: string,
  path: string,
  operationId: string,
  api: string,
): Safety {
  if (isBatch(path)) return "write";
  if (READ_METHODS.has(method.toUpperCase())) return "read";
  const tail = operationId.split(".").pop() ?? "";
  const overrides = READ_OVERRIDES[api] ?? [];
  return overrides.some((s) => s === tail) ? "read" : "write";
}

/**
 * Risk tier drives which write tool an operation is reachable through.
 * Unknown privilege is treated as high: 22% of Graph has no permission
 * mapping, and unmapped must not silently mean "safe".
 */
export function riskFor(
  safety: Safety,
  privilegeLevel: number | null,
  path: string,
): Risk {
  if (isBatch(path)) return "high";
  if (safety === "read") return "routine";
  if (privilegeLevel === null) return "high";
  return privilegeLevel >= 4 ? "high" : "routine";
}
