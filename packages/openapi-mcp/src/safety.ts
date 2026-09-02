import type { Risk, Safety } from "./types";

const READ_METHODS = new Set(["GET", "HEAD"]);

/**
 * Operation-id suffixes that are POSTs by protocol but reads by semantics.
 * Derived from Microsoft Graph, where 53 operations match. This list is
 * engine code, not artifact data: the server recomputes safety at load and
 * honours a stored `read` on a mutating method only if it also appears here.
 */
export const READ_OVERRIDE_SUFFIXES = [
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
] as const;

/** A batch endpoint bundles arbitrary sub-request methods, so it is never a read. */
export function isBatch(path: string): boolean {
  return path === "/$batch" || path.endsWith("/$batch");
}

/**
 * Classifies an operation as read or write. Method is the default; the
 * override list corrects semantically-read POSTs. `$batch` always wins.
 */
export function classifySafety(
  method: string,
  path: string,
  operationId: string,
): Safety {
  if (READ_METHODS.has(method.toUpperCase())) return "read";
  if (isBatch(path)) return "write";
  const tail = operationId.split(".").pop() ?? "";
  return READ_OVERRIDE_SUFFIXES.some((s) => s === tail) ? "read" : "write";
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
  if (safety === "read") return "routine";
  if (isBatch(path)) return "high";
  if (privilegeLevel === null) return "high";
  return privilegeLevel >= 4 ? "high" : "routine";
}
