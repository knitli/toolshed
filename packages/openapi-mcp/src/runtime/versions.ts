/** Version of the portable runtime API and its persisted contract. */
export const RUNTIME_CONTRACT_VERSION = 1 as const;

/** Version of immutable, signed logical release artifacts. */
export const ARTIFACT_FORMAT_VERSION = 4 as const;

/** Version of the credential-free prepared-call representation. */
export const PREPARED_CALL_VERSION = 1 as const;

/** Application security and availability limits for every runtime adapter. */
export const DEFAULT_RUNTIME_LIMITS = {
  maxManifestBytes: 8 * 1024 * 1024,
  maxManifestRecords: 100_000,
  maxRecordBytes: 1 * 1024 * 1024,
  maxJsonDepth: 64,
  maxSchemaClosureBytes: 4 * 1024 * 1024,
  maxSchemaRefHops: 16,
  maxSearchResults: 50,
  defaultSearchResults: 10,
  maxArgumentsBytes: 256 * 1024,
  maxResponseBytes: 8 * 1024 * 1024,
  maxPages: 10,
  maxPaginationBytes: 16 * 1024 * 1024,
  maxRedirects: 3,
  requestDeadlineMs: 30_000,
} as const;

export type RuntimeLimits = typeof DEFAULT_RUNTIME_LIMITS;
