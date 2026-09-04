/** Version of the portable runtime API and its persisted contract. */
export const RUNTIME_CONTRACT_VERSION = 1 as const;

/** Version of immutable, signed logical release artifacts. */
export const ARTIFACT_FORMAT_VERSION = 4 as const;

/** Version of the credential-free prepared-call representation. */
export const PREPARED_CALL_VERSION = 1 as const;

/** Fixed UTF-8 envelope for a single catalog search query. */
export const MAX_SEARCH_QUERY_BYTES = 4 * 1024;

/** Application security and availability limits for every runtime adapter. */
export interface RuntimeLimits {
  readonly maxManifestBytes: number;
  readonly maxManifestRecords: number;
  readonly maxRecordBytes: number;
  readonly maxJsonDepth: number;
  readonly maxSchemaClosureBytes: number;
  readonly maxSchemaRefHops: number;
  readonly maxSearchResults: number;
  readonly defaultSearchResults: number;
  readonly maxArgumentsBytes: number;
  readonly maxResponseBytes: number;
  readonly maxPages: number;
  readonly maxPaginationBytes: number;
  readonly maxRedirects: number;
  readonly requestDeadlineMs: number;
}

export const DEFAULT_RUNTIME_LIMITS = Object.freeze({
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
} as const satisfies RuntimeLimits);

const malformedOverridesMessage =
  "Runtime limits overrides must be an exact plain data object";

function malformedOverrides(): RangeError {
  return new RangeError(malformedOverridesMessage);
}

/**
 * Apply operator limits without allowing a caller to relax the signed-runtime
 * availability envelope. Every supplied value must be a positive safe integer
 * no greater than the portable default.
 */
export function resolveRuntimeLimits(
  overrides: Partial<RuntimeLimits> = {},
): RuntimeLimits {
  const resolved: Record<keyof RuntimeLimits, number> = {
    ...DEFAULT_RUNTIME_LIMITS,
  };

  let supplied: ReadonlyArray<readonly [keyof RuntimeLimits, unknown]>;
  try {
    if (
      overrides === null ||
      typeof overrides !== "object" ||
      Array.isArray(overrides)
    ) {
      throw malformedOverrides();
    }

    const prototype = Object.getPrototypeOf(overrides);
    if (prototype !== Object.prototype && prototype !== null) {
      throw malformedOverrides();
    }

    supplied = Reflect.ownKeys(overrides).map((candidate) => {
      if (
        typeof candidate !== "string" ||
        !Object.hasOwn(DEFAULT_RUNTIME_LIMITS, candidate)
      ) {
        throw malformedOverrides();
      }
      const descriptor = Object.getOwnPropertyDescriptor(overrides, candidate);
      if (
        descriptor === undefined ||
        !descriptor.enumerable ||
        !("value" in descriptor)
      ) {
        throw malformedOverrides();
      }
      return [candidate as keyof RuntimeLimits, descriptor.value] as const;
    });
  } catch {
    throw malformedOverrides();
  }

  for (const [key, value] of supplied) {
    if (
      value === undefined ||
      typeof value !== "number" ||
      !Number.isSafeInteger(value) ||
      value < 1 ||
      value > DEFAULT_RUNTIME_LIMITS[key]
    ) {
      throw new RangeError(`Runtime limit ${key} must only lower its default`);
    }
    resolved[key] = value;
  }

  return Object.freeze(resolved);
}
