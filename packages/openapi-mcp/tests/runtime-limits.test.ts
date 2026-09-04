import { expect, test } from "bun:test";
import {
  DEFAULT_RUNTIME_LIMITS,
  type RuntimeLimits,
  resolveRuntimeLimits,
} from "../src/runtime/index.ts";

const legacyRuntimeLimits: RuntimeLimits = {
  maxManifestBytes: 8 * 1024 * 1024,
  maxManifestRecords: 100_000,
  maxRecordBytes: 1024 * 1024,
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
};

const malformedLimitsMessage =
  "Runtime limits overrides must be an exact plain data object";

function expectMalformedLimits(value: unknown): void {
  expect(() => resolveRuntimeLimits(value as never)).toThrow(
    new RangeError(malformedLimitsMessage),
  );
}

test("resolves omitted and null-prototype partial runtime limits", () => {
  expect(resolveRuntimeLimits()).toEqual(DEFAULT_RUNTIME_LIMITS);
  expect(DEFAULT_RUNTIME_LIMITS.maxReleaseInventoryBytes).toBe(
    128 * 1024 * 1024,
  );
  const overrides = Object.create(null) as { maxPages: number };
  overrides.maxPages = 1;
  expect(resolveRuntimeLimits(overrides)).toEqual({
    ...DEFAULT_RUNTIME_LIMITS,
    maxPages: 1,
  });
});

test("resolves legacy complete RuntimeLimits objects with the new default", () => {
  const resolved = resolveRuntimeLimits(legacyRuntimeLimits);
  expect(resolved.maxReleaseInventoryBytes).toBe(
    DEFAULT_RUNTIME_LIMITS.maxReleaseInventoryBytes,
  );
});

test("only permits lowering the release inventory byte ceiling", () => {
  expect(
    resolveRuntimeLimits({ maxReleaseInventoryBytes: 1024 })
      .maxReleaseInventoryBytes,
  ).toBe(1024);
  expect(() =>
    resolveRuntimeLimits({
      maxReleaseInventoryBytes:
        DEFAULT_RUNTIME_LIMITS.maxReleaseInventoryBytes + 1,
    }),
  ).toThrow(
    new RangeError(
      "Runtime limit maxReleaseInventoryBytes must only lower its default",
    ),
  );
});

test("rejects malformed runtime limit containers without invoking accessors", () => {
  let accessorReads = 0;
  const accessorBacked = Object.defineProperty({}, "maxPages", {
    enumerable: true,
    get: () => {
      accessorReads += 1;
      return 1;
    },
  });
  const symbolBacked = {
    maxPages: 1,
    [Symbol("limits-secret")]: true,
  };
  const poisonedProxy = new Proxy(
    {},
    {
      ownKeys: () => {
        throw new Error("limits-proxy-secret");
      },
    },
  );

  for (const value of [
    null,
    [],
    new Date(),
    Object.create({}),
    accessorBacked,
    symbolBacked,
    { unexpectedLimit: 1 },
    poisonedProxy,
  ]) {
    expectMalformedLimits(value);
  }
  expect(accessorReads).toBe(0);
});

test("rejects undefined own limit values while applying numeric data values once", () => {
  expect(() => resolveRuntimeLimits({ maxPages: undefined })).toThrow(
    new RangeError("Runtime limit maxPages must only lower its default"),
  );
  expect(resolveRuntimeLimits({ maxPages: 1 }).maxPages).toBe(1);
});
