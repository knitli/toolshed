import { expect, test } from "bun:test";
import {
  DEFAULT_RUNTIME_LIMITS,
  resolveRuntimeLimits,
} from "../src/runtime/index.ts";

const malformedLimitsMessage =
  "Runtime limits overrides must be an exact plain data object";

function expectMalformedLimits(value: unknown): void {
  expect(() => resolveRuntimeLimits(value as never)).toThrow(
    new RangeError(malformedLimitsMessage),
  );
}

test("resolves omitted and null-prototype partial runtime limits", () => {
  expect(resolveRuntimeLimits()).toEqual(DEFAULT_RUNTIME_LIMITS);
  const overrides = Object.create(null) as { maxPages: number };
  overrides.maxPages = 1;
  expect(resolveRuntimeLimits(overrides)).toEqual({
    ...DEFAULT_RUNTIME_LIMITS,
    maxPages: 1,
  });
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
