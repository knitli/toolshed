import { describe, expect, test } from "bun:test";
import { OpenApiMcpError } from "../src/runtime/errors.ts";
import type {
  CatalogId,
  JsonObject,
  PreparedCall,
  ReleaseId,
  Sha256,
  TypedOperationId,
} from "../src/runtime/types.ts";
import {
  type ArgumentConstraint,
  compileExactPolicy,
  type ExactPolicyTemplate,
  matchesExactPolicy,
} from "../src/stdio/exact-policy.ts";

const digestA = "a".repeat(64) as Sha256;
const digestB = "b".repeat(64) as Sha256;
const digestC = "c".repeat(64) as Sha256;

function template(
  overrides: Partial<ExactPolicyTemplate> = {},
): ExactPolicyTemplate {
  return {
    version: 1,
    catalogId: "catalog" as CatalogId,
    releaseId: "release" as ReleaseId,
    manifestDigest: digestA,
    operationId: "operation:api:createWidget" as TypedOperationId,
    operationDigest: digestB,
    credentialProfileDigest: digestC,
    actionKind: "create",
    cardinality: "single",
    maxAffected: 1,
    expiresAt: 2_000,
    arguments: {
      kind: "object",
      properties: {
        body: {
          kind: "object",
          properties: {
            count: { kind: "number", min: 1, max: 3 },
            labels: {
              kind: "array",
              maxItems: 2,
              items: { kind: "string-set", values: ["z", "a"] },
            },
          },
        },
        enabled: { kind: "exact", value: true },
      },
    },
    ...overrides,
  };
}

function call(overrides: Partial<PreparedCall> = {}): PreparedCall {
  return {
    version: 2,
    catalogId: "catalog" as CatalogId,
    releaseId: "release" as ReleaseId,
    operationId: "operation:api:createWidget" as TypedOperationId,
    operationDigest: digestB,
    manifestDigest: digestA,
    credentialProfileId: "profile",
    credentialProfileDigest: digestC,
    reservedSlotsDigest: digestA,
    method: "POST",
    origin: "https://api.example.test",
    relativeUrl: "/widgets",
    headers: {},
    body: null,
    normalizedArguments: {
      body: { count: 2, labels: ["a", "z"] },
      enabled: true,
    },
    safety: "action",
    actionKind: "create",
    cardinality: { kind: "single" },
    inputDigest: digestA,
    preparedCallDigest: digestB,
    ...overrides,
  };
}

async function expectInvalid(value: unknown): Promise<void> {
  try {
    await compileExactPolicy(value);
    throw new Error("expected exact policy compilation to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(OpenApiMcpError);
    expect(error).toMatchObject({
      code: "INPUT_INVALID",
      message: "Exact policy template is invalid",
    });
  }
}

describe("exact policy compilation and matching", () => {
  test("normalizes a detached frozen template and matches its exact call", async () => {
    const input = template();
    const compiled = await compileExactPolicy(input);

    expect(compiled.policyDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(compiled.template).not.toBe(input);
    expect(Object.isFrozen(compiled.template)).toBe(true);
    expect(Object.isFrozen(compiled.template.arguments)).toBe(true);
    expect(
      Object.isFrozen(
        (compiled.template.arguments as { properties: JsonObject }).properties,
      ),
    ).toBe(true);
    const body = (
      compiled.template.arguments as {
        properties: Record<string, { properties: Record<string, unknown> }>;
      }
    ).properties.body;
    expect(
      (
        body.properties.labels as {
          items: { values: readonly string[] };
        }
      ).items.values,
    ).toEqual(["a", "z"]);
    expect(matchesExactPolicy(compiled, call(), 1_999)).toBe(true);
    expect(matchesExactPolicy(compiled, call(), 2_000)).toBe(false);
  });

  test("snapshots all own data before the digest await", async () => {
    const input = template();
    const properties = (
      input.arguments as {
        properties: Record<string, ArgumentConstraint>;
      }
    ).properties;
    const pending = compileExactPolicy(input);
    (input as unknown as { catalogId: CatalogId }).catalogId =
      "changed" as CatalogId;
    properties.enabled = { kind: "exact", value: false };

    const compiled = await pending;
    expect(compiled.template.catalogId).toBe("catalog");
    expect(matchesExactPolicy(compiled, call(), 1_000)).toBe(true);
  });

  test("canonicalizes equivalent string sets to one digest", async () => {
    const first = await compileExactPolicy(
      template({ arguments: { kind: "string-set", values: ["z", "a"] } }),
    );
    const second = await compileExactPolicy(
      template({ arguments: { kind: "string-set", values: ["a", "z"] } }),
    );
    expect(first.policyDigest).toBe(second.policyDigest);
  });

  test("matches exact JSON leaves and closed objects", async () => {
    const compiled = await compileExactPolicy(
      template({
        arguments: {
          kind: "exact",
          value: { body: { tags: ["one", null, true], count: 0 } },
        },
      }),
    );
    const exact = { body: { tags: ["one", null, true], count: 0 } };
    expect(
      matchesExactPolicy(compiled, call({ normalizedArguments: exact }), 1_000),
    ).toBe(true);
    expect(
      matchesExactPolicy(
        compiled,
        call({ normalizedArguments: { ...exact, extra: null } }),
        1_000,
      ),
    ).toBe(false);
  });

  test("applies inclusive number, closed set, and array boundaries", async () => {
    const compiled = await compileExactPolicy(template());
    const args = (count: number, labels: string[]) => ({
      body: { count, labels },
      enabled: true,
    });
    for (const count of [1, 3]) {
      expect(
        matchesExactPolicy(
          compiled,
          call({ normalizedArguments: args(count, ["a", "z"]) }),
          1_000,
        ),
      ).toBe(true);
    }
    for (const argumentsValue of [
      args(0.999, ["a"]),
      args(3.001, ["a"]),
      args(2, ["other"]),
      args(2, ["a", "z", "a"]),
    ]) {
      expect(
        matchesExactPolicy(
          compiled,
          call({ normalizedArguments: argumentsValue }),
          1_000,
        ),
      ).toBe(false);
    }
  });

  test("requires exact object keys at every level", async () => {
    const compiled = await compileExactPolicy(template());
    expect(
      matchesExactPolicy(
        compiled,
        call({
          normalizedArguments: {
            body: { count: 2, labels: ["a"] },
          },
        }),
        1_000,
      ),
    ).toBe(false);
    expect(
      matchesExactPolicy(
        compiled,
        call({
          normalizedArguments: {
            body: { count: 2, labels: ["a"], extra: true },
            enabled: true,
          },
        }),
        1_000,
      ),
    ).toBe(false);
  });

  test("denies hostile argument shapes without invoking accessors", async () => {
    const compiled = await compileExactPolicy(template());
    let getterCalls = 0;
    const accessorArguments = {
      body: { count: 2, labels: ["a"] },
      get enabled() {
        getterCalls += 1;
        return true;
      },
    };
    expect(
      matchesExactPolicy(
        compiled,
        call({
          normalizedArguments: accessorArguments as unknown as JsonObject,
        }),
        1_000,
      ),
    ).toBe(false);
    expect(getterCalls).toBe(0);

    const labels = ["a"];
    Object.setPrototypeOf(labels, Object.create(Array.prototype));
    expect(
      matchesExactPolicy(
        compiled,
        call({
          normalizedArguments: {
            body: { count: 2, labels },
            enabled: true,
          },
        }),
        1_000,
      ),
    ).toBe(false);
  });

  test("binds every release, operation, manifest, and profile identity", async () => {
    const compiled = await compileExactPolicy(template());
    const changes: Partial<PreparedCall>[] = [
      { catalogId: "other" as CatalogId },
      { releaseId: "other" as ReleaseId },
      { manifestDigest: digestB },
      { operationId: "operation:api:other" as TypedOperationId },
      { operationDigest: digestA },
      { credentialProfileDigest: digestA },
    ];
    for (const change of changes) {
      expect(matchesExactPolicy(compiled, call(change), 1_000)).toBe(false);
    }
  });

  test("permits only routine action safety with the same kind and cardinality", async () => {
    const single = await compileExactPolicy(template());
    for (const change of [
      { safety: "read", actionKind: null, cardinality: null },
      { actionKind: "update" },
      { actionKind: "delete" },
      { actionKind: "unknown" },
      { cardinality: { kind: "unknown" } },
      { cardinality: { kind: "unbounded" } },
      { cardinality: { kind: "bounded", maxAffected: 1 } },
    ] as Partial<PreparedCall>[]) {
      expect(matchesExactPolicy(single, call(change), 1_000)).toBe(false);
    }

    const bounded = await compileExactPolicy(
      template({ cardinality: "bounded", maxAffected: 5 }),
    );
    expect(
      matchesExactPolicy(
        bounded,
        call({ cardinality: { kind: "bounded", maxAffected: 5 } }),
        1_000,
      ),
    ).toBe(true);
    expect(
      matchesExactPolicy(
        bounded,
        call({ cardinality: { kind: "bounded", maxAffected: 6 } }),
        1_000,
      ),
    ).toBe(false);
    for (const maxAffected of [Number.NaN, 1.5, 10_001]) {
      expect(
        matchesExactPolicy(
          bounded,
          call({ cardinality: { kind: "bounded", maxAffected } }),
          1_000,
        ),
      ).toBe(false);
    }
    expect(
      matchesExactPolicy(
        bounded,
        call({ cardinality: { kind: "single" } }),
        1_000,
      ),
    ).toBe(false);
  });
});

describe("exact policy validation", () => {
  test("returns one fixed safe error for invalid top-level fields", async () => {
    const cases: unknown[] = [
      { ...template(), extra: true },
      { ...template(), version: 2 },
      { ...template(), catalogId: "../bad" },
      { ...template(), releaseId: ".." },
      { ...template(), manifestDigest: "A".repeat(64) },
      { ...template(), operationId: "schema:api:#/components/schemas/Thing" },
      { ...template(), operationDigest: "short" },
      { ...template(), credentialProfileDigest: "g".repeat(64) },
      { ...template(), actionKind: "delete" },
      { ...template(), cardinality: "unbounded" },
      { ...template(), cardinality: "single", maxAffected: 2 },
      { ...template(), cardinality: "bounded", maxAffected: 0 },
      { ...template(), cardinality: "bounded", maxAffected: 10_001 },
      { ...template(), expiresAt: 1.5 },
      { ...template(), expiresAt: Number.MAX_SAFE_INTEGER + 1 },
    ];
    for (const value of cases) await expectInvalid(value);
  });

  test("rejects malformed constraint nodes and numeric bounds", async () => {
    const constraints: unknown[] = [
      { kind: "wildcard" },
      { kind: "exact", value: true, extra: true },
      { kind: "number", min: 2, max: 1 },
      { kind: "number", min: 0, max: Number.POSITIVE_INFINITY },
      { kind: "number", min: Number.NaN, max: 1 },
      { kind: "array", maxItems: -1, items: { kind: "exact", value: 1 } },
      {
        kind: "array",
        maxItems: 10_001,
        items: { kind: "exact", value: 1 },
      },
      { kind: "object", properties: [], extra: false },
      { kind: "string-set", values: ["same", "same"] },
      { kind: "string-set", values: ["valid", 1] },
      {
        kind: "string-set",
        values: Array.from({ length: 257 }, (_, index) => String(index)),
      },
    ];
    for (const argumentsValue of constraints) {
      await expectInvalid({ ...template(), arguments: argumentsValue });
    }
  });

  test("allows zero-length arrays and the 10000 hard cap", async () => {
    await expect(
      compileExactPolicy(
        template({
          cardinality: "bounded",
          maxAffected: 10_000,
          arguments: {
            kind: "array",
            maxItems: 0,
            items: { kind: "exact", value: null },
          },
        }),
      ),
    ).resolves.toBeDefined();
  });

  test("rejects proxies, accessors, symbols, custom prototypes, cycles, and sparse arrays", async () => {
    const accessor = template() as unknown as Record<string, unknown>;
    Object.defineProperty(accessor, "catalogId", {
      enumerable: true,
      get: () => "catalog",
    });
    const symbol = template() as unknown as Record<PropertyKey, unknown>;
    symbol[Symbol("hidden")] = true;
    const custom = Object.assign(
      Object.create({ inherited: true }),
      template(),
    );
    const cycle = template() as unknown as Record<string, unknown>;
    cycle.arguments = { kind: "exact", value: cycle };
    const sparse = template() as unknown as Record<string, unknown>;
    sparse.arguments = {
      kind: "exact",
      value: Object.assign(new Array(2), { 1: "present" }),
    };
    const hostileProxy = new Proxy(template(), {
      ownKeys() {
        throw new Error("do not leak this message");
      },
    });

    for (const value of [
      accessor,
      symbol,
      custom,
      cycle,
      sparse,
      hostileProxy,
    ]) {
      await expectInvalid(value);
    }
  });

  test("enforces the 64KiB, depth-32, and 4096-node snapshot limits", async () => {
    await expectInvalid(
      template({
        arguments: { kind: "exact", value: "x".repeat(65_536) },
      }),
    );

    let deep: ArgumentConstraint = { kind: "exact", value: null };
    for (let index = 0; index < 40; index += 1) {
      deep = { kind: "array", maxItems: 1, items: deep };
    }
    await expectInvalid(template({ arguments: deep }));

    await expectInvalid(
      template({
        arguments: {
          kind: "exact",
          value: Array.from({ length: 4_096 }, () => null),
        },
      }),
    );
  });
});
