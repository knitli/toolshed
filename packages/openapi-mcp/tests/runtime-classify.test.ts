import { describe, expect, test } from "bun:test";
import { classifyOperation } from "../src/runtime/classify.ts";
import type {
  OperationRecordV4,
  SchemaRecordV4,
  TypedSchemaId,
} from "../src/runtime/types.ts";

function operation(
  operationId: string,
  overrides: Partial<OperationRecordV4> = {},
): OperationRecordV4 {
  return {
    id: `operation:tiny:${operationId}`,
    api: "tiny",
    operationId,
    method: "POST",
    path: "/widgets",
    origin: "https://api.example.test",
    summary: null,
    deprecated: false,
    parameters: [],
    requestBody: null,
    schemaIds: [],
    tags: [],
    advisory: {
      safety: "read",
      actionKind: "create",
      cardinality: { kind: "single" },
      risk: "routine",
    },
    ...overrides,
  };
}

function requiredId(
  name = "widgetId",
): OperationRecordV4["parameters"][number] {
  const schemaId = `schema:tiny:#/components/schemas/${name}` as TypedSchemaId;
  return {
    name,
    in: "path",
    required: true,
    deprecated: false,
    style: "simple",
    explode: false,
    allowReserved: false,
    value: { kind: "schema", schemaId },
  };
}

describe("classifyOperation", () => {
  test("does not trust poisoned compiler advisory hints", () => {
    expect(
      classifyOperation(
        operation("deleteWidget", {
          method: "DELETE",
          path: "/widgets/{widgetId}",
          parameters: [requiredId()],
        }),
      ),
    ).toEqual({
      safety: "action",
      actionKind: "delete",
      cardinality: { kind: "single" },
      dangerous: true,
      highRisk: true,
    });
  });

  test.each([
    ["createWidget", "POST", "/widgets", "create"],
    ["updateWidget", "PATCH", "/widgets/{widgetId}", "update"],
    ["deleteWidget", "DELETE", "/widgets/{widgetId}", "delete"],
    ["sendInvitation", "POST", "/users/{widgetId}/invite", "communicate"],
    ["grantRole", "PUT", "/users/{widgetId}/roles", "authority"],
    ["refundPayment", "POST", "/payments/{widgetId}/refund", "transaction"],
    ["runJob", "POST", "/jobs/{widgetId}/run", "execute"],
    ["inspectWidget", "OPTIONS", "/widgets/{widgetId}/inspect", "unknown"],
  ] as const)("classifies %s as %s from verified method and bounded operation tokens", (operationId, method, path, actionKind) => {
    const result = classifyOperation(
      operation(operationId, {
        method,
        path,
        parameters: [requiredId()],
      }),
    );
    expect(result.safety).toBe("action");
    expect(result.actionKind).toBe(actionKind);
  });

  test("keeps non-batch GET and HEAD operations read regardless of name", () => {
    for (const method of ["GET", "HEAD"] as const) {
      expect(
        classifyOperation(
          operation("deleteEverything", {
            method,
            path: "/widgets",
          }),
        ),
      ).toEqual({
        safety: "read",
        actionKind: null,
        cardinality: null,
        dangerous: false,
        highRisk: false,
      });
    }
  });

  test("treats batch GET as unknown unbounded action", () => {
    expect(
      classifyOperation(
        operation("listWidgets", { method: "GET", path: "/$batch" }),
      ),
    ).toEqual({
      safety: "action",
      actionKind: "unknown",
      cardinality: { kind: "unbounded" },
      dangerous: true,
      highRisk: true,
    });
  });

  test("derives bounded cardinality only from a linked verified array maxItems", () => {
    const ids = "schema:tiny:#/components/schemas/Ids" as TypedSchemaId;
    const schemas: readonly SchemaRecordV4[] = [
      { id: ids, schema: { type: "array", maxItems: 25 } },
    ];
    const result = classifyOperation(
      operation("updateWidgets", {
        method: "PATCH",
        parameters: [
          {
            ...requiredId("ids"),
            in: "query",
            value: { kind: "schema", schemaId: ids },
          },
        ],
        schemaIds: [ids],
      }),
      schemas,
      { query: { ids: ["widget-1"] } },
    );
    expect(result.cardinality).toEqual({ kind: "bounded", maxAffected: 25 });
    expect(result.highRisk).toBe(false);
  });

  test("does not infer bounded cardinality from an unlinked or invalid maxItems", () => {
    const ids = "schema:tiny:#/components/schemas/Ids" as TypedSchemaId;
    const result = classifyOperation(
      operation("updateWidgets", {
        method: "PATCH",
        parameters: [{ ...requiredId("ids"), in: "query", required: false }],
      }),
      [{ id: ids, schema: { type: "array", maxItems: -1 } }],
    );
    expect(result.cardinality).toEqual({ kind: "unknown" });
    expect(result.highRisk).toBe(true);
  });

  test("treats an omitted optional bounded selector as unknown and high-risk", () => {
    const ids = "schema:tiny:#/components/schemas/Ids" as TypedSchemaId;
    const result = classifyOperation(
      operation("updateWidgets", {
        method: "PATCH",
        parameters: [
          {
            ...requiredId("ids"),
            in: "query",
            required: false,
            value: { kind: "schema", schemaId: ids },
          },
        ],
      }),
      [{ id: ids, schema: { type: "array", maxItems: 25 } }],
      {},
    );
    expect(result.cardinality).toEqual({ kind: "unknown" });
    expect(result.highRisk).toBe(true);
  });

  test("rejects a zero maxItems selector bound as non-concrete", () => {
    const ids = "schema:tiny:#/components/schemas/Ids" as TypedSchemaId;
    const result = classifyOperation(
      operation("updateWidgets", {
        method: "PATCH",
        parameters: [
          {
            ...requiredId("ids"),
            in: "query",
            value: { kind: "schema", schemaId: ids },
          },
        ],
      }),
      [{ id: ids, schema: { type: "array", maxItems: 0 } }],
      { query: { ids: ["widget-1"] } },
    );
    expect(result.cardinality).toEqual({ kind: "unknown" });
    expect(result.highRisk).toBe(true);
  });

  test("does not let a bounded selector mask a supplied unbounded selector", () => {
    const ids = "schema:tiny:#/components/schemas/Ids" as TypedSchemaId;
    const targetIds =
      "schema:tiny:#/components/schemas/TargetIds" as TypedSchemaId;
    const result = classifyOperation(
      operation("updateWidgets", {
        method: "PATCH",
        parameters: [
          {
            ...requiredId("ids"),
            in: "query",
            value: { kind: "schema", schemaId: ids },
          },
          {
            ...requiredId("targetIds"),
            in: "query",
            value: { kind: "schema", schemaId: targetIds },
          },
        ],
      }),
      [
        { id: ids, schema: { type: "array", maxItems: 25 } },
        { id: targetIds, schema: { type: "array" } },
      ],
      { query: { ids: ["widget-1"], targetIds: ["widget-2"] } },
    );
    expect(result.cardinality).toEqual({ kind: "unknown" });
    expect(result.highRisk).toBe(true);
  });

  test("rejects an array selector whose linked schema is not an array", () => {
    const ids = "schema:tiny:#/components/schemas/Ids" as TypedSchemaId;
    const targetIds =
      "schema:tiny:#/components/schemas/TargetIds" as TypedSchemaId;
    const result = classifyOperation(
      operation("updateWidgets", {
        method: "PATCH",
        parameters: [
          {
            ...requiredId("ids"),
            in: "query",
            value: { kind: "schema", schemaId: ids },
          },
          {
            ...requiredId("targetIds"),
            in: "query",
            value: { kind: "schema", schemaId: targetIds },
          },
        ],
      }),
      [
        { id: ids, schema: { type: "array", maxItems: 25 } },
        { id: targetIds, schema: { type: "string" } },
      ],
      { query: { ids: ["widget-1"], targetIds: ["widget-2"] } },
    );
    expect(result.cardinality).toEqual({ kind: "unknown" });
    expect(result.highRisk).toBe(true);
  });

  test("does not let a supplied optional unbounded selector mask a bounded one", () => {
    const ids = "schema:tiny:#/components/schemas/Ids" as TypedSchemaId;
    const targetIds =
      "schema:tiny:#/components/schemas/TargetIds" as TypedSchemaId;
    const result = classifyOperation(
      operation("updateWidgets", {
        method: "PATCH",
        parameters: [
          {
            ...requiredId("ids"),
            in: "query",
            value: { kind: "schema", schemaId: ids },
          },
          {
            ...requiredId("targetIds"),
            in: "query",
            required: false,
            value: { kind: "schema", schemaId: targetIds },
          },
        ],
      }),
      [
        { id: ids, schema: { type: "array", maxItems: 25 } },
        { id: targetIds, schema: { type: "array" } },
      ],
      { query: { ids: ["widget-1"], targetIds: ["widget-2"] } },
    );
    expect(result.cardinality).toEqual({ kind: "unknown" });
    expect(result.highRisk).toBe(true);
  });

  test("bounds a supplied root-array request body with one verified media schema", () => {
    const ids = "schema:tiny:#/components/schemas/Ids" as TypedSchemaId;
    const result = classifyOperation(
      operation("updateWidgets", {
        method: "PATCH",
        requestBody: {
          required: true,
          content: [
            {
              mediaType: "application/json" as never,
              schemaId: ids,
              encoding: [],
            },
          ],
        },
      }),
      [{ id: ids, schema: { type: "array", maxItems: 2 } }],
      { body: ["widget-1"] },
    );
    expect(result.cardinality).toEqual({ kind: "bounded", maxAffected: 2 });
    expect(result.highRisk).toBe(false);
  });

  test.each([
    ["without a body record", null],
    [
      "with ambiguous body media",
      {
        required: true,
        content: [
          {
            mediaType: "application/json" as never,
            schemaId: "schema:tiny:#/components/schemas/Ids" as TypedSchemaId,
            encoding: [],
          },
          {
            mediaType: "application/xml" as never,
            schemaId:
              "schema:tiny:#/components/schemas/OtherIds" as TypedSchemaId,
            encoding: [],
          },
        ],
      },
    ],
  ] as const)("treats a supplied root-array body %s as unproven", (_label, requestBody) => {
    const ids = "schema:tiny:#/components/schemas/Ids" as TypedSchemaId;
    const result = classifyOperation(
      operation("updateWidgets", { method: "PATCH", requestBody }),
      [{ id: ids, schema: { type: "array", maxItems: 2 } }],
      { body: ["widget-1"] },
    );
    expect(result.cardinality).toEqual({ kind: "unknown" });
    expect(result.highRisk).toBe(true);
  });

  test("treats duplicate schema records for a present array selector as ambiguous", () => {
    const ids = "schema:tiny:#/components/schemas/Ids" as TypedSchemaId;
    const result = classifyOperation(
      operation("updateWidgets", {
        method: "PATCH",
        parameters: [
          {
            ...requiredId("ids"),
            in: "query",
            value: { kind: "schema", schemaId: ids },
          },
        ],
      }),
      [
        { id: ids, schema: { type: "array", maxItems: 2 } },
        { id: ids, schema: { type: "array", maxItems: 2 } },
      ],
      { query: { ids: ["widget-1"] } },
    );
    expect(result.cardinality).toEqual({ kind: "unknown" });
    expect(result.highRisk).toBe(true);
  });

  test("uses signed tags but never poisoned advisory tags", () => {
    const result = classifyOperation(
      operation("inspectWidget", {
        method: "POST",
        tags: ["refund"],
        advisory: { tags: ["delete", "execute"] },
      }),
    );
    expect(result.actionKind).toBe("transaction");
    expect(result.cardinality).toEqual({ kind: "unknown" });
    expect(result.highRisk).toBe(true);
  });

  test("fails closed when later dangerous path evidence is beyond the token bound", () => {
    const filler = Array.from({ length: 64 }, () => "filler").join("/");
    const result = classifyOperation(
      operation("createWidget", {
        method: "POST",
        path: `/widgets/${filler}/refund`,
        parameters: [requiredId()],
      }),
    );
    expect(result).toEqual({
      safety: "action",
      actionKind: "unknown",
      cardinality: { kind: "unknown" },
      dangerous: true,
      highRisk: true,
    });
  });

  test("scans a dangerous signed tag at its independent token boundary", () => {
    const tag = [...Array.from({ length: 47 }, () => "filler"), "refund"].join(
      " ",
    );
    const result = classifyOperation(
      operation("inspectWidget", {
        method: "POST",
        tags: [tag],
        parameters: [requiredId()],
      }),
    );
    expect(result).toEqual({
      safety: "action",
      actionKind: "transaction",
      cardinality: { kind: "single" },
      dangerous: true,
      highRisk: true,
    });
  });

  test("fails closed on conflicting signed action evidence", () => {
    const result = classifyOperation(
      operation("createWidget", {
        method: "POST",
        tags: ["refund", "run"],
        parameters: [requiredId()],
      }),
    );
    expect(result).toEqual({
      safety: "action",
      actionKind: "unknown",
      cardinality: { kind: "single" },
      dangerous: true,
      highRisk: true,
    });
  });

  test("does not mistake an arbitrary path parameter ending in id for a resource identifier", () => {
    const result = classifyOperation(
      operation("updateWidget", {
        method: "PATCH",
        parameters: [{ ...requiredId("grid"), name: "grid" }],
      }),
    );
    expect(result.cardinality).toEqual({ kind: "unknown" });
    expect(result.highRisk).toBe(true);
  });

  test("gives explicit bulk semantics precedence over an identifier", () => {
    const result = classifyOperation(
      operation("deleteAllWidgets", {
        method: "DELETE",
        path: "/widgets/all/{widgetId}",
        parameters: [requiredId()],
      }),
    );
    expect(result.cardinality).toEqual({ kind: "unbounded" });
    expect(result.highRisk).toBe(true);
  });
});
