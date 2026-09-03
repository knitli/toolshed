import { describe, expect, test } from "bun:test";
import { loadSpec } from "../src/load.ts";
import { extractOperations } from "../src/operations.ts";
import {
  applyPermissions,
  buildPermissionIndex,
  lookupPermissions,
  type PermissionsDataset,
} from "../src/permissions.ts";

const dataset = (await Bun.file(
  `${import.meta.dir}/../fixtures/tiny-permissions.json`,
).json()) as PermissionsDataset;
const index = buildPermissionIndex(dataset);

describe("lookupPermissions", () => {
  test("matches an exact path", () => {
    const m = lookupPermissions(index, "/widgets", "GET");
    expect(m?.confidence).toBe("exact");
    expect(m?.permissions).toEqual(["Widget.Read"]);
    expect(m?.privilegeLevel).toBe(2);
  });

  test("normalises differing parameter names", () => {
    const m = lookupPermissions(index, "/widgets/{widget-id}", "GET");
    expect(m?.confidence).toBe("exact");
  });

  test("strips OData suffixes", () => {
    const m = lookupPermissions(index, "/widgets/$count", "GET");
    expect(m?.confidence).toBe("suffix");
    expect(m?.permissions).toEqual(["Widget.Read"]);
  });

  test("falls back to longest-prefix inheritance", () => {
    const m = lookupPermissions(index, "/widgets/{id}/parts/{part-id}", "GET");
    expect(m?.confidence).toBe("prefix");
  });

  test("longest prefix wins over a shorter one when both exist", () => {
    // Both depths carry a different permission at a different privilege
    // level, so picking the wrong one is observable.
    const depthDataset: PermissionsDataset = {
      permissions: {
        "Foo.Read": {
          schemes: { DelegatedWork: { privilegeLevel: 1 } },
          pathSets: [{ methods: ["GET"], paths: { "/foo": {} } }],
        },
        "Foo.Bar.ReadWrite": {
          schemes: { DelegatedWork: { privilegeLevel: 8 } },
          pathSets: [{ methods: ["GET"], paths: { "/foo/bar": {} } }],
        },
      },
    };
    const depthIndex = buildPermissionIndex(depthDataset);
    const m = lookupPermissions(depthIndex, "/foo/bar/baz", "GET");
    expect(m?.permissions).toEqual(["Foo.Bar.ReadWrite"]);
    expect(m?.privilegeLevel).toBe(8);
  });

  test("returns null when nothing matches", () => {
    expect(lookupPermissions(index, "/gadgets", "GET")).toBeNull();
  });

  test("is method-scoped", () => {
    expect(lookupPermissions(index, "/widgets", "PATCH")).toBeNull();
  });

  test("takes the highest privilege level when several permissions match", () => {
    const m = lookupPermissions(index, "/widgets", "POST");
    expect(m?.privilegeLevel).toBe(5);
  });

  test("resolves the true maximum privilege when two permissions overlap on the same path and method, not the alphabetically-first one", () => {
    // "AAA.Low" sorts before "ZZZ.High" but has the lower privilege level.
    // A naive `levels[0]` after sorting `permissions` would wrongly return 1.
    const overlapDataset: PermissionsDataset = {
      permissions: {
        "AAA.Low": {
          schemes: { DelegatedWork: { privilegeLevel: 1 } },
          pathSets: [{ methods: ["GET"], paths: { "/overlap": {} } }],
        },
        "ZZZ.High": {
          schemes: { DelegatedWork: { privilegeLevel: 9 } },
          pathSets: [{ methods: ["GET"], paths: { "/overlap": {} } }],
        },
      },
    };
    const overlapIndex = buildPermissionIndex(overlapDataset);
    const m = lookupPermissions(overlapIndex, "/overlap", "GET");
    expect(m?.permissions).toEqual(["AAA.Low", "ZZZ.High"]);
    expect(m?.privilegeLevel).toBe(9);
  });
});

describe("applyPermissions", () => {
  test("annotates records and recomputes risk", async () => {
    const ops = extractOperations(
      await loadSpec(`${import.meta.dir}/../fixtures/tiny-api.yaml`),
      "tiny",
    );
    applyPermissions(ops, index);

    const list = ops.find((o) => o.qualifiedId === "tiny:widgets.ListWidgets");
    expect(list?.permissions).toEqual(["Widget.Read"]);
    expect(list?.permConfidence).toBe("exact");
    expect(list?.privilegeLevel).toBe(2);
    expect(list?.risk).toBe("routine");

    const create = ops.find((o) => o.qualifiedId === "tiny:widgets.CreateWidget");
    expect(create?.privilegeLevel).toBe(5);
    expect(create?.risk).toBe("high");

    // Exact match beats the prefix fallback, and the low privilege level it
    // resolves to must actually flip risk from its pre-mapping "high".
    const del = ops.find(
      (o) => o.qualifiedId === "tiny:widgets.widget.DeleteWidget",
    );
    expect(del?.permissions).toEqual(["Widget.ReadWrite.Own"]);
    expect(del?.permConfidence).toBe("exact");
    expect(del?.privilegeLevel).toBe(1);
    expect(del?.risk).toBe("routine");
  });

  test("unmapped write operations stay high risk", async () => {
    const ops = extractOperations(
      await loadSpec(`${import.meta.dir}/../fixtures/tiny-api.yaml`),
      "tiny",
    );
    applyPermissions(ops, index);
    const batch = ops.find((o) => o.qualifiedId === "tiny:batch.Batch");
    expect(batch?.permissions).toBeNull();
    expect(batch?.risk).toBe("high");
  });
});
