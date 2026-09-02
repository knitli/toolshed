import { describe, expect, test } from "bun:test";
import { loadSpec } from "../src/load";
import { extractOperations } from "../src/operations";
import {
  applyPermissions,
  buildPermissionIndex,
  lookupPermissions,
  type PermissionsDataset,
} from "../src/permissions";

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
    expect(list?.privilegeLevel).toBe(2);
    expect(list?.risk).toBe("routine");

    const create = ops.find((o) => o.qualifiedId === "tiny:widgets.CreateWidget");
    expect(create?.privilegeLevel).toBe(5);
    expect(create?.risk).toBe("high");
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
