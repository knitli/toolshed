import { describe, expect, test } from "bun:test";
import { classifySafety, isBatch, riskFor } from "../src/safety";

describe("classifySafety", () => {
  test("GET and HEAD are reads", () => {
    expect(classifySafety("GET", "/widgets", "widgets.ListWidgets")).toBe("read");
    expect(classifySafety("HEAD", "/widgets", "widgets.Head")).toBe("read");
  });

  test("method matching is case-insensitive", () => {
    expect(classifySafety("get", "/widgets", "widgets.Do")).toBe("read");
  });

  test("POST, PATCH, PUT, DELETE are writes", () => {
    for (const m of ["POST", "PATCH", "PUT", "DELETE"]) {
      expect(classifySafety(m, "/widgets", "widgets.Do")).toBe("write");
    }
  });

  test("overrides reclassify semantically-read POSTs", () => {
    expect(classifySafety("POST", "/widgets/getByIds", "widgets.getByIds")).toBe("read");
    expect(
      classifySafety("POST", "/users/{id}/getMemberGroups", "users.user.getMemberGroups"),
    ).toBe("read");
    expect(
      classifySafety("POST", "/users/{id}/checkMemberObjects", "users.user.checkMemberObjects"),
    ).toBe("read");
  });

  test("overrides match a dotless operationId as its own tail", () => {
    expect(classifySafety("POST", "/x/getByIds", "getByIds")).toBe("read");
  });

  test("$batch is a write even though overrides might match", () => {
    expect(classifySafety("POST", "/$batch", "batch.Batch")).toBe("write");
    expect(isBatch("/$batch")).toBe(true);
    expect(classifySafety("POST", "/$batch", "widgets.getByIds")).toBe("write");
  });

  test("$batch is hard-pinned to write even on a GET", () => {
    // A GET would normally short-circuit to "read" before the batch check
    // ever runs — $batch must win regardless of method.
    expect(classifySafety("GET", "/$batch", "batch.Batch")).toBe("write");
  });

  test("overrides never promote a GET to a write", () => {
    expect(classifySafety("GET", "/widgets/getByIds", "widgets.getByIds")).toBe("read");
  });
});

describe("riskFor", () => {
  test("reads are always routine", () => {
    expect(riskFor("read", 5, "/widgets")).toBe("routine");
  });

  test("low privilege writes are routine", () => {
    expect(riskFor("write", 1, "/widgets")).toBe("routine");
    expect(riskFor("write", 3, "/widgets")).toBe("routine");
  });

  test("high privilege writes are high", () => {
    expect(riskFor("write", 4, "/widgets")).toBe("high");
    expect(riskFor("write", 5, "/widgets")).toBe("high");
  });

  test("unknown privilege defaults to high", () => {
    expect(riskFor("write", null, "/widgets")).toBe("high");
  });

  test("$batch is always high regardless of privilege", () => {
    expect(riskFor("write", 1, "/$batch")).toBe("high");
  });

  test("$batch is high risk even if safety is (incorrectly) read", () => {
    // safety="read" would normally short-circuit to "routine" before the
    // batch check ever runs — a batch path can never be routine.
    expect(riskFor("read", 1, "/$batch")).toBe("high");
  });
});
