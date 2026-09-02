import { describe, expect, test } from "bun:test";
import { buildScopeRouting } from "./scopes.mts";

describe("buildScopeRouting", () => {
  test("includes plugin names and marketplace", () => {
    const { allScopes } = buildScopeRouting(["ctx"], undefined);
    expect(allScopes).toEqual(["ctx", "marketplace"]);
  });

  test("includes extra non-plugin scopes", () => {
    const { allScopes } = buildScopeRouting(["ctx"], undefined, ["openapi-mcp"]);
    expect(allScopes).toContain("openapi-mcp");
  });

  test("extra scopes accept aliases", () => {
    const { allScopes, aliasesByScope } = buildScopeRouting(
      ["ctx"],
      { "openapi-mcp": ["oam"] },
      ["openapi-mcp"],
    );
    expect(aliasesByScope["openapi-mcp"]).toEqual(["oam"]);
    expect(allScopes).toContain("oam");
  });

  test("rejects an extra scope colliding with a plugin name", () => {
    expect(() => buildScopeRouting(["ctx"], undefined, ["ctx"])).toThrow(
      /collides/,
    );
  });

  test("rejects an alias colliding with a canonical scope", () => {
    expect(() =>
      buildScopeRouting(["ctx"], { marketplace: ["ctx"] }),
    ).toThrow(/collides/);
  });
});
