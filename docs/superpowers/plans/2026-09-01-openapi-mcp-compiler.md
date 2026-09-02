# OpenAPI → MCP Compiler Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a CLI that compiles any OpenAPI document into a signed SQLite artifact holding one thin row per operation, an fts5 search index, and an unresolved schema store.

**Architecture:** A build-time Bun program. It parses an OpenAPI document with `Bun.YAML.parse`, extracts one thin record per operation with `$ref`s left unresolved, classifies each operation's safety and risk, maps operations to upstream permissions where a dataset is available, and writes everything to a SQLite file signed with Ed25519. Nothing here runs at request time; the server (a later plan) only reads the artifact.

**Tech Stack:** Bun 1.4 (`Bun.YAML`, `bun:sqlite` with fts5/bm25, `bun test`), TypeScript strict, Biome, Ed25519 via `node:crypto`. No runtime dependencies.

**Spec:** `docs/superpowers/specs/2026-09-01-openapi-mcp-engine-design.md` (revision 2)


## As-built deltas

This plan was executed; the code is in `packages/openapi-mcp`. Five things the
shipped compiler does differently, recorded here so nobody implements the plan's
version of them a second time:

- **Append validation runs inside the transaction, and `ROLLBACK` is guarded.**
  Task 12's snippet validates `format_version` and duplicate mounts before
  `BEGIN` while keeping Task 8's unconditional rollback, which throws
  `cannot rollback - no transaction is active` and masks the real diagnostic.
  Shipped: `BEGIN` first, rollback wrapped in its own try.
- **Read overrides are keyed by API.** `READ_OVERRIDE_SUFFIXES` as planned was a
  flat list applied to every mount, so a second API's genuinely mutating
  `POST .../query` would classify as `read`. Shipped as `READ_OVERRIDES`, a
  `Record<api, suffixes>`; an unlisted API gets none.
- **Request bodies keep inline schemas and their media type.** The planned
  `bodyRefOf` stored only a direct `application/json` `$ref` and silently
  dropped everything else. Shipped with `body_schema` and `body_media_type`
  columns beside `body_ref` (FORMAT_VERSION 2).
- **Path-item and operation parameters merge on `(name, in)`**, operation
  winning, rather than concatenating into two conflicting entries.
- **A fresh compile builds into a `.building` sibling and renames on success**
  rather than unlinking the target first.

## Global Constraints

- Runtime is **Bun 1.4.0**; Node 24 is the declared floor in `mise.toml`. Use `bun test`, not vitest or jest.
- **No new runtime dependencies.** YAML parsing is `Bun.YAML.parse`; SQLite is `bun:sqlite`; signing is `node:crypto`.
- TypeScript is **strict** with `verbatimModuleSyntax` — type-only imports must use `import type`.
- Biome formats: **double quotes, 2-space indent, trailing newline.** Run `bunx biome check --write` before every commit.
- Commit convention is `type(scope): message`; **scope is mandatory** and validated by commitlint. This plan's scope is `openapi-mcp`, which does not exist yet — **Task 1 creates it and must land first or no other commit in this plan can be made.**
- `fts5` must be lower-case in SQL. D1 rejects `FTS5` as "not authorized", and the artifact must load on both hosts.
- Never dereference `$ref`s at compile time. Measured at ≥342 MB for Graph; per-`$ref`-hop resolution did not terminate.
- Artifacts are untrusted input to the server. The compiler writes `safety`, but the server recomputes it — do not treat the compiler as the security boundary.

---

## File Structure

```
scripts/lib/scopes.mts          NEW  — extracted scope routing, now supports non-plugin scopes
scripts/generate.mts            MOD  — imports scopes.mts instead of defining routing inline
.claude-plugin/marketplace.json MOD  — gains shared.extraScopes

packages/openapi-mcp/
  package.json                  NEW  — private workspace package
  tsconfig.json                 NEW  — extends root, bundler resolution
  src/
    types.ts                    NEW  — shared record types, no logic
    schema.ts                   NEW  — SQLite DDL, createSchema(db)
    load.ts                     NEW  — loadSpec(path): YAML or JSON
    operations.ts               NEW  — extractOperations(doc, api)
    safety.ts                   NEW  — classifySafety() + READ_OVERRIDES
    permissions.ts              NEW  — permission index + three-strategy lookup
    schemas.ts                  NEW  — extractSchemas(), unresolved
    compile.ts                  NEW  — orchestration, writes the artifact
    sign.ts                     NEW  — Ed25519 sign/verify over the file bytes
    cli.ts                      NEW  — argument parsing, entry point
  tests/
    scopes.test.ts              NEW
    schema.test.ts              NEW
    load.test.ts                NEW
    operations.test.ts          NEW
    safety.test.ts              NEW
    permissions.test.ts         NEW
    schemas.test.ts             NEW
    compile.test.ts             NEW
    sign.test.ts                NEW
    cli.test.ts                 NEW
    graph-invariants.test.ts    NEW  — opt-in, runs against the real 42 MB spec
  fixtures/
    tiny-api.yaml               NEW  — 6-operation fixture exercising every branch
    tiny-permissions.json       NEW  — matching permissions dataset
```

Files split by responsibility, not layer: each `src/*.ts` owns one transformation and is testable without the others. `compile.ts` is the only file that knows the order they run in.

---

### Task 1: Commit scopes for non-plugin workspaces

**Why first:** `scripts/generate.mts` derives commitlint's `scope-enum` solely from the `plugins` array, and every entry must resolve to a directory containing `.claude-plugin/plugin.json`. `packages/openapi-mcp` is not a plugin, so `feat(openapi-mcp): …` is currently rejected by the PR gate. Until this lands, no other task in this plan can be committed.

**Files:**
- Create: `scripts/lib/scopes.mts`
- Create: `packages/openapi-mcp/tests/scopes.test.ts`
- Modify: `scripts/generate.mts` (delete the inline `buildScopeRouting`, import instead)
- Modify: `.claude-plugin/marketplace.json` (add `shared.extraScopes`)

**Interfaces:**
- Consumes: nothing.
- Produces: `buildScopeRouting(pluginNames: string[], rawAliases: Record<string, unknown> | undefined, extraScopes?: string[]): { aliasesByScope: Record<string, string[]>; allScopes: string[] }`

- [ ] **Step 1: Write the failing test**

Create `packages/openapi-mcp/tests/scopes.test.ts`:

```ts
import { describe, expect, test } from "bun:test";
import { buildScopeRouting } from "../../../scripts/lib/scopes.mts";

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test packages/openapi-mcp/tests/scopes.test.ts`
Expected: FAIL — cannot resolve `../../../scripts/lib/scopes.mts`.

- [ ] **Step 3: Write the implementation**

Create `scripts/lib/scopes.mts`. This is the existing `buildScopeRouting` from `generate.mts` with two changes: it accepts `extraScopes`, and it **throws** instead of calling `process.exit(1)` so it is testable.

```ts
/**
 * Validate shared.scopeAliases and materialize a routing table.
 *
 * Canonical scopes are plugin names, any extra non-plugin workspace scopes,
 * and "marketplace". Extra scopes appear in commitlint's scope-enum but get
 * no release config — they are not plugins.
 */
export function buildScopeRouting(
  pluginNames: string[],
  rawAliases: Record<string, unknown> | undefined,
  extraScopes: string[] = [],
): { aliasesByScope: Record<string, string[]>; allScopes: string[] } {
  const pluginSet = new Set(pluginNames);
  for (const extra of extraScopes) {
    if (pluginSet.has(extra) || extra === "marketplace") {
      throw new Error(
        `ERROR: extraScope "${extra}" collides with a plugin name or "marketplace".`,
      );
    }
  }

  const canonicals = [...pluginNames, ...extraScopes, "marketplace"];
  const canonicalSet = new Set(canonicals);
  const aliasesByScope: Record<string, string[]> = Object.fromEntries(
    canonicals.map((c) => [c, [] as string[]]),
  );
  const seenAliases: string[] = [];
  const seenAliasSet = new Set<string>();

  if (rawAliases !== undefined && rawAliases !== null) {
    if (typeof rawAliases !== "object" || Array.isArray(rawAliases)) {
      throw new Error("ERROR: shared.scopeAliases must be an object.");
    }
    for (const [canonical, aliases] of Object.entries(rawAliases)) {
      if (!canonicalSet.has(canonical)) {
        throw new Error(
          `ERROR: shared.scopeAliases key "${canonical}" is not a canonical scope. ` +
            `Expected one of: ${canonicals.join(", ")}.`,
        );
      }
      if (!Array.isArray(aliases)) {
        throw new Error(
          `ERROR: shared.scopeAliases["${canonical}"] must be an array of strings.`,
        );
      }
      for (const alias of aliases) {
        if (typeof alias !== "string" || alias.length === 0) {
          throw new Error(
            `ERROR: shared.scopeAliases["${canonical}"] contains an invalid alias.`,
          );
        }
        if (canonicalSet.has(alias)) {
          throw new Error(
            `ERROR: alias "${alias}" (under "${canonical}") collides with a canonical scope name.`,
          );
        }
        if (seenAliasSet.has(alias)) {
          throw new Error(
            `ERROR: alias "${alias}" is defined more than once in shared.scopeAliases.`,
          );
        }
        seenAliasSet.add(alias);
        seenAliases.push(alias);
        aliasesByScope[canonical].push(alias);
      }
    }
  }

  return { aliasesByScope, allScopes: [...canonicals, ...seenAliases] };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test packages/openapi-mcp/tests/scopes.test.ts`
Expected: PASS, 5 tests.

- [ ] **Step 5: Wire it into generate.mts**

In `scripts/generate.mts`, delete the entire inline `buildScopeRouting` function body and replace it with an import at the top of the file:

```ts
import { buildScopeRouting } from "./lib/scopes.mts";
```

Then change the call site so it reads `shared.extraScopes` and converts a thrown error into the script's existing exit behavior:

```ts
let aliasesByScope: Record<string, string[]>;
let allScopes: string[];
try {
  ({ aliasesByScope, allScopes } = buildScopeRouting(
    pluginNames,
    shared.scopeAliases,
    shared.extraScopes ?? [],
  ));
} catch (err) {
  console.error((err as Error).message);
  process.exit(1);
}
```

- [ ] **Step 6: Declare the scope in the manifest**

In `.claude-plugin/marketplace.json`, add `extraScopes` inside `shared`, immediately after `scopeAliases`:

```json
"extraScopes": ["openapi-mcp"]
```

- [ ] **Step 7: Regenerate and verify the scope is live**

Run:
```bash
bun run generate
bun run validate
grep -o '"openapi-mcp"' .commitlintrc.json
```
Expected: validate passes, and `grep` prints `"openapi-mcp"` — proving commitlint will now accept the scope. Confirm `.github/workflows/release.yml`'s matrix is **unchanged** (extra scopes get no release job).

- [ ] **Step 8: Commit**

```bash
bunx biome check --write scripts/ packages/
git add scripts/lib/scopes.mts scripts/generate.mts .claude-plugin/marketplace.json .commitlintrc.json packages/openapi-mcp/tests/scopes.test.ts
git commit -m "feat(marketplace): support commit scopes for non-plugin workspaces"
```

---

### Task 2: Package scaffold and SQLite schema

**Files:**
- Create: `packages/openapi-mcp/package.json`
- Create: `packages/openapi-mcp/tsconfig.json`
- Create: `packages/openapi-mcp/src/types.ts`
- Create: `packages/openapi-mcp/src/schema.ts`
- Create: `packages/openapi-mcp/tests/schema.test.ts`
- Modify: `package.json` (root) — add `packages/*` to workspaces

**Interfaces:**
- Consumes: nothing.
- Produces: `createSchema(db: Database): void`, `FORMAT_VERSION: number`, and the record types `OperationRecord`, `SchemaRecord`, `Safety`, `Risk`, `PermConfidence`.

- [ ] **Step 1: Write the failing test**

Create `packages/openapi-mcp/tests/schema.test.ts`:

```ts
import { Database } from "bun:sqlite";
import { describe, expect, test } from "bun:test";
import { createSchema, FORMAT_VERSION } from "../src/schema";

describe("createSchema", () => {
  test("creates every table the artifact needs", () => {
    const db = new Database(":memory:");
    createSchema(db);
    const names = db
      .query<{ name: string }, []>(
        "SELECT name FROM sqlite_master WHERE type IN ('table','view') ORDER BY name",
      )
      .all()
      .map((r) => r.name);
    expect(names).toContain("operations");
    expect(names).toContain("operations_fts");
    expect(names).toContain("schemas");
    expect(names).toContain("meta");
  });

  test("fts5 index supports bm25 ranking", () => {
    const db = new Database(":memory:");
    createSchema(db);
    db.run(
      `INSERT INTO operations
       (qualified_id, api, operation_id, method, path, safety, risk,
        pageable, deprecated, params_json, server_url)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
      "g:users.ListMessages", "g", "users.ListMessages", "GET",
      "/users/{id}/messages", "read", "routine", 0, 0, "[]",
      "https://graph.microsoft.com",
    );
    db.run(
      `INSERT INTO operations_fts (rowid, qualified_id, operation_id, summary, path, tags, api)
       SELECT rowid, qualified_id, operation_id, summary, path, tags, api FROM operations`,
    );
    const hits = db
      .query<{ qualified_id: string }, [string]>(
        `SELECT o.qualified_id FROM operations_fts f
         JOIN operations o ON o.rowid = f.rowid
         WHERE operations_fts MATCH ? ORDER BY bm25(operations_fts)`,
      )
      .all("messages");
    expect(hits.map((h) => h.qualified_id)).toEqual(["g:users.ListMessages"]);
  });

  test("rejects a duplicate qualified_id", () => {
    const db = new Database(":memory:");
    createSchema(db);
    const insert = () =>
      db.run(
        `INSERT INTO operations
         (qualified_id, api, operation_id, method, path, safety, risk,
          pageable, deprecated, params_json, server_url)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
        "g:dup", "g", "dup", "GET", "/dup", "read", "routine", 0, 0, "[]", "https://x",
      );
    insert();
    expect(insert).toThrow();
  });

  test("FORMAT_VERSION is a positive integer", () => {
    expect(Number.isInteger(FORMAT_VERSION)).toBe(true);
    expect(FORMAT_VERSION).toBeGreaterThan(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test packages/openapi-mcp/tests/schema.test.ts`
Expected: FAIL — cannot resolve `../src/schema`.

- [ ] **Step 3: Create the package files**

`packages/openapi-mcp/package.json`:

```json
{
  "name": "@knitli/openapi-mcp",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "description": "Compiles OpenAPI documents into signed SQLite artifacts for MCP serving.",
  "license": "MIT OR Apache-2.0",
  "bin": { "openapi-mcp": "./src/cli.ts" },
  "scripts": {
    "test": "bun test",
    "check": "bunx biome check ."
  }
}
```

`packages/openapi-mcp/tsconfig.json`:

```json
{
  "extends": "../../tsconfig.json",
  "compilerOptions": {
    "module": "preserve",
    "moduleResolution": "bundler",
    "types": ["bun"],
    "noEmit": true
  },
  "include": ["src/**/*.ts", "tests/**/*.ts"]
}
```

`packages/openapi-mcp/src/types.ts`:

```ts
export type Safety = "read" | "write";
export type Risk = "routine" | "high";
export type PermConfidence = "exact" | "suffix" | "prefix";

export interface OperationRecord {
  qualifiedId: string;
  api: string;
  operationId: string;
  method: string;
  path: string;
  safety: Safety;
  risk: Risk;
  operationType: string | null;
  pageable: boolean;
  deprecated: boolean;
  permissions: string[] | null;
  permConfidence: PermConfidence | null;
  privilegeLevel: number | null;
  summary: string | null;
  tags: string | null;
  paramsJson: string;
  bodyRef: string | null;
  serverUrl: string;
}

export interface SchemaRecord {
  api: string;
  name: string;
  json: string;
}
```

- [ ] **Step 4: Write the schema module**

`packages/openapi-mcp/src/schema.ts`:

```ts
import type { Database } from "bun:sqlite";

/** Bumped when the artifact layout changes incompatibly. Servers refuse unknown versions. */
export const FORMAT_VERSION = 1;

// `fts5` MUST be lower-case: D1 rejects `FTS5` as "not authorized".
const DDL = `
CREATE TABLE operations (
  qualified_id    TEXT PRIMARY KEY,
  api             TEXT NOT NULL,
  operation_id    TEXT NOT NULL,
  method          TEXT NOT NULL,
  path            TEXT NOT NULL,
  safety          TEXT NOT NULL CHECK (safety IN ('read','write')),
  risk            TEXT NOT NULL CHECK (risk IN ('routine','high')),
  operation_type  TEXT,
  pageable        INTEGER NOT NULL DEFAULT 0,
  deprecated      INTEGER NOT NULL DEFAULT 0,
  permissions     TEXT,
  perm_confidence TEXT,
  privilege_level INTEGER,
  summary         TEXT,
  tags            TEXT,
  params_json     TEXT NOT NULL,
  body_ref        TEXT,
  server_url      TEXT NOT NULL
);

CREATE INDEX operations_api ON operations (api);
CREATE INDEX operations_safety ON operations (api, safety, risk);

CREATE VIRTUAL TABLE operations_fts USING fts5(
  qualified_id, operation_id, summary, path, tags, api,
  content='operations', content_rowid='rowid'
);

CREATE TABLE schemas (
  api  TEXT NOT NULL,
  name TEXT NOT NULL,
  json TEXT NOT NULL,
  PRIMARY KEY (api, name)
);

CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`;

/** Creates every table, index, and virtual table the artifact needs. */
export function createSchema(db: Database): void {
  db.run(DDL);
}
```

- [ ] **Step 5: Register the workspace**

In root `package.json`, change `workspaces.packages` from `["plugins/*"]` to:

```json
"packages": ["plugins/*", "packages/*"]
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `bun install && bun test packages/openapi-mcp/tests/schema.test.ts`
Expected: PASS, 4 tests.

- [ ] **Step 7: Commit**

```bash
bunx biome check --write packages/ package.json
git add packages/openapi-mcp package.json bun.lock
git commit -m "feat(openapi-mcp): add package scaffold and SQLite artifact schema"
```

---

### Task 3: Spec loading

**Files:**
- Create: `packages/openapi-mcp/src/load.ts`
- Create: `packages/openapi-mcp/fixtures/tiny-api.yaml`
- Create: `packages/openapi-mcp/tests/load.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `loadSpec(path: string): Promise<OpenApiDoc>` and the `OpenApiDoc`, `OpenApiOperation` types.

- [ ] **Step 1: Write the fixture**

Create `packages/openapi-mcp/fixtures/tiny-api.yaml`. Every branch the compiler has is exercised here: a plain GET, a pageable GET, a mutating POST, a POST that is semantically a read, a `$batch`, and a deprecated operation.

```yaml
openapi: 3.0.4
info:
  title: Tiny API
  version: v1
servers:
  - url: https://tiny.example.com
paths:
  /widgets:
    get:
      operationId: widgets.ListWidgets
      summary: List widgets
      tags: [widgets]
      x-ms-pageable:
        nextLinkName: "@odata.nextLink"
      responses:
        "200": { description: ok }
    post:
      operationId: widgets.CreateWidget
      summary: Create a widget
      tags: [widgets]
      requestBody:
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/Widget"
      responses:
        "201": { description: created }
  /widgets/{widget-id}:
    get:
      operationId: widgets.widget.GetWidget
      summary: Get a widget
      tags: [widgets]
      parameters:
        - name: widget-id
          in: path
          required: true
          schema: { type: string }
      responses:
        "200": { description: ok }
    delete:
      operationId: widgets.widget.DeleteWidget
      summary: Delete a widget
      tags: [widgets]
      deprecated: true
      parameters:
        - name: widget-id
          in: path
          required: true
          schema: { type: string }
      responses:
        "204": { description: gone }
  /widgets/getByIds:
    post:
      operationId: widgets.getByIds
      summary: Look up widgets by id
      tags: [widgets]
      responses:
        "200": { description: ok }
  /$batch:
    post:
      operationId: batch.Batch
      summary: Send a batch of requests
      tags: [batch]
      responses:
        "200": { description: ok }
components:
  schemas:
    Widget:
      type: object
      properties:
        id: { type: string }
        owner: { $ref: "#/components/schemas/Owner" }
    Owner:
      type: object
      properties:
        name: { type: string }
```

- [ ] **Step 2: Write the failing test**

Create `packages/openapi-mcp/tests/load.test.ts`:

```ts
import { describe, expect, test } from "bun:test";
import { loadSpec } from "../src/load";

const FIXTURE = `${import.meta.dir}/../fixtures/tiny-api.yaml`;

describe("loadSpec", () => {
  test("parses YAML", async () => {
    const doc = await loadSpec(FIXTURE);
    expect(doc.openapi).toBe("3.0.4");
    expect(Object.keys(doc.paths)).toHaveLength(4);
  });

  test("parses JSON with the same result", async () => {
    const yaml = await loadSpec(FIXTURE);
    const jsonPath = `${import.meta.dir}/tmp-load.json`;
    await Bun.write(jsonPath, JSON.stringify(yaml));
    const json = await loadSpec(jsonPath);
    expect(json).toEqual(yaml);
  });

  test("rejects a document with no paths", async () => {
    const bad = `${import.meta.dir}/tmp-bad.json`;
    await Bun.write(bad, JSON.stringify({ openapi: "3.0.4" }));
    expect(loadSpec(bad)).rejects.toThrow(/paths/);
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `bun test packages/openapi-mcp/tests/load.test.ts`
Expected: FAIL — cannot resolve `../src/load`.

- [ ] **Step 4: Write the implementation**

`packages/openapi-mcp/src/load.ts`:

```ts
export interface OpenApiOperation {
  operationId?: string;
  summary?: string;
  description?: string;
  tags?: string[];
  deprecated?: boolean;
  parameters?: unknown[];
  requestBody?: unknown;
  [key: string]: unknown;
}

export interface OpenApiDoc {
  openapi: string;
  servers?: Array<{ url: string }>;
  paths: Record<string, Record<string, OpenApiOperation>>;
  components?: {
    schemas?: Record<string, unknown>;
    parameters?: Record<string, unknown>;
    responses?: Record<string, unknown>;
  };
  [key: string]: unknown;
}

/**
 * Reads an OpenAPI 3.x document from disk. YAML is parsed with Bun's native
 * parser, which handles the 44 MB Microsoft Graph document in well under a
 * second — do not add a JS YAML dependency.
 */
export async function loadSpec(path: string): Promise<OpenApiDoc> {
  const text = await Bun.file(path).text();
  const doc = (
    path.endsWith(".json") ? JSON.parse(text) : Bun.YAML.parse(text)
  ) as OpenApiDoc;

  if (!doc || typeof doc !== "object" || typeof doc.paths !== "object") {
    throw new Error(`${path}: not an OpenAPI document (no "paths" object)`);
  }
  return doc;
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `bun test packages/openapi-mcp/tests/load.test.ts`
Expected: PASS, 3 tests.

- [ ] **Step 6: Commit**

```bash
rm -f packages/openapi-mcp/tests/tmp-load.json packages/openapi-mcp/tests/tmp-bad.json
bunx biome check --write packages/
git add packages/openapi-mcp
git commit -m "feat(openapi-mcp): load OpenAPI documents from YAML or JSON"
```

---

### Task 4: Safety classification

**Files:**
- Create: `packages/openapi-mcp/src/safety.ts`
- Create: `packages/openapi-mcp/tests/safety.test.ts`

**Interfaces:**
- Consumes: `Safety`, `Risk` from `src/types.ts`.
- Produces: `classifySafety(method: string, path: string, operationId: string): Safety`, `riskFor(safety: Safety, privilegeLevel: number | null, path: string): Risk`, `READ_OVERRIDE_SUFFIXES: readonly string[]`, `isBatch(path: string): boolean`.

**Why this is not just "method === GET":** 53 Microsoft Graph operations are POSTs that are semantically reads (`getByIds`, `getMemberGroups`, `checkMemberObjects`). OData's own taxonomy does not help — `x-ms-docs-operation-type: function` is exclusively GET and `action` exclusively POST, so it agrees with the method rather than correcting it. The override list is therefore explicit and lives in engine code, because the server must be able to recompute it without trusting the artifact.

- [ ] **Step 1: Write the failing test**

Create `packages/openapi-mcp/tests/safety.test.ts`:

```ts
import { describe, expect, test } from "bun:test";
import { classifySafety, isBatch, riskFor } from "../src/safety";

describe("classifySafety", () => {
  test("GET and HEAD are reads", () => {
    expect(classifySafety("GET", "/widgets", "widgets.ListWidgets")).toBe("read");
    expect(classifySafety("HEAD", "/widgets", "widgets.Head")).toBe("read");
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

  test("$batch is a write even though overrides might match", () => {
    expect(classifySafety("POST", "/$batch", "batch.Batch")).toBe("write");
    expect(isBatch("/$batch")).toBe(true);
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
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test packages/openapi-mcp/tests/safety.test.ts`
Expected: FAIL — cannot resolve `../src/safety`.

- [ ] **Step 3: Write the implementation**

`packages/openapi-mcp/src/safety.ts`:

```ts
import type { Risk, Safety } from "./types";

const READ_METHODS = new Set(["GET", "HEAD"]);

/**
 * Operation-id suffixes that are POSTs by protocol but reads by semantics.
 * Derived from Microsoft Graph, where 53 operations match. This list is
 * engine code, not artifact data: the server recomputes safety at load and
 * honours a stored `read` on a mutating method only if it also appears here.
 */
export const READ_OVERRIDE_SUFFIXES = [
  "getByIds",
  "getMemberGroups",
  "getMemberObjects",
  "checkMemberGroups",
  "checkMemberObjects",
  "getAvailableExtensionProperties",
  "findMeetingTimes",
  "getSchedule",
  "translateExchangeIds",
  "preview",
  "query",
] as const;

/** A batch endpoint bundles arbitrary sub-request methods, so it is never a read. */
export function isBatch(path: string): boolean {
  return path === "/$batch" || path.endsWith("/$batch");
}

/**
 * Classifies an operation as read or write. Method is the default; the
 * override list corrects semantically-read POSTs. `$batch` always wins.
 */
export function classifySafety(
  method: string,
  path: string,
  operationId: string,
): Safety {
  if (READ_METHODS.has(method.toUpperCase())) return "read";
  if (isBatch(path)) return "write";
  const tail = operationId.split(".").pop() ?? "";
  return READ_OVERRIDE_SUFFIXES.some((s) => s === tail) ? "read" : "write";
}

/**
 * Risk tier drives which write tool an operation is reachable through.
 * Unknown privilege is treated as high: 22% of Graph has no permission
 * mapping, and unmapped must not silently mean "safe".
 */
export function riskFor(
  safety: Safety,
  privilegeLevel: number | null,
  path: string,
): Risk {
  if (safety === "read") return "routine";
  if (isBatch(path)) return "high";
  if (privilegeLevel === null) return "high";
  return privilegeLevel >= 4 ? "high" : "routine";
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `bun test packages/openapi-mcp/tests/safety.test.ts`
Expected: PASS, 10 tests.

- [ ] **Step 5: Commit**

```bash
bunx biome check --write packages/
git add packages/openapi-mcp
git commit -m "feat(openapi-mcp): classify operation safety and risk with explicit overrides"
```

---

### Task 5: Operation extraction

**Files:**
- Create: `packages/openapi-mcp/src/operations.ts`
- Create: `packages/openapi-mcp/tests/operations.test.ts`

**Interfaces:**
- Consumes: `OpenApiDoc` from `src/load.ts`; `classifySafety`, `riskFor` from `src/safety.ts`; `OperationRecord` from `src/types.ts`.
- Produces: `extractOperations(doc: OpenApiDoc, api: string): OperationRecord[]`, `MAX_SUMMARY = 600`.

- [ ] **Step 1: Write the failing test**

Create `packages/openapi-mcp/tests/operations.test.ts`:

```ts
import { describe, expect, test } from "bun:test";
import { loadSpec } from "../src/load";
import { extractOperations, MAX_SUMMARY } from "../src/operations";

const FIXTURE = `${import.meta.dir}/../fixtures/tiny-api.yaml`;
const load = async () => extractOperations(await loadSpec(FIXTURE), "tiny");
const byId = async (id: string) => {
  const op = (await load()).find((o) => o.qualifiedId === id);
  if (!op) throw new Error(`missing ${id}`);
  return op;
};

describe("extractOperations", () => {
  test("extracts one record per method per path", async () => {
    expect(await load()).toHaveLength(6);
  });

  test("qualified ids are namespaced by api", async () => {
    const ids = (await load()).map((o) => o.qualifiedId).sort();
    expect(ids).toContain("tiny:widgets.ListWidgets");
  });

  test("carries method, path, summary and tags", async () => {
    const op = await byId("tiny:widgets.ListWidgets");
    expect(op.method).toBe("GET");
    expect(op.path).toBe("/widgets");
    expect(op.summary).toBe("List widgets");
    expect(op.tags).toBe("widgets");
  });

  test("detects x-ms-pageable", async () => {
    expect((await byId("tiny:widgets.ListWidgets")).pageable).toBe(true);
    expect((await byId("tiny:widgets.widget.GetWidget")).pageable).toBe(false);
  });

  test("detects deprecated", async () => {
    expect((await byId("tiny:widgets.widget.DeleteWidget")).deprecated).toBe(true);
    expect((await byId("tiny:widgets.ListWidgets")).deprecated).toBe(false);
  });

  test("stores requestBody as an unresolved $ref", async () => {
    const op = await byId("tiny:widgets.CreateWidget");
    expect(op.bodyRef).toBe("#/components/schemas/Widget");
  });

  test("applies safety classification including overrides", async () => {
    expect((await byId("tiny:widgets.ListWidgets")).safety).toBe("read");
    expect((await byId("tiny:widgets.CreateWidget")).safety).toBe("write");
    expect((await byId("tiny:widgets.getByIds")).safety).toBe("read");
    expect((await byId("tiny:batch.Batch")).safety).toBe("write");
  });

  test("$batch is high risk", async () => {
    expect((await byId("tiny:batch.Batch")).risk).toBe("high");
  });

  test("collects path parameters", async () => {
    const op = await byId("tiny:widgets.widget.GetWidget");
    const params = JSON.parse(op.paramsJson) as Array<{ name: string; required: boolean }>;
    expect(params).toHaveLength(1);
    expect(params[0].name).toBe("widget-id");
    expect(params[0].required).toBe(true);
  });

  test("uses the document server url", async () => {
    expect((await byId("tiny:widgets.ListWidgets")).serverUrl).toBe(
      "https://tiny.example.com",
    );
  });

  test("truncates summaries at MAX_SUMMARY", async () => {
    const doc = await loadSpec(FIXTURE);
    doc.paths["/widgets"].get.summary = "x".repeat(MAX_SUMMARY + 50);
    const op = extractOperations(doc, "tiny").find(
      (o) => o.qualifiedId === "tiny:widgets.ListWidgets",
    );
    expect(op?.summary?.length).toBe(MAX_SUMMARY);
  });

  test("throws on a duplicate operationId", async () => {
    const doc = await loadSpec(FIXTURE);
    doc.paths["/widgets"].get.operationId = "widgets.CreateWidget";
    expect(() => extractOperations(doc, "tiny")).toThrow(/duplicate/i);
  });

  test("throws when an operation has no operationId", async () => {
    const doc = await loadSpec(FIXTURE);
    doc.paths["/widgets"].get.operationId = undefined;
    expect(() => extractOperations(doc, "tiny")).toThrow(/operationId/);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test packages/openapi-mcp/tests/operations.test.ts`
Expected: FAIL — cannot resolve `../src/operations`.

- [ ] **Step 3: Write the implementation**

`packages/openapi-mcp/src/operations.ts`:

```ts
import type { OpenApiDoc, OpenApiOperation } from "./load";
import { classifySafety, riskFor } from "./safety";
import type { OperationRecord } from "./types";

/** The gatekeeper caps rendered descriptions at 600 characters. */
export const MAX_SUMMARY = 600;

const HTTP_METHODS = new Set([
  "get", "post", "put", "patch", "delete", "head", "options",
]);

interface ParamRecord {
  name: string;
  in: string;
  required: boolean;
  schema: unknown;
}

function resolveLocal(doc: OpenApiDoc, ref: string): unknown {
  let node: unknown = doc;
  for (const part of ref.replace(/^#\//, "").split("/")) {
    if (typeof node !== "object" || node === null) return undefined;
    node = (node as Record<string, unknown>)[part];
  }
  return node;
}

function collectParams(
  doc: OpenApiDoc,
  pathItem: Record<string, unknown>,
  op: OpenApiOperation,
): ParamRecord[] {
  const raw = [
    ...((pathItem.parameters as unknown[]) ?? []),
    ...((op.parameters as unknown[]) ?? []),
  ];
  const out: ParamRecord[] = [];
  for (const entry of raw) {
    const p = (
      typeof entry === "object" && entry !== null && "$ref" in entry
        ? resolveLocal(doc, (entry as { $ref: string }).$ref)
        : entry
    ) as Record<string, unknown> | undefined;
    if (!p || typeof p.name !== "string") continue;
    out.push({
      name: p.name,
      in: typeof p.in === "string" ? p.in : "query",
      required: p.required === true,
      schema: p.schema ?? { type: "string" },
    });
  }
  return out;
}

function bodyRefOf(op: OpenApiOperation): string | null {
  const rb = op.requestBody as Record<string, unknown> | undefined;
  if (!rb) return null;
  if (typeof rb.$ref === "string") return rb.$ref;
  const content = rb.content as Record<string, { schema?: unknown }> | undefined;
  const schema = content?.["application/json"]?.schema as
    | { $ref?: string }
    | undefined;
  return typeof schema?.$ref === "string" ? schema.$ref : null;
}

/** Extracts one thin record per operation. `$ref`s are stored, never resolved. */
export function extractOperations(
  doc: OpenApiDoc,
  api: string,
): OperationRecord[] {
  const serverUrl = doc.servers?.[0]?.url ?? "";
  if (!serverUrl) throw new Error("document declares no servers[0].url");

  const seen = new Set<string>();
  const records: OperationRecord[] = [];

  for (const [path, pathItem] of Object.entries(doc.paths)) {
    for (const [method, op] of Object.entries(pathItem)) {
      if (!HTTP_METHODS.has(method)) continue;

      const operationId = op.operationId;
      if (typeof operationId !== "string" || operationId.length === 0) {
        throw new Error(`${method.toUpperCase()} ${path}: missing operationId`);
      }
      const qualifiedId = `${api}:${operationId}`;
      if (seen.has(qualifiedId)) {
        throw new Error(`duplicate operationId: ${operationId}`);
      }
      seen.add(qualifiedId);

      const upper = method.toUpperCase();
      const safety = classifySafety(upper, path, operationId);
      const summary = (op.summary ?? op.description ?? null)?.slice(
        0,
        MAX_SUMMARY,
      );

      records.push({
        qualifiedId,
        api,
        operationId,
        method: upper,
        path,
        safety,
        risk: riskFor(safety, null, path),
        operationType:
          typeof op["x-ms-docs-operation-type"] === "string"
            ? (op["x-ms-docs-operation-type"] as string)
            : null,
        pageable: op["x-ms-pageable"] !== undefined,
        deprecated: op.deprecated === true,
        permissions: null,
        permConfidence: null,
        privilegeLevel: null,
        summary: summary ?? null,
        tags: Array.isArray(op.tags) ? op.tags.join(" ") : null,
        paramsJson: JSON.stringify(collectParams(doc, pathItem, op)),
        bodyRef: bodyRefOf(op),
        serverUrl,
      });
    }
  }
  return records;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `bun test packages/openapi-mcp/tests/operations.test.ts`
Expected: PASS, 13 tests.

- [ ] **Step 5: Commit**

```bash
bunx biome check --write packages/
git add packages/openapi-mcp
git commit -m "feat(openapi-mcp): extract thin operation records with unresolved refs"
```

---

### Task 6: Permission mapping

**Files:**
- Create: `packages/openapi-mcp/src/permissions.ts`
- Create: `packages/openapi-mcp/fixtures/tiny-permissions.json`
- Create: `packages/openapi-mcp/tests/permissions.test.ts`

**Interfaces:**
- Consumes: `OperationRecord`, `PermConfidence` from `src/types.ts`; `riskFor` from `src/safety.ts`.
- Produces: `buildPermissionIndex(dataset: PermissionsDataset): PermissionIndex`, `lookupPermissions(index: PermissionIndex, path: string, method: string): PermissionMatch | null`, `applyPermissions(ops: OperationRecord[], index: PermissionIndex): void`.

**Why three strategies:** Microsoft publishes permissions separately from the OpenAPI document, keyed by permission rather than by operation, and with different path templating. Exact matching covers 18% of Graph; adding OData suffix stripping reaches 23%; adding longest-prefix inheritance reaches 77%. The remaining 22% stays unmapped. `perm_confidence` records which strategy produced a row, because prefix inheritance is a heuristic that can understate what a child path requires.

- [ ] **Step 1: Write the fixture**

Create `packages/openapi-mcp/fixtures/tiny-permissions.json`:

```json
{
  "permissions": {
    "Widget.Read": {
      "schemes": { "DelegatedWork": { "privilegeLevel": 2 } },
      "pathSets": [
        { "methods": ["GET"], "paths": { "/widgets": {}, "/widgets/{id}": {} } }
      ]
    },
    "Widget.ReadWrite.All": {
      "schemes": { "DelegatedWork": { "privilegeLevel": 5 } },
      "pathSets": [
        { "methods": ["POST", "DELETE"], "paths": { "/widgets": {} } }
      ]
    }
  }
}
```

- [ ] **Step 2: Write the failing test**

Create `packages/openapi-mcp/tests/permissions.test.ts`:

```ts
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `bun test packages/openapi-mcp/tests/permissions.test.ts`
Expected: FAIL — cannot resolve `../src/permissions`.

- [ ] **Step 4: Write the implementation**

`packages/openapi-mcp/src/permissions.ts`:

```ts
import { riskFor } from "./safety";
import type { OperationRecord, PermConfidence } from "./types";

export interface PermissionsDataset {
  permissions: Record<
    string,
    {
      schemes?: Record<string, { privilegeLevel?: number }>;
      pathSets?: Array<{ methods?: string[]; paths?: Record<string, unknown> }>;
    }
  >;
}

export interface PermissionMatch {
  permissions: string[];
  privilegeLevel: number | null;
  confidence: PermConfidence;
}

export interface PermissionIndex {
  /** method -> normalised path -> permission names */
  byMethod: Map<string, Map<string, Set<string>>>;
  privilege: Map<string, number>;
}

/** Parameter names differ between the two Microsoft datasets; erase them. */
function normalise(path: string): string {
  return path.replace(/\{[^}]*\}/g, "{}").replace(/\/+$/, "").toLowerCase();
}

const ODATA_SUFFIX = /\/(\$count|\$ref|\$value|microsoft\.graph\.[a-z0-9.]+)$/;

export function buildPermissionIndex(
  dataset: PermissionsDataset,
): PermissionIndex {
  const byMethod = new Map<string, Map<string, Set<string>>>();
  const privilege = new Map<string, number>();

  for (const [name, body] of Object.entries(dataset.permissions ?? {})) {
    const level = body.schemes?.DelegatedWork?.privilegeLevel;
    if (typeof level === "number") privilege.set(name, level);

    for (const set of body.pathSets ?? []) {
      for (const method of set.methods ?? []) {
        const key = method.toUpperCase();
        let table = byMethod.get(key);
        if (!table) {
          table = new Map();
          byMethod.set(key, table);
        }
        for (const path of Object.keys(set.paths ?? {})) {
          const n = normalise(path);
          let names = table.get(n);
          if (!names) {
            names = new Set();
            table.set(n, names);
          }
          names.add(name);
        }
      }
    }
  }
  return { byMethod, privilege };
}

function finish(
  index: PermissionIndex,
  names: Set<string>,
  confidence: PermConfidence,
): PermissionMatch {
  const permissions = [...names].sort();
  // Several permissions can authorise one operation; the strictest bounds risk.
  const levels = permissions
    .map((p) => index.privilege.get(p))
    .filter((l): l is number => typeof l === "number");
  return {
    permissions,
    privilegeLevel: levels.length ? Math.max(...levels) : null,
    confidence,
  };
}

/**
 * Three strategies in order: exact, OData-suffix-stripped, then longest
 * prefix. Prefix matches are a heuristic and are marked as such — a child
 * path can require a broader permission than its parent.
 */
export function lookupPermissions(
  index: PermissionIndex,
  path: string,
  method: string,
): PermissionMatch | null {
  const table = index.byMethod.get(method.toUpperCase());
  if (!table) return null;

  const exact = normalise(path);
  const hitExact = table.get(exact);
  if (hitExact) return finish(index, hitExact, "exact");

  const stripped = exact.replace(ODATA_SUFFIX, "");
  if (stripped !== exact) {
    const hitSuffix = table.get(stripped);
    if (hitSuffix) return finish(index, hitSuffix, "suffix");
  }

  const parts = stripped.split("/");
  for (let i = parts.length - 1; i > 1; i--) {
    const hitPrefix = table.get(parts.slice(0, i).join("/"));
    if (hitPrefix) return finish(index, hitPrefix, "prefix");
  }
  return null;
}

/** Annotates records in place and recomputes risk now that privilege is known. */
export function applyPermissions(
  ops: OperationRecord[],
  index: PermissionIndex,
): void {
  for (const op of ops) {
    const match = lookupPermissions(index, op.path, op.method);
    if (match) {
      op.permissions = match.permissions;
      op.permConfidence = match.confidence;
      op.privilegeLevel = match.privilegeLevel;
    }
    op.risk = riskFor(op.safety, op.privilegeLevel, op.path);
  }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `bun test packages/openapi-mcp/tests/permissions.test.ts`
Expected: PASS, 9 tests.

- [ ] **Step 6: Commit**

```bash
bunx biome check --write packages/
git add packages/openapi-mcp
git commit -m "feat(openapi-mcp): map operations to upstream permissions and tier risk"
```

---

### Task 7: Schema store

**Files:**
- Create: `packages/openapi-mcp/src/schemas.ts`
- Create: `packages/openapi-mcp/tests/schemas.test.ts`

**Interfaces:**
- Consumes: `OpenApiDoc` from `src/load.ts`; `SchemaRecord` from `src/types.ts`.
- Produces: `extractSchemas(doc: OpenApiDoc, api: string): SchemaRecord[]`.

- [ ] **Step 1: Write the failing test**

Create `packages/openapi-mcp/tests/schemas.test.ts`:

```ts
import { describe, expect, test } from "bun:test";
import { loadSpec } from "../src/load";
import { extractSchemas } from "../src/schemas";

const FIXTURE = `${import.meta.dir}/../fixtures/tiny-api.yaml`;

describe("extractSchemas", () => {
  test("stores one row per component schema", async () => {
    const rows = extractSchemas(await loadSpec(FIXTURE), "tiny");
    expect(rows).toHaveLength(2);
    expect(rows.map((r) => r.name).sort()).toEqual([
      "#/components/schemas/Owner",
      "#/components/schemas/Widget",
    ]);
  });

  test("leaves nested $refs unresolved", async () => {
    const rows = extractSchemas(await loadSpec(FIXTURE), "tiny");
    const widget = rows.find((r) => r.name.endsWith("/Widget"));
    const parsed = JSON.parse(widget?.json ?? "{}");
    expect(parsed.properties.owner).toEqual({
      $ref: "#/components/schemas/Owner",
    });
  });

  test("namespaces rows by api", async () => {
    const rows = extractSchemas(await loadSpec(FIXTURE), "tiny");
    expect(rows.every((r) => r.api === "tiny")).toBe(true);
  });

  test("returns an empty list when there are no components", async () => {
    const doc = await loadSpec(FIXTURE);
    doc.components = undefined;
    expect(extractSchemas(doc, "tiny")).toEqual([]);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test packages/openapi-mcp/tests/schemas.test.ts`
Expected: FAIL — cannot resolve `../src/schemas`.

- [ ] **Step 3: Write the implementation**

`packages/openapi-mcp/src/schemas.ts`:

```ts
import type { OpenApiDoc } from "./load";
import type { SchemaRecord } from "./types";

/**
 * Stores each component schema exactly as written, with `$ref`s intact.
 * Resolution happens at request time against one operation's closure;
 * eager dereferencing of Microsoft Graph exceeds 342 MB and, resolved per
 * `$ref` hop rather than per nesting level, does not terminate at all.
 */
export function extractSchemas(doc: OpenApiDoc, api: string): SchemaRecord[] {
  const schemas = doc.components?.schemas;
  if (!schemas) return [];
  return Object.entries(schemas).map(([name, value]) => ({
    api,
    name: `#/components/schemas/${name}`,
    json: JSON.stringify(value),
  }));
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `bun test packages/openapi-mcp/tests/schemas.test.ts`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
bunx biome check --write packages/
git add packages/openapi-mcp
git commit -m "feat(openapi-mcp): store component schemas with refs unresolved"
```

---

### Task 8: Artifact assembly

**Files:**
- Create: `packages/openapi-mcp/src/compile.ts`
- Create: `packages/openapi-mcp/tests/compile.test.ts`

**Interfaces:**
- Consumes: everything from Tasks 2–7.
- Produces: `compile(options: CompileOptions): Promise<CompileResult>` where `CompileOptions = { specPath: string; api: string; outPath: string; permissionsPath?: string }` and `CompileResult = { operations: number; schemas: number; mapped: number }`.

- [ ] **Step 1: Write the failing test**

Create `packages/openapi-mcp/tests/compile.test.ts`:

```ts
import { Database } from "bun:sqlite";
import { afterEach, describe, expect, test } from "bun:test";
import { unlinkSync } from "node:fs";
import { compile } from "../src/compile";
import { FORMAT_VERSION } from "../src/schema";

const OUT = `${import.meta.dir}/tmp-compile.sqlite`;
const opts = {
  specPath: `${import.meta.dir}/../fixtures/tiny-api.yaml`,
  api: "tiny",
  outPath: OUT,
  permissionsPath: `${import.meta.dir}/../fixtures/tiny-permissions.json`,
};

afterEach(() => {
  try { unlinkSync(OUT); } catch { /* already gone */ }
});

describe("compile", () => {
  test("writes every operation and schema", async () => {
    const result = await compile(opts);
    expect(result.operations).toBe(6);
    expect(result.schemas).toBe(2);
    expect(result.mapped).toBeGreaterThan(0);

    const db = new Database(OUT, { readonly: true });
    expect(
      db.query<{ n: number }, []>("SELECT COUNT(*) n FROM operations").get()?.n,
    ).toBe(6);
    expect(
      db.query<{ n: number }, []>("SELECT COUNT(*) n FROM schemas").get()?.n,
    ).toBe(2);
    db.close();
  });

  test("populates the fts index so search returns the right operation", async () => {
    await compile(opts);
    const db = new Database(OUT, { readonly: true });
    const hits = db
      .query<{ qualified_id: string }, [string]>(
        `SELECT o.qualified_id FROM operations_fts f
         JOIN operations o ON o.rowid = f.rowid
         WHERE operations_fts MATCH ? ORDER BY bm25(operations_fts) LIMIT 5`,
      )
      .all("widget");
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.map((h) => h.qualified_id)).toContain("tiny:widgets.CreateWidget");
    db.close();
  });

  test("records provenance in meta, namespaced per api", async () => {
    await compile(opts);
    const db = new Database(OUT, { readonly: true });
    const meta = Object.fromEntries(
      db.query<{ key: string; value: string }, []>("SELECT key, value FROM meta")
        .all()
        .map((r) => [r.key, r.value]),
    );
    expect(meta.format_version).toBe(String(FORMAT_VERSION));
    // `apis` is the mounted-API list; per-api keys are namespaced so a second
    // mount (Task 12) cannot collide with the first.
    expect(JSON.parse(meta.apis)).toEqual(["tiny"]);
    expect(meta["tiny.source_path"]).toContain("tiny-api.yaml");
    expect(meta["tiny.compiled_at"]).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    db.close();
  });

  test("works without a permissions dataset", async () => {
    const result = await compile({ ...opts, permissionsPath: undefined });
    expect(result.operations).toBe(6);
    expect(result.mapped).toBe(0);

    const db = new Database(OUT, { readonly: true });
    const write = db
      .query<{ risk: string }, [string]>(
        "SELECT risk FROM operations WHERE qualified_id = ?",
      )
      .get("tiny:widgets.CreateWidget");
    // Unmapped writes must default to high, never silently to routine.
    expect(write?.risk).toBe("high");
    db.close();
  });

  test("produces identical rows across runs", async () => {
    const rowsOf = async () => {
      await compile(opts);
      const db = new Database(OUT, { readonly: true });
      const rows = db
        .query<Record<string, unknown>, []>(
          `SELECT qualified_id, method, path, safety, risk, pageable, deprecated,
                  permissions, perm_confidence, privilege_level, params_json, body_ref
           FROM operations ORDER BY qualified_id`,
        )
        .all();
      db.close();
      return rows;
    };
    const first = await rowsOf();
    unlinkSync(OUT);
    const second = await rowsOf();
    // meta.compiled_at is a timestamp and differs by design; every row must not.
    expect(second).toEqual(first);
    expect(first).toHaveLength(6);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test packages/openapi-mcp/tests/compile.test.ts`
Expected: FAIL — cannot resolve `../src/compile`.

- [ ] **Step 3: Write the implementation**

`packages/openapi-mcp/src/compile.ts`:

```ts
import { Database } from "bun:sqlite";
import { unlinkSync } from "node:fs";
import { loadSpec } from "./load";
import { extractOperations } from "./operations";
import {
  applyPermissions,
  buildPermissionIndex,
  type PermissionsDataset,
} from "./permissions";
import { createSchema, FORMAT_VERSION } from "./schema";
import { extractSchemas } from "./schemas";

export interface CompileOptions {
  specPath: string;
  api: string;
  outPath: string;
  permissionsPath?: string;
}

export interface CompileResult {
  operations: number;
  schemas: number;
  mapped: number;
}

const COMPILER_VERSION = "0.1.0";

export async function compile(
  options: CompileOptions,
): Promise<CompileResult> {
  const doc = await loadSpec(options.specPath);
  const operations = extractOperations(doc, options.api);
  const schemas = extractSchemas(doc, options.api);

  if (options.permissionsPath) {
    const dataset = (await Bun.file(
      options.permissionsPath,
    ).json()) as PermissionsDataset;
    applyPermissions(operations, buildPermissionIndex(dataset));
  } else {
    // Still recompute risk so unmapped writes land on `high`.
    applyPermissions(operations, { byMethod: new Map(), privilege: new Map() });
  }

  try {
    unlinkSync(options.outPath);
  } catch {
    // No previous artifact; nothing to remove.
  }

  const db = new Database(options.outPath, { create: true });
  try {
    createSchema(db);
    db.run("BEGIN");

    const insertOp = db.prepare(
      `INSERT INTO operations
       (qualified_id, api, operation_id, method, path, safety, risk,
        operation_type, pageable, deprecated, permissions, perm_confidence,
        privilege_level, summary, tags, params_json, body_ref, server_url)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    );
    for (const op of operations) {
      insertOp.run(
        op.qualifiedId, op.api, op.operationId, op.method, op.path,
        op.safety, op.risk, op.operationType,
        op.pageable ? 1 : 0, op.deprecated ? 1 : 0,
        op.permissions ? JSON.stringify(op.permissions) : null,
        op.permConfidence, op.privilegeLevel, op.summary, op.tags,
        op.paramsJson, op.bodyRef, op.serverUrl,
      );
    }

    const insertSchema = db.prepare(
      "INSERT INTO schemas (api, name, json) VALUES (?,?,?)",
    );
    for (const s of schemas) insertSchema.run(s.api, s.name, s.json);

    // External-content fts5: populate from the base table after loading it.
    db.run(
      `INSERT INTO operations_fts (rowid, qualified_id, operation_id, summary, path, tags, api)
       SELECT rowid, qualified_id, operation_id, summary, path, tags, api FROM operations`,
    );

    // Global keys plus per-api namespaced provenance. `apis` is a JSON array so
    // a second mount can append to it without rewriting anything.
    const insertMeta = db.prepare(
      "INSERT OR REPLACE INTO meta (key, value) VALUES (?,?)",
    );
    for (const [key, value] of Object.entries({
      format_version: String(FORMAT_VERSION),
      compiler_version: COMPILER_VERSION,
      apis: JSON.stringify([options.api]),
      [`${options.api}.source_path`]: options.specPath,
      [`${options.api}.compiled_at`]: new Date().toISOString(),
    })) {
      insertMeta.run(key, value);
    }

    db.run("COMMIT");
  } catch (err) {
    db.run("ROLLBACK");
    throw err;
  } finally {
    db.close();
  }

  return {
    operations: operations.length,
    schemas: schemas.length,
    mapped: operations.filter((o) => o.permissions !== null).length,
  };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `bun test packages/openapi-mcp/tests/compile.test.ts`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
bunx biome check --write packages/
git add packages/openapi-mcp
git commit -m "feat(openapi-mcp): assemble the compiled SQLite artifact"
```

---

### Task 9: Signing and verification

**Files:**
- Create: `packages/openapi-mcp/src/sign.ts`
- Create: `packages/openapi-mcp/tests/sign.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `generateKeypair(): { publicKeyPem: string; privateKeyPem: string }`, `signArtifact(path: string, privateKeyPem: string): Promise<string>`, `verifyArtifact(path: string, signatureB64: string, publicKeyPem: string): Promise<boolean>`.

**Why signing, not hashing:** the artifact decides whether a call prompts for approval (`safety`) and where a bearer token is sent (`server_url`). A digest published beside the download is trust-on-first-use, not integrity — the verifying key must ship in source.

- [ ] **Step 1: Write the failing test**

Create `packages/openapi-mcp/tests/sign.test.ts`:

```ts
import { afterEach, describe, expect, test } from "bun:test";
import { unlinkSync } from "node:fs";
import { generateKeypair, signArtifact, verifyArtifact } from "../src/sign";

const FILE = `${import.meta.dir}/tmp-sign.bin`;
afterEach(() => {
  try { unlinkSync(FILE); } catch { /* already gone */ }
});

describe("artifact signing", () => {
  test("a signature made with the private key verifies with the public key", async () => {
    const { publicKeyPem, privateKeyPem } = generateKeypair();
    await Bun.write(FILE, "artifact bytes");
    const sig = await signArtifact(FILE, privateKeyPem);
    expect(await verifyArtifact(FILE, sig, publicKeyPem)).toBe(true);
  });

  test("verification fails when the file is modified", async () => {
    const { publicKeyPem, privateKeyPem } = generateKeypair();
    await Bun.write(FILE, "artifact bytes");
    const sig = await signArtifact(FILE, privateKeyPem);
    await Bun.write(FILE, "tampered bytes");
    expect(await verifyArtifact(FILE, sig, publicKeyPem)).toBe(false);
  });

  test("verification fails against a different key", async () => {
    const a = generateKeypair();
    const b = generateKeypair();
    await Bun.write(FILE, "artifact bytes");
    const sig = await signArtifact(FILE, a.privateKeyPem);
    expect(await verifyArtifact(FILE, sig, b.publicKeyPem)).toBe(false);
  });

  test("a malformed signature returns false rather than throwing", async () => {
    const { publicKeyPem } = generateKeypair();
    await Bun.write(FILE, "artifact bytes");
    expect(await verifyArtifact(FILE, "not-base64!!", publicKeyPem)).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test packages/openapi-mcp/tests/sign.test.ts`
Expected: FAIL — cannot resolve `../src/sign`.

- [ ] **Step 3: Write the implementation**

`packages/openapi-mcp/src/sign.ts`:

```ts
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";

/** Ed25519 keypair, PEM encoded. The public key ships in plugin source. */
export function generateKeypair(): {
  publicKeyPem: string;
  privateKeyPem: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey
      .export({ type: "pkcs8", format: "pem" })
      .toString(),
  };
}

/** Signs the artifact's exact bytes. Returns a base64 signature. */
export async function signArtifact(
  path: string,
  privateKeyPem: string,
): Promise<string> {
  const bytes = Buffer.from(await Bun.file(path).arrayBuffer());
  const key = createPrivateKey(privateKeyPem);
  return sign(null, bytes, key).toString("base64");
}

/**
 * Verifies an artifact against a public key. Returns false rather than
 * throwing on malformed input — callers treat any failure identically.
 */
export async function verifyArtifact(
  path: string,
  signatureB64: string,
  publicKeyPem: string,
): Promise<boolean> {
  try {
    const bytes = Buffer.from(await Bun.file(path).arrayBuffer());
    const key = createPublicKey(publicKeyPem);
    return verify(null, bytes, key, Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `bun test packages/openapi-mcp/tests/sign.test.ts`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
bunx biome check --write packages/
git add packages/openapi-mcp
git commit -m "feat(openapi-mcp): sign and verify compiled artifacts with ed25519"
```

---

### Task 10: CLI

**Files:**
- Create: `packages/openapi-mcp/src/cli.ts`
- Create: `packages/openapi-mcp/tests/cli.test.ts`

**Interfaces:**
- Consumes: `compile` from `src/compile.ts`; `generateKeypair`, `signArtifact` from `src/sign.ts`.
- Produces: an executable entry point. No exported API.

- [ ] **Step 1: Write the failing test**

Create `packages/openapi-mcp/tests/cli.test.ts`:

```ts
import { afterEach, describe, expect, test } from "bun:test";
import { unlinkSync } from "node:fs";

const CLI = `${import.meta.dir}/../src/cli.ts`;
const OUT = `${import.meta.dir}/tmp-cli.sqlite`;
const SPEC = `${import.meta.dir}/../fixtures/tiny-api.yaml`;

afterEach(() => {
  for (const f of [OUT, `${OUT}.sig`]) {
    try { unlinkSync(f); } catch { /* already gone */ }
  }
});

const run = async (args: string[]) => {
  const proc = Bun.spawn(["bun", CLI, ...args], {
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  return { code: await proc.exited, stdout, stderr };
};

describe("cli", () => {
  test("compiles a spec and reports counts", async () => {
    const r = await run(["compile", "--spec", SPEC, "--api", "tiny", "--out", OUT]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("6 operations");
    expect(await Bun.file(OUT).exists()).toBe(true);
  });

  test("exits non-zero when --spec is missing", async () => {
    const r = await run(["compile", "--api", "tiny", "--out", OUT]);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toContain("--spec");
  });

  test("exits non-zero on an unknown subcommand", async () => {
    const r = await run(["frobnicate"]);
    expect(r.code).not.toBe(0);
  });

  test("keygen prints a usable keypair", async () => {
    const r = await run(["keygen"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("BEGIN PUBLIC KEY");
    expect(r.stdout).toContain("BEGIN PRIVATE KEY");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test packages/openapi-mcp/tests/cli.test.ts`
Expected: FAIL — `src/cli.ts` does not exist.

- [ ] **Step 3: Write the implementation**

`packages/openapi-mcp/src/cli.ts`:

```ts
#!/usr/bin/env bun
import { parseArgs } from "node:util";
import { compile } from "./compile";
import { generateKeypair, signArtifact } from "./sign";

const USAGE = `openapi-mcp — compile OpenAPI documents into signed MCP artifacts

  compile --spec <path> --api <name> --out <path> [--permissions <path>] [--sign-key <path>]
  keygen
`;

function fail(message: string): never {
  console.error(`error: ${message}\n\n${USAGE}`);
  process.exit(1);
}

const [command, ...rest] = Bun.argv.slice(2);

if (command === "keygen") {
  const { publicKeyPem, privateKeyPem } = generateKeypair();
  console.log(publicKeyPem);
  console.log(privateKeyPem);
  process.exit(0);
}

if (command !== "compile") {
  fail(command ? `unknown command "${command}"` : "no command given");
}

const { values } = parseArgs({
  args: rest,
  options: {
    spec: { type: "string" },
    api: { type: "string" },
    out: { type: "string" },
    permissions: { type: "string" },
    "sign-key": { type: "string" },
  },
  strict: true,
});

if (!values.spec) fail("--spec is required");
if (!values.api) fail("--api is required");
if (!values.out) fail("--out is required");

const started = Date.now();
const result = await compile({
  specPath: values.spec,
  api: values.api,
  outPath: values.out,
  permissionsPath: values.permissions,
});

console.log(
  `compiled ${result.operations} operations, ${result.schemas} schemas ` +
    `(${result.mapped} permission-mapped) in ${Date.now() - started} ms -> ${values.out}`,
);

if (values["sign-key"]) {
  const privateKeyPem = await Bun.file(values["sign-key"]).text();
  const sig = await signArtifact(values.out, privateKeyPem);
  await Bun.write(`${values.out}.sig`, sig);
  console.log(`signed -> ${values.out}.sig`);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `bun test packages/openapi-mcp/tests/cli.test.ts`
Expected: PASS, 4 tests.

- [ ] **Step 5: Run the whole suite**

Run: `bun test packages/openapi-mcp`
Expected: PASS, all tests from Tasks 1–10.

- [ ] **Step 6: Commit**

```bash
bunx biome check --write packages/
git add packages/openapi-mcp
git commit -m "feat(openapi-mcp): add compile and keygen CLI"
```

---

### Task 11: Invariants against the real Microsoft Graph spec

**Files:**
- Create: `packages/openapi-mcp/tests/graph-invariants.test.ts`
- Modify: `.github/workflows/validate.yml`

**Interfaces:**
- Consumes: `compile` from `src/compile.ts`.
- Produces: nothing importable.

**Why:** the fixture proves the branches work; only the real 44 MB document proves the compiler survives scale and that its headline numbers still hold. This test downloads the spec, so it is opt-in via `OPENAPI_MCP_GRAPH_SPEC` and skipped by default.

- [ ] **Step 1: Write the test**

Create `packages/openapi-mcp/tests/graph-invariants.test.ts`:

```ts
import { Database } from "bun:sqlite";
import { describe, expect, test } from "bun:test";
import { unlinkSync } from "node:fs";
import { compile } from "../src/compile";

const SPEC = process.env.OPENAPI_MCP_GRAPH_SPEC;
const OUT = `${import.meta.dir}/tmp-graph.sqlite`;

describe.skipIf(!SPEC)("Microsoft Graph invariants", () => {
  test("compiles the full v1.0 surface within budget", async () => {
    const started = Date.now();
    const result = await compile({
      specPath: SPEC as string,
      api: "graph",
      outPath: OUT,
    });

    // Counts measured 2026-09-01 against msgraph-metadata@master.
    expect(result.operations).toBe(17777);
    expect(result.schemas).toBe(5127);
    // Parsing alone is ~650 ms; the whole compile must stay well under CI patience.
    expect(Date.now() - started).toBeLessThan(120_000);

    const db = new Database(OUT, { readonly: true });

    // Every operationId is unique, so no row was silently dropped.
    expect(
      db.query<{ n: number }, []>(
        "SELECT COUNT(DISTINCT operation_id) n FROM operations",
      ).get()?.n,
    ).toBe(17777);

    // Safety invariant: no mutating method may be stored as a read unless an
    // override produced it. Overrides only ever apply to POST.
    expect(
      db.query<{ n: number }, []>(
        `SELECT COUNT(*) n FROM operations
         WHERE safety = 'read' AND method NOT IN ('GET','HEAD','POST')`,
      ).get()?.n,
    ).toBe(0);

    // $batch is never a read and never routine.
    const batch = db
      .query<{ safety: string; risk: string }, []>(
        "SELECT safety, risk FROM operations WHERE path LIKE '%$batch'",
      )
      .all();
    expect(batch.every((b) => b.safety === "write" && b.risk === "high")).toBe(true);

    // Pageable and deprecated counts measured on the same revision.
    expect(
      db.query<{ n: number }, []>(
        "SELECT COUNT(*) n FROM operations WHERE pageable = 1",
      ).get()?.n,
    ).toBe(2760);
    expect(
      db.query<{ n: number }, []>(
        "SELECT COUNT(*) n FROM operations WHERE deprecated = 1",
      ).get()?.n,
    ).toBe(85);

    // Search must actually find something for a plain-language query.
    const hits = db
      .query<{ qualified_id: string }, [string]>(
        `SELECT o.qualified_id FROM operations_fts f
         JOIN operations o ON o.rowid = f.rowid
         WHERE operations_fts MATCH ? ORDER BY bm25(operations_fts) LIMIT 10`,
      )
      .all("message");
    expect(hits.length).toBeGreaterThan(0);

    db.close();
    unlinkSync(OUT);
  }, 180_000);
});
```

- [ ] **Step 2: Run it against the real spec**

```bash
curl -sL -o /tmp/graph-v1.yaml \
  https://raw.githubusercontent.com/microsoftgraph/msgraph-metadata/master/openapi/v1.0/openapi.yaml
OPENAPI_MCP_GRAPH_SPEC=/tmp/graph-v1.yaml bun test packages/openapi-mcp/tests/graph-invariants.test.ts
```
Expected: PASS. If operation counts differ, Microsoft has revised the spec — update the expected numbers **and** the spec document's §4 table in the same commit, never silently.

- [ ] **Step 3: Verify it skips without the env var**

Run: `bun test packages/openapi-mcp/tests/graph-invariants.test.ts`
Expected: the suite is skipped, exit code 0.

- [ ] **Step 4: Wire the unit suite into CI**

In `.github/workflows/validate.yml`, add a step after the existing validation step. Do **not** add the Graph download to the PR gate — it is a 44 MB fetch on every run.

```yaml
      - name: Test packages
        run: bun test packages/
```

- [ ] **Step 5: Commit**

```bash
bunx biome check --write packages/ .github/
git add packages/openapi-mcp .github/workflows/validate.yml
git commit -m "test(openapi-mcp): assert compiler invariants against the real Graph spec"
```

---

### Task 12: Mounting a second API into one artifact

**Files:**
- Modify: `packages/openapi-mcp/src/compile.ts`
- Modify: `packages/openapi-mcp/src/cli.ts`
- Create: `packages/openapi-mcp/fixtures/other-api.yaml`
- Create: `packages/openapi-mcp/tests/mount.test.ts`

**Interfaces:**
- Consumes: `compile` from `src/compile.ts`.
- Produces: `CompileOptions` gains `append?: boolean`.

**Why:** the spec requires that multiple APIs share one database, distinguished by the `api` column, so that one server can mount several APIs and still fit the 40-servers-per-portal budget. `compile()` as written in Task 8 unlinks its output, so a second mount would erase the first.

- [ ] **Step 1: Write the second fixture**

Create `packages/openapi-mcp/fixtures/other-api.yaml`:

```yaml
openapi: 3.0.4
info:
  title: Other API
  version: v1
servers:
  - url: https://other.example.com
paths:
  /zones:
    get:
      operationId: zones.ListZones
      summary: List zones
      tags: [zones]
      responses:
        "200": { description: ok }
    post:
      operationId: zones.CreateZone
      summary: Create a zone
      tags: [zones]
      responses:
        "201": { description: created }
```

- [ ] **Step 2: Write the failing test**

Create `packages/openapi-mcp/tests/mount.test.ts`:

```ts
import { Database } from "bun:sqlite";
import { afterEach, describe, expect, test } from "bun:test";
import { unlinkSync } from "node:fs";
import { compile } from "../src/compile";

const OUT = `${import.meta.dir}/tmp-mount.sqlite`;
const TINY = `${import.meta.dir}/../fixtures/tiny-api.yaml`;
const OTHER = `${import.meta.dir}/../fixtures/other-api.yaml`;

afterEach(() => {
  try { unlinkSync(OUT); } catch { /* already gone */ }
});

describe("mounting a second api", () => {
  test("appending keeps the first api's rows", async () => {
    await compile({ specPath: TINY, api: "tiny", outPath: OUT });
    await compile({ specPath: OTHER, api: "other", outPath: OUT, append: true });

    const db = new Database(OUT, { readonly: true });
    expect(
      db.query<{ n: number }, []>("SELECT COUNT(*) n FROM operations").get()?.n,
    ).toBe(8);
    const apis = db
      .query<{ api: string }, []>("SELECT DISTINCT api FROM operations ORDER BY api")
      .all()
      .map((r) => r.api);
    expect(apis).toEqual(["other", "tiny"]);
    db.close();
  });

  test("records both apis in meta", async () => {
    await compile({ specPath: TINY, api: "tiny", outPath: OUT });
    await compile({ specPath: OTHER, api: "other", outPath: OUT, append: true });

    const db = new Database(OUT, { readonly: true });
    const meta = Object.fromEntries(
      db.query<{ key: string; value: string }, []>("SELECT key, value FROM meta")
        .all()
        .map((r) => [r.key, r.value]),
    );
    expect(JSON.parse(meta.apis).sort()).toEqual(["other", "tiny"]);
    expect(meta["other.source_path"]).toContain("other-api.yaml");
    expect(meta["tiny.source_path"]).toContain("tiny-api.yaml");
    db.close();
  });

  test("search can be scoped to one api", async () => {
    await compile({ specPath: TINY, api: "tiny", outPath: OUT });
    await compile({ specPath: OTHER, api: "other", outPath: OUT, append: true });

    const db = new Database(OUT, { readonly: true });
    const hits = db
      .query<{ qualified_id: string }, [string, string]>(
        `SELECT o.qualified_id FROM operations_fts f
         JOIN operations o ON o.rowid = f.rowid
         WHERE operations_fts MATCH ? AND o.api = ?
         ORDER BY bm25(operations_fts)`,
      )
      .all("list", "other");
    expect(hits.map((h) => h.qualified_id)).toEqual(["other:zones.ListZones"]);
    db.close();
  });

  test("refuses to mount the same api twice", async () => {
    await compile({ specPath: TINY, api: "tiny", outPath: OUT });
    expect(
      compile({ specPath: TINY, api: "tiny", outPath: OUT, append: true }),
    ).rejects.toThrow(/already mounted/);
  });

  test("refuses to append to an artifact with a different format_version", async () => {
    await compile({ specPath: TINY, api: "tiny", outPath: OUT });
    const db = new Database(OUT);
    db.run("UPDATE meta SET value = '999' WHERE key = 'format_version'");
    db.close();
    expect(
      compile({ specPath: OTHER, api: "other", outPath: OUT, append: true }),
    ).rejects.toThrow(/format_version/);
  });

  test("append on a missing file fails rather than silently creating one", async () => {
    expect(
      compile({ specPath: OTHER, api: "other", outPath: OUT, append: true }),
    ).rejects.toThrow(/does not exist/);
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `bun test packages/openapi-mcp/tests/mount.test.ts`
Expected: FAIL — `append` is not a recognised option, so the second compile wipes the first and the count is 2, not 8.

- [ ] **Step 4: Write the implementation**

In `packages/openapi-mcp/src/compile.ts`, add `append?: boolean` to `CompileOptions`:

```ts
export interface CompileOptions {
  specPath: string;
  api: string;
  outPath: string;
  permissionsPath?: string;
  /** Mount into an existing artifact instead of replacing it. */
  append?: boolean;
}
```

Replace the unlink block and the `createSchema` call with this. Everything after it — the inserts, the fts population, the meta writes — stays as written in Task 8:

```ts
  const exists = await Bun.file(options.outPath).exists();

  if (options.append && !exists) {
    throw new Error(`${options.outPath} does not exist; cannot append`);
  }
  if (!options.append) {
    try {
      unlinkSync(options.outPath);
    } catch {
      // No previous artifact; nothing to remove.
    }
  }

  const db = new Database(options.outPath, { create: true });
  try {
    if (options.append) {
      const version = db
        .query<{ value: string }, [string]>(
          "SELECT value FROM meta WHERE key = ?",
        )
        .get("format_version")?.value;
      if (version !== String(FORMAT_VERSION)) {
        throw new Error(
          `format_version mismatch: artifact is ${version}, compiler is ${FORMAT_VERSION}`,
        );
      }
      const mounted = JSON.parse(
        db
          .query<{ value: string }, [string]>(
            "SELECT value FROM meta WHERE key = ?",
          )
          .get("apis")?.value ?? "[]",
      ) as string[];
      if (mounted.includes(options.api)) {
        throw new Error(`api "${options.api}" is already mounted`);
      }
      existingApis = mounted;
    } else {
      createSchema(db);
    }
    db.run("BEGIN");
```

Declare `existingApis` above the `Database` construction:

```ts
  let existingApis: string[] = [];
```

Then change the fts population so appending does not re-index rows already present, and the `apis` meta value so it accumulates:

```ts
    db.run(
      `INSERT INTO operations_fts (rowid, qualified_id, operation_id, summary, path, tags, api)
       SELECT rowid, qualified_id, operation_id, summary, path, tags, api
       FROM operations WHERE api = ?`,
      options.api,
    );
```

```ts
      apis: JSON.stringify([...existingApis, options.api]),
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `bun test packages/openapi-mcp/tests/mount.test.ts`
Expected: PASS, 6 tests.

- [ ] **Step 6: Expose it on the CLI**

In `packages/openapi-mcp/src/cli.ts`, add `append: { type: "boolean" }` to the `options` object passed to `parseArgs`, and pass it through:

```ts
    append: values.append === true,
```

Add the flag to `USAGE`:

```
  compile --spec <path> --api <name> --out <path> [--append] [--permissions <path>] [--sign-key <path>]
```

- [ ] **Step 7: Run the whole suite**

Run: `bun test packages/openapi-mcp`
Expected: PASS, every test from Tasks 1-12.

- [ ] **Step 8: Commit**

```bash
bunx biome check --write packages/
git add packages/openapi-mcp
git commit -m "feat(openapi-mcp): mount multiple APIs into one artifact"
```

---

## Verification

After Task 12, all of the following must hold:

```bash
bun test packages/          # every unit test passes
bun run validate            # marketplace validation + generate --check in sync
bunx biome check .          # no lint or format violations
bunx commitlint --from main --to HEAD   # every commit scope accepted
```

## What this plan deliberately does not build

- **The server.** Tool surface, lazy `$ref` resolution, guarded fetch, and auth are the next plan. This one ends at a signed artifact on disk.
- **Signature verification at load.** The compiler signs; the server verifies. `verifyArtifact` exists here and is tested, but nothing consumes it yet.
- **Local retrieval parity or AI Search.** Explicitly out of scope per the spec's §12.1.
- **Cloudflare API mount.** The compiler is API-agnostic, Task 11 proves it on the larger of the two, and Task 12 proves two APIs coexist in one artifact. Compiling Cloudflare's actual spec is configuration and belongs with the deployment plan.
