# OpenAPI → MCP Engine — Design

**Date:** 2026-09-01
**Status:** Approved design, pending implementation plan
**Scope:** A reusable engine in `knitli/toolshed` that turns any OpenAPI document into a
three-tool MCP server, deployable as a Cloudflare Worker or run locally, with Microsoft Graph
and the Cloudflare API as the first two mounts.

## 1. Problem

Large APIs cannot be exposed as MCP tools by enumeration. Microsoft Graph v1.0 has **17,777
operations** across 11,493 paths; the Cloudflare API has roughly 2,500. Every layer that would
consume them imposes a ceiling far below that:

- Knitli's own gatekeeper caps a server at **`MAX_TOOLS_PER_SERVER = 200`**
  (`cloudflare-os/packages/mcp-shared/src/tools.ts:40`).
- The portal tool index caps at **1,000** and throws on truncation
  (`gatekeeper-mcp-portal/src/portal.ts:92,218`).
- No LLM context can hold a 17,777-entry tool list regardless of transport.

The fix is to stop shipping tools and start shipping *search*. The agent receives three tools and
discovers operations at runtime against a compiled index.

## 2. Non-goals

Recorded explicitly because each was considered, investigated, and cut on evidence:

- **We do not build or operate code mode.** Where code mode is wanted it is supplied by the layer
  above — the MCP Portal's own Code Mode, or a Dynamic Worker's built-in one. `@cloudflare/codemode`
  is not a dependency.
- **We do not ship a bare-tools surface.** It fails the 200-tool cap for both target APIs. If an API
  under 200 operations is ever mounted, revisit; do not build it speculatively.
- **We do not own a code sandbox.** No `node:vm`, no `isolated-vm`, no local `workerd`. The
  `search`/`read`/`write` contract needs no code execution.
- **We do not dereference `$ref`s at build time.** Measured at 342 MB for Graph (§4).
- **We do not invent a tool-naming scheme.** Measured: zero collisions (§4).

## 3. Architecture

```
BUILD TIME (CI, Node)                      RUNTIME (two hosts, one implementation)
  openapi.yaml (42 MB)                       Worker + D1          local process + SQLite
        |                                         \                     /
        v  compile                                 \                   /
  api.sqlite                                        three MCP tools:
    operations      (thin rows, $refs intact)         search(query)
    operations_fts  (fts5, external-content)          read(id, params)
    schemas         (name -> raw JSON)                write(id, params)
        |                                                  |
        +--> wrangler d1 import  --> D1                    v
        +--> shipped/downloaded  --> local            upstream API
                                                  (caller's credential)
```

One compiled artifact serves both hosts because **D1 is SQLite**: the Worker binds it as D1, a local
process opens it with `node:sqlite`/`bun:sqlite`. Same schema, same fts5 queries.

### Repository layout

```
plugins/<name>/          marketplace manifest only (existing convention)
packages/openapi-mcp/    the engine: compiler + server, host-agnostic
servers/<deployment>/    wrangler.jsonc, D1 binding, mounted APIs
```

This introduces TypeScript, a build step, and `packages/*` to a repo whose `CLAUDE.md` currently
states it has "no compiled code" and "no build step." That documentation must be updated as part of
implementation; root `package.json` `workspaces.packages` gains `packages/*` and `servers/*`.

### Consumers

| Consumer | Path | Surface |
|---|---|---|
| Knitli internal | Access → Workshop → `knitlios-gk-mcp-portal` → Portal → us | `search`/`read`/`write` |
| `knitli-site` Dynamic Workers | via the Portal, code mode applied by the Worker | same |
| M365 Copilot | direct remote MCP, no portal | same |
| Marketplace users | local process, `plugins/<api>-mcp` manifest | same |

Every consumer gets the identical three-tool contract. There is no per-consumer surface variation,
which was the source of most complexity in earlier drafts of this design.

## 4. Measurements

All figures measured 2026-09-01 against `microsoftgraph/msgraph-metadata@master`,
`openapi/v1.0/openapi.yaml`.

| Fact | Value |
|---|---|
| Spec size | 44,146,442 B (42 MB); beta 70,582,558 B (67 MB) |
| Paths / operations | 11,493 / **17,777** |
| Component schemas / responses | 5,127 / 1,267 |
| Thin compilation (all ops) | **4.9 MB** — mean 286 B, p50 233 B, p99 661 B, max 819 B |
| Dereferenced, depth 4 | **342.4 MB** — mean 20 KB, p99 130 KB, max 140 KB |
| `operationId` coverage | 17,777 / 17,777, all unique |
| After `sanitizeToolName` | 17,777 unique — **zero collisions** |
| `operationId` length | p50 52, p99 142, max 276; 5,447 > 64 chars, 392 > 128 |

Two conclusions follow directly. **Dereferencing is not viable** — 70× growth, and it is why
Cloudflare's own `openApiMcpServer()` cannot ingest Graph, since it dereferences local `$ref`s
before use. **Naming needs no scheme.** Raw operationIds are already unique under Cloudflare's
sanitizer, so neither hashing nor UUIDs are required. This is moot for the three-tool surface, where
operation names are data rather than MCP tool names; it is retained as the evidence that would apply
if a bare-tools surface for a small API is ever added (§2).

### Platform ceilings

| Limit | Value | Source |
|---|---|---|
| Worker bundle | 3 MB gzip free / 10 MB paid; 64 MB uncompressed | Workers limits |
| Worker memory | 128 MB per isolate | Workers limits |
| Worker startup | 1 s for global scope | Workers limits |
| D1 database | 10 GB | D1 limits |
| Tools per server | 200 | `mcp-shared/src/tools.ts:40` |
| Portal tool index | 1,000, throws on truncation | `portal.ts:92,218` |
| Servers per portal | 40 | MCP Portals docs |
| Description / arguments | 600 / 4,000 chars | `mcp-shared/src/tools.ts:172,175` |

## 5. The compiler

A build-time Node program. Input: an OpenAPI 3.x document plus a mount name. Output: one SQLite
file. Runs in CI on spec change; never at request time.

```sql
CREATE TABLE operations (
  qualified_id  TEXT PRIMARY KEY,   -- 'graph:users.messages.ListMessages'
  api           TEXT NOT NULL,      -- mount name, for filtering
  operation_id  TEXT NOT NULL,
  method        TEXT NOT NULL,      -- upper-case
  path          TEXT NOT NULL,
  safety        TEXT NOT NULL,      -- 'read' | 'write', derived from method
  summary       TEXT,               -- truncated to 600 (MAX_DESCRIPTION)
  tags          TEXT,
  params_json   TEXT NOT NULL,      -- resolved path/query/header params
  body_ref      TEXT,               -- '#/components/schemas/...' UNRESOLVED
  server_url    TEXT NOT NULL
);

CREATE VIRTUAL TABLE operations_fts USING fts5(
  qualified_id, operation_id, summary, path, tags, api,
  content='operations', content_rowid='rowid'
);

CREATE TABLE schemas (
  api  TEXT NOT NULL,
  name TEXT NOT NULL,               -- '#/components/schemas/microsoft.graph.message'
  json TEXT NOT NULL,               -- raw, $refs intact
  PRIMARY KEY (api, name)
);
```

`fts5` must be lower-case — D1 rejects `FTS5` as "not authorized". External-content mode
(`content=`) stores only the inverted index rather than duplicating text.

**Lazy resolution is the core mechanism.** `body_ref` is stored unresolved. At `read`/`write` time
the server walks the `$ref` closure for that one operation against `schemas`, with a cycle guard and
a depth cap. This is what converts 342 MB of eager flattening into a few KB per call.

**Multi-API mounting.** Multiple APIs share one database, distinguished by the `api` column.
Qualified ids (`<api>:<operationId>`) keep `read`/`write` to a single string argument. This
conserves the 40-servers-per-portal budget: one server can mount many APIs and still expose three
tools.

**Operational note:** D1 export does not work on databases containing virtual tables. The documented
workaround is drop → export → recreate; compilation is reproducible from source, so prefer
recompiling over exporting.

## 6. The server surface

Three tools, host-agnostic.

| Tool | Arguments | Behavior | Annotation |
|---|---|---|---|
| `search` | `query`, optional `api`, optional `limit` | fts5 ranked match; returns qualified id, method, path, truncated summary, parameter schema | read-only |
| `read` | `id`, `params` | GET/HEAD only; refuses anything else | read-only |
| `write` | `id`, `params` | POST/PATCH/PUT/DELETE; refuses GET/HEAD | destructive |

`id` is always the **qualified** id (`<api>:<operationId>`) exactly as returned by `search`, never a
bare `operationId` — unqualified ids are ambiguous once a second API is mounted.

**Why `read` and `write` are split rather than one `invoke`.** The gatekeeper's rule is "Reads
happen straight away. Anything that writes waits for your approval." A single `invoke` capable of
issuing either a GET or a DELETE forces the gatekeeper to treat every call as a write. Splitting on
HTTP method lets reads flow without prompting while writes are named per operation in the approval
prompt. The split is enforced server-side against the `safety` column, not merely advertised.

Search results must respect `MAX_DESCRIPTION = 600`; raw Graph descriptions routinely exceed it.

## 7. Auth

**Per-API adapters, not one scheme.** The engine defines a credential adapter interface; each mount
supplies one.

- **Graph** — MCP-native OAuth 2.1. Hosted, the Worker is a resource server publishing
  `/.well-known/oauth-protected-resource` (RFC 9728) and issuing `WWW-Authenticate` challenges on
  401; the client runs the auth-code flow against Entra and we forward its user-scoped bearer
  untouched. Local, the process runs auth-code + PKCE with a loopback redirect and stores the token
  in the OS keychain.
- **Cloudflare API** — an API token supplied by the caller, not held by the Worker.

**The invariant, in both cases: we never hold a credential that can exceed the caller.** This is
already Knitli's established internal pattern — `deployment.jsonc` sets `mcpPortal.auth: "oauth"`,
and the chain user → Access → Workshop → `knitlios-gk-mcp-portal` → Portal → server carries the
user's identity at every hop with no shared secret.

## 8. Security model

Because the server stores no credential, an attacker who defeats Access **and** holds a valid
upstream token gains nothing they could not obtain by calling the upstream API directly. The server
confers no privilege. Residual risk is compute consumption (denial-of-wallet) and read access to
compiled artifacts derived from specifications that are published publicly.

Recorded caveats:

1. **Portal auth gaps.** Independent MFA, purpose justification, and temporary authentication are
   documented as *not enforced* for servers reached through an MCP Portal. Emails, Groups, Country,
   and Device Posture still apply. Pointed at a mail and calendar API, this deserves an explicit
   deployment note.
2. **`Require user auth` must stay enabled.** Disabled, every user rides the admin's credential,
   silently breaking "users stay within their permissions."
3. **Never log `Authorization`.** The Portal can route calls through Gateway for HTTP logging and
   DLP; bearer tokens must never reach a log line.
4. **`trustAnnotations: false`** means our annotations cannot drive auto-approval, so every `write`
   prompts. Correct default for this API class; a real UX cost that should be a conscious choice.
5. **Portal namespacing** is `{server_id}_{original_name}` split on the *first* underscore, so
   **server ids must contain no underscores** — `graph-api`, never `graph_api`.

## 9. Error handling

- **Unknown `operationId`** — refuse with the closest `search` matches rather than a bare error.
- **Method/safety mismatch** — `read` on a write operation refuses and names `write`, and vice
  versa. Enforced against stored `safety`.
- **Parameter validation** — validate against the lazily-resolved schema before any upstream call;
  return the validation failure, never a malformed request.
- **`$ref` cycles** — cycle guard and depth cap; a truncated branch is marked rather than dropped
  silently.
- **Upstream errors** — pass through status and body, sanitized of any `Authorization` echo.
- **Missing/expired credential** — hosted, a 401 with `WWW-Authenticate` per the MCP auth spec;
  local, re-run the PKCE flow.
- **Oversized responses** — truncate with an explicit marker; never silently drop content.

## 10. Testing

- **Compiler, golden-file:** a small fixture spec compiles to a known SQLite state. Plus invariant
  assertions run against the *real* Graph spec in CI — operation count, uniqueness of
  `qualified_id`, zero sanitizer collisions, artifact size within budget.
- **Resolution:** unit tests for `$ref` closure resolution, cycles, depth capping.
- **Surface:** `read` refuses writes and vice versa; search respects `limit` and 600-char
  truncation; unknown ids return suggestions.
- **Auth:** unauthenticated requests get 401 + `WWW-Authenticate`; the token is forwarded verbatim
  and never logged.
- **Host parity:** the same query suite runs against D1 and local SQLite, asserting identical
  results — this is the guarantee that makes one artifact serve two hosts.

## 11. Versioning and distribution

The compiled artifact is versioned by the **upstream spec revision**, not by our package version —
a Graph spec change is not an engine change. Artifacts carry a `meta` row recording source URL,
upstream commit, compile timestamp, and compiler version.

Local plugins download the artifact on first run rather than bundling 5 MB in a marketplace plugin,
with an integrity check against a published digest. Release routing needs a change that this design does not
yet specify: `scripts/generate.mts` derives commit scopes solely from the `plugins` array, and each
entry must resolve to a directory containing `.claude-plugin/plugin.json`. `packages/*` and
`servers/*` are not plugins and would currently produce no scope, so commits touching the engine
have nowhere valid to land. Extending the generator to emit scopes for non-plugin workspaces is a
prerequisite task in the implementation plan, not an assumption.

## 12. Open questions

1. **Search quality.** BM25 over operation ids, summaries, and paths is the starting point. Whether
   it is good enough for an agent to reliably find "accept a meeting invite" among 17,777 operations
   is unproven and should be measured against a fixed query set early.
2. **Graph v1.0 vs beta.** v1.0 is the target. The original motivating case — Outlook invite actions
   with consistent metadata — may only exist in beta (67 MB, preview stability). Verify before
   committing to v1.0 only.
3. **Round-trip cost.** Without code mode, "accept 5 invites and mark them private" is roughly ten
   calls. Acceptable for now; if it proves painful, the answer is a portal-side Code Mode policy,
   not a sandbox of ours.
