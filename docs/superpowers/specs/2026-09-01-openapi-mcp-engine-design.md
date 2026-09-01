# OpenAPI → MCP Engine — Design

**Date:** 2026-09-01
**Revision:** 2 — revised after adversarial review (architecture, security, fact-check)
**Status:** Approved shape, pending implementation plan
**Scope:** A reusable engine in `knitli/toolshed` that turns any OpenAPI document into a small,
searchable MCP tool surface, deployable as a Cloudflare Worker or run locally, with Microsoft Graph
and the Cloudflare API as the first two mounts.

## 1. Problem

Large APIs cannot be exposed as MCP tools by enumeration. Microsoft Graph v1.0 has **17,777
operations** across 11,493 paths; the Cloudflare API has **3,412 operations** across 2,129 paths
(measured against `cloudflare/api-schemas`, `openapi.json`). Every layer that would consume them
imposes a ceiling far below that:

- Knitli's gatekeeper caps a server at **`MAX_TOOLS_PER_SERVER = 200`**
  (`mcp-shared/src/tools.ts:40`), and `connection.ts:202` hard-caps any endpoint's tool listing at
  200. The generic connector's grant UI (`gatekeeper-mcp/src/mcp.ts:370`,
  `requireCompleteCatalogForToolSelection`) **refuses outright** on a truncated catalog rather than
  silently truncating — so exceeding 200 breaks the connect flow, it does not merely lose tools.
- The portal tool index caps at 1,000 and throws on truncation (`portal.ts:92,218`).
- No LLM context can hold a 17,777-entry tool list regardless of transport.

The fix is to stop shipping tools and start shipping *search*. The agent receives a small fixed set
of tools and discovers operations at runtime against a compiled index.

## 2. Non-goals

Each was considered, investigated, and cut on evidence:

- **We do not build or operate code mode.** Where wanted it is supplied by the layer above — the MCP
  Portal's Code Mode, or a Dynamic Worker's built-in one. `@cloudflare/codemode` is not a dependency.
- **We do not ship a bare-tools surface.** It fails the 200-tool cap for both target APIs.
- **We do not own a code sandbox.** No `node:vm`, no `isolated-vm`, no local `workerd`.
- **We do not dereference `$ref`s at build time** (§4).
- **We do not invent an operation-naming scheme** (§4).

Note what is *not* a non-goal: minimising tool count. Revision 1 treated "exactly three tools" as a
design pillar. It was an aesthetic preference, and §6 now spends tool budget deliberately, because
tool name is the only approval-granularity knob the surrounding infrastructure exposes.

## 3. Architecture

```
BUILD TIME (CI, Node)                      RUNTIME (two hosts, one implementation)
  openapi.yaml (42 MB)                       Worker + D1          local process + SQLite
  + permissions dataset                           \                     /
        |                                          \                   /
        v  compile                                  tool surface (§6):
  api.sqlite                                          <api>_search
    operations      (thin rows, $refs intact)         <api>_read
    operations_fts  (fts5, external-content)          <api>_write_routine
    schemas         (name -> raw JSON)                <api>_write_high
    meta            (provenance + format version)          |
        |                                                  v
        +--> wrangler d1 import  --> D1              upstream API
        +--> signed download     --> local        (caller's credential, guarded fetch)
```

One compiled artifact serves both hosts because **D1 is SQLite**: the Worker binds it as D1, a local
process opens it with `node:sqlite`/`bun:sqlite`.

**A driver abstraction is a named component, not an implementation detail.** D1's binding API is
async (`env.DB.prepare().bind().all()`); `node:sqlite` and `bun:sqlite` are synchronous, and
`node:sqlite` is still an experimental Node API. The layer reconciling these is where host-specific
bugs will live (prepared-statement caching, parameter binding, error shapes), so §10 tests it
directly rather than only testing query results.

### Repository layout

```
plugins/<name>/          marketplace manifest only (existing convention)
packages/openapi-mcp/    the engine: compiler + server + driver abstraction
servers/<deployment>/    wrangler.jsonc, D1 binding, mounted APIs
```

This introduces TypeScript and a build step to a repo whose `CLAUDE.md` states it has "no compiled
code" and "no build step"; that must be rewritten during implementation. Root `package.json` already
has `workspaces.packages: ["plugins/*"]`, which gains `packages/*` and `servers/*`.

### Consumers

| Consumer | Path | Approval layer |
|---|---|---|
| Knitli internal | Access → Workshop → `knitlios-gk-mcp-portal` → Portal → us | gatekeeper |
| `knitli-site` Dynamic Workers | via the Portal, code mode applied by the Worker | gatekeeper |
| M365 Copilot | direct remote MCP, no portal | client-dependent |
| Marketplace users | local process | **the MCP client only** (§8.6) |

## 4. Measurements

Measured 2026-09-01 against `microsoftgraph/msgraph-metadata@master`, `openapi/v1.0/openapi.yaml`.
Independently reproduced during adversarial review.

| Fact | Value |
|---|---|
| Spec size | 44,146,442 B; beta 70,582,558 B |
| Paths / operations | 11,493 / **17,777** |
| Component schemas / responses | 5,127 / 1,267 |
| Thin compilation (all ops) | **4.9 MB** — mean 286 B, p50 233 B, p99 661 B, max 819 B |
| Dereferenced, structural depth 4 | **342.4 MB** — mean 20 KB, p99 130 KB, max 140 KB |
| Dereferenced, per-`$ref`-hop | **intractable** — see below |
| `operationId` coverage | 17,777 / 17,777, all unique |
| After `sanitizeToolName` | 17,777 unique, **zero collisions** |
| `operationId` length | p50 52, p99 142, max 276; 5,447 > 64 chars, 392 > 128 |
| Descriptions exceeding 600 chars | 241 (1.4%); max 1,439 |
| `x-ms-pageable` | 2,760 operations |
| `deprecated` | 85 operations |
| `x-ms-docs-operation-type` | `operation` 11,191, absent 3,350, `action` 2,073, `function` 1,163 |

**Dereferencing is not viable, and the 342 MB figure understates it.** That measurement decremented
its depth budget on *every* level of JSON nesting, which is a stricter cap than the `$ref`-hop cap
§5 actually describes. Re-measured spending budget only on `$ref` traversal, a 300-operation sample
(1.7% of the set) reached 35.5 MB with a single operation —
`admin.teams.CreateUserConfigurations` — at **6.4 MB**, versus a 140 KB maximum for *any* operation
under the stricter cap. The full-set run did not terminate, because Graph's schema graph is heavily
diamond-shaped through shared base types like `microsoft.graph.entity`. **342.4 MB is a lower
bound.**

**Cloudflare's own OpenAPI code-mode server cannot ingest Graph**, for two independent reasons.
`codemode.spec()` eagerly dereferences the entire raw spec on first call (`__resolveRefs`, recursive,
cycle guard only, no depth cap). More immediately, `createOpenApiSandboxCode` `JSON.stringify`s the
*entire* raw spec into the generated sandbox code string on **every tool call**, for both `search`
and `execute`, whether or not `spec()` is ever invoked — roughly 44 MB re-serialised per call,
independent of dereferencing.

**Operation naming needs no scheme.** `sanitizeToolName`
(`cloudflare/agents/packages/codemode/src/utils.ts`) does character replacement with **no length
truncation**; run against all 17,777 real operationIds it yields zero collisions. This is moot for
the surface in §6, where operation ids are data rather than tool names, and is retained as evidence.

### Platform ceilings

| Limit | Value | Source |
|---|---|---|
| Worker bundle | 3 MB gzip free / 10 MB paid; 64 MB uncompressed both | Workers limits |
| Worker memory | 128 MB per isolate | Workers limits |
| Worker startup | 1 s for global scope | Workers limits |
| D1 database | 10 GB paid / **500 MB free** | D1 limits |
| Tools per server | 200 | `mcp-shared/src/tools.ts:40`, `connection.ts:202` |
| Portal tool index | 1,000, throws on truncation | `portal.ts:92,218` |
| Servers per portal | 40 | MCP Portals docs |
| Description / arguments | 600 / 4,000 chars | `mcp-shared/src/tools.ts:172,175` |

## 5. The compiler

A build-time Node program. Inputs: an OpenAPI 3.x document, a mount name, and (where published) a
permissions dataset. Output: one signed SQLite file. Runs in CI on spec change; never at request
time.

```sql
CREATE TABLE operations (
  qualified_id    TEXT PRIMARY KEY,   -- 'graph:users.messages.ListMessages'
  api             TEXT NOT NULL,
  operation_id    TEXT NOT NULL,
  method          TEXT NOT NULL,
  path            TEXT NOT NULL,
  safety          TEXT NOT NULL,      -- 'read' | 'write'  (see below)
  risk            TEXT NOT NULL,      -- 'routine' | 'high'
  operation_type  TEXT,               -- action | function | operation
  pageable        INTEGER NOT NULL DEFAULT 0,
  deprecated      INTEGER NOT NULL DEFAULT 0,
  permissions     TEXT,               -- JSON array, may be NULL (22% of Graph)
  perm_confidence TEXT,               -- 'exact' | 'suffix' | 'prefix' | NULL
  privilege_level INTEGER,            -- 1-5, from the permissions dataset
  summary         TEXT,               -- truncated to 600
  tags            TEXT,
  params_json     TEXT NOT NULL,
  body_ref        TEXT,               -- UNRESOLVED
  server_url      TEXT NOT NULL       -- cross-checked at load, §8.3
);

CREATE VIRTUAL TABLE operations_fts USING fts5(
  qualified_id, operation_id, summary, path, tags, api,
  content='operations', content_rowid='rowid'
);

CREATE TABLE schemas (
  api TEXT NOT NULL, name TEXT NOT NULL, json TEXT NOT NULL,
  PRIMARY KEY (api, name)
);

CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
-- source_url, upstream_commit, compiled_at, compiler_version, format_version
```

`fts5` must be lower-case — D1 rejects `FTS5` as "not authorized". External-content mode stores only
the inverted index. `format_version` is a compatibility contract: a server refuses an artifact whose
`format_version` it does not implement.

**Lazy resolution is the core mechanism.** `body_ref` is stored unresolved; at call time the server
walks the `$ref` closure for one operation against `schemas` with a cycle guard and a `$ref`-hop
depth cap. Resolution is **breadth-first and batched** — one `IN (...)` query per hop, not one query
per discovered `$ref` — because a naive recursive resolver is N+1 against D1. Given the 6.4 MB
single-operation result in §4, resolution is also **byte-capped**, returning a marked-truncated
schema rather than an unbounded one.

### Safety classification

`safety` is derived from HTTP method, **corrected by an explicit override list**. Method alone is
wrong for both target APIs: 53 Graph operations are POSTs that are semantically reads (`getByIds`,
`getMemberGroups`, `checkMemberObjects`). OData's own taxonomy does not rescue this — `function` is
exclusively GET (1,163) and `action` exclusively POST (2,073), so `x-ms-docs-operation-type` agrees
with the method rather than correcting it. The override list is compiled data but **never trusted at
runtime**: §8.3 recomputes the method-to-safety default at load and treats any artifact claiming
`safety='read'` for a non-GET/HEAD method as valid only if that override is also present in an
engine-side constant.

**`$batch` is hard-pinned to `write`** regardless of its contents, since a single POST can bundle
arbitrary sub-request methods.

`risk` is derived from `privilege_level` where known, defaulting to `high` when unknown.

### Permission mapping

The Graph OpenAPI document contains **no permission data** — zero operation-level `security`, empty
`securitySchemes`. Microsoft publishes it separately in `microsoft-graph-devx-content`
(`permissions/new/permissions.json`): 818 permissions inverting to 10,571 `(path, method)` pairs.
Coverage against Graph's 17,777 operations:

| Strategy | Coverage |
|---|---|
| Exact path match | 18% |
| + OData suffix stripping (`$count`, `$ref`, `$value`) | 23% |
| + longest-prefix inheritance | **77%** |
| Unmapped | **22%** (3,935 operations) |

`perm_confidence` records which strategy produced each row, because 54 points of that coverage come
from prefix inheritance — a heuristic that can *understate* the permission a child path requires.
**This is advisory data, not an authorization boundary** (§7).

### Multi-API mounting

Multiple APIs share one database, distinguished by `api`, with qualified ids keeping tool arguments
to a single string. This conserves the 40-servers-per-portal budget, and the trade-off is stated
rather than free: the portal's grant and approval model has no concept of `api=graph` vs
`api=cloudflare`, so mounting is only safe because §6 gives each API its own tool names.

**Operational note:** D1 export does not work on databases containing virtual tables. Recompile from
source rather than exporting.

## 6. The tool surface

**Tool names are the approval-granularity knob**, so the surface is per-API and per-risk-tier rather
than universal. `actionKindFor(scopeTag, toolName)` (`tools.ts:118`) mints the persisted-approval key
as `${scopeTag}:${toolName}`, and `describeCall` renders the prompt title as
`${serverName}: ${tool.name}` — the *tool name*, never the operation, which appears only inside the
arguments block. A single `write` tool would therefore collapse Graph mail deletion, calendar
deletion, and Cloudflare DNS changes into one approval identity, and one remembered decision would
cover all of them. Locally the same applies to a client-side allowlist.

This is confirmed, not hypothetical. `overseer.ts` exposes
`setAutoApprovedActionKind(gatekeeperId, actionKind)`, which persists a user opt-in into
`autoApproveTags` keyed by `${gatekeeperId}:${actionKind.tag}` — and `actionKind.tag` is
`${scopeTag}:${toolName}`. The stored rule is **workspace-wide per gatekeeper**, not per user. So the
tool split is load-bearing, not defence in depth: without it, one person's single "always allow"
on `write` would auto-approve every mutation on every mounted API, for the whole workspace.

Per mounted API:

| Tool | Does | Classification |
|---|---|---|
| `<api>_search` | fts5 ranked match; returns qualified id, method, path, truncated summary, params, required permissions | read-only |
| `<api>_read` | GET/HEAD, plus the explicit read-override list | read-only |
| `<api>_write_routine` | mutations at `privilege_level` 1-3 | requires approval |
| `<api>_write_high` | mutations at `privilege_level` 4-5, unknown privilege, or `$batch` | requires approval |

Four tools per API against a 200 cap supports roughly 50 mounts. `id` is always the **qualified** id
(`<api>:<operationId>`) exactly as returned by search; unqualified ids are ambiguous once a second
API mounts. Underscores in tool names are safe — portal namespacing splits on the *first* underscore
only, which constrains server ids, not tool names.

`search` returns descriptions truncated to 600 chars; only 1.4% of Graph operations need it, but the
cap is the gatekeeper's. Deprecated operations are demoted in ranking and flagged. Pageable
operations (`x-ms-pageable`) expose an explicit continuation parameter so `read` handles
`@odata.nextLink` rather than silently returning a first page.

## 7. Auth

**Per-API adapters.** Graph uses MCP-native OAuth 2.1: hosted, the Worker is a resource server
publishing `/.well-known/oauth-protected-resource` (RFC 9728) and issuing `WWW-Authenticate`
challenges on 401, forwarding the caller's user-scoped bearer untouched; local, the process runs
auth-code + PKCE against Entra. The Cloudflare API takes a caller-supplied token. **We never hold a
credential that can exceed the caller** — already Knitli's established pattern
(`deployment.jsonc` sets `mcpPortal.auth: "oauth"`).

**Scope pre-flight is advisory.** Using the §5 permission data, the server can tell a caller that an
operation needs `Mail.ReadWrite` before attempting it, and drive incremental consent for exactly that
scope. It **fails open with a warning** on the 22% it cannot map, and it is not an authorization
boundary — Entra is.

**The admin-consent ceiling protects everyone except the operator.** 517 of 653 delegated permissions
require admin consent, so an ordinary marketplace user cannot self-consent to most of Graph — a real
bound we neither control nor need to. That bound **does not apply to a tenant owner**, who can
consent to everything. For the primary operator, therefore, the engine's own controls — the §6 tool
split, §8.1 approval-on-write, and scope pre-flight — are the *only* thing between an injected
instruction and full tenant access. The mitigation that protects third parties is exactly absent for
the person most likely to run this.

**Local credential handling.** The PKCE loopback listener binds `127.0.0.1` with short-lived state,
and the authorization code — which appears in a query string — is covered by the same never-log rule
as bearer tokens (§8.5), as are Entra token-endpoint error bodies. Refresh tokens go in the OS
keychain, which gates other *users* but **not other processes running as the same user** — so a
long-lived broad-scope token coexists with whatever else that account runs, including package
postinstall scripts. Stated rather than implied.

## 8. Security model

The server stores no credential, so an attacker who defeats Access *and* holds a valid upstream token
gains nothing they could not obtain by calling the upstream API directly. That is necessary but not
sufficient: the real exposure is whether one approved action, one poisoned artifact, or one injected
instruction generalises beyond what a human intended.

### 8.1 Prompt injection is the primary threat

`read` returns attacker-controlled content — mail bodies, invite text, display names, file
contents — into an agent that can then call `write`. This is the canonical email-to-agent-to-tool
chain, and for a mail API it is the threat that matters most.

**Approval-on-every-write is the load-bearing mitigation, not a UX side effect.** Auto-approval
requires two gates (`overseer.ts`): the action's own `autoApprovable` verdict, which needs
`trust === "vetted"`, AND a stored user opt-in rule. `trustAnnotations: false` fails the first gate,
so the mechanism is inert today — but it is one configuration flag away from active, and the opt-in
rules it would then honour are workspace-wide per gatekeeper. `trustAnnotations` staying `false` is
therefore a **permanent invariant for this deployment**, not a tunable; revision 1 wrongly framed it
as "a real UX cost that should be a conscious choice."

Rendering discipline follows: `mcp-shared` already has `quoteUntrusted`/`defuseFences` so a malicious
*tool description* cannot hijack an approval prompt's Markdown. `read` results echoed into a later
`write` prompt need equivalent hardening, or the same fence- and heading-injection tricks work
against the human approver.

Injection plus a single approved `write` also yields **persistence** — an Outlook forwarding or inbox
rule outlives the session and exfiltrates mail indefinitely. That, not "read access to public specs,"
is the correct ceiling on residual risk.

### 8.2 Outbound requests must not leak the bearer

Graph legitimately 302s content endpoints (`driveItem/content`, attachment `$value`) to SharePoint
and blob hosts. Under default fetch semantics the caller's `Authorization` header follows the
redirect to a non-Microsoft origin. `mcp-shared/src/fetch.ts` already solves exactly this for the
portal's own outbound leg: manual redirect following, `MAX_REDIRECTS = 3`, per-hop revalidation, and
`headers.delete("Authorization")` when a hop leaves the original origin. **The engine adopts the same
pattern**; this is a solved problem one file away.

### 8.3 The compiled artifact is untrusted input

`safety` and `server_url` are compiled data that decide whether a call prompts and where a bearer is
sent. A poisoned artifact could mark a destructive operation `read` — executing with no prompt at
all — or redirect every request to an attacker host. Therefore:

1. Artifacts are **signed**, with the verifying key shipped in plugin source rather than fetched
   alongside the artifact. A digest published beside the download is trust-on-first-use, not
   integrity.
2. `safety` is **recomputed from `method` at load**; a stored `read` on a mutating method is honoured
   only if the same override exists in an engine-side constant.
3. `server_url` is checked against a **small engine-side allowlist per mount**, independent of the
   artifact.

### 8.4 Grant scope versus what is mounted

The portal's grant model scopes to one upstream server, and its approval key
(`mcp-portal:{endpoint}:{serverId}-{scope.serverId}`) contains no tool name and no API. Per-API tool
names (§6) are what keep "grant calendar access" from silently meaning "grant Cloudflare DNS access."

### 8.5 Logging

Never log `Authorization`, PKCE authorization codes, or token-endpoint error bodies. The Portal can
route calls through Gateway for HTTP logging and DLP, so this is not hypothetical.

The engine emits its own **audit record per call** — qualified id, caller subject, timestamp,
approval path, outcome — independent of Gateway. The local deployment has no portal and no Gateway,
so without this it has *no* audit trail at all.

### 8.6 The local path has a different control set

Local means no gatekeeper, no portal, no Gateway. Authorization is still strictly bounded by the
user's own delegated token, and cross-user risk is zero. But the approval layer becomes **whatever
the MCP client provides**, and client permission is granted per tool name — the same failure mode as
the portal, which is why §6's tool split serves both paths.

### 8.7 Rate limiting and revocation

The engine rate-limits per caller independently of upstream throttling: a `write` loop against the
Cloudflare API creates and destroys real infrastructure, which is not comparable to burning compute.
Local installs get a documented revocation path for the stored refresh token.

### 8.8 Recorded platform caveats

- Independent MFA, purpose justification, and temporary authentication are **not enforced** for
  servers reached through an MCP Portal. There is no session-freshness control at this layer for a
  mail, calendar, and identity API. This is a gap, not a documentation task.
- The portal's `Require user auth` must stay enabled; disabled, every user rides the admin's
  credential.
- Server ids must contain no underscores (portal namespacing splits on the first one). Currently
  inert, but it becomes a collision surface if per-mount tool prefixing is ever added.

## 9. Error handling

- **Unknown id** — refuse with closest `search` matches.
- **Safety mismatch** — `read` on a mutating operation refuses and names the correct tool; enforced
  against recomputed safety, not the stored column alone.
- **Parameter validation** — validate against the resolved schema before any upstream call. Graph's
  polymorphic `@odata.type` schemas use `oneOf`/discriminators; validation resolves the discriminator
  or refuses rather than guessing.
- **`$ref` cycles / oversized closures** — cycle guard, hop cap, byte cap; truncation is marked.
- **Upstream errors** — pass through status and body, sanitised of credential echo.
- **Retries** — `read` may be retried; `write` is **not** retried automatically, since accept-invite
  and send-mail are non-idempotent and a timeout is not proof of non-execution.
- **Missing/expired credential** — 401 with `WWW-Authenticate` hosted; re-run PKCE locally.
- **Oversized responses** — truncate with an explicit marker.

## 10. Testing

- **Compiler golden-file** on a fixture spec, plus invariants asserted against the *real* Graph spec
  in CI: operation count, `qualified_id` uniqueness, artifact size, and that no mutating method
  carries `safety='read'` without an engine-side override.
- **Resolution:** cycles, hop caps, byte caps, and that resolution is batched rather than N+1.
- **Surface:** tool split enforced server-side; search honours `limit` and 600-char truncation;
  unknown ids return suggestions; `$batch` always classifies high.
- **Security:** artifact signature rejection; a tampered `safety` column does not bypass approval; a
  tampered `server_url` is refused; `Authorization` is dropped across a cross-origin redirect;
  credentials never appear in logs.
- **Host parity:** the same suite runs against D1 and local SQLite, testing the driver abstraction
  itself — async/sync, parameter binding, error shapes — not only result equality.

## 11. Versioning and distribution

Artifacts are versioned by **upstream spec revision**, not engine version, and carry `meta` recording
source, upstream commit, compile time, compiler version, and `format_version`. Local plugins download
on first run — **signature-verified against a key in plugin source** — rather than bundling 5 MB in a
marketplace plugin.

**Prerequisite:** `scripts/generate.mts` derives commit scopes solely from the `plugins` array, and
each entry must resolve to a directory containing `.claude-plugin/plugin.json`. `packages/*` and
`servers/*` are not plugins and would produce no valid scope, so engine commits would fail the
commitlint gate. Extending the generator is prerequisite work in the implementation plan.

## 12. Open questions

1. **Search quality is the load-bearing unknown.** BM25 over ids, summaries, paths and tags is the
   starting point; whether an agent reliably finds "accept a meeting invite" among 17,777 operations
   is unproven. The `tags` column supports a cheap two-stage retrieval (facet narrow, then rank
   within facet) if flat ranking disappoints. This needs a fixed query set and the §8.5 audit records
   as instrumentation — measure before building alternatives.
2. **Round-trip cost.** "Accept 5 invites and mark them private" is roughly twelve calls and ten
   approval prompts. Graph's `$batch` is itself a catalogued operation and could collapse that
   without new mechanism — at the cost of pinning it to `write_high` and rendering bundled
   sub-requests intelligibly in one approval prompt. Worth prototyping before accepting the friction.
3. **v1.0 vs beta.** v1.0 is the target; the motivating Outlook-invite workflow may need beta
   (70,582,558 B, preview stability). Verify before committing.
*(A fourth question — whether a human "remember this decision" affordance exists independent of
`trustAnnotations` — was resolved during review. It does exist, is keyed at tool-name granularity,
and its rules are workspace-wide per gatekeeper; it is gated off only by `trustAnnotations: false`.
See §6 and §8.1.)*
