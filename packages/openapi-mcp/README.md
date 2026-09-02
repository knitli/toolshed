# @knitli/openapi-mcp

Compiles OpenAPI documents into signed SQLite artifacts for MCP serving. Point it
at an OpenAPI spec (and, optionally, a permissions dataset) and it produces a
single portable `.sqlite` file that an MCP server can load and query directly —
no runtime spec parsing, no schema walking at request time.

## Install

```bash
npm i -g @knitli/openapi-mcp
# or run without installing:
bunx @knitli/openapi-mcp compile --spec ./openapi.yaml --api my-api --out ./my-api.sqlite
```

Requires Node >=24 or Bun. Both runtimes work end to end; Bun is substantially
faster on large YAML specs (see Performance below).

## CLI

### `compile`

```bash
openapi-mcp compile --spec <path> --api <name> --out <path> \
  [--append] [--permissions <path>] [--sign-key <path>]
```

- `--spec` — path to an OpenAPI document (YAML or JSON).
- `--api` — short name for this API, used to namespace rows when multiple
  specs are mounted into one artifact.
- `--out` — output artifact path.
- `--append` — mount this API into an existing artifact at `--out` instead of
  creating a new one, alongside APIs already compiled into it.
- `--permissions` — path to a permissions dataset JSON file (see below) used
  to annotate operations with required scopes/privilege level.
- `--sign-key` — path to an Ed25519 private key PEM; if given, the artifact is
  signed and the signature written to `<out>.sig`.

### `keygen`

```bash
openapi-mcp keygen
```

Generates an Ed25519 keypair and prints the public key PEM followed by the
private key PEM to stdout. Keep the private key to sign artifacts with
`compile --sign-key`; ship the public key alongside consumers so they can
verify.

### `verify` (in progress)

```bash
openapi-mcp verify --artifact <path> --sig <path> --pub <path>
```

Verifies an artifact's Ed25519 signature against a public key PEM, exiting
non-zero on mismatch. This subcommand is landing in a parallel change to this
package; the signing/verification primitives it wraps already exist in
`src/sign.ts`.

## Artifact format

Each artifact is a plain SQLite database (readable with `sqlite3`, `node:sqlite`,
or any SQLite client) with:

- **`operations`** — one row per OpenAPI operation: method, path, safety
  (`read`/`write`), risk (`routine`/`high`), permissions, privilege level,
  summary, tags, parameters, and request body schema reference.
- **`operations_fts`** — an `fts5` full-text index over operation id, summary,
  path, tags, and api, for fast keyword lookup across large specs.
- **`schemas`** — named JSON schema definitions, keyed by `(api, name)`.
- **`meta`** — key/value provenance: `format_version`, `compiler_version`,
  the JSON array `apis` of every API mounted into this artifact, and
  per-API `<api>.source_path` / `<api>.compiled_at` timestamps.

`FORMAT_VERSION` is bumped whenever the layout changes incompatibly; artifacts
carry their format version in `meta` so a server can refuse to load an
artifact it doesn't understand. `--append` mounts an additional API into an
existing artifact without disturbing rows already compiled from other APIs.

## Permissions dataset format

A permissions dataset is a JSON file shaped as:

```json
{
  "permissions": {
    "SomePermission.ReadWrite": {
      "schemes": { "application": { "privilegeLevel": 2 } },
      "pathSets": [
        { "methods": ["GET", "POST"], "paths": { "/some/path/{id}": {} } }
      ]
    }
  }
}
```

`compile --permissions` builds an index from this shape and annotates matching
operations with `permissions`, `privilege_level`, and a `perm_confidence`
(exact vs. heuristic match).

The Microsoft Graph dataset is a convenient real-world example:

- Spec: https://raw.githubusercontent.com/microsoftgraph/msgraph-metadata/master/openapi/v1.0/openapi.yaml
- Permissions: https://raw.githubusercontent.com/microsoftgraph/microsoft-graph-devx-content/master/permissions/new/permissions.json

```bash
curl -o graph.yaml https://raw.githubusercontent.com/microsoftgraph/msgraph-metadata/master/openapi/v1.0/openapi.yaml
curl -o graph-permissions.json https://raw.githubusercontent.com/microsoftgraph/microsoft-graph-devx-content/master/permissions/new/permissions.json
openapi-mcp compile --spec graph.yaml --api graph --out graph.sqlite --permissions graph-permissions.json
```

## Performance

YAML parsing dominates compile time on large specs; JSON specs are fast under
either runtime. On the 44 MB Microsoft Graph OpenAPI YAML:

- Bun (native YAML parsing): ~0.5 s
- Node (falls back to the `yaml` package): ~12.6 s

End-to-end compile of the full Graph API (17,777 operations, 5,127 schemas)
takes ~1.2 s on Bun on Apple Silicon, producing a ~25 MB artifact.
