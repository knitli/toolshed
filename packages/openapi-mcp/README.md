# @knitli/openapi-mcp

Compile OpenAPI documents into immutable, signed SQLite catalogs. The local MCP
server exposes `search`, `read`, and `action`; it verifies the catalog, request,
destination, credentials, and any required action authorization before dispatch.

The executable artifact format is **5**, runtime contract **1**, and prepared-call
format **2**. This package is compiled TypeScript, separate from the Toolshed
prompt plugins.

## Install and check the runtime

Local serving requires Node `>=24.16.0 <25`. Packed consumers exercise Node 24
and Bun 1.4 compiler/SQLite imports. Bun HTTP socket-adapter support has not been
established; use Node for `serve`. `/runtime` and `/conformance` pass an isolated
WebWorker-only declaration check and browser bundle. This is not evidence of an
actual Cloudflare D1 deployment or D1 conformance.

The source version is `0.0.0`. That version was published under the `bootstrap`
dist-tag on 2026-09-05; its public installation, signatures, provenance, and
installed consumer were verified. See the [bootstrap release record](../../docs/superpowers/reviews/2026-09-05-openapi-mcp-bootstrap.md)
for the exact artifact and workflow binding. This is not a stable `latest`
release or evidence of a successful trusted-publishing release.

For a locally built and tested tarball, install its absolute path from a clean
consumer directory:

```sh
npm install --ignore-scripts /absolute/path/to/openapi-mcp.tgz
node --version
```

After a real stable version is observed in npm, pin that exact verified version
with `npm install --save-exact @knitli/openapi-mcp@<verified-version>`. A bootstrap
`0.0.0` publication uses the `bootstrap` dist-tag and is not a stable release.
The CLI examples below use the consumer's `node_modules/.bin` binary.

## Generate a signing key and compile a release

Use a private operator directory. The generation-state parent must be owned by
the serving user and mode `0700`; retain that state across upgrades and restarts.

```sh
mkdir -m 700 operator operator/keys operator/releases operator/state
./node_modules/.bin/openapi-mcp keygen --out ./operator/keys
./node_modules/.bin/openapi-mcp compile-release \
  --spec ./openapi.yaml --source-label widgets-spec --source-revision revision-1 \
  --catalog widgets --release widgets-1 --generation 1 \
  --issuer example-operator --key-id signing-1 --policy-id local-policy-1 \
  --allowed-origin https://api.example.com \
  --out ./operator/releases --sign-key ./operator/keys/openapi-mcp.key
```

Replace the spec, provenance, identifiers, and origin with your reviewed inputs.
`--source-uri <https-uri>` is an alternative to `--source-label`. Compilation
does not grant permission to call the API. Local references can be bounded with
`--reference-root` and `--reference-map`; do not treat remote spec fetching as a
runtime feature. `--permissions` accepts the permissions dataset used by the
legacy compiler, but permissions annotations are advisory, not authorization.

Keep each v5 SQLite payload beside its matching `.manifest.json` and
`.manifest.sig` files with the same filename stem. Local executable ingress
checks bounded, matching sidecars and admits only a complete manifest-last
bundle. Startup proves every configured release's full record inventory before
starting its conditional generation admissions. A valid signature alone does
not admit a release with missing, malformed, or digest-mismatched records.

The command publishes `widgets-1.sqlite`, `widgets-1.manifest.json`, and
`widgets-1.manifest.sig` under the output directory without replacing an existing
release. `keygen` refuses to overwrite existing files and writes the private key
with mode `0600`. Keep the private key out of runtime deployments. Obtain the
base64url SPKI public key for the config with:

```sh
node --input-type=module -e 'import {readFileSync} from "node:fs"; import {createPublicKey} from "node:crypto"; console.log(createPublicKey(readFileSync("operator/keys/openapi-mcp.pub")).export({type:"spki",format:"der"}).toString("base64url"))'
```

## Configure and start the local MCP server

Save this as `operator/config.json`, substituting absolute paths, the public key,
and the origin present in the signed catalog. Config objects are strict: unknown
fields, duplicate identifiers, unresolved profile references, and invalid limits
are rejected. Origins must be HTTPS origins without credentials, paths, or query
strings. Do not put bearer tokens or API keys in this file; use environment
variable names. Supply those variables through your process supervisor or secret
manager before starting the process.

```json
{
  "version": 1,
  "generationStatePath": "/absolute/path/operator/state/generations.json",
  "catalogs": [{
    "catalogId": "widgets", "releaseId": "widgets-1",
    "path": "/absolute/path/operator/releases/widgets-1.sqlite",
    "profileId": "widgets-user"
  }],
  "trust": {
    "releaseKeys": [{"issuer": "example-operator", "keyId": "signing-1", "publicKey": "REPLACE_WITH_BASE64URL_SPKI"}],
    "rollbackKeys": []
  },
  "allowedOrigins": ["https://api.example.com"],
  "profiles": [{
    "profileId": "widgets-user", "revision": 1,
    "allowedOrigins": ["https://api.example.com"],
    "auth": {"type": "bearer-env", "env": "WIDGETS_TOKEN"}
  }]
}
```

```sh
./node_modules/.bin/openapi-mcp serve --config /absolute/path/operator/config.json
```

This speaks MCP on stdio. Startup errors go to stderr; keep stdout reserved for
the protocol. A client configuration using the installed Node CLI can be:

```json
{
  "mcpServers": {
    "widgets": {
      "command": "/absolute/path/to/node",
      "args": ["/absolute/path/to/node_modules/@knitli/openapi-mcp/dist/cli.js", "serve", "--config", "/absolute/path/operator/config.json"]
    }
  }
}
```

An API-key profile uses `{"type":"api-key-env","env":"WIDGETS_API_KEY",
"placement":"header","name":"X-API-Key"}` (query placement is also supported).
OAuth uses `{"type":"oauth2-pkce","authorizationEndpoint":"https://auth.example.com/authorize",
"tokenEndpoint":"https://auth.example.com/token","clientId":"public-client-id",
"scopes":["widgets.read"]}` with optional `resource`. The resource is a fixed
absolute URI without a fragment, including identifiers such as
`urn:example:widgets`; it is audience metadata, not a credential destination or
token-claim validation. Authorization and token endpoints remain HTTPS URLs.
These endpoints and client
registration must be configured by the operator. The server uses authorization
code PKCE with S256 and a temporary `127.0.0.1` callback listener on an ephemeral
port at `/oauth/callback`; the identity provider must support that redirect.
The client needs URL elicitation for OAuth and form elicitation for confirmation.
Open the offered authorization URL, finish login, then follow the client's resume
flow. Unsupported elicitation fails closed.

## Use the three tools

These are tool names and input objects, not shell commands. Use the opaque
`operation` returned by search unchanged; it binds the release and manifest.

```json
{"name":"search","arguments":{"query":"list widgets","limit":5}}
```

```json
{"name":"read","arguments":{"operation":"<operation returned by search>","arguments":{"query":{"limit":10}}}}
```

```json
{"name":"action","arguments":{"operation":"<action operation returned by search>","arguments":{"path":{"id":"widget-1"},"body":{"label":"Reviewed label"}}}}
```

Choose arguments from the returned input outline and your API's schema. An API
namespace can be supplied as `search.api` when advertised by the mounted catalog.
Read pagination uses the returned opaque `pageToken`; do not construct one.
Upstream response content is untrusted data and cannot authorize further calls.

Each search shares one candidate, record-proof, store-call, work, and response
budget across catalogs. It can authenticate and completely prove at most eight
candidate releases; broad matches or exhausted budgets produce safe omission
warnings. Narrowing the query or selecting an API can reach later configured
catalogs, including catalogs sharing an API namespace. Results are a bounded
ranked sample, not an exhaustive catalog listing. Deprecation demotion and the
requested result limit apply across the combined candidates.

Successful search results, including the MCP content wrapper, trust text, and
warnings, obey the configured `limits.maxResponseBytes`. A smaller-than-minimum
result budget returns a bounded `RESPONSE_LIMIT_EXCEEDED` control error; the
server does not raise the supplied limit to manufacture a successful result.
When embedding `createOpenApiMcpServer`, provide its required `searchRuntime`
port backed by one semantic search context, alongside `routes`, `authorizer`,
and the same reduction-only `limits`. A single-catalog embedding can pass its
existing runtime as `searchRuntime`; the CLI assembles shared search itself.

If an action reports `UPSTREAM_OUTCOME_UNKNOWN`, its error includes the exact
`details.preparedCallDigest` and `retryable: false`. Use that digest to reconcile
the uncertain outcome; the server has consumed the authorization and does not
automatically retry the action.

Actions require server-controlled authorization bound to the prepared request,
credential profile, release, and argument digest. Review the elicited destination,
operation, effect, and arguments, then explicitly confirm. Rejection, cancellation,
expiry, a changed request, or a changed credential binding prevents dispatch.
Destructive operations require the stronger destructive acknowledgment. An operator
may supply narrowly bound `exactPolicies` for eligible create/update operations;
they are not broad scopes or a general confirmation bypass. Do not construct policy
digests from model-supplied values. Policies expire and must match the verified
manifest, operation, credentials, cardinality, and constrained arguments exactly.

## Rotate credentials, keys, and catalogs

Access and refresh tokens are held in process memory. OAuth refresh is supported;
closing or restarting the process clears its token state and pending authorization
flows. Environment credentials are still present if the process supervisor
injects them again. Process restart is local cleanup, not upstream revocation:
revoke the credential at the identity provider/API, remove or rotate its source,
increment the profile revision, then restart the server. The library credential
provider also exposes local revocation; it does not imply provider-side revocation.

For a signing-key rotation, distribute the new public key through the trusted
operator config, compile a new immutable release with a higher generation and the
new key ID, validate it, update the catalog selection, and restart. Remove the old
trust key when no retained approved release needs it. Keep rollback-authority keys
separate from routine release keys. Never overwrite a catalog or reset/delete the
generation state to make an old signature pass.

To disable a catalog, stop the server, remove that catalog from `catalogs`, and
restart with the remaining valid catalogs. Config requires at least one catalog;
leave the server stopped if disabling the last one. Removing a file while the
process is using it is not a reliable disable procedure.

## Recover from a bad release

Before release, record the prior **observed package version**, its tarball digest,
the prior immutable catalog ID/release ID/generation/manifest digest, and the
generation-state location. No prior published package version is asserted here.
After a stable predecessor exists, the downgrade command is
`npm install --save-exact @knitli/openapi-mcp@<recorded-known-good-version>` from the
consumer directory. Restart with the retained catalog and state. Package downgrade
alone does not authorize a signed-data rollback.

The packed Node/Bun exercise compiles generations 1 and 2 with fresh fixture keys.
A damaged generation-2 signature is rejected while generation 1 still searches
and its operation record verifies. After valid generation 2 is admitted, generation
1 is rejected until the separate rollback authority signs the existing v1 rollback
authorization. Activation retains the highest generation at 2, changes the active
generation to 1, consumes the authorization ID, and survives reopening the same
`FileGenerationStore`. This is fixture evidence, not a production rollback.

The stdio config accepts rollback trust keys but does **not** accept an attached
rollback envelope. An operator can activate a pre-signed authorization through the
public API while the server is stopped, then restart stdio against the retained
catalog and the same state. Save the following as `activate-rollback.mjs` inside
an installed consumer. The input authorization must come from your separate
rollback authority; this procedure does not generate or weaken its signature.

```js
import { readFile } from "node:fs/promises";
import { admitManifest } from "@knitli/openapi-mcp/runtime";
import { FileGenerationStore, SqliteCatalogStore } from "@knitli/openapi-mcp/sqlite";
import { parseOpenApiStdioConfig } from "@knitli/openapi-mcp/stdio";

const [configPath, catalogId, authorizationPath] = process.argv.slice(2);
const config = parseOpenApiStdioConfig(await readFile(configPath, "utf8"));
const selected = config.catalogs.find((entry) => entry.catalogId === catalogId);
if (!selected) throw new Error("Catalog is not configured");
const store = new SqliteCatalogStore(selected.path);
try {
  const envelope = await store.getManifest(selected.catalogId, selected.releaseId);
  if (!envelope) throw new Error("Manifest not found");
  const rollback = JSON.parse(await readFile(authorizationPath, "utf8"));
  const admitted = await admitManifest({ ...envelope, rollback }, config.trust,
    new FileGenerationStore(config.generationStatePath));
  console.log({ releaseId: admitted.manifest.releaseId, generation: admitted.manifest.generation });
} finally {
  store.close();
}
```

```sh
node activate-rollback.mjs /absolute/path/operator/config.json widgets /absolute/path/operator/approved-rollback.json
```

Select the prior catalog in the config before running this command. The existing
authorization binds the catalog, issuer, current highest generation, target
generation and manifest digest, expiry, unique ID, reason, and authorized key ID.
It is Ed25519 over `knitli.openapi-mcp.rollback-authorization.v1` followed by a NUL
byte and canonical JSON of the unsigned authorization. The runtime validates that
contract and replay/state constraints. Use the packed consumer fixture as an
executable example for a nonproduction signing exercise; never copy its generated
keys into operator trust.

## Migrate older artifacts

Legacy `compile --spec ... --api ... --out ... [--sign-key ...]` still creates v3
artifacts; `verify --artifact ... --sig ... --pub ...` verifies the exact SQLite
file signature. V3 is inventory-only and does not gain executable trust from that
signature. Recompile the reviewed source with `compile-release` for v5 execution.
Do not relabel or mutate a v3 database as a v5 release.

Strict historical v4 manifests support their tagless read compatibility contract.
Do not add v5 tags to a historical v4 signed record or describe historical v4 as
the current compiler output. V5 signs the manifest and record digests; the legacy
exact-file `verify` command is not a v5 admission test. Use `admitManifest` and the
runtime/store checks when validating release trust.

## Troubleshoot and verify a build

`MANIFEST_INVALID` calls for checking the selected release, exact envelope, and
trusted issuer/key. `MANIFEST_ROLLBACK_REJECTED` requires the recovery procedure,
not a generation-state reset. A generation-state permission error means its
parent must be a real, owner-only directory. Generic startup errors are deliberate
to avoid exposing config secrets; validate with `parseOpenApiStdioConfig` in a
controlled operator process. Missing environment credentials or OAuth elicitation
must be resolved before a call can proceed. An action refused for lack of
confirmation needs an elicitation-capable client or an eligible reviewed exact
policy. Do not retry a changed action with old approval state.

From the repository, the package checks are:

```sh
mise exec -- bun run --cwd packages/openapi-mcp build
mise exec -- bun test packages/openapi-mcp
mise exec -- bun run --cwd packages/openapi-mcp test:node-transport
mise exec -- bun run --cwd packages/openapi-mcp test:node-stdio
mise exec -- bun scripts/generate.mts --check
mise exec -- bun run validate
(cd packages/openapi-mcp && mise exec -- bun pm pack --dry-run)
```

`tests/package-consumers.test.ts` builds/packs once, installs that tarball in fresh
Node, Bun, and Worker directories outside the repository, executes the fixtures
there, and prints the artifact path, SHA-256, and evidence directory. Set
`OPENAPI_MCP_TARBALL` to an absolute tarball path to verify those exact bytes.
The tarball includes all five public subpaths, declarations, the CLI, README, and
unmodified MIT and Apache 2.0 licenses. Test specs, credentials, fixture databases,
and consumer scripts are excluded. The exported conformance fixture module is
part of the public `/conformance` API and does ship.

Phase 3 must run the exported `runRuntimeConformanceSuite` against actual D1 in
a Workers test environment and verify the deployed integration. A structural D1
fake, portable declarations, or a browser bundle does not establish that result.
The optional large Microsoft Graph corpus check remains skipped when its local
fixture is absent; no large-corpus performance claim is made here.

## Release gates

Only the protected `npmrelease` GitHub environment may publish this package.
Steady-state npm trusted publishing must bind exactly `knitli/toolshed`,
`.github/workflows/release.yml` (publisher workflow name `release.yml`), and
`npmrelease`, with `id-token: write`. It must not receive `NPM_TOKEN` or
`NODE_AUTH_TOKEN`. The release adapter tests a Bun-packed artifact and invokes
npm with that exact tarball from a clean directory under `RUNNER_TEMP`.
`OPENAPI_MCP_OIDC_READY` is operator-controlled release enablement, not proof of
publisher configuration or provenance. Set it to `true` only after recording the
external setup and bootstrap-cleanup gates. Until then, build/test/validation
still run and publication is explicitly reported as pending. A real build,
publication, or audit failure continues to fail the job and its dependents.

The one-time `0.0.0` bootstrap is complete. Its manual dispatch and token-backed
jobs have been removed; do not rerun publication of that version. The adapter
still rejects token environment mappings, including mappings in disabled jobs.
The [bootstrap release record](../../docs/superpowers/reviews/2026-09-05-openapi-mcp-bootstrap.md)
separates verified publication and secret removal from owner-reported npm setup
and the remaining first-`latest` gate.

After publication, the verification step waits for the exact version to appear
in the public package listing before attempting a fresh installation. Only a
missing package or missing version is retried: at most six requests, each with
a ten-second timeout, separated by ten-second waits. Invalid metadata and other
errors fail the check. This readiness probe cannot guarantee every registry
replica or tarball URL is ready. Installation, cryptographic verification, and
consumer checks remain mandatory; publication itself is never retried by this
probe.

For bootstrap and every stable release, retain a fresh public install's
`npm audit signatures --json --include-attestations` output in the protected job
artifact, along with its SHA-256. Require successful cryptographic verification
and verify package identity/integrity, source commit, repository, workflow, and
CI run against the release being approved. Registry metadata from `npm view`
alone is insufficient. Record CI and semantic-release completion, registry
version/dist-tag visibility, the matching stable Git tag/release, protected
environment and publisher configuration, bootstrap cleanup/revocation when used,
and the exact-version public consumer result. Any unobserved or failed gate stays
pending. Local tests and workflow code are not evidence of publication.
