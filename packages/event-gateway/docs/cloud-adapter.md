# Closed cloud control-plane adapter

For the private config format and explicit attach invocation, see the
[README quick start](../README.md#explicit-cloud-attachment-lifecycle).

`src/event_gateway/cloud.py` supplies an injected, asynchronous HTTP client for
the existing Event API. It has no default HTTP transport, credential discovery,
CLI wiring, listener activation, native submission, or attachment qualification.
The shipped gateway still uses its existing unavailable authority. Cloud claims
are returned as the exact validated cloud DTO, not the older local `Permit`.

## Ports and boundaries

Construct `CloudClient` with the exact HTTPS Event origin, owner, agent, node ID,
node generation, local Ed25519 key, asynchronous `credentials` and `send`
callables. Its node generation is a snapshot; construct a new client after
owner-approved reenrollment. Credentials are obtained anew on every request,
kept in memory, omitted from their representation, and never persisted or logged.
The provider must supply a fresh human Event Access token and a registered
agent's short-lived token for that same Event origin and owner. This module does
not manufacture either identity or change Access policy.

The HTTP port receives `method`, `url`, `headers`, `body`, `timeout`,
`max_response_bytes`, and `follow_redirects=False`; it returns
`(status, lowercase_header_dict, body_bytes)`. The port must enforce the byte
limit while reading, honor cancellation/deadlines, and never follow redirects.
The adapter independently rejects redirects, encoded bodies, non-JSON replies,
duplicate JSON keys, bodies over 8 KiB, unknown fields and unknown outcomes.
One five-second deadline covers credentials, signing and the HTTP call.
Provider/transport exceptions, including exceptions already typed as `CloudError`,
become fixed codes without their original message. Timeouts retain
`request_timeout`; cancellation propagates.
Malformed response JSON, UTF-8, duplicate keys and excessive nesting return
`invalid_response`, distinct from provider/transport `unavailable`.
Envelope and ACK identity mismatches retain `identity_mismatch`; parse failures
retain their separate `invalid_envelope` or `invalid_acknowledgment` codes.

`cf-access-token` authenticates to the Access edge, which supplies the original
`cf-access-jwt-assertion` to Event. `Authorization: Bearer ...` carries the agent
token. Node proofs use a fresh nonce and timestamp and bind exact raw request
bytes, POST path, Event origin, owner, node ID and generation. No credentials
occur in signed node-proof JSON.

- `claim(envelope)` returns the closed `admitted` or `over_budget` DTO. An
  original queued envelope is validated at its issuance time so transport expiry
  cannot prevent fresh cloud admission. An admitted reply includes UUID `permitId`, matching `nodeId`, an exact
  five-second window, and the returned envelope. An authentic historical reply
  may contain an expired original permit; durable recovery stores it for
  settlement, and the final submission transaction rejects its use for a start. Only transport `issuedAt` and
  `expiresAt` may differ from the requested envelope. All semantic fields,
  including runtime, attempt and generation identity, remain bound. The returned
  envelope must cover the permit lifetime. No conversion discards refreshed data.
- `settle_no_start(admission, evidence)` sends the exact admitted delivery,
  attempt, permit and node generation to `/v1/dispatch/settle-no-start`. Evidence
  is a retained native terminal receipt UUID or durable `local_not_submitted`
  proof. The closed response must echo the entire tuple, evidence and node ID
  with `status: "not_started"`. A retry obtains fresh credentials and node proof
  while retaining the same settlement identity. Expiry does not prevent
  reconciliation. This method does not claim or submit a native turn.
- `acknowledge(envelope, acknowledgment)` validates the pinned ACK protocol and
  delivery identity, then sends only `/v1/ack`. A caller retry keeps those bytes
  and native IDs while obtaining fresh credentials/node proof. It neither claims
  again nor invokes native submission. Late reconciliation may outlive transport
  expiry. The reply's status must match the submitted ACK; a submitted ACK cannot
  advance the current watermark. Direct native input observation uses the separate
  `native_input_recorded` correlation after confirmed submitted registration;
  [its consumer](native-input-observation.md) persists both phases independently.
- `complete_enrollment(challenge, mesh_ip=..., mesh_port=..., agents=...)` checks
  the exact owner challenge against the configured node/public key and explicitly
  reviewed Mesh binding before signing its bytes. Challenge expiry is at most five
  minutes. The completion reply must match the configured expected generation;
  it never updates local enrollment or authority automatically.
- `native_challenge(intent)` records one exact attach, renew, or transfer intent,
  including the current native binding and every runtime/attachment CAS pair.
  The CLI then asks the foreground launcher for a fresh read-only native witness
  correlated to that challenge and commits it with a newly signed node proof.
  A `native_binding_unqualified` response is a server admission gate refusal;
  this client does not treat it as an unconditional local refusal or override it.
  The production native-admission flag remains disabled until controlled
  qualification enables the server route.

The explicit `attach`, `renew`, and `transfer` commands require a private
mode-600 cloud configuration, a separate mode-600 credential file reread for
each request, and the already enrolled node key. The bounded HTTPS transport
uses the fixed `/usr/bin/curl` executable, passes headers and request bytes over
stdin, verifies TLS, refuses redirects, and kills the process when its total
deadline expires. These commands run in the foreground; they do not install a
background service or refresh credentials themselves.

Before its first commit send the CLI atomically writes a mode-600, secret-free
exact-request record under `.native-pending`. A timeout or invalid success
response reports an unknown result and retains that record. Repeating the same
operation for the same session and cloud identity retries the exact body within
the server's 90-second receipt window, without another challenge or native
sample. Its local cutoff is conservatively anchored to challenge issuance, so it
can expire before the full receipt horizon. After that cutoff, the command
preserves the unknown state for operator reconciliation; it will not mint a
replacement request. On a confirmed
commit, the CLI rechecks the live native binding and writes the local attachment
mapping. When the daemon is running, it remains the single SQLite writer for
that mapping and an atomic transfer fence; otherwise the foreground CLI writes
the store directly. No command renews leases automatically or enables wake or
dispatch.

General claim, settlement, and acknowledgment calls have no automatic retry
loop. A native attachment commit gets at most one bounded retry after an
ambiguous send, using identical request bytes with fresh credentials and node
proof. The CLI retains that exact request for receipt recovery through a
conservative cutoff anchored to challenge issuance; expiry preserves the
unknown result for operator reconciliation. Neither path interprets a timeout
as permission to create a new native attempt or attachment request.

## Separate control-plane source pin

The `github-pinned-history-read` family pairs two actual merged cloud revisions:
`event-v1` at `59940bde10db5584247c8648c985f246f546226f` embeds the canonical
45 semantic verdicts, and `event-control-v1` at
`49122dd4ac2a358d87e8cd727fd8e817ae183dac` pins 37 Event source paths plus the
Zod version and fixture SHA-256. Both runtimes execute the same 30 raw-parser,
six digest and nine ACK-binding cases. Authorization of the complete family on
trusted main precedes the consumer rotation; all ten older families stay intact.

The selected sources now include `github/pinned-read-contract.ts` and retain
its host, controller and grants boundaries. The helper's grants and readback
imports are already hash-pinned; Zod is pinned separately by version 4.6.5. The
helper is hashed but never evaluated by the exporter. The cloud pin includes metadata-reader hardening and invalid-counter
refusal. The generated control DTO fixture and all five event-v1 files are
byte-identical to the previous family.

The other selected sources cover watch-kernel and owner-proof, delegated read
authority, source-control, watches, manual/native canary boundaries, admin
API/types, and memory authentication/admin security. The create-only flag is
unset in deployment configuration; this does not add a public route or activate
watches, delivery or native attachment. This is offline source/fixture provenance,
not qualification of deployed RPC topology, live authority or native idle wake.
In `--check` mode, the exporter verifies the committed revision, every source
hash and installed Zod version before evaluating source. A mismatch stops before
any data-module import. It then executes the pinned source's claim/settlement
and native admission Zod schemas and `canonicalNodeProof()` to check the
cross-language fixtures. Generation
without `--check` is an explicit operation on reviewed, fully trusted local
source and an installed trusted Zod dependency; it executes that code and writes
a new pin for review. The fixture includes the native admission challenge,
attach/renew/transfer and historical runtime-status DTOs, error codes, rejection
vectors, and node-proof
canonicalization. Neither mode imports Worker runtime code or makes network
requests. The source extraction is deliberately specific to the pinned
functions and imports; changing that source requires reviewing the exporter
again.

`tests/test_cloud.py` consumes the exported `nativeAdmission` vectors directly.
It checks attach, renew, and transfer challenge/commit bodies, NodeProof
canonical bytes and signatures, successful response DTOs, and named rejection
cases against the Python client. `tests/test_runtime_status_contract.py` checks
the exported historical status, request rejections, and signed node-proof vectors.

From `packages/event-gateway`, using Node 24.19.0 and the pinned Zod 4.6.5 module:

```sh
node contracts/event-control-v1/export.mjs /path/to/pinned-os/apps/os /path/to/zod/index.js --check
UV_CACHE_DIR=/private/tmp/event-cloud-uv-cache uv run --frozen python -m unittest discover -s tests -p test_cloud.py -v
UV_CACHE_DIR=/private/tmp/event-cloud-uv-cache uv run --frozen ruff check src/event_gateway/cloud.py tests/test_cloud.py
```

Qualification used Python 3.13.14, uv 0.12.15 and Node 24.19.0: 21 focused tests
and all 97 package tests passed, and lint passed. Twenty-two isolated production mutations each produced assertion
failures, zero test errors, and passed the same case after restoration:

| Removed or weakened guard | Focused case |
| --- | --- |
| Pre-evaluation source pin verification | Modified source cannot execute a side effect |
| Historical validation of queued claim input | Expired original gets fresh admission |
| Deterministic response decode refusal | Invalid UTF-8, JSON, duplicate keys and nesting |
| Envelope identity reason preserved | Wrong agent differs from malformed envelope |
| ACK identity reason preserved | Wrong delivery differs from malformed acknowledgment |
| Single enrollment clock snapshot | Clock advance cannot widen the five-minute window |
| Credential provider exception sanitization | Credential `CloudError` regression |
| HTTP transport exception sanitization | Transport `CloudError` regression |
| Closed response fields | Claim DTO fences |
| Permit time window | Claim DTO fences |
| Permit node binding | Claim DTO fences |
| Semantic envelope equality | Every admitted semantic field |
| Fresh node nonce | Fresh credentials and nonce |
| Canonical body digest | Source vector and signed request |
| Budget accounting | Closed budget |
| Unknown error redaction | HTTP refusal codes |
| Redirect refusal | HTTP refusal codes |
| Response byte bound | Bounded unambiguous wire body |
| ACK delivery identity | ACK identity and closed reply |
| Exact challenge payload | Challenge tampering |
| Attach qualification fence | Attach and renew |
| Timeout outcome code | Credential deadline |

The results above describe the earlier cloud adapter checkpoint. The current
settlement implementation and its separate trusted policy rotation are recorded
in [no-start settlement](no-start-settlement.md).

These are local injected-port and cross-source conformance proofs. They do not
establish a live Access session, production enrollment, or native delivery.

## Current GitHub finding material

`github-source-material` retrieves the text identified by a retained source
projection's subject, `sourceId` and `fingerprint`. It signs each
`POST /v1/github/source/material` using the existing enrolled node identity and
fresh credentials. Cloud checks the current source grant and permission on every
page; an old source projection does not grant historical access.

```sh
mkdir -m 700 ./private-findings
knitli-event-gateway --state-dir "$STATE_DIR" github-source-material \
  --cloud-config "$CLOUD_CONFIG" \
  --installation-id 123 --repository-id 456 --pr-number 7 \
  --source-id comment:890 --fingerprint "$FINGERPRINT" \
  --private-output ./private-findings/finding.txt
```

The output path must be new, its parent must already be owned by the current
user with mode `0700`, and no path component may be a symlink. Only after all
pages verify does the command write a private sibling temporary file, sync it,
and atomically publish the complete file with mode `0600`. It never replaces
an existing file or prints finding text, source identity, or opaque cursors.
The terminal reports only `materialRead: written` and `complete: true`, or a safe
failure code.

The client validates closed request/response shapes, subject/source/fingerprint
binding, contiguous UTF-16 offsets, stable first version/body digest/total length,
opaque cursor cycles, and the SHA-256 digest of the assembled UTF-8 text. It
bounds requests to 4096 bytes, responses to 8192 bytes, material to 1 Mi UTF-16
units, and a traversal to 4096 pages. Unavailable, deleted, conflict, malformed,
changed, or interrupted reads return no partial text and create no output file.
A process crash can leave a private `.finding-material-*` temporary file; it
never exposes a partially written final filename. A filesystem failure after
publication may leave the fully verified final file even when the command reports
failure. Inspect/remove only that explicit output before retrying; existing files
are never replaced.

Retry the command from page zero after a read failure; reads are idempotent and there
is no locally persisted continuation or partial body to trust after restart.

`CloudClient.github_source_material()` exposes one validated page;
`github_source_material_all()` is the complete verified-body API used by the CLI.
Fetched text is untrusted review data. Reading or processing it does not mark a
finding resolved, establish review completion, or authorize a repository change.
This consumer does not enable a cloud route or change the pinned contract trust;
the matching producer and normal contract rotation must land before live use.
