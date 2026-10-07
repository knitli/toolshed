# Closed cloud control-plane adapter

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
- `attach(runtime_id)` and `renew(runtime_id)` preserve
  `native_binding_unqualified`, including if a server unexpectedly returns 200.

The module has no retry loop. A timeout has unknown remote outcome; the caller
must reconcile or retry the same durable identity. It cannot interpret a timeout
as permission to start another native attempt.

## Separate control-plane source pin

`contracts/event-control-v1/manifest.json` pins the exact Event source files from
OS commit `737dca25de52ae39e2aa293c878521d02adacf60`, plus the Zod version and
fixture SHA-256. It does not modify the earlier frozen `event-v1` transport pin.
In `--check` mode, the exporter verifies the committed revision, every source
hash and installed Zod version before evaluating source. A mismatch stops before
any data-module import. It then executes the source's actual Zod claim and settlement schemas
and `canonicalNodeProof()` to check the cross-language fixture. Generation
without `--check` is an explicit operation on reviewed, fully trusted local
source and an installed trusted Zod dependency; it executes that code and writes
a new pin for review. Neither mode imports Worker runtime code or makes network
requests. The source extraction is deliberately specific to the pinned function
and imports; changing that source requires reviewing the exporter again.

From `packages/event-gateway`, using Node 24.19.0 and the pinned Zod 4.5.4 module:

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
