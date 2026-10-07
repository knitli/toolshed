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

`cf-access-token` authenticates to the Access edge, which supplies the original
`cf-access-jwt-assertion` to Event. `Authorization: Bearer ...` carries the agent
token. Node proofs use a fresh nonce and timestamp and bind exact raw request
bytes, POST path, Event origin, owner, node ID and generation. No credentials
occur in signed node-proof JSON.

- `claim(envelope)` returns the closed `admitted` or `over_budget` DTO. An
  admitted reply includes UUID `permitId`, matching `nodeId`, an unexpired exact
  five-second window, and the returned envelope. Only transport `issuedAt` and
  `expiresAt` may differ from the requested envelope. All semantic fields,
  including runtime, attempt and generation identity, remain bound. The returned
  envelope must cover the permit lifetime. No conversion discards refreshed data.
- `acknowledge(envelope, acknowledgment)` validates the pinned ACK protocol and
  delivery identity, then sends only `/v1/ack`. A caller retry keeps those bytes
  and native IDs while obtaining fresh credentials/node proof. It neither claims
  again nor invokes native submission. Late reconciliation may outlive transport
  expiry. The reply's status must match the submitted ACK; a submitted ACK cannot
  advance the current watermark.
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
The exporter executes the source's actual Zod claim schemas and
`canonicalNodeProof()` to generate the cross-language fixture. It does not import
Worker runtime code or make network requests.

From `packages/event-gateway`, using Node 24.19.0 and the pinned Zod 4.5.4 module:

```sh
node contracts/event-control-v1/export.mjs /path/to/pinned-os/apps/os /path/to/zod/index.js --check
UV_CACHE_DIR=/private/tmp/event-cloud-uv-cache uv run --frozen python -m unittest discover -s tests -p test_cloud.py -v
UV_CACHE_DIR=/private/tmp/event-cloud-uv-cache uv run --frozen ruff check src/event_gateway/cloud.py tests/test_cloud.py
```

Qualification used Python 3.13.14 and uv 0.12.15: 18 focused tests and all 94
package tests passed, and lint passed. Sixteen isolated production mutations each produced assertion
failures, zero test errors, and passed the same case after restoration:

| Removed or weakened guard | Focused case |
| --- | --- |
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

These are local injected-port and cross-source conformance proofs. They do not
establish a live Access session, production enrollment, or native delivery.
