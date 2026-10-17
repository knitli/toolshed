# Dormant Messaging v2 admission validation

`event_gateway.messaging_admission_v2` supplies callable metadata validators only.
No active gateway ingress, journal, native dispatch, CLI, or production v2 support
is enabled by this module.

`validate_authenticated_envelope` requires exact built-in bytes (at most 4096),
configured audience and an explicit trusted `public_key`, and the existing Ed25519 exact-byte
signature domain from `security.verify`. The caller selects this key from trusted
configuration; message-supplied key material is never authoritative. Key-ID
selection belongs to the caller. It authenticates before decoding, then
uses the v2 bounded duplicate/depth decoder, freshness rules and delivery digest.
It requires the enrolled node ID and trusted current attachment metadata:
`principal`, `agent`, `nodeId`, `runtimeId`, `nodeGeneration`,
`runtimeGeneration`, `attachmentGeneration`, `consumerGeneration`,
`routingGeneration`, `namespace`, `agentIncarnation`, and `leaseExpiresAt` (Unix
seconds). `now_ms` is finite Unix milliseconds. Attachment lease and destination
checks are metadata checks, not a lease acquisition or persistence transaction.

`validate_admission(admission, expected_envelope, now_ms=..., node_id=...)`
validates an already-authenticated cloud response containing exactly `status`,
`permitId`, `nodeId`, `permitIssuedAt`, `permitExpiresAt`, and `envelope`. Status
must be `admitted`; a permit spans exactly five seconds and cannot be issued in
the future. Both historical envelopes must have valid v2 shapes and delivery
digests, match the enrolled node, and match every semantic field except
`issuedAt`/`expiresAt`. The admitted envelope lifespan contains the entire permit.
Returned nested envelope data is detached from the input.

Expired immutable permits are accepted as **history only**, to recover the same
admission after response loss. A successful return does **not** authorize native
start; current admission authority, durable journaling, and live start checks
remain outside this module. The envelope signature and cloud response
credentials remain distinct external authentication boundaries.

Use `messaging_protocol_v2.acknowledgment_matches_delivery` against the admitted
envelope for submitted/observed ACK metadata. This does not authenticate an ACK,
bind its permit ID to an admission, verify native evidence, or settle delivery.
ACK authentication remains the existing external node-proof RPC responsibility;
this module introduces no signed ACK contract.
