# Dormant Messaging v2 journal

`Store.put_messaging_attachment(mapping)` persists trusted metadata supplied by
the host: the exact `messaging_admission_v2.ATTACHMENT_FIELDS`, `namespace`,
`agentIncarnation`, and `leaseExpiresAt` (Unix seconds). It accepts no native
route, transfer, or generation reset. Existing v1 attachments, including legacy
native routes and metadata-only attachments, cannot be replaced by this writer.
Migration between attachment families requires a separate contract. Legacy attachment writers cannot
overwrite or transfer a Messaging attachment.

`Gateway.accept_messaging_v2(body, signature=..., audience=..., key_id=...,
node_id=..., runtime_id=...)` is callable only. The host supplies the enrolled
node and trusted runtime; the gateway selects a configured verification key and
reads the current attachment from the existing Store. The existing signature
domain and v2 validator authenticate the exact bytes before Store validation,
deduplication, or persistence. The HTTP listener, daemon configuration, and CLI
continue to expose only the existing v1 ingress.

The existing SQLite ledger retains the complete v2 envelope as `held`, with no
attempt, admission, receipt, or ACK. Delivery IDs remain protocol-derived.
Semantic comparison includes source and the complete subject, excluding only
attempt ID and transport issue/expiry timestamps; integral JSON numbers are
normalized consistently. The Store rechecks every attachment field plus
namespace, incarnation, and lease before returning a duplicate or inserting.
Metadata rotation or detach fences held work to `stale`.

Held rows count against the existing pending/storage limits but never enter
dispatch or reconciliation polling. Explicit dispatch, reconciliation, claim,
submit, native-start, and no-start-settlement entry points refuse v2. There is no
promotion API. Mere passage of time does not retire held rows: they retain
capacity until detach, metadata rotation, or an explicit local stale transition;
stale rows use the existing seven-day retention policy.

The first successful v2 attachment or delivery transaction advances the ledger
format from 4 to 5 atomically. Failed writes roll back that marker with their
data. V1-only ledgers remain format 4, opening format 5 never downgrades it, and
older binaries reject format 5. Removing held rows does not make the ledger
safe for an older binary.

This slice does not grant cloud admission or native execution authority. V2
claim/settlement/ACK RPC contracts, authenticated attachment provisioning, and
qualified native Messaging subject/receipt recovery remain prerequisites for
any subsequent activation.
