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
attempt, admission, receipt, or ACK at acceptance. Delivery IDs remain protocol-derived.
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

## Private one-shot admission history

Based on journal commit `cb6fabdf65a9a4b2109e6e1ad9415d3378974882` (PR #122),
`Gateway._claim_messaging_history(delivery_id)` is a private integration seam.
No HTTP listener, daemon loop, CLI, public dispatch, or reconciler calls it.
Its injected trusted authority uses `CloudClient.claim_messaging_history`, which
validates the configured principal, agent, enrolled node ID and generation
before obtaining credentials. The client uses its existing configured HTTPS
origin, credentials, signed node proof, bounded response, and redirect refusal
for `POST /v1/dispatch/claim` with the exact delivery and attempt IDs. No new
route or transport authentication mechanism is introduced. A dictionary or
nominal wrapper does not authenticate an admission; the configured cloud
client and its trusted HTTP transport establish that boundary.

Before the RPC, the Store commits an exact v2 attempt with `state=held`,
`claim_uncertain=1`, and a bounded reservation for recording the response.
It rechecks the attachment tuple and live lease inside `BEGIN IMMEDIATE`.
The reservation is storage capacity only; it enables no native execution.
Existing attempt history is one-shot: admission or an authenticated over-budget
response is returned without another RPC, while unresolved intent returns
`claim_outcome_unknown`. There is no attempt replacement, automatic retry,
settlement, or local budget fallback.

`Store._record_messaging_admission_history` repeats the v2 metadata validator,
requires the complete original envelope including attempt and transport
timestamps, and repeats the live attachment fence transactionally. It requires
and fills the exact preexisting intent; a writer call without intent is refused.
Identical replay performs no write;
conflicts are rejected. The closed over-budget response is immutable history
in the existing evidence field with `reason=over_budget` and
`claim_uncertain=0`; it can resolve only its preexisting intent even if detached.
Successful response recording releases the history storage reservation.

Timeout, cancellation, malformed response, admission after detach, or failed
storage leaves the original uncertain intent intact. Restart never resends it.
Detach fences further admission writes. All v2 attempts, including admitted
and refused history, remain retained and count toward capacity even after a
stale delivery passes the usual retention horizon. No settlement exists yet
to retire those obligations. This uses existing columns and Python-decoded
versions; it requires neither a schema migration nor SQLite JSON1.

Expired five-second permits remain valid **history only**. Attempt and delivery
remain `held` until the existing attachment fence makes the delivery stale.
Neither stored permits nor recovery permit start, ACK, settlement, dispatch,
or reconciliation; existing v2 execution refusals remain in force.

The integration tests exercise the actual `CloudClient` with injected HTTP,
including committed intent visibility from a second SQLite connection inside
send, signed request bindings, response bounds, immutable replay, uncertainty,
retention, and refusal history. They do not establish deployed Cloud/client
interoperability or activate any listener. Publication of the coordinated
client/server change remains separate from live activation.
