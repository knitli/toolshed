# Dormant historical terminal-query inputs

`event_gateway.native_terminal_inputs.collect_terminal_inputs(connection,
delivery_id, attempt_id)` reads one exact attempt from a caller-trusted, already
open **read-only** SQLite connection. It opens no paths and initializes no Store.
One SELECT with `LIMIT 2` and `fetchmany(2)` detects duplicate matches without
counting or materializing all matching rows. It snapshots the saved admission, original native request and previously
validated InputRecorded receipt together. No current attachment, delivery envelope,
clock, native bridge, gateway or eligibility query participates.

A successful result contains `admission`, `request`, `input_recorded_receipt` and
`binding`. The first three preserve the decoded saved values. Binding contains
only the original request's `clientId`, `generation`, `serverInstanceId`,
`serverGeneration` and `threadId`. It is **not a complete session route**: the
journal does not retain the original launcher/session mapping per attempt. A later
trusted caller must independently obtain that original route before any native
query. This module has no dependency on the dormant terminal-query client.

The request must explicitly select integer receipt version 3. The collector
revalidates the historical admission at its saved issue time, request/admission
identity, exact queried attempt/delivery and full InputRecorded identity including
generation. Started, unknown and terminal outcomes cannot substitute for an
InputRecorded anchor. Duplicate rows, missing fields, malformed JSON, duplicate
JSON keys, unsupported versions and SQL/schema failures raise only
`NativeError("invalid_native_terminal_inputs")`. Each projected JSON value is
limited to 4096 UTF-8 bytes; the existing protocol decoder enforces depth 32 and
rejects non-finite numbers, and the native copy boundary is reapplied.

`None` means the exact attempt is absent. Cleanup can erase historical rows, so
absence does not establish that an attempt never ran or that no debt remains.
No result establishes terminal completion or grants ACK, settlement, release,
retry or quarantine-clearance authority. No terminal history is written. Storage
ownership and the original provenance of the saved pair remain caller trust
requirements; internally consistent fabricated rows cannot prove provenance.

The V1 envelope has no `nodeId`. The authenticated CloudClient originally checks
admission node identity against its own node before Store persistence; Store's
admission validator does not independently repeat that check. This collector
validates the saved admission shape, but cannot independently authenticate its
node from the envelope. A future caller must retain trusted journal provenance
and independently establish the original node and session route. No current
attachment or invented envelope node field can supply that historical proof.

Tests create disposable SQLite databases only and include a URI opened with
`mode=ro`, one-SELECT tracing, altered identities/envelopes, legacy rejection,
ambiguous rows, malformed/oversized/deep JSON and current attachment rotation.
