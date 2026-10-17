# Dormant native terminal query client

`event_gateway.native_terminal_evidence.NativeTerminalEvidenceAdapter` adds an
explicit historical query over an already qualified private bridge. No gateway,
daemon, CLI, poller, or settlement path calls it.

The trusted recovery caller must supply its **original persisted v3 request** and
its **previously validated InputRecorded receipt**. The adapter checks the full
identity, original turn, and input-item correlation. It does not establish the
provenance of arbitrary caller-supplied dictionaries or load persistence itself.
The paired native endpoint is responsible for proving the exact durable original
InputRecorded anchor; the adapter independently matches its returned item to the
trusted saved receipt. A volatile reader cache is not required after restart.

The private TUI request is `{nonce, terminalEvidence: originalBridgeEvent}`.
The reply retains `{version: 3, nonce, receipt: {fullV3Identity, outcome}}`.
`outcome` is exactly one of:

```json
{"status":"unknown"}
```

```json
{"status":"terminal","turnId":"original turn UUID","itemId":"recorded input UUID","receiptId":"durable receipt UUID","terminalStatus":"completed","replayed":true}
```

`terminalStatus` also accepts `failed` and `canceled`. All IDs must satisfy the
existing canonical UUID grammar; the item differs from the turn. Extra fields,
wrong identity types or values, inconsistent anchors, and non-replayed results
are rejected. Terminal evidence remains invalid under the existing
`validate_receipt()` used by acknowledgment and settlement paths.

`SessionNativeBridge` maps the internal `nativeTerminalEvidence` command to the
TUI operation through the existing private session socket and launcher lock.
The reader restores the exact request's start-once ledger before lookup. It does
not challenge selection, renew a lease, Start a turn, grant another delivery
attempt, or emit an acknowledgment. Unknown, unsupported, malformed, and timed-out
responses never trigger receipt lookup or Start fallback. Unsupported pinned
binaries remain Unknown/unavailable; binary pins are unchanged.

## Qualification and publication gate

Offline fixtures cover a fresh reader and session proxy, a changed/ineligible
selection, a trusted saved input anchor, repeated stable terminal receipts,
all three outcomes, exact identity and item mismatches, unsupported/malformed
wire replies, and inability to reuse the consumed Start identity. No native
binary, owner profile, provider, or live client is used.

Launcher source is protected by exact reviewed provenance. The separate
policy-first change landed in Toolshed PR #129 at
`681c2774956c592c56ec1f167e6a2c935721eeb8` before this client was published.
It authorizes this exact launcher transition while retaining the older transition
and both binary pins, and freezes the historical fixture bytes. Candidate code
does not authorize its own launcher change. All 1,015 offline tests pass on that
merged policy base.

This slice establishes query transport and correlation only. It does not claim
live-client compatibility, native deployment, event settlement, quarantine
clearance, or an active recovery loop.
