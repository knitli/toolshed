# Native continuity signal: bounded source spike

Status: proposed follow-up to [same-session reauthorization](same-session-reauthorization-plan.md),
pending contract review. No runtime changes, adopted schema, or live acceptance.
The [controlled runbook](three-session-acceptance.md) remains a separate gate.

## Inspected evidence

Inspected the cumulative patch and 52-file manifest in this directory, plus
launcher/native/Gateway code. Recomputed patch SHA-256:
`922c3b2aa733564f67765aec27d4128b96b697441b37b42665b6656a4ad884fb`.
Manifest base: `a956835d020762cb2b570053af06f643a11c0ecc`.
Inspected the private restored source tree:
`upstream` HEAD matches that base; `dependency-source/codex-rs` contains the
patched source. Fresh hashes of all five files below match the manifest.

| Rust source under `codex-rs/` | Manifest SHA-256 |
| --- | --- |
| `tui/src/app/startup.rs` | `eeee83c92181a459e416af108ce982a30da4d48d433d43fba5d8967cc5bfcd10` |
| `tui/src/app/selection_witness.rs` | `db9157ccc1f57a80f7f0658752e8930db9bbb2b56e5715f5f30239b54f4e13cb` |
| `tui/src/app/selection_binding.rs` | `925aa481fee11547f1292903a8358f98e10ee6867dfcbb0fd6907b97522f626c` |
| `tui/src/app/selection_bridge.rs` | `ce20533db15be26aee969d45a19ae1dd03b46aafd3d9be5037e04065abaa7c50` |
| `app-server/src/request_processors/native_selection_processor.rs` | `c43087232b1ee34a023c73bbb928356e6bbc436819c8c829fee13782d7d0ff6b` |

Also inspected unchanged handlers and matched their hashes between restored
upstream and dependency-source (under `codex-rs/tui/src/app/`):
`thread_routing.rs`: `877e8b8482a24f0bc81e39896c795401e712b14c34eed4e3e918c329d0380991`;
`thread_events.rs`: `6d437825d41db5942be4ad933772250c4430239036745f1856bedfd8989662ca`;
`app_server_events.rs`: `16a089d4b34380f58484d6b89da70813a3abf3e069eb1254466e18e4d6c35297`.

## Exact order visible in the patch

1. `startup.rs` connects the witness. Each loop first revokes for unready native
   selection, before transition work; then buffers one pending application event.
2. It calls `sync_selection`, which checks readiness, polling gap and binding
   expiry, revokes as needed, renews/updates the server lease, then publishes.
   Server acknowledgment awaits can allow more events to queue.
3. The heartbeat branch rechecks application/active-thread readiness after that
   await. A pending change revokes; otherwise it enters `bridge_tick`.
4. `bridge_tick` first calls `emit("heartbeat")`. `emit` expires loop gaps,
   overwrites `state.cause`, and polls the private socket. A parsed operation is
   then taken by that tick; Start checks exact current selection and binding
   before issuing the server request. Server/Core retain their commit-time guard.
5. Alternative select branches revoke before awaiting their handlers: active
   thread (`"thread-event"`), server (`"server-event"`), non-Draw terminal
   (`"tui-event"`), and semantic application (`"app-event"`) events. Reconnect
   revokes and creates a new connection witness. Draw skips unconditional revoke;
   only validated display-only periodic rate-limit responses do likewise.

Concrete handler evidence: `thread_events.rs:198` handles
`ServerNotification::TurnStarted` using `turn.turn.id`; line 208 handles
`TurnCompleted`, conditionally clears matching active turn state, and checks
`TurnStatus::Completed`. These provide exact turn correlation candidates.
But `thread_routing.rs:2142` handles the broader `ThreadBufferedEvent`: a
`ThreadClosed` can trigger automatic failover/selection, an `ItemCompleted`
user message can trigger title generation, and handling can introduce a modal.
`app_server_events.rs:63` also handles lag, protected server requests and
disconnect/reconnect; its notification path recognizes hidden helper threads.
Thus neither notification origin nor selected thread ID alone is sufficient.

Patch anchors: `selection_binding.rs` starts at line 17601; `bridge_tick` at
18300; `SelectionState` at 18948; `emit` at 19355; readiness helpers at 19382;
startup loop changes at 19818. `Transport::poll` authenticates provenance through
the inherited private socket and enforces increasing challenge nonce; it does
not sign a standalone remotely verifiable continuity assertion.

## Why current metadata cannot authorize continuity

The generic thread-event fence covers ordinary turn notifications but does not
classify their semantic effects. Diagnostic categories distinguish some metadata
events, not a full transition history. A later heartbeat overwrites a revoke
cause; `sequence` counts challenge responses, not every UI transition.
Away-and-back selection can therefore end with the same stable identifiers and
fresh generations as ordinary turn completion. Loop gaps also rotate generations.
Existing metadata supports refusal and fresh presence, not automatic continuity.

## Smallest candidate signal, not a wire contract

Retain all existing generations, revocations, Start checks and historical receipt
identities. Add a sticky native continuity-break epoch to the witness, sampled in
the same fresh private challenge as the binding. Record its initial value with
explicit owner admission; only equal values could support later reauthorization.
Never infer permission from a diagnostic string or reset the epoch at completion.

Increment/break continuity before any disqualifying handler await, including
non-Draw user input, selection changes, reconnect, backend/incarnation change,
loop/lease gaps, transport failure, protected-state transitions, and unknown
event categories. Increment even while already ineligible: repeated `revoke`
currently need not change generation, but a later user action must remain visible.
New process/connection identity rejects continuity independently of epoch value.

Preserve the epoch only for an explicitly inspected allowlist of passive events
and the exact native-started turn lifecycle. Associate that lifecycle with the
existing native attempt/turn receipt; a turn-complete label alone is insufficient.
If a notification races the awaited Start reply, stage/classify it without
granting continuity until its identity is resolved. Unknown or lost Start outcome
cannot enable reauthorization. Generic `thread-event` must not be allowlisted.

Async ordering adds two implementation blockers:

- `bridge_tick` awaits Start for up to 1750 ms inside the selected heartbeat
  branch, then stores its outcome and emits `event-receipt`. The UI loop cannot
  handle turn notifications during that await, although the transport may queue
  them. Receipt publication must not also grant continuity: keep attribution
  pending until the exact attempt's successful receipt identifies the turn and
  buffered notifications have been classified. Timeout, mismatch, queue loss or
  bounded staging overflow must deny, never guess attribution or erase a break.
- The post-selection-ACK readiness check inspects application/active-thread
  queues, not pending terminal input or every server-stream event. `select!`
  can choose a heartbeat while terminal input is ready. A handler-only epoch
  can therefore miss a queued key during challenge/reauthorization. A reviewed
  input/event observation barrier must record disqualifying arrivals before any
  positive continuity sample, including after awaited ACKs. Increment before
  `revoke_ack` itself awaits, not merely before the eventual event handler.
  Existing post-commit comparison cannot detect an input never observed by the
  epoch. The proposal remains blocked until this barrier and its linearization
  point are proved; a sticky epoch alone does not close the race.

The TUI attests only local causal continuity. Launcher validates the full tuple,
nonce and freshness under its reader lock; authenticated node evidence conveys
it to cloud review. Cloud still owns owner allowlists, policy/source authority,
budgets, generation CAS and fresh delivery admission. Policy changes cannot be
detected by a native epoch and must independently deny. No signature or new
endpoint is proposed here; wire/version and trust-model changes require review.

## Required proof and blockers

- Complete the audit of every readiness-changing path before choosing the
  passive/turn allowlist; the inspected handlers establish IDs, not exhaustive safety.
- Prove normal native Start through correlated completion preserves the epoch
  while rotating existing selection generations; fresh challenge enables only
  the reviewed attach lifecycle, never direct stale Start.
- Prove away-and-back, cancelled picker, input while already busy/ineligible,
  reconnect, backend replacement, loop gap, protected prompt and unknown events
  permanently break continuity for the admitted baseline.
- Race queued changes across selection acknowledgment, Start reply, challenge
  and cloud commit. Preserve post-commit revalidation; false negatives fail closed.
- Queue exact-turn notifications before a delayed/lost Start reply; require no
  positive continuity until exact attribution and queue classification succeed.
  Inject an unrelated turn, queue overflow and an intervening user action;
  a later successful receipt must not clear the resulting denial.
- Queue key/paste/focus/resize during selection ACK and Start ACK awaits, then
  force heartbeat selection before terminal handling. Continuity must be denied
  before challenge publication, even with empty application/active-thread queues.
- Test replayed challenge, stale epoch, forged field, missing/version-old signal,
  ambiguous receipt and policy change. None may gain automatic authority.

Recommendation: inspect and test a sticky epoch plus exact-turn causal classifier
before implementing automatic attach reuse. A bare epoch without that classifier
either rejects ordinary turns or wrongly permits unrelated semantic changes.
Exhaustive event-path classification, contract review, historical ACK reconciliation, and the
cloud retained-source settlement/delivery writer remain blockers. No tests or
native execution were performed for this documentation-only spike.
