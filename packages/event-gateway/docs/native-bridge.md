# Native bridge foundation

Production wake remains disabled. This work targets a disposable Codex 0.160.0
source patch; it does not install or configure the owner's Codex client/daemon.
The [transport checkpoint](native-bridge/transport-checkpoint.md) and
[live no-turn proof](native-bridge/live-transport-evidence.json) are complete.
The [combined native patch](native-bridge/native-binding-checkpoint.md) now
implements server-enforced binding, guarded Core start, and TUI event handoff.
Its [synthetic start proof](native-bridge/live-native-start-evidence.json)
recovered the exact committed receipt using a loopback mock model. Cloud
integration and production qualification remain pending.

## Execution choices

Use the actual TUI's existing app-server connection. The server assigns the
connection identity, creates a fresh incarnation on boot, and owns selection
generations and expiry. The private inherited socket is the launcher's TUI
channel, not an independent daemon identity or cloud authority proof. Processes
running as the same OS user remain trusted local principals.
The launcher descriptor is adopted at process entry, before startup children;
close-on-exec and removal of its environment markers prevent accidental inheritance.
Non-TUI commands and internal helpers drop the unused channel before entering their work.
The native selection lease lasts 750 ms and renews at most 250 ms apart.
The five-second cloud permit is a separate limit; both must remain live at
registration. A freshness gap requires generation resynchronization.
Permit expiry is anchored to a monotonic deadline before asynchronous preparation.

Keep busy events in the existing Event Gateway SQLite spool. Do not put them
in Codex's unfenced native queue, and do not use `turn/start`, which can steer an
active turn. The new conditional start uses Core's idle-only path.

```text
TUI selection → native connection binding
private event → TUI RPC → final Core fence → registered native task + receipt
```

The final check belongs at native task registration, after preparation awaits.
It must validate generation, selection, connection liveness, and the remaining
permit/lease window, then synchronously register the task and its receipt under
the same short binding lock. No await belongs inside that commit. Revocation
winning the lock means no turn; commitment winning means an already-started
turn remains submitted or ambiguous after later revocation.

Task preparation after registration must finish before model execution. Ordinary
Codex start paths keep their existing behavior. Guard refusal must not write an
event user message or emit a started turn. Selection changes require an
acknowledged native revoke before the TUI changes its selected thread.

## Receipts and uncertainty

This first native patch uses a bounded in-memory receipt cache. It does not add
a native SQLite schema. Recover an exact retained receipt before checking
transient lease expiry: a lost response followed by expiry must not turn a
committed start into a false no-start. Distinct deliveries must not reuse one
native turn ID or consume one permit twice. Permit conflicts are checked again
under the shared receipt commit lock; exact committed replay still recovers its receipt.

An explicit Core refusal proves that particular call did not start. Errors, lost replies, and
timeouts remain unknown unless an exact committed receipt exists. A daemon
restart invalidates bindings and can lose these receipts; the gateway's durable
submission ledger must retain ambiguity and forbid replay. No absence scan
proves non-submission.

## Terminal no-start settlement

The [terminal no-start checkpoint](native-bridge/terminal-no-start-checkpoint.md)
records the cumulative patch, final binary and native-only synthetic evidence.

The follow-up patch records terminal no-start outcomes under the same lock as
committed starts. `terminalNotStarted` carries a retained UUID and exact replay
identity; an ordinary `notStarted` response carries no settlement authority.
The bounded ledger shares the existing 256-entry capacity with starts and never
evicts live evidence. Capacity failure returns unknown when proof cannot be
retained. Restart can lose this ledger, so the durable gateway retains ambiguity.

The local gateway stores claim intent, admission and the entire native request
before issuing the event operation. It accepts either an exact native terminal
receipt or an atomic proof that the admitted attempt was never submitted. Lost
settlement replies repeat only the same cloud settlement. An exact echoed cloud
result closes the old attempt and creates one fresh attempt; neither timeout nor
an unknown native receipt authorizes retry. The original budget charge remains.

Cloud PR [#683](https://github.com/knitli/knitli-site/pull/683) implements exact
permit retirement and immutable historical admission recovery. The local and
native changes require their own review and coupled qualification. This does
not enable production wake. Direct native starts use the separately pinned
submitted correlation `{kind:"native_turn_started",permitId,turnId}`. The gateway
retains the full original native request/receipt and persists one immutable ACK
before HTTP. Exact recovery keeps `acknowledgedAt` and all identity fields, while
obtaining a fresh node proof. Completion is bound to that exact attempt and ACK,
even after detach marks its state ambiguous. Queue receipts retain their
existing correlation; no queue submission ID is fabricated.

A submitted ACK means Core registered the turn. It returns `current:false` and
retains slot, budget charge and source watermark. Native input observation is a
separate proof gate. Public native binding remains unqualified; these changes
do not install a client or qualify production delivery.

The prototype checks stale/expired/wrong-thread/disconnected refusal, busy
refusal, revoke/start ordering, post-commit cancellation, and exact retained
receipts. The Python qualifier exercises the actual patched TUI/Core path and
read-only receipt recovery without a real model or cloud event. Native restart
still loses the in-memory ledger; production must retain ambiguity durably.

Focused Rust and Python checks passed, including assertion-red/restored-green
mutation checks. Broader upstream runs retain baseline/host failures; the
authorized full workspace attempt stops at missing macOS GLib, and the separate
code-mode helper cannot download its pinned V8 artifact (HTTP 404). The checkpoint
records those limits; this is not a green full-workspace result.

After terminal no-start settlement spans native/local/cloud, coupled qualification
and an authorized manual canary can proceed. Mesh delivery and three-session
acceptance remain later gates.
