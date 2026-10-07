# Definite no-start settlement

Automatic wake remains disabled. This slice joins the existing injected cloud
client, private native bridge and SQLite gateway; it does not install a client,
enroll an owner or configure a production listener.

```text
queued → durable claim intent → exact original admission
  → full native request persisted + submitting → native operation
      → retained terminal receipt → durable settlement_pending
      → authentic started receipt → submitted, ACK pending
      → uncertain outcome → ambiguous, exact read-only recovery
  → admitted but never written → durable settlement_pending
settlement_pending → exact echoed cloud confirmation → old attempt settled
                                                    → one fresh waiting attempt
```

Claim recovery keeps the original attempt and immutable admission even after
permit expiry. An expired permit is retirement evidence only. Submission checks
its live deadline in the transaction that stores the complete native request.
Availability, destination or capacity failures after admission use the same
never-written retirement path. Cancellation after submission cannot produce that
proof. A call-level `notStarted` has no settlement authority; only the retained
`terminalNotStarted` UUID and exact request identity do.

Lost settlement replies and restart repeat only the same settlement. The
response must echo delivery, attempt, permit, node, generation and evidence.
Closing the old attempt and creating its replacement is atomic. Old replies
cannot close a replacement, and cloud retirement retains the original budget
charge. A native restart or missing receipt leaves ambiguity fenced.

Cloud implementation: [OS PR #683](https://github.com/knitli/knitli-site/pull/683).
The control snapshot pins immutable OS commit
`3aaedc306640631e49001b99d02cba589eaebc4a`; its exporter checks all eight source
hashes and Zod 4.5.4 before evaluating the actual claim/settlement schemas and
node-proof vectors. [Toolshed PR #39](https://github.com/knitli/toolshed/pull/39)
authorizes this complete fixture/manifest pair separately. The transport
`event-v1` pin remains unchanged. Policy approval and merge must precede the
snapshot update's trusted status on main.

## Proof and remaining gates

The complete local suite passes 162 tests after integrating the canonical
snapshot and trusted policy; Ruff passes. Sixty-four distinct new or repaired
cases have individual causal assertion-red/restored-green evidence, including
two real defects found in the independent audit: concurrent dispatch used an
attempt captured before its lock, and successful admission retained a stale
budget refusal reason. Both fixes passed independent reinspection. The renewed
settlement-vector proof also catches a shared signer/verifier using the wrong
path. Final source hashes and case results are retained in
[the local proof record](no-start-settlement-proof.json).

The composed local tests use the real Gateway, CloudClient, NativeBridgeAdapter
and Store with a controlled wire/native peer. They verify Ed25519 node proofs,
SQLite writes before native operations, terminal settlement and lost-response
recovery. Those tests do not prove a deployed Access session, production Mesh
delivery or an installed native client.

The native qualifier's additive `--terminal-retry` mode holds one loopback mock
model response, obtains and recovers a retained terminal refusal for another
event, then retries that same delivery with a fresh attempt and permit. It uses
the disposable patched TUI and explicitly reports cloud settlement unproven.
Run it with the new immutable binary named in the terminal checkpoint:

```sh
uv run --frozen python scripts/qualify_native_bridge.py --binary /absolute/path/to/disposable/codex --terminal-retry
```

A direct Core start supplies authentic turn evidence but is not a queued receipt.
The canonical cloud submitted ACK currently requires `kind: "queued"`; this
slice persists direct starts with `native_started_ack_unqualified` and keeps ACK
pending. A separately reviewed canonical correlation extension is required
before production qualification. Never fabricate queue evidence.

SQLite schema 2 retains the attempt ledger and settlement proof. Stop the daemon
before upgrade or rollback; older binaries refuse this version. Retain the
private database rather than deleting evidence or attempting a down migration.
Cloud rollback likewise requires admissions disabled and settlement records
retained before deploying code that does not understand `not_started`.
