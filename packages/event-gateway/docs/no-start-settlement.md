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
Closing the old attempt and creating its replacement is atomic for a live,
unchanged destination. An expired or fenced destination remains stale: existing
policy requires a new attachment generation and newly identified delivery. Old replies
cannot close a replacement, and cloud retirement retains the original budget
charge. A native restart or missing receipt leaves ambiguity fenced.

Cloud no-start implementation: [OS PR #683](https://github.com/knitli/knitli-site/pull/683),
original immutable commit `3aaedc306640631e49001b99d02cba589eaebc4a`.
The current event and control snapshots both pin the direct-start ACK follow-up,
[OS PR #684](https://github.com/knitli/knitli-site/pull/684), at
`9b1ab6e2c2cf801fe035c766d03f26f1b2f85790`. The control exporter checks all
eight source hashes and Zod 4.5.4 before evaluating the actual claim, settlement
and ACK schemas and node-proof vectors. All immutable source hashes were checked
against GitHub. The separately reviewed trusted policy must authorize this
complete event/control family before the consumer receives a successful trusted
status. [Toolshed PR #39](https://github.com/knitli/toolshed/pull/39) retains the
original no-start family for older consumers; it does not authorize the ACK family.

## Proof and remaining gates

The original no-start checkpoint passed 165 tests after integrating its canonical
snapshot, trusted policy and review corrections; Ruff passes. New and repaired
cases have individual causal assertion-red/restored-green evidence, including
two real defects found in the independent audit: concurrent dispatch used an
attempt captured before its lock, and successful admission retained a stale
budget refusal reason. Both fixes passed independent reinspection. Further review corrections preserve
read-only receipt recovery after lease expiry, ignore harmless live lease renewal,
and report a delivery pruned during lock wait without claiming or starting it. The renewed
settlement-vector proof also catches a shared signer/verifier using the wrong
path. Final source hashes and case results are retained in
[the local proof record](no-start-settlement-proof.json).

The composed local tests use the real Gateway, CloudClient, NativeBridgeAdapter
and Store with a controlled wire/native peer. They verify Ed25519 node proofs,
SQLite writes before native operations, terminal settlement and lost-response
recovery. Those tests do not prove a deployed Access session, production Mesh
delivery or an installed native client.

The native qualifier's additive `--terminal-retry` mode obtains a retained
terminal receipt using an expired synthetic permit while idle. It recovers that
receipt while an unrelated mock turn is held busy, then retries the refused
delivery with a fresh attempt and permit. The actual disposable TUI proof passes:
two primary mock calls, one title call, zero unknown or real-model calls. It
explicitly reports cloud settlement and a busy-race refusal unproven.
Run it with the new immutable binary named in the terminal checkpoint:

```sh
uv run --frozen python scripts/qualify_native_bridge.py --binary /absolute/path/to/disposable/codex --terminal-retry
```

A direct Core start supplies authentic turn evidence but is not a queued receipt.
The original no-start checkpoint left direct starts ACK-pending. The follow-up
canonical submitted correlation is `native_turn_started`, bound to the original
permit and authentic turn. It retains the full local request/receipt and one
immutable ACK; successful ACK recovery does not imply input observation or free
the pending slot. Older cloud parsers reject this branch and leave evidence
pending until compatible recovery is restored. Never downgrade to queue evidence.

SQLite schema 3 introduced the immutable submitted native ACK; schema 4 adds
the actual input-recorded receipt and separate observed ACK. Migration preserves legacy
queue receipts and clears only proven direct-turn submission aliases. Stop the daemon
before upgrade or rollback; older binaries refuse this version. Retain the
private database rather than deleting evidence or attempting a down migration.
Cloud rollback likewise requires admissions disabled and settlement records
retained before deploying code that does not understand `not_started`.
