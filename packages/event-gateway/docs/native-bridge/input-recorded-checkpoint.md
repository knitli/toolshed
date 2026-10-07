# Native input-recording checkpoint

This cumulative experimental patch extends the terminal no-start checkpoint on
Codex `rust-v0.160.0`, commit `a956835d020762cb2b570053af06f643a11c0ecc`.
Historical patches and binaries remain unchanged. Production binding is disabled;
the owner client is not installed or replaced.

Core's actual `ItemCompleted(UserMessage)` event can strengthen an existing,
fully bound committed-start receipt to `inputRecorded`. The event must match
the thread, turn, client message ID and exact single-text input without extra
text elements. The first Core item ID is retained. Read-only receipt lookup
returns that ID; start and start replay continue to return `started`.
The TUI polls Core after a cached start rather than treating registration as
input observation. Terminal no-start receipts remain recoverable from its cache.

Apply [the cumulative patch](input-recorded-codex-v0.160.0.patch) to the exact
upstream commit. [The source manifest](input-recorded-source-manifest.json)
records clean pinned apply and byte comparison. Use the same Rust 1.95.0 and
pinned dependency cache as the [terminal checkpoint](terminal-no-start-checkpoint.md).
In a disposable environment, run:

```sh
python scripts/qualify_native_bridge.py --binary /path/to/disposable/codex --input-recorded
```

The qualifier uses a private Codex home, inherited local socket and held loopback
mock response. It requires the actual Core item ID, then recovers the same receipt
while the client is ineligible after permit expiry. It rejects `started` as
observation and unexpected model traffic. It uses no owner credentials.

[Checkpoint JSON](input-recorded-checkpoint.json) binds the final binary, patch,
checks and [actual synthetic qualification](input-recorded-live.json).
[Individual native proof](input-recorded-test-proof.json) and
[harness proof](input-recorded-harness-proof.json) record intended assertion-red
and restored-green cases; tooling failures and reason-only changes do not count.

The receipt ledger is still bounded to 256 entries without evidence eviction
and is process-local. Restart or missing evidence remains `unknown`. History
alone lacks the original permit, generation, incarnation and full request binding,
so it cannot reconstruct this receipt. Durable native recovery remains required
before claiming restart convergence.

The real-binary check proves native input observation with a mock model. It does
not prove cloud observation settlement, real-model completion, an owner-client
canary or Mesh delivery. The gateway/cloud registration ACKs are a separate
submitted-only phase; they retain delivery capacity until observation is separately
implemented and qualified. Broad upstream suite failures and the full-workspace
GLib/V8 blockers remain recorded in the earlier checkpoint, not claimed green.
