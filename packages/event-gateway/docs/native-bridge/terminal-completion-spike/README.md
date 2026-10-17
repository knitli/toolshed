# Native terminal completion spike

Bounded offline prototype. Production Stage 3 automatic round completion remains blocked. This bundle enables no workflow, public protocol, runtime pin change, or owner installation.

## Proven behavior

Provider-free Core SessionTask execution emits real completed, failed, and canceled events. A private hash-checked fixture carries them into the actual app-server ThreadStateManager observer and StateRuntime transaction. The observer requires trusted thread context, exact registered turn, and complete v3 attempt identity. State requires an existing Started/InputRecorded anchor. An immutable committed receipt survives abrupt exit and reopen. Pending, mismatched, unregistered, conflicting, and failed-write observations cannot create a positive terminal result.

The rollout-failure producer attaches real persistence, shuts down its writer, and asserts failed flush and append before collecting events. This is not an operating-system disk-failure test. Fixture error text is redacted; terminal receipts do not store it.

## Evidence

- Upstream base: `a956835d020762cb2b570053af06f643a11c0ecc`.
- Cumulative Toolshed overlay: `99d00ba8b1b19f9fde66b1c0605e7f670b4a41a4`. All 57 historical source-manifest entries remained unchanged in the original generation and replay trees.
- `terminal-completion.patch` applies to that cumulative tree, not bare upstream. SHA-256: `4e6054b7ca9ab0e4d447102a421b99945e6bb8adab8d9877e6dd6c3e893b3481`.
- `manifest.json` records tested and final hashes for all 11 changed files. `proof/source-hashes.json` records matrix sources. `tested-to-formatted.diff` preserves their formatting delta. All 11 final files equal exact Rust 1.95 rustfmt output of the tested sources.
- 29 scoped State/native-selection regression tests passed. The 14-phase matrix includes 10 passing runs and four expected abrupt child exits: 71 before commit, 72 after commit (nextest wrapper exit 100). Reopen checks preserve committed receipt IDs and report no positive result before commit. Closed-database writes produce no positive receipt for all three outcomes.
- A deliberate producer mutation from fatal failure to success failed the expected error assertion. It was reverted before the passing matrix.
- Required `just fix` passed with baseline warnings. Required `just fmt` completed Rust formatting, but the aggregate command failed because dotslash and uv were missing. Unrelated auto-fixes and Cargo.lock normalization were restored. No tests ran after fix/fmt. The full workspace suite was not run.

Sanitized evidence retains exact fixture bytes, phase commands, exit codes, source and raw-log hashes, and synthetic receipt rows. Raw logs, databases, WAL files, caches, and binaries are excluded. Log hashes identify locally audited evidence and cannot be reverified from this bundle alone. The reproduction runner parameterizes the original paths, requires a new output directory, and rejects any source-hash mismatch against the sibling manifest before launching a test process. Its single Python artifact test uses 11 dummy sources and a fake tool marker: removing the preflight fails because the tool runs; restoring it passes with no tool execution. Ruff formatting and lint pass. The native matrix has not been rerun.

## Production limitation

The live listener was not exercised end to end. The processor persists Pending, awaits Core start, then persists Started. Guarded start registers the in-memory receipt indexes before Core commit releases the task, so ordinary same-process terminal-before-registration is structurally excluded. Terminal delivery can still race the asynchronous durable Started anchor. Such an early terminal is rejected as Unknown without durable retry; listener or restart loss of volatile evidence and process loss before commit likewise leave no positive result. These checks prove fail-closed behavior, not completion liveness or automatic recovery. No active-turn fallback is used.

Source trace in the patched checkout: `codex-rs/app-server/src/request_processors/native_selection_processor.rs:242-252` inserts all three in-memory indexes before `commit()`; `codex-rs/core/src/tasks/guarded_start.rs:85-98,159,212` keeps the task dormant until guarded registration and preparation complete. The asynchronous `record_native_turn_started` at `native_selection_processor.rs:517` follows `start_turn_if_idle().await`, leaving the durable-anchor ordering gap.

Before promotion, qualify live ordering and recovery for terminal-before-anchor, missing registration, and restart. A possible next design stores exact-attempt deferred terminal evidence that remains non-authoritative until its matching start/input anchor commits. Missing evidence must remain Unknown unless exact durable history and attempt registration establish the same thread/turn/attempt. That design is not implemented here. TUI, cloud delivery, public protocol, and Python terminal consumers are outside this spike.

## Reproduction

Use a disposable checkout with the upstream base and historical cumulative overlay, then apply this patch. Supply Rust 1.95.0, just 1.58.0, cargo-nextest, and a populated offline dependency cache. The runner uses repository `just test`, disables retries, and disables core dumps.

```sh
export CODEX_SPIKE_ROOT=/absolute/path/to/disposable-codex
export SPIKE_PROOF_DIR=/absolute/path/to/new-proof-directory
export JUST_BIN=/absolute/path/to/just
python3 reproduce.py
```

Set PATH, RUSTUP_HOME, and CARGO_HOME to isolated tooling/cache first. The runner builds tests and writes its disposable checkout/build cache and proof directory. It installs no tooling and enables no production behavior. Do not reuse an existing proof directory.
