# Native terminal no-start checkpoint

This cumulative experimental patch targets Codex `rust-v0.160.0`, commit
`a956835d020762cb2b570053af06f643a11c0ecc`. It extends the earlier native binding
patch with exact, retained terminal no-start receipts. Historical checkpoints,
patches and qualified binaries remain unchanged. No owner client is installed
and production wake remains disabled.

## Behavior

Core refusal and committed start arbitrate under the same receipt lock.
`terminalNotStarted` includes a retained UUID; ordinary `notStarted` has no
settlement authority. Exact request replay and read-only lookup recover the
same terminal evidence. A retired attempt or reused permit cannot start again;
a fresh attempt and permit for the same delivery can. Starts and terminal
receipts share a bounded 256-entry ledger with no evidence eviction. If proof
cannot be retained, the result remains unknown. Native restart can lose the
ledger; absence never authorizes retry.

The companion gateway/cloud settlement changes are [Toolshed #40](https://github.com/knitli/toolshed/pull/40)
and [cloud #683](https://github.com/knitli/knitli-site/pull/683). This native
checkpoint alone does not qualify their coupled production lifecycle.

## Reproduction

Apply [the patch](terminal-no-start-codex-v0.160.0.patch) to a clean checkout of
the exact upstream commit. Use Rust 1.95.0, just, cargo-nextest and the populated
pinned dependency cache. The release lockfile needs the previously documented
build-only local workspace version normalization; external dependencies must
stay unchanged. From `codex-rs`:

```sh
cargo metadata --offline --format-version 1 > /dev/null
just fix -p codex-app-server -p codex-app-server-protocol -p codex-tui
just test -p codex-app-server-protocol --cargo-profile dev-small
just test -p codex-app-server --cargo-profile dev-small native_selection_processor
just test -p codex-tui --cargo-profile dev-small selection_bridge
cargo build -p codex-cli --bin codex --profile dev-small
```

From the gateway package in a disposable environment:

```sh
python scripts/qualify_native_bridge.py --binary /path/to/disposable/codex
python scripts/qualify_native_bridge.py --binary /path/to/disposable/codex --terminal-retry
```

The qualifier uses a private child environment, temporary Codex home, inherited
local socket and loopback mock model. It does not use owner credentials.

## Evidence and limits

[Checkpoint JSON](terminal-no-start-checkpoint.json) records the final binary,
patch and required lint outcome. [Source manifest](terminal-no-start-source-manifest.json)
records all changed file hashes; clean pinned apply and byte comparison passed.
[Individual proof](terminal-no-start-test-proof.json) and [exact log excerpts](terminal-no-start-red-green.log.excerpt)
record nine assertion-red/restored-green pairs across eight new/repaired tests.
Tool and compilation failures are excluded from those pairs.

- Protocol: 313 passes, one skip; generated Python SDK checks: five passes.
- Full app-server: 1,816 passes, 24 failures, one skip. The exact 24 failure
  selectors match the previous pinned-source baseline.
- Full TUI: 5,587 passes, 44 failures, eight skips. The exact 44 failure
  selectors match the earlier pinned-source baseline. Neither broad run is green.
- The authorized full workspace attempt stopped before tests at missing macOS
  `glib-2.0.pc`. The separate pinned V8 helper archive returns HTTP 404.
  No dependency or host-package upgrade was used to hide either blocker.
- [Actual synthetic start](terminal-no-start-live-start.json) recovered the exact
  committed receipt with one primary mock request and zero real model calls.
- [Actual synthetic terminal retry](terminal-no-start-live-retry.json) recorded
  an expired-permit terminal receipt without model traffic, recovered it while
  an unrelated turn was busy, then started the same delivery once using a new
  attempt, permit and message. It proves native-only replay/recovery, not a
  Core busy refusal or cloud settlement. Unknown mock request count is zero.

A positive direct Core start still needs a separately reviewed cloud ACK
correlation extension. Do not fabricate a queued submission ID, infer user-input
observation, release delivery capacity, or enable production binding from this
checkpoint. Coupled cloud/local/native qualification and an authorized manual
canary remain release gates.
