# Native binding source checkpoint

The combined experimental patch targets upstream Codex commit
`a956835d020762cb2b570053af06f643a11c0ecc` (`rust-v0.160.0`).
`native-binding-source-manifest.json` records the patch SHA and every changed file.
The binary diff includes new Rust modules, JSON/TypeScript schemas, compressed
schema exports, and the generated Python SDK enums. Applying it to a clean archive
of that exact commit succeeded; all 39 resulting files byte-matched the built source.
The prior transport checkpoint and its binary remain separate, unchanged artifacts.

`native-binding-checkpoint.json` records the final binary SHA and checks. This is
an opt-in experimental build, not a production native adapter or a full-workspace
qualification. Runtime evidence is recorded separately against the binary SHA.

## Reproduction

Use the pinned Rust **1.95.0** toolchain, `just`, and `cargo-nextest`. From a clean
checkout of the pinned commit, apply `native-binding-codex-v0.160.0.patch`, then work
in `codex-rs`:

```sh
rustc --version
cargo metadata --offline --format-version 1 > /dev/null
just clippy -p codex-arg0 -p codex-utils-pty -p codex-tui --profile dev-small
just test -p codex-tui --cargo-profile dev-small selection_witness
cargo build --locked -p codex-cli --bin codex -p codex-tui --bin codex-tui --profile dev-small
```

The release commit's lockfile lists 159 local workspace packages as `0.0.0`, while
its workspace manifest uses `0.160.0`. The metadata step normalizes those local
versions; a populated dependency cache is required for offline resolution. This
build-only lockfile normalization is excluded from the patch. A structural check
verified exactly those 159 version changes, with all external packages and every
dependency list unchanged. Do not replace it with a general dependency update.

The unchanged upstream `just test` recipe sets `RUST_MIN_STACK=8388608` (8 MiB)
and `NEXTEST_PROFILE=local`. Use `--cargo-profile dev-small` for nextest, rather
than the Cargo build spelling `--profile dev-small`.

## Verification boundaries

- Final nonmutating arg0/PTY/TUI clippy, 18 focused witness tests, and CLI plus
  standalone TUI builds passed. The Linux-only PTY callback was source inspected;
  this macOS host did not compile or execute that conditional branch.
- R1 added eight descriptor-adoption mutation pairs across four tests and four
  live helper cleanup pairs (both entrypoints, both bridge modes). Removing the
  fs-helper cleanup callback retained the socket while the helper blocked on
  stdin; restoration closed it while the helper stayed alive. See
  `review-r1-fd-mutation-results.json` and `review-r1-helper-causal-results.json`.
- Fourteen earlier production mutation pairs across 12 new/repaired tests failed at their
  intended assertions and passed after restoration. See the causal proof files.
- The full TUI crate run had 5,585 passes, 44 failures, and eight skipped tests.
  The failures were classified as 38 release-version snapshot cases and six host
  environment cases. All 44 reproduced with identical failure signatures on the
  clean pinned baseline (8,775 tracked blobs verified; only build-only Cargo.lock
  normalization differed), with zero unresolved cases. See
  `tui-project-baseline-results.json` and `review-r1-tui-baseline-comparison.json`.
  This broad run precedes the final helper cleanup; focused witness and integration
  checks were rerun afterward. The full crate run is not claimed green.
- Earlier patched-source host controls passed all six cases with process-only `NO_COLOR`
  removal and Git `commit.gpgsign=false`; no global Git settings, accepted
  snapshots, or product behavior were changed for that check.
- Two guarded Core tests, nine native-binding server tests, 313 protocol tests
  (one skipped), and five Python SDK generation checks passed. Three Core/server
  earlier mutations failed at the intended assertions and passed after restoration.
  R1 adds three server pairs covering deadline anchoring, permit preflight, and
  shared commit conflict; see `native-guard-mutation-results.json` (`review_r1`).
- Full Core: 4,835 passed, 21 failed, 27 skipped. Eighteen failures reproduce on
  the clean pin; three helper-dependent cases passed after building the pinned
  test helper. Two additional process-only controls passed. Eight reproduced
  failures remain without a complete root-cause diagnosis; none is claimed fixed.
- R1 full app-server: 1,819 passed, 16 failed, one skipped, with process-only
  signing disabled. All 16 match the clean pin: 12 unavailable code-mode helper
  cases and four MCP HTTP 404 cases.
- The scoped arg0/PTY suite initially had 60 passes, two failures, and one skip.
  Both failures reproduce on the clean baseline only inside the sandbox: the
  shell cannot reopen `/dev/fd`. Both pass with local sandbox escalation; see
  `review-r1-helper-baseline-results.json`. The final escalated scoped suite
  passed all 62 tests, with one skip.
- The authorized `just test --cargo-profile dev-small` workspace attempt stopped
  before tests at missing macOS `glib-2.0.pc`. Separately, the pinned V8 archive for
  `aarch64-apple-darwin` returns HTTP 404, preventing the code-mode helper build.
  No source/dependency versions or system packages were changed to bypass either
  failure. See [detailed native results](native-guard-mutation-results.json) for
  exact commands, counts, controls, and blockers.
- Final TUI integration passed 23 tests with four skipped (exit 0). Nextest
  marked `screen_reader::startup_records_screen_reader_detection` as leaky;
  its assertions passed. The CLI used here byte-matches the immutable qualified build.
- The final binary passed the [synthetic start qualifier](live-native-start-evidence.json):
  one primary loopback model request, one recognized automatic title request,
  zero real model calls, and exact read-only committed receipt recovery.
