# Deferred terminal ordering spike

Frozen offline evidence for the ordering gap identified by the sibling terminal-completion spike. This bundle enables no production behavior, runtime pin, native installation, or automatic round completion.

## Change and proof

A terminal event can arrive before the asynchronous durable Started write. The six-file incremental patch stores a candidate on the existing bounded receipt row using trusted listener thread context and the explicit Core turn ID. The complete original v3 identity remains immutable. A candidate alone is not terminal proof: a matching genuine Started/InputRecorded transaction atomically promotes it. Conflicting candidates remain Unknown; committed proofs are immutable. Durable correlation survives an empty volatile receipt store.

Guarded start already registers its volatile receipt before releasing Core execution. This spike does not claim a same-process terminal-before-guard-registration race.

The real-path test constructs the actual NativeTurnStartGuard and app-server listener, starts through Core `start_turn_if_idle`, and delays the caller's durable Started write. A trusted prompt hook demonstrably runs and delays cancellation's input-preservation path beyond the abort grace. The real canceled event reaches the listener while the row remains Pending with no input item; the later Started write promotes it. The mock provider records zero requests. This is a guard/Core/listener test, not a full RPC/process-startup test.

## Recorded validation

All commands ran in an isolated Rust 1.95.0 checkout with just 1.58.0, cargo-nextest, and an offline dependency cache. The original fixed-local qualification script generated evidence; it was not a portable hardened reproducer and checked only its 13 modified source files. Its hash is retained in `manifest.json`. It is intentionally not copied here.

- **34 scoped regressions:** `just test -p codex-state --lib native_ --retries 0` (15) and `just test -p codex-app-server --lib native_selection_processor --retries 0` (19).
- **20 recorded phases:** those two regression groups, two actual Core fixture exports, and 16 observer/recovery phases. Fourteen runs passed normally; six deliberately exited their child process: 71 before observation, 73 after candidate persistence, and 72 after promotion. Nextest returned 100 for each expected child exit. Exact portable command arguments, environment placeholders, exit codes, and original log hashes are in `proof/results.json`.
- **Six causal assertion RED checks:** four state tests disabled promotion, conflict retention, full-v3 validation, or atomic rollback; two app tests disabled promotion. Each failed at the intended assertion, then production bytes were restored before the final GREEN run. `proof/causal-red.json` records commands, mutations, bounded assertion excerpts, and original log hashes.
- Completed, failed, and canceled outcomes were produced by actual Core tasks, both normally and with the real rollout writer closed. That is a persistence-writer failure test, not an operating-system disk-failure test. Exact fixture bytes and their hashes are preserved. Before/candidate/after recovery rows show non-authoritative candidates before anchoring and stable committed receipt IDs afterward. Failed database writes leave candidate and terminal fields null.
- `just fix -p codex-state -p codex-app-server --lib` passed with existing warnings and four test diagnostic `eprintln!` warnings. `just fmt` completed Rust and Just formatting; unrelated Bazel/Python formatters lacked `dotslash` and `uv`. **No Rust tests ran after fix/fmt. The full workspace suite remains unrun.** All 13 final files equal exact rustfmt output of the tested bytes; `tested-to-formatted.diff` records the delta.

Raw logs, databases, WAL files, caches, and binaries are excluded. Raw-log hashes identify locally audited evidence and cannot be independently reverified from this bundle alone. The portable manifest is a path-redacted derivative; `frozenManifestSha256` identifies the unchanged original local manifest.

## Patch and source provenance

`ordering-incremental.patch` applies after the sibling terminal-completion patch. `terminal-ordering-cumulative.patch` contains terminal completion plus ordering and applies after the historical native Core idle overlay, not directly to bare upstream. Exact patch bytes and SHA-256 values are in `manifest.json`.

The recorded upstream base is `a956835d020762cb2b570053af06f643a11c0ecc`. The original historical 57-file generation/replay trees and prior frozen 11 terminal files remained unchanged. Each new patch was applied to a separate selected-source replay and reproduced **61 selected file hashes**: the historical 57-file manifest with the final 13-file manifest overlaid, final bytes winning overlaps. This is **selected source closure provenance, not full upstream Git HEAD, complete-tree, or deployed-binary verification**. The disposable source checkout has an unborn Git HEAD.

## Bounded verification

The short checker executes no native commands, subprocesses, repository recipes, or database operations. Before loading the historical source entries, it enforces the recorded byte hashes of the parent historical manifest and sibling terminal-completion patch. It then verifies bundled artifact hashes and the historical/final manifest union; optionally it checks every selected source file. The original frozen manifest is not bundled: its recorded hash is checked only when supplied with `--frozen-manifest`, otherwise the result explicitly reports it as not checked. Consequently it needs neither `JUST_BIN` nor SQLite URI handling. It does not rerun or independently reproduce the native behavior.

```sh
python3 packages/event-gateway/docs/native-bridge/terminal-ordering-spike/verify.py
python3 packages/event-gateway/docs/native-bridge/terminal-ordering-spike/verify.py --source-root /absolute/path/to/disposable-patched-source
python3 packages/event-gateway/docs/native-bridge/terminal-ordering-spike/verify.py --frozen-manifest /absolute/path/to/original-frozen-manifest.json
python3 -m unittest discover -s packages/event-gateway/tests -p test_terminal_ordering_artifacts.py -v
```

Keep both the parent historical manifest and sibling `terminal-completion-spike/terminal-completion.patch` alongside this folder. The artifact tests include a qualified synthetic source control followed by historical-only and final-file mutations, rejection, restoration, and a passing control. Deliberately skipping historical-only hashes, skipping final hashes, and leaking an executable path each produced a failing artifact-test assertion before restoration; all six tests then passed. `proof/package-validation.json` records these checks. A later provenance regression changes the historical manifest metadata and prior patch bytes while preserving the selected source closure, and tests the optional frozen-manifest check; all seven artifact tests pass. The original six-test packaging record remains unchanged. Packaging checks do not execute Rust tests.

## Remaining limits

Actual notification loss, history repair, and durable history reconciliation are not implemented or qualified. A pending row without a genuine anchor and a conflicting candidate remain Unknown. There is no fsync/power-loss durability claim, public terminal wire change, TUI/Python consumer, cloud integration, runtime activation, or owner installation. Automatic round completion remains blocked pending its later integration gates.
