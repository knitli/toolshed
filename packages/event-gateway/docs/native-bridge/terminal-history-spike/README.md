# Offline canonical terminal history spike

Frozen artifact-only evidence for recovering terminal receipts after the native observer misses Core events. The internal prototype reads existing canonical history and updates an existing receipt atomically. This bundle adds no public API, consumer, runtime pin, activation, or automatic round completion.

## Behavior and boundaries

The reader accepts only complete plain paginated history, bounded to 256 records and 16 MiB. It requires the original thread, turn, client-message identity, exact input, a genuine Core user-item ID, and one later completed/failed/canceled event. Malformed or duplicate JSON, incomplete history, inherited lineage, conflicting anchors or terminals, reused user-item IDs, repeated/late target starts, and changed snapshots remain Unknown. A target start event is optional; if present, it must precede the input anchor.

The reader holds the existing OS writer lock through its two snapshots and State transaction. This excludes cooperating writers sharing the same Codex home. Owner-controlled history is trusted; this is not protection from arbitrary external file writes. The State transaction requires the full original v3 reservation identity, preserves conflicting candidates, and commits InputRecorded plus terminal evidence together. No new receipt row or eviction mechanism is introduced.

The real Core fixture has no app-server listener or volatile receipt map. Nine cases cover completed, failed, and canceled outcomes with a normal writer, a writer closed before input, or a writer closed before terminal persistence. Actual append/flush failures are asserted while Core events still arrive. This is a closed-writer failure test, not an operating-system disk-failure test. Every reservation remains Pending before the owned child exits without Rust destructors, after explicit flush and fixture-manifest writing. Two fresh recovery processes recover the three normal cases with stable receipt IDs; the six failed-write cases remain Unknown/Pending. There is no fsync or power-loss claim.

## Recorded native validation

The frozen runs used isolated Rust 1.95.0, just 1.58.0, cargo-nextest, and an offline dependency cache. `proof/results.json` contains portable command arguments, environment placeholders, exit codes, summaries, and original log hashes. It records five phases:

- **46 scoped regression tests passed:** 18 State, nine reader, eight Core native tests, and 11 Core task tests.
- The producer deliberately exited its owned test process with **71**; nextest returned **100**. Both subsequent fresh recovery processes passed.
- **18 causal assertion RED checks:** five State, 12 reader, and one Core persistence mutation. The latter drops the canonical user-item event while actual Core delivery still succeeds; recovery then fails its required-anchor assertion. Each production mutation was restored before the final GREEN runs.
- Independent review found two ambiguous-history cases, now rejected: repeated/late target starts and user-item ID reuse across turns. Both corrections have causal RED/GREEN evidence.
- Scoped `just fix` passed with existing warnings. Three unrelated unused-import edits and build-only workspace-version lock normalization were restored. Strict Clippy separately failed on unchanged Core `turn_input_tests.rs:272` and `:368` for guards held across await.
- `just fmt` completed Rust and Just formatting; its aggregate Python/Bazel stages lacked `uv` and `dotslash`. All 19 final files equal the repository's exact rustfmt output of tested bytes; `tested-to-formatted.diff` records that delta. **No Rust tests ran after fix/fmt. The full workspace suite remains unrun.**

`proof/core-fixtures.json` is an explicitly typed projection of real canonical records and process-asserted recovery results. It preserves thread/turn/item IDs and the relevant actual event payloads, but omits paths, base instructions, and unrelated response records. It is neither a replayable canonical rollout nor a database export. The three receipt records retain their exact original JSON bytes. Original canonical-rollout and fixture-output hashes identify the unbundled evidence.

Raw logs, canonical rollout files, databases/WAL files, binaries, caches, and credentials are excluded. The manifest is a portable, path-redacted derivative linked to the unchanged original by `frozenManifestSha256`. Hashes of original logs and scripts identify locally audited evidence; the artifact checker cannot reverify those unbundled files or reproduce native behavior.

## Patch and source provenance

This Toolshed unit is based on PR125 commit `4808cbf30c4895afc6dcc4ad64ea042a296b0769`, after the existing completion and ordering units. Their bundled bytes are unchanged.

`history-incremental.patch` changes eight files after the frozen ordering patch. `terminal-history-cumulative.patch` contains completion, ordering, and history changes and applies after the historical native Core idle overlay, not to bare upstream. The recorded upstream base is `a956835d020762cb2b570053af06f643a11c0ecc`.

Both patches were applied to separate selected-source replays and reproduced **66 selected file hashes**: the prior 61-file closure overlaid with the final 19-file map, with final bytes winning overlaps. The original historical 57-file generation/replay trees and frozen ordering closure remained unchanged. This proves selected source consistency, not a complete upstream checkout, native public binding, or deployed binary.

## Artifact-only verification

The bounded checker uses only local file reads and hashes. It executes no native code, subprocesses, repository recipes, or database operations. It verifies all five bundled provenance pins before parsing their JSON or deriving a closure, then verifies all payload hashes before parsing proof JSON. It checks the historical57/prior13/prior61/final19/selected66 unions and patch pins. Optional source verification hashes every selected file.

```sh
python3 packages/event-gateway/docs/native-bridge/terminal-history-spike/verify.py
python3 packages/event-gateway/docs/native-bridge/terminal-history-spike/verify.py --source-root /absolute/path/to/frozen-patched-source
python3 packages/event-gateway/docs/native-bridge/terminal-history-spike/verify.py --frozen-manifest /absolute/path/to/original-native-history-manifest.json
python3 -m unittest discover -s packages/event-gateway/tests -p test_terminal_history_artifacts.py -v
```

Keep the historical source manifest and sibling completion/ordering bundles alongside this directory. The original native-history manifest is unbundled and explicitly reported as unchecked unless supplied. Supplying it checks that file's hash only; original raw logs, rollouts, and other original evidence remain unverified. The checker assumes the reviewed manifest is trusted and makes no independent authenticity claim.

The new Python artifact tests and `proof/package-validation.json` record packaging verification separately from native tests. Runtime integration, public terminal reporting, TUI/Python consumers, cloud integration, activation, and automatic round completion remain outside this unit.
