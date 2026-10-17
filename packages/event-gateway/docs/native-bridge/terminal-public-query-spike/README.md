# Native terminal public query artifact

This review bundle packages a bounded public terminal query and paired TUI bridge spike. It does not activate an installed client, Start, selection renewal, provider execution, cloud settlement, or production binding.

Apply the patches in order to the frozen 66-file terminal-history selected source closure plus the hashed app-server test-module supplement described below:

1. `01-public-query.patch`: public protocol and app-server query (8 files).
2. `02-tui-terminal-query.patch`: paired TUI query bridge (4 files).
3. `03-generated-protocol.patch`: generated JSON, TypeScript and compressed exports (6 files).
4. `04-generated-sdk.patch`: subsequent Python SDK regeneration (1 file, 12 added lines).

The first three patches preserve the original frozen 18-file proof. The fourth is a separately qualified generation follow-up; it was not part of the 375-test run. The original tested and final hashes are retained independently. `finalSelectedSourceClosureSha256` changes only the Python generated file within the 71-file selected closure.

The replay required the original 66-file history closure plus the existing app-server test module `codex-rs/app-server/tests/suite/v2/mod.rs`. Its base hash was checked against the frozen history bytes and the frozen-history baseline Git object recorded in `proof/replay.json`. This is local baseline provenance, not independent upstream authentication. All four patches passed `git apply --check`, were applied in a disposable directory, and produced the recorded final 71 hashes. No native executable ran during artifact packaging.

## Evidence and limits

`proof/source-qualification.json` records the earlier native proof: 313 protocol, 23 app-server, 38 TUI tests, and one RPC scenario (375 total). It includes causal checks and wire/bridge observations. These are recorded results, not tests rerun by this bundle. Seven tested files differ from the final formatted source. `tested-to-final.diff`, `clippy-source-delta.diff`, and the tested/pre-format hashes preserve that distinction. The retained Clippy edit removes a redundant Copy clone in one new TUI test. The original proof records successful formatting equivalence; native tests did not run after fix/format.

`proof/sdk-generation.json` closes the original missing-wheel SDK generation gate using the exact locked 27-package tool environment. Generation exited successfully, changed only `sdk/python/src/openai_codex/generated/v2_all.py`, and left the original 18 frozen files and dependency lock unchanged. It preserves source log/cache digests and sanitized environment details without bundling tool caches or raw logs.

Full native workspace tests remain pending owner approval under native repository instructions. Aggregate Bazel/Starlark formatting remains blocked by unavailable Dotslash. Installed-client, owner/provider, cloud settlement and activation qualification remain outstanding.

## Offline artifact check

Run `python3 verify.py` from this directory. It checks bounded inventory, payload hashes, source-map consistency, patch structure and recorded replay metadata. It does not execute native code or repeat the historical test run. Optional `--source-root` verifies the complete final 71-file closure against a supplied source tree; `--frozen-base-manifest` authenticates the original external history manifest by its pinned digest. The sibling `terminal-history-spike/manifest.json` supplies the immutable parent source closure.

The manifest and verifier are review roots, not signatures. Hash consistency detects damage or contradictory evidence; it cannot independently attest a producer or establish test execution. Raw logs and private source trees are not included. Review any source changes and complete the remaining qualification gates before integration or activation.
