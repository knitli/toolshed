# Native durable restart v3 checkpoint

**Candidate:** Rust commit `a956835d020762cb2b570053af06f643a11c0ecc`, with explicit v3 TUI bridge identity and nullable StateDB migration 0060. The 48-file cumulative source patch applies cleanly to that commit; the clean apply reproduced every source hash. `Cargo.lock` is excluded as build-only churn.

**Protocol and identity:** v3 is opt-in through `CODEX_NATIVE_BRIDGE_RECEIPT_VERSION=3`; absent selects v2 and invalid values fail closed. The TUI includes its bridge client UUID and local generation in exact read-only receipt requests, separately from the app-server generation. Start still requires a current matching selection. StateDB migration 0060 adds nullable pair fields and preserves 0059 rows as v2/null identity; exact receipt reads require a complete matching pair. Terminal retries may advance local and server generations only for the same bridge client and explicit terminal attempt.

**Causal test inventory:** [durable-restart-v3-method-causals.json](durable-restart-v3-method-causals.json) maps all 12 substantive new/strengthened test methods and 7 mechanical fixture edits. Eleven substantive methods have v3-specific semantic red/restored-green pairs. The remaining app-server in-memory lookup test has inherited method-level coverage; its added v3 candidates are nondiscriminating because the helper must return `Unknown` for every in-memory receipt. The map records this limitation and excludes setup/compile failures as causal evidence.

**Rust validation:** pinned Rust 1.95, Cargo offline, `dev-small`. Protocol fixtures: 313/313. App-server native processor tests: 18/18. TUI selection witness tests: 28/28 after independent-generation updates. The State suite was 215/215 before adding the migration regression; the migration, retry, and exact-identity tests have focused causal green runs, but there is no logged full 216-test State run. The app-server restart and DB-write-failure integration tests passed before a final test-only SQLite helper change. A separate scratch causal run also proves the final helper bytes; no test was rerun in the frozen owner checkout. Scoped `just fix` passed, including a final app-server fix after the helper change; no tests ran after the final fix. No full workspace test suite ran in this v3 iteration.

Scoped rustfmt and `git diff --check` passed. Repository `just fmt` was partial: Rust formatting succeeded, while the Starlark formatter could not start without `dotslash` and the offline Python/SDK Ruff wheels were uncached.

**Historical native TUI runtime proof:** The historical result retained at `/private/tmp/native-v3-tui-restart-result.json` records a synthetic two-TUI restart using the frozen CLI (SHA-256 `2dcd17b33116eebe7026443b85e35be0fce85912c4a675d96c3af6a0456d9a61`) and historical SDK PR50 head `21eceae56a2b605ba9634892f757bb1f06d8c4cd` / reader `bf649c17c4adbbc0a5ca21195229742e0e5b8420edab0eacc662387252edaa44`. It recovered the exact `inputRecorded` receipt twice after permit expiry, proved the old attachment unavailable, rejected 15 changed tuple fields, and made zero real model calls. The replacement TUI had a new selected thread and new server/client incarnation. It does not prove global idle/ineligible witness behavior; old Start was locally refused, but cloud no-start settlement was not proven.

A separate coupled Workerd proof used the same CLI and SDK snapshot. Its local store restarted and its model counts were primary/title/unknown = 1/1/0, but the native process did not restart and production admission was not proven. The harness only set `receipt_version=3`; the exercise/assertion ASTs and Worker/broker sources were unchanged.

**SDK boundary:** the runtime artifacts pin SDK head `21eceae`. Two P2 SDK findings were later identified and assigned for correction: persist v3-required mode before Start to prevent downgrade after restart, and use UUIDv4/v7 grammar for qualifier item IDs. These proofs are historical evidence for the pinned SDK snapshot only; they do not validate the corrected SDK head.

The machine-readable [proof manifest](durable-restart-v3-proof-manifest.json), [source manifest](durable-restart-v3-source-manifest.json), and [cumulative patch](durable-restart-v3-implementation.patch) contain the exact commands, file hashes, test boundaries, and runtime evidence. Root owns commit and publication.

## Corrected SDK runtime and replay

The bundled [runtime proof](durable-restart-v3-runtime-proof.json) now records the corrected SDK #50 snapshot `b2f55b0e0e476d9667073909bdf45174daa5334c`: 203 package tests, nine correction causal pairs, strict mode metadata persisted before Start, and corrected UUIDv4/v7 validation. The installed wheel matches all eleven modules and five contracts. Both the corrected two-TUI restart and portable exported reproduction pass with fifteen valid negative probes, exact expired receipt recovery, an unavailable old mapping, and one primary/one title/zero unknown or real model calls. InputRecorded proves a genuine Core item plus durable receipt anchoring, not model success or transcript materialization.

Controlled workerd also passes against these corrected SDK sources with an identical observed ACK after local restart and permit expiry. That run does not restart the native process. Native restart and cloud settlement are separate proofs; production admission and Mesh delivery remain unproved. Historical SDK snapshots above remain separate evidence and do not validate this correction.

Replay requires Python 3.13 with the exact corrected wheel SHA `e226efcababfb66fc15fd14330224827d006d0700374a20a7710dad6a0c634a9`, the reader from the SDK pin above (SHA `31a630277c0c0a552036233586792c1c04528faf7d2c5fec2eef70d83e270425`), and the frozen native CLI at the stated SHA. The runner checks reader, installed module, and supplied binary hashes; it creates only disposable private homes and loopback mock-model listeners. It does not install a client or deploy. Set existing verified artifact paths, then run from this directory:

```sh
EVENT_NATIVE_QUALIFIER="$EVENT_PINNED_READER" "$EVENT_PROOF_PYTHON" durable-restart-v3-qualify.py \
  --binary "$EVENT_NATIVE_BINARY" \
  --sha256 2dcd17b33116eebe7026443b85e35be0fce85912c4a675d96c3af6a0456d9a61 \
  --output "$EVENT_PROOF_OUTPUT"
```

The executable and wheel are external prerequisites, so this is not a self-contained fresh-checkout test. The exported runner differs from its executed reproduction only by two narrow fixture subprocess annotations; its whole AST is identical and Ruff passes. Historical failed busy-witness and daemon-route attempts remain excluded from causal evidence.
