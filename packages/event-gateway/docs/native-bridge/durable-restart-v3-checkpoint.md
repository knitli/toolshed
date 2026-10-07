# Native durable restart v3 checkpoint

The corrected cumulative prototype applies cleanly to upstream `a956835d020762cb2b570053af06f643a11c0ecc`; all 48 source hashes match a fresh pinned apply. It adds explicit v3 bridge identity and StateDB migration 0060 while preserving 0059 and default v2 behavior. Exact historical receipt recovery is read-only: it never restores the old selection or authorizes Start.

Failed Core preparation now cleans only its matching provisional turn and returns non-Started. The app-server still checks durable positive proof first; absent that proof, the registered attempt remains Unknown. It does not manufacture terminal no-start or retry authority. Concurrent replacement turns are preserved.

The current frozen CLI is SHA `0fb3a5de06ab2ccb8dcc20c11cb71cad1f0c1b85fbfa3a5c6fd16ca1f57d22de`, built with Rust 1.95, offline Cargo, and `dev-small`. Current Core turn-input checks passed 22/22; guarded-start 4/4; adjacent MCP start 1/1; actual app-server/Core-input integration 1/1. Two new regression methods have three meaningful assertion-red/restored-green pairs, including a separate replacement-helper sensitivity campaign. Owner tests preceded final scoped `just fix`; the CLI was built afterward. No tests ran afterward in that frozen source checkout.

The prior v3 inventory retains twelve substantive methods, eleven v3-specific causal pairs, seven mechanical fixture edits, and one explicitly nondiscriminating in-memory lookup subcase. Existing protocol 313, app-server processor 18, TUI 28, and State 215 suite counts are historical pre-correction runs; there is no claimed full 216-test State run. Those source files are unchanged. Repository formatting remains partial because non-Rust tools/dependencies were unavailable; scoped Rust formatting and fix passed. No full workspace suite ran in this iteration. Loopback-denied setup runs and invalid mutation trials are excluded.

The captured portable runner retains all 31 former assert validations as explicit checks under `-O`, verifies SDK files before importing them, and cleans resources acquired during partial restart setup. Isolated meaningful sensitivity checks pass in normal and optimized Python. The installed wheel matches all eleven modules and five contracts at SDK #50 head `57896c36fdc4e8298fa2d7aeea6f9c0b4f635d8e`; its checksum is `01f9d61ee6a915b0ee12f25b047ecc6ddc4110b1c5b45f455e8e9e4f940d3f16`.

The bundled [runtime proof](durable-restart-v3-runtime-proof.json) executed the captured runner under `-O` with that wheel and corrected CLI. After stopping the original TUI/backend, a different selected thread recovers the exact expired Core receipt twice. All fifteen structurally valid changed-identity probes exercise Receipt and return Unknown; the old mapping stays unavailable. Start is probed once with the exact original stale request. Counts are one synthetic primary, one title, zero unknown or real model calls. A local stale-Start refusal does not prove prior-attempt no-start settlement. InputRecorded proves a genuine Core item plus durable receipt anchoring, not model success or transcript materialization. Witness readiness does not certify Core idle; the final Core idle fence remains authoritative.

The current runner adds a later cleanup correction: SIGKILL escalation targets the owned process group even after its leader exits, and thread/PTY cleanup still runs if reaping times out. Focused lifecycle tests cover this correction. The bundled native/workerd proofs and their hashes remain unchanged historical evidence; they do not certify a new live run of the cleanup-corrected runner.

A separate controlled workerd run uses the same corrected CLI/current SDK and cloud #685 `ed23882`. It proves real claim, Submitted then Observed, separate immutable ACKs, slot release/current watermark, and an identical observed ACK after a lost committed reply, local-store restart and permit expiry. Its native process does not restart. The harness now stops the entire owned native process group and verifies backend absence before removing its temporary directory. The first cleanup-failed trial is excluded; its exact writer was not traced. Qualified-admin/runtime, Access/Messaging credentials and budget, manual source, queue, and loopback transport are explicit fixtures. Production admission and Mesh delivery remain unproved.

The [proof manifest](durable-restart-v3-proof-manifest.json), [source manifest](durable-restart-v3-source-manifest.json), [causal map](durable-restart-v3-method-causals.json), and [patch](durable-restart-v3-implementation.patch) retain hashes, commands, independent audit closures, and separate historical snapshots. Earlier SDK/native proofs do not validate this correction.

Replay requires Python 3.13, the exact current wheel above, SDK reader SHA `31a630277c0c0a552036233586792c1c04528faf7d2c5fec2eef70d83e270425`, and the corrected CLI. Set their existing verified paths, then run from this directory:

```sh
EVENT_NATIVE_QUALIFIER="$EVENT_PINNED_READER" "$EVENT_PROOF_PYTHON" -O durable-restart-v3-qualify.py \
  --binary "$EVENT_NATIVE_BINARY" \
  --sha256 0fb3a5de06ab2ccb8dcc20c11cb71cad1f0c1b85fbfa3a5c6fd16ca1f57d22de \
  --output "$EVENT_PROOF_OUTPUT"
```

The binary and wheel are external prerequisites; this is not a self-contained fresh-checkout test. The runner uses disposable homes and a loopback mock model. No installed owner client, production binding, automatic wake, deployment or submodule pin changed.
