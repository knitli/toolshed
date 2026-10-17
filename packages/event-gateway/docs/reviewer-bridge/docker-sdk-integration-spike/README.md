# Local reviewer SDK / Docker integration spike

Current packaged source passed **attempt 3: four cases and all five containment controls**, using actual SDK **0.3.209** with a fixed Docker protocol fixture. Root recorded launcher exit 0, independent absence for all four exact container IDs and four names, unchanged daemon identity, and no remaining owned host processes. The repository source is copied byte for byte from the qualified private bundle; the [result receipt](result-receipt.json) records its provenance.

The sandbox permits the **whole Node process** to access Docker's Unix socket. API guards do **not** contain a hostile SDK using a raw socket to reach the daemon. This is a pinned synthetic-fixture proof, not a general hostile-SDK or daemon security boundary.

## Current attempt 3 evidence

The [root receipt](evidence/attempt-3/root-attempt-3.json), [exact absence receipt](evidence/attempt-3/root-attempt-3-exact-absence.json), [capture receipt](evidence/attempt-3/capture.json), and [stdout](evidence/attempt-3/stdout.log) record the final run. The frozen manifest SHA256 is `d4f23dfa5846905d57d61832e560ac69f73bd9c73ea4cd1653d62cc3f63f33d2`. Daemon ID remained `804dc7e7-2939-459e-b28d-4e1a35038c92` through execution and independent readback.

Success completed; early terminal, EOF, and abort produced the expected `incomplete`, `missing_terminal`, and `timeout` refusals. The abort container's exit 137 was expected. All five controls passed: denied outside-scratch read, positive scratch write, denied IPv4, denied IPv6, and denied access to the other Unix socket. The canary remained unchanged and was removed; the forbidden listener was closed and removed.

[Captured stderr](evidence/attempt-3/stderr.log) retains four `CLAUDE_SDK_CAN_USE_TOOL_SHADOWED` warnings: the bare allowed-tool entry bypasses `canUseTool` for `mcp__frozen__read_next`. Their presence is recorded, not accepted as production authorization behavior or used as evidence of security containment.

The private-fixture manifest and README remain unchanged creation-time snapshots, including UNEXECUTED wording. The subsequent attempt 3 receipts establish execution; those frozen files were not rewritten after the run.

## Historical evidence

The immutable [root receipt](evidence/history-attempt-2/root-attempt-2.json), [capture receipt](evidence/history-attempt-2/capture.json), and [captured stdout](evidence/history-attempt-2/stdout.log) record attempt 2. The [independent absence receipt](evidence/history-attempt-2/root-attempt-2-exact-absence.json) records empty exact-CID and exact-name listings for all four containers and no remaining owned host processes. Daemon ID before and after was `804dc7e7-2939-459e-b28d-4e1a35038c92`. These are archived root observations, not new checks performed during packaging.

Success completed; early terminal was refused as `incomplete`, EOF as `missing_terminal`, and abort as `timeout`. All four passed their expected outcomes. Captured guards report one denied subprocess probe, one denied fetch probe, and four custom spawns. Containment observations report denied outside-scratch read, IPv4, IPv6, and other Unix socket access, with a positive scratch-write control. The capture receipt records an unchanged then removed canary and closed/removed forbidden Unix socket.

The [manifest](evidence/history-attempt-2/manifest.json) is the unchanged **pre-execution snapshot**: its UNEXECUTED fields describe creation-time state. The subsequent receipts and capture establish historical execution. The manifest hash matches the root and capture receipts.

For historical attempt 2, only eight explicitly allowlisted regular, non-symlink files smaller than 2 MiB each were copied. Capture `stdout.bin` and `stderr.bin` retain exact bytes under `.log` names. No historical executable source, SDK, or completion-driver bytes are packaged as active or disguised source. Full historical source remains private at `/private/tmp/reviewer-docker-sdk-integration-20261017/history-attempt-2`; dependency paths below are the original inventory, not repository dependencies.

| Archived evidence file | SHA256 |
| --- | --- |
| `manifest.json` | `d422a903077f40a00c94f836e7bb93839f2d57fc177d1dd25a6e2b41c11a6c98` |
| `root-attempt-2.json` | `91b90c8e8244bb3fd98586abb30c0708f667895feab8460357a566e62462da5c` |
| `root-attempt-2-exact-absence.json` | `24e6bf864346c50b5dc5a92de1fed9770b892e49ae5c57e90c9b8f9214d1087f` |
| `root-attempt-2-stdout.log` | `1eeed4034774b97b5ae6926029b2da7cc891db6d2369776a41751df842cb4340` |
| `root-attempt-2-stderr.log` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `capture.json` | `3b1fd59eb1be23e102400f76ccf8c03c1413a2cfff77466f4c8487e1f9d00d68` |
| `stdout.log` | `cf6acaaee1941cc1264edcad34881005fa0f5bc6346497e4b097b6435f399b6a` |
| `stderr.log` | `cb23d2389ea6c500cb5826c37b56c095af8f9dddb73481ec094cf1cfa502fe6c` |

## Historical source inventory

These hashes come from the attempt 2 manifest and identify that historical source only. They are not the current attempt 3 source inventory.

| Original file / dependency | SHA256 |
| --- | --- |
| `fixture.mjs` | `62ff66b8a9d3c2fb6742f11a27914493127bb9ab38d17dd2835691371e815564` |
| `launch.py` | `d552c611a6203dce651b7cd94b14bf17bc5beb1e1444ee3e31e93850bb3a359f` |
| `profile.sb` | `dc6c4ddbf8c1fd356580842eb5c6df29d1941104b47fbfeb5c3dddc701919f87` |
| `README.md` | `04ec289a4e96bfb6af10e784bde7c1402d6fd769bc708fe47bbcc04dc25d386b` |
| `/private/tmp/reviewer-sdk-process-protocol-20261017/frozen/sdk.mjs` | `7b3577a1078660a3ec43471e6738c730ca1b172070ddcf3f9a9384bcb68bd3ca` |
| `/private/tmp/reviewer-sdk-process-protocol-20261017/frozen/reviewer-completion-driver.mjs` | `4ff7c66588d16f33f67ca89670b5efe4540170bf5708d28cea7b19a2d0298eee` |
| `/private/tmp/reviewer-docker-sdk-adapter-20261017/adapter.mjs` | `aa8fb8dbb5bec8f8eb7da122a5d891af6277893b47873d00a15e92fe10ec50f4` |
| `/private/tmp/reviewer-docker-sdk-adapter-20261017/fixture/protocol-child.py` | `11777085c97fe3ebf8ce95e6bdd1dce91abe544256daad886b9b42b802d9a71c` |

The completion driver was recorded unchanged from `knitli/.github` revision `e516ab4803311cd58fc860f57371aedb0fb24f4d`, path `scripts/reviewer-completion-driver.mjs`.

## Current candidate and limits

The candidate is copied byte for byte into `private-fixture/` (the five-file private bundle: `fixture.mjs`, `launch.py`, `profile.sb`, `manifest.json`, and its frozen `README.md`) and `adapter/` (adapter sources, tests, and protocol child), with the frozen manifest bound to successful root attempt 3. This root README is separate from the frozen private README. Launch paths remain historical; the copied launcher is designed to reject invocation outside its approved private location before reading files or allocating resources. SDK and completion-driver dependencies remain external hash references only. The root performed the recorded actual SDK/Docker run privately; documentation packaging performed no live execution. The [result receipt](result-receipt.json) records copied source hashes and current qualification.

The result is limited to the tested local actual-SDK / fixed-Docker-protocol integration. Native Claude execution, provider calls, hosted qualification, and production activation remain excluded. It does not establish a production reviewer transport or complete dynamic runtime read closure.

Pre-proof checks passed: launcher Ruff/E306/C901 ≤15 and mocked historical-path refusal; fixture Node syntax and repository Biome lint; adapter owner reports 20 fake-backend cases and 8 host-only protocol-child unit cases. The separate root SDK/Docker proof passed as recorded above. No formatter or quality configuration change was applied.
