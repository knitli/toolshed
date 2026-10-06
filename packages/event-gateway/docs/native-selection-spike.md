# Native Codex selection witness feasibility spike

Result: **partial; not production-ready**. A real source-built Codex TUI can emit its selected thread, input readiness and revocations from its own event loop. The disposable FIFO transport fails closed under ordinary burst typing, and successful saved-thread resume was not established without a model turn. This does not enable native ingress, queue draining or execution fencing.

## Reproducible candidate

- Upstream `openai/codex`, tag `rust-v0.160.0`, commit `a956835d020762cb2b570053af06f643a11c0ecc`.
- [Source patch](native-selection-spike/codex-v0.160.0.patch). Apply from the upstream repository root with `git apply`. It includes the new source file and the release lockfile's 159 workspace-package version corrections (`0.0.0` to `0.160.0`). All external package pins and dependency lists were compared unchanged.
- Exact upstream Rust 1.95.0, macOS arm64, `cargo build --locked -p codex-cli --bin codex --profile dev-small` from `codex-rs`. Build succeeded. Binary SHA-256: `07908cc2fd502c3e43ac741b6a402a904ef99d57f3d0b380ebf925aa33433c40`.
- Run `python3 scripts/observe_codex_bridge.py --binary /absolute/patched/codex --client-binary /absolute/patched/codex` from this package. Both backend and TUI came from the same source build; backend implementation was unchanged. The harness creates private home, sockets and per-client FIFOs, blocks all turn/queue calls and server-request responses, and records metadata only. It permits ordinary thread naming to investigate persistence.
- `CODEX_SELECTION_WITNESS_PIPE` opts a client into the disposable witness. No shared installation, config or daemon was changed.

The witness owns a random client ID, queries backend PID through its actual app-server handle, and issues a new connection nonce after reconnect. The nonce is **not** a server-attested incarnation. Selection generation advances on readiness changes, revocation and reconnect. Native eligibility requires a matching configured selected thread, live attachment, enabled composer, and no modal/protected request/transition/reconnect/startup work. Each selected event branch revokes before its handler awaits. Heartbeats run inside the native UI loop every 250 ms; the sink expires after 1 second. A 750 ms native loop gap revokes before any renewal, so a paused process cannot renew an expired generation unchanged.

## Live evidence and limits

[Metadata evidence](native-selection-spike/live-evidence.json) contains all 227 wire rows and compact native transitions from the final binary, with shared observation order. The 727 total native rows include heartbeats; the retained artifact excludes unchanged normal heartbeats. Zero turn or queue requests occurred.

| Case | Observed result |
| --- | --- |
| New client/thread | Client `a` became eligible for `01a1120e-4833-7631-aab5-626161772b30`; a distinct client `c` became eligible for another thread. |
| Native `/new` | Selection moved to `01a1120f-5a0f-7990-8157-5393c4e35429`, generation 86. |
| Ordinary `/rename spike-a` | Native `thread/name/set` succeeded and emitted `thread/name/updated`, without a turn. |
| Resume renamed empty thread | `thread/read` found metadata, but `thread/resume` did not establish a resumed native selection. A second client attempting the same thread exited. Successful saved-thread resume and same-thread multi-client readiness remain unproven. |
| Burst slash-command typing | Receiver reported malformed at order 133; subsequent typing ended client `a`'s witness at order 514 (EOF). Conservative per-key revoke/renew emission creates heavy FIFO traffic. Native code closes on any unsuccessful nonblocking write; exact errno was not captured. Transport availability therefore fails this spike. Separately, the receiver checks aggregate buffer size before splitting lines: a valid 89-byte partial plus the next 4096-byte read exceeds its limit and drops valid records. This confirmed receiver bug is consistent with order 133, but does not establish the cause of native writer closure. The retained harness subsequently fixes framing to enforce the bound per line or partial record, with a burst/oversize-recovery regression and individual assertion-red/restored-green proof; this live trace predates that harness correction. |
| SIGSTOP / SIGCONT | Client `c` expired at order 668, generation 17. First native emission after continuation was **ineligible generation 18**, cause `loop-gap` (670), followed by eligible generation 19 (671). |
| Disconnect | Client `c` revoked at 765 and rebound with a different connection nonce at 788; it stayed unavailable after the empty-thread resume attempt. |
| Backend restart | Sink rejected the previous backend as `unknown-backend` at 844; native diagnostics changed PID 33324 → 52228 and connection nonce at 889, remaining unavailable. |
| Client death / cleanup | Client `c` death produced EOF at 953. Harness exit returned zero; only the two metadata logs remained in its private directory (home, FIFO and socket cleanup completed). |

An earlier candidate established modal `/model` and resume-picker cancellation revocations, but exposed same-generation renewal after a long stop. That candidate is not final acceptance evidence. The final loop-gap change fixes that specific state-machine defect and was observed live above. Remaining modal routes, successful saved resume, same-thread writable/read-only arbitration, exact write-failure diagnosis, and a stable transport need further work.

Native pre-handler revocation is a source property. FIFO observation is asynchronous: wire order can precede receiver observation of a revocation. This is not atomic ingress authorization or execution-start fencing. PID plus a connection nonce is not authenticated server identity. No production adapter consumes these records.

## Focused verification

Two new native tests ran through upstream `just test -p codex-tui --cargo-profile dev-small <test-name>` (nextest), individually:

- `revocation_and_reconnect_never_reuse_selection_generation`: production sabotage retained eligibility on revocation; assertion `revocation must clear eligibility` failed. Restoring production passed.
- `delayed_loop_revokes_before_renewal`: production sabotage disabled the 750 ms expiration; assertion `delayed loop must revoke before renewing` failed. Restoring production passed.

[Red/green excerpts](native-selection-spike/) retain exact focused result lines. The final source was restored before the successful final binary build. Python sink expiry likewise had an individual assertion-red/restored-green check. After the cleanup corrections below, the full Python suite passed: 76 tests in 1.044 seconds (local-socket permission was required). Sink and emitter mutation evidence is retained alongside the native test excerpts.

Scoped Rust formatting completed with pinned rustfmt. The repository-wide `just fmt` could not complete because unrelated formatter/download tooling was unavailable; its incidental justfile edit was restored. This is a bounded feasibility patch, not an upstream-ready or cross-platform release.

## PR 35 cleanup follow-up

The FIFO reader now waits for its initial writer, then emits EOF once and ends after that writer disconnects (or the child exits before connecting). Previously it continued polling every 25 ms after permanent EOF. Both metadata logs now close even if earlier resource cleanup raises. Two regressions each passed an isolated production-sabotage assertion-red/restored-green check; see [review proof](native-selection-spike/review35-red-green.log.excerpt). The native spike remains partial; these harness fixes do not repair the native writer or establish saved-thread resume.
