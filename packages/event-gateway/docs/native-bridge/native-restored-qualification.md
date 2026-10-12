# Restored native build qualification

**PASS, 2026-10-12 UTC.** The restored CLI
`62eac2a58bdac388850948aa82bf341c376e8653010d628de12ba642a2e343a3`
passed the current production launcher and installed command path in a disposable
consumer. Launcher, builder, and host-qualification pins now agree on this build.
The companion host remains
`679eedaea70529aa1cffc9bc0a0788c186412663544fa76c09d63b57f383a65a`.
No runtime pin override, owner-client installation, real model call, or cloud call
was used. This is an offline release qualification; `liveQualified` remains false.

The [release proof](native-restored-release-proof.json) records the exact wheel,
executed source hashes, installed package inventory, build verification, and
individual results. Raw synthetic provider requests, duplicate trace fields, and
PTY tails stay in the separately hashed local artifacts; the tracked proof
identifies those omissions explicitly. The correlated Start, receipt, tool output,
binding, configuration hashes, and cleanup results are retained in the proof.

| Check | Result |
| --- | --- |
| Actual launcher and code-mode host | One Start; fresh private file contents returned in the correlated tool result; matching `inputRecorded` |
| Installed `github-source-read` command | One signed synthetic transport call; exact response validated and returned by the real host; matching receipt |
| Foreground lifecycle | Six active redraw samples with unchanged binding; resize revocation and composer readiness fences; graceful exit 0 |
| Two-TUI restart recovery | Exact expired receipt recovered twice; all 15 changed identity probes returned Unknown; stale Start refused; old attachment unavailable |
| Cleanup | Control sockets removed, backends and owned groups stopped; final exact-artifact process readback empty; recovery bytecode cache empty |
| Gateway regression suite | 502 tests passed; Ruff and contract synchronization passed |

The wheel is
`7a284c0154519a5140e0335aeec36d0c5a773a976ea6975cc4aef5820d5ce841`.
All 20 installed module/contract files matched source, wheel RECORD, and the
post-proof inventory. The restored build uses the same upstream commit
`a956835d020762cb2b570053af06f643a11c0ecc`, metadata patch
`922c3b2aa733564f67765aec27d4128b96b697441b37b42665b6656a4ad884fb`,
and source manifest
`8f40ca398770501412963786ade67891749f3c9296a1c82c14d62f6257e98469`.
All 52 retained patched files, the original before/after source inventories, and
Rust/Cargo/rustup executable hashes were rechecked against the current builder.
No Rust source changed or rebuild was needed. This does not claim bitwise
reproducibility: the original build evidence remains unchanged and still records
`launcherQualified: false` against the former launcher pin.

The first new invocation stopped at installed-wheel preflight because `/opt` and
`/opt/coder` are group-writable on this machine. It launched no native process.
The successful runs used fresh private `/private/tmp` copies of the same verified
executables and installed wheel. Ancestor checks were preserved; no shared
permissions were changed. The host proofs used their mandatory outer sandbox.
Recovery and lifecycle runs additionally denied external networking and permitted
only loopback and Unix sockets, with a clean synthetic environment for native
processes.

Repeat the actual installed-launcher checks using the commands in
[native host qualification](native-host-qualification.md), once without and once
with `--github-source-read`. Use the current wheel and this exact CLI/host pair;
choose distinct new proof outputs. The current `durable-restart-v3-qualify.py`
reader, adapter, and qualifier hashes still match the installed consumer and
support the separate two-TUI check. Its direct bridge proof complements the
production-launcher checks; it does not exercise production cloud admission.

Earlier `362074…5f27` live wake evidence, candidate-only proofs, and unknown or
ambiguous attempts remain historical. This qualification does not resolve those
attempts or establish live authorization, automatic delivery, real-model tool
selection, or useful work after a notification. The separately recorded coupled
Workerd settlement proofs retain their own source versions and synthetic scope.
