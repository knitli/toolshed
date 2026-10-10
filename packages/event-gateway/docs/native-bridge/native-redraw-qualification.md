# Native redraw qualification

The proposed release pins `d82007ca79c2d73cfdf811bcb5efe949831c2652b3114b836f5eefea9f269c02`.
It fixes repeated selection-generation changes during idle redraws, which made
the gateway reject an otherwise successful cloud attachment with
`native_binding_changed_after_commit`.

The native TUI now skips its unconditional selection revocation only for
`Draw`. Keys, resize, paste, focus, resume, other events, and closed streams
retain revocation. Draw handlers can change readiness: they finish in the same
serialized UI loop before pending transitions and selection readiness are
checked before the next bridge tick. The server still checks binding identity,
readiness and the 750 ms selection lease at Start commit. The gateway's
post-commit binding comparison is unchanged.

The [release proof](native-redraw-release-proof.json) contains the clean build,
foreground regression, two-TUI recovery, controlled admission, and installed
wheel inventories. The new [cumulative patch](native-redraw-v1-implementation.patch) and
[source manifest](native-redraw-v1-source-manifest.json) are separate from the
historical v3 inputs, whose bytes and proof references remain intact. The patch
applies cleanly to pinned upstream
`a956835d020762cb2b570053af06f643a11c0ecc`; all 48 source hashes are checked.
Only `tui/src/app/startup.rs` changed from the previous native source manifest.
The clean macOS ARM64 build uses Rust 1.95.0 and the full upstream Git tree.
Its original evidence truthfully records `launcherQualified: false` against
the former `3e88…387c` pin. This PR proposes the matching launcher/builder pin
update after runtime qualification; it does not rewrite the build evidence.
A rebuild can have a different digest and needs separate qualification and review.

The foreground regression uses the built-in Astra idle starfield with a
synthetic model provider and disposable configuration. It answers terminal
color queries, requires sustained terminal output, and samples complete fresh
bindings over at least three seconds without input or resize. The old
`3e88…387c` binary fails this same scenario; the corrected binary preserves
the binding. A real resize advances the selection generations; a keyboard-opened
composer popup denies readiness, and clearing it restores a fresh selection.
Graceful `/quit` exits 0, removes the control socket, and stops the backend.
Model calls remain zero. The earlier idle-only test lacked an
animation trigger and passed the old binary; the resize test exercised an
intentional input fence. Neither is counted as redraw regression evidence.

Fresh two-TUI recovery restores the exact expired receipt twice, rejects all
15 identity mutations, and refuses stale Start. Controlled workerd admission
exercises two actual native sessions, 16 API requests, lost attach replies,
renewal, denial paths and transfer through fixture authority. All 20 installed
module/contract files match source and the wheel archive before and after
qualification; fresh private bytecode caches remain empty under `-I -B -O`.
Launcher tests reject the retired caller digest and retired opened-file hash,
accept only the promoted pair, and check builder/launcher pin parity.
The seven cross-repo contract blobs are unchanged; this native source/artifact
update requires no cloud contract-family or deployment change.

The full TUI crate run has 38 version-sensitive fixture mismatches: upstream
expects development version `0.0.0` while its pinned workspace builds `0.160.0`.
Two Git fixtures pass with test-only signing disabled, and an Insta assertion
passes in isolation. Integration tests pass after supplying the qualified
CLI artifact through the test binary locator. Snapshots were not accepted.
The proof records aggregate failures separately from successful scoped checks.

These are local and fixture-backed proofs. Production attachment must be
retried after this pin update is reviewed and merged. Automatic turns, manual
delivery and GitHub delivery remain disabled. The earlier pending production
commit artifact is retained; no local mapping is forced current. Public
admission, Mesh delivery, live wake, and cloud settlement are still unproved.
No owner Codex client, configuration, history, database or authentication was changed.
