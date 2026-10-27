# Native workspace qualification

The hosted full-workspace attempt on 2026-10-26 (run
[40401329025](https://github.com/knitli/toolshed/actions/runs/40401329025))
completed the test command but did not qualify the workspace: nextest reported
20,984 tests run, 20,713 passed, 265 failed, 6 timed out, and 66 skipped.
The disk reserve was released and 16 GiB remained available after the run; disk
exhaustion was not the cause of this failure.

The next harness revision passes `--features codex-v8-poc/sandbox` both to the
`cargo metadata` dependency-prime command and to the actual `just test`
invocation. This aligns the enabled `codex-v8-poc` feature with the pinned
Rusty V8 sandbox archive and binding used for the test build. The metadata file
is produced with the same feature selection, so its resolved graph records the
feature set the test command requests.

This only corrects the crate feature selection. It does not establish a passing
workspace run or address other observed failure groups. In particular, the
prior run contained 113 distinct failing test names with nested
`sandbox-exec` failures (`sandbox_apply: Operation not permitted`) under the
workflow's outer Seatbelt profile. That isolation conflict remains unresolved;
the source also has version-sensitive snapshots expecting `0.0.0` while its
workspace declares `0.160.0`, a Kitty file-payload assertion that matches part
of the encoded filename, and unresolved process, fixture, and timeout failures.
These remain blockers. No tests are excluded and no assertions are weakened.

The next isolation design must run the suite without an enclosing Seatbelt
profile while denying Internet and host-network access outside the guest. A
disposable Apple Silicon macOS VM on the owner-selected Mac is being prepared;
this change does not install, start, or qualify that VM. An in-guest firewall
was not selected: the default hosted runner can use passwordless sudo, while
whole-runner packet filtering could interrupt the runner connection. GitHub
also [does not offer private networking for macOS larger runners](https://docs.github.com/en/actions/reference/runners/larger-runners#limitations-for-macos-larger-runners).
Do not dispatch another full attempt until the replacement boundary and the
remaining source-fixture adaptations have been reviewed and validated.
