# Durable native Start anchor handoff

The prototype now stores an attempt-keyed native Start reservation and monotone `Started` / `InputRecorded` proof in SQLite. After an app-server restart with the same `codex_home`, the exact historical receipt is readable; a Start carrying the old server incarnation returns `Unknown` before consulting that durable positive and does not send another `/responses` request.

The bounded app-server/State proof is green: State 213/213, app-server native selection plus durable Core integration 21/21, and fresh same-delivery retry with a new selection generation 1/1. The Core DB-failure integration test injects a SQLite stage-update failure, observes `Unknown`, waits for `turn/completed`, verifies exactly one real request reached the mock Responses server, then verifies retry is still `Unknown` and does not increase request count. Scratch-only semantic mutants for this and restart guard both produced assertion failures; restored exact-source reruns passed.

This validates app-server process restart only. It does not recover local TUI/client identity or prove a local native/TUI restart, and it makes no power-loss claim. See `durable-restart-proof-manifest.json` for full log paths and hashes, exact child/test binary hashes, and limitations. See `durable-restart-source-manifest.json` and `durable-restart-implementation.patch` for source hashes and the cumulative app-server/State/Core/protocol patch.

Post-test `just fix -p codex-state -p codex-app-server` completed successfully. Clippy emitted a `question_mark` suggestion and a test-only disallowed `SqlitePool::connect_with` warning; it made no observed source rewrite. Per upstream AGENTS guidance, no further tests were run in that frozen source checkout after `just fix`. Full app-server package and full formatter recipe remain unqualified as described in the manifest.

The cumulative app-server patch applies cleanly to upstream `a956835d020762cb2b570053af06f643a11c0ecc`; all 29 patched files match the source manifest. It intentionally omits the TUI/CLI transport files. For the full private-client lineage, compose the prior input-recorded checkpoint with these 29 app-server/State files; do not apply overlapping cumulative patches on top of one another.

Both independent source/evidence audits closed without P1/P2 findings. The actual DB-failure integration proves initial/retry Start remain Unknown; the read-only receipt failure path is source/unit-covered, not asserted by that same Core integration. Exact test binaries were copied to read-only private artifacts after their hashes were verified.

[The per-method causal map](durable-restart-method-causals.json) covers all 19 changed or new test methods with 21 intended-assertion-red/restored-green pairs. The additional campaign ran in a separate exact-source scratch checkout and isolated build target; it did not edit or rerun the frozen source. Source, test and log hashes tie every pair to this checkpoint.
