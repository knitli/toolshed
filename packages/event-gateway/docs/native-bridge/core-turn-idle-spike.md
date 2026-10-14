# Core active-turn snapshot spike

This spike tests a native observation that can suppress new cloud dispatch while
a selected Core thread is already running a turn. It carries
`nativeCoreTurnState: busy|idle|unknown` beside the existing exact seven-field
selection binding. It does not reserve the thread or change Core's atomic `Start`
decision.

## Signal path

1. The TUI renews the selected-thread acknowledgment about every 250 ms. The
   app-server reads Core's `active_turn` slot under its lock for that exact
   thread. A populated slot is `busy`; an empty slot is `idle`; a missing,
   stale, unready, or unresolvable selection is `unknown`. After the async Core
   read, the app-server rechecks the selected thread and generation before
   returning the sample.
2. The TUI retains the acknowledgment's local `Instant` deadline, based on the
   request-send time and capped at 750 ms. Request send precedes the Core read,
   so this is a conservative expiry point. The TUI keeps that deadline local;
   it does not send a monotonic timestamp across processes.
3. When a nonce-correlated challenge is parsed, the TUI computes the remaining
   lease immediately before serializing its response. This matters if the TUI
   pauses after preparing a binding view but before reading the challenge. An
   expired or missing local deadline yields `leaseMs: 0`, which the reader
   rejects for an eligible witness. The launcher checks the existing nonce,
   deadline, and exact binding. The Python reader starts its deadline before
   the TUI response, so socket and scheduling delay consume the returned
   remaining lease instead of restarting it.
4. The disposable adapter accepts `idle` for **new dispatch admission**.
   `busy`, `unknown`, a missing or malformed field, a stale or wrong-thread
   witness, and an expired lease stop that initial dispatch before cloud claim.
   The state remains separate from the seven binding fields and cannot replace
   any of them.

## Reproducing the native source patch chain

The idle patch is incremental; it does **not** apply directly to raw Codex
`a956835d020762cb2b570053af06f643a11c0ecc`. First apply the public cumulative
`native-metadata-v1` prerequisite, then the idle patch. Use the full clean Codex
repository root at that commit; it contains both `codex-rs/` and `sdk/python/`.
With `TOOLSHED` set to this Toolshed checkout:

```sh
CODEX=/path/to/codex
TOOLSHED=/path/to/toolshed
git -C "$CODEX" checkout --detach a956835d020762cb2b570053af06f643a11c0ecc
test -z "$(git -C "$CODEX" status --porcelain)"

git -C "$CODEX" apply --check --binary -p1 \
  "$TOOLSHED/packages/event-gateway/docs/native-bridge/native-metadata-v1-implementation.patch"
git -C "$CODEX" apply --binary -p1 \
  "$TOOLSHED/packages/event-gateway/docs/native-bridge/native-metadata-v1-implementation.patch"
# Verify all 52 fileSha256 entries in native-metadata-v1-source-manifest.json;
# the manifest paths are relative to this full Codex repository root.

git -C "$CODEX" apply --check --binary -p1 --directory=codex-rs \
  "$TOOLSHED/packages/event-gateway/docs/native-bridge/core-turn-idle-native.patch"
git -C "$CODEX" apply --binary -p1 --directory=codex-rs \
  "$TOOLSHED/packages/event-gateway/docs/native-bridge/core-turn-idle-native.patch"
```

The prerequisite patch SHA-256 is
`922c3b2aa733564f67765aec27d4128b96b697441b37b42665b6656a4ad884fb`; its
52-file manifest SHA-256 is
`8f40ca398770501412963786ade67891749f3c9296a1c82c14d62f6257e98469`. The
incremental idle patch SHA-256 is
`a27af5ad6be69969597636b149a47d4d3e915f109dba5433b394227131aaa54a`. An
independent replay matched all 52 prerequisite outputs and all 18 idle-patch
outputs. The complete replayed source tree also matched the qualified source
after the existing public packaging preparation normalizes 159 local package
version entries in `Cargo.lock` from `0.0.0` to `0.160.0`; no external package
versions changed. That deterministic normalization is implemented in
`packages/event-gateway/scripts/package_native_client.py` (allowlist and
Cargo metadata steps). Pre/post lock hashes were
`5553f06583159ed64666b6eb4beea3154e06b612e6312528131bdc226a6a860c` and
`f0ea6b033508c394980bfc011907947beffcb7f7b1a56addbff90196617c14a4`.
This source replay does not claim a bit-for-bit reproducible native binary.

## Evidence

The native source checks passed on a disposable source reconstructed from the
clean Codex `a956835d020762cb2b570053af06f643a11c0ecc` base, then the cumulative
`native-metadata-v1` prerequisite and this spike's incremental patch. They used
the pinned Rust 1.95 toolchain through the required `just` wrapper:

- `just write-app-server-schema` regenerated protocol JSON, TypeScript, and
  precomputed exports; its schema fixture test passed. Python SDK type
  generation ran separately with the pinned typewriter in a disposable SDK
  copy; its exact invocation was not retained. Its output comparison is
  recorded separately in the proof manifest.
- `just test -p codex-app-server-protocol --cargo-profile dev-small`: 313 passed.
- `just test -p codex-core --cargo-profile dev-small core_turn_activity_tracks_reservation_until_task_completion`: 1 passed.
- `just test -p codex-app-server --cargo-profile dev-small client_selection_update_reports_core_busy_during_tool_and_idle_after_completion`: 1 passed. It holds a real Core turn during an actual dynamic-tool call, observes busy, completes the tool, then observes idle from a fresh selection update. Its local mock SSE listener required local-only sandbox escalation; it contacted no external service.
- `just test -p codex-tui --cargo-profile dev-small selection_`: 218 passed (one is marked leaky), including the selection witness tests.
- `just test -p codex-tui --cargo-profile dev-small delayed_challenge_refreshes_from_original_sample_deadline`: 1 passed.
- `just test -p codex-tui --cargo-profile dev-small fragmented_challenge_survives_state_burst`: 1 passed; the test verifies the state is carried beside the unchanged seven-field binding under a fresh nonce.
- `just fmt-check` passed after the source changes.
- The Python patch applies cleanly to Toolshed `ba696db45b3d19fac11963c46e125e8d2cfe8eb8` (the current main after PR #93). Replaying it reproduced all ten patched package files byte-for-byte against the qualified `cf85e25692141e4000e80c796da38cacf558b686` candidate. The complete event-gateway package suite passed **655 tests** on the patched `ba696` checkout. The earlier `cf85` candidate suite passed **606 tests**; 159 focused gateway/daemon/PTY checks and 20 launcher binding/freshness checks also passed against that candidate.

The native runtime attempts have separate outcomes:

- Attempt 1 timed out before a validated bridge response. Its original `Popen`-based `runtimeExecuted` field overstated the evidence, and its own cleanup check failed; root later verified and separately cleaned the retained scratch.
- Attempt 2 started only the sandbox wrapper. Seatbelt rejected `127.0.0.1:<port>` in a remote-IP rule before native execution; it made zero provider requests and cleanup verified its owned groups and scratch removal.
- Attempt 3 proved native execution and a mock tool turn. Busy reached the gateway gate with no claim, and a fresh idle witness followed. The run still failed because the harness expected the wrong stale-binding rejection layer and its original cleanup proof was false. Root later verified the owned groups empty and recorded manual scratch cleanup separately; the original failure proof remains unchanged.
- Attempt 4 passed the controlled native bridge proof, including busy/no-claim, a mock tool call, fresh idle, and stale-binding rejection. **It used a pre-`cf85` Python candidate whose `launcher.py` and `native_reader.py` had dropped current `nativeObservation` behavior, so it does not qualify the current-head consumer patch.** It observed a `git-remote-https` helper during native startup. Seatbelt allowed outbound traffic only to the fixed loopback provider; no Cloud calls or real model calls occurred. The helper observation does not establish whether any external connection was attempted or succeeded.
- Attempt 5 failed before native process launch because the AF_UNIX control-socket path exceeded the platform limit. `runtimeExecuted` was false; cleanup verified the owned groups and scratch removal. This is a harness-path failure, not a native signal result.
- Attempt 6 passed with the current `cf85` Python consumer and the same experimental native binary; replaying its ten-file patch onto `ba696` reproduces those consumer files exactly. It observed a real active dynamic-tool call as `busy`; a fresh busy witness reached `Gateway.dispatch` and was queued with `client_unavailable_or_busy`, with zero claim calls and no attempt created. After the mock tool completed, the completion changed the native binding counters: the old binding was rejected as `native_binding_changed`, and a fresh challenge with the current exact seven-field binding reported `idle` and an available adapter. The busy sample carried a 696 ms lease (670 ms remained at reader acceptance); the busy dispatch sample carried 672 ms (657 ms remained); the fresh idle sample carried 734 ms (718 ms remained). Each witness included `clientId`, `connectionId`, `backendPid`, `threadId`, `generation`, `serverInstanceId`, and `serverGeneration`; values are omitted from this report. The controlled turn used two mock main requests, one title request, and one tool request. Cloud calls, real model calls, and native Start calls were all zero. A `git-remote-http` helper was observed during startup; the sandbox allowed outbound traffic only to the loopback mock provider, so this does not establish an external connection attempt or success. Cleanup verified the owned groups, control socket, and scratch removal.

The companion [sanitized proof manifest](core-turn-idle-proof.json) records patch and output hashes, scoped checks, and the attempt-6 proof digest without private identifiers or host paths.

The full upstream Rust workspace suite was not run. The passing attempt-4 proof
used an experimental compiled native binary, not the installed/promoted launcher
pin `763e5e2…`; that promoted binary does not emit `nativeCoreTurnState`. The
attempt-6 bridge proof also does not qualify the installed launcher, change a
pin, enable delivery, or establish a live wake. Promotion needs a separately
qualified paired native source/binary and Python consumer.

Release order is the exact unchanged-pin launcher policy on main, then the
reviewed Python consumer with existing pins, then the attested native pin
promotion. Hold client installation until the final paired release: the interim
consumer rejects the old binary's witnesses because they lack
`nativeCoreTurnState`. The policy transition does not authorize a simultaneous
launcher logic and executable pin change.

## Limits and follow-up

The snapshot is read under Core's lock at selection-update time, then conveyed
later with the challenge. The local deadline prevents its lease from being
extended by the TUI/launcher path, but it does not make the sample a reservation.
Rechecking on every new dispatch can suppress claims while a sustained busy
observation holds; idle can still become busy after the observation and before
the remote claim. A universal zero-claim guarantee across that race needs a
separate reservation/admission protocol.

The gate applies to initial dispatch. Recovery reconciliation intentionally
uses the recorded exact attempt and native receipt path without rejecting it on
a newer busy observation; otherwise an interrupted claim or native operation
could remain ambiguous forever. That recovery path can still contact cloud
authority to resolve an earlier claim, so this spike does not claim that every
claim request is blocked while Core is busy.

`idle` describes only Core's active-turn slot. It does not prove mode,
pending-input, drain, authorization, or other Core `Start` predicates permit a
turn. Non-Draw events continue to revoke native selection. This spike changes
no production eligibility, source hashes, pins, or activation. Promotion needs
the audited compiled-client bridge run, current-head qualification, and a
separate decision on whether the residual idle-to-busy claim race is acceptable.
