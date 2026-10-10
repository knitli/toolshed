# Native release candidate runtime qualification

This is the historical `3e88…387c` checkpoint. The redraw-fix candidate,
updated source manifest, and fresh runtime proofs are recorded separately in
[redraw qualification](native-redraw-qualification.md). Historical replay
commands below require the matching wheel and source checkout at Toolshed
`1d7babb7a6f294ffdc41113f46a377c56834e5f6`.

The preserved clean-build candidate `3e88bd929a8c1d6e29dd562c47c9264df5b8f5904847695b8b490ddcf492387c`
passed a macOS ARM64 two-TUI restart qualification with the corrected
standalone gateway wheel and an explicit `--no-daemon` qualifier. The
[release proof](native-release-runtime-proof.json) records the binary, build
evidence, executed runner, qualifier, installed reader, wheel, and raw logs.

The preserved binary and build JSON match the earlier clean-build proof. All
48 patched source hashes matched the source manifest at this checkpoint; no Rust
rebuild was needed. The initial wheel SHA was
`09be6b33fbdb64224e4f008faa38703821d928c6594963f6c3312944e8294b7b`.
All 20 packaged modules/contracts match both the wheel archive and the base
commit. This is the **pre-promotion wheel**: the later launcher pin update is
separate from that earlier reader/adapter runtime qualification. The latest
two-TUI run uses dispatch wheel
`63c5ac411234f4a619540386c01183925e8bbdf84037734d95d08ea6bc251123`
and adapter SHA `25e7221ab4b8b378d2f7378b7e4b7f85b0ccf1f8f286b0385c88f4fee23fbf9e`.
Earlier runs, including release wheel `d11642c3ca2eb96f72f7ce192c422c60be174487cea418c243157d87fd1322a2`,
and their exact source hashes remain separately recorded.

The current runner verifies the qualifier, adapter, package initializer, and
extracted installed reader before loading them. It ran under Python 3.13.14
with `-I -B -O` and an explicit fresh 0700 bytecode-cache prefix, verified empty
before and after execution. All 20 installed module/contract files matched
source and wheel bytes before and after the run. Its three focused cleanup tests also passed. The first attempt
was denied loopback binding by the sandbox before native launch and is
excluded. The authorized loopback-capable retry exited successfully.

After the first TUI/backend stopped, a second TUI with a different selection
recovered the exact expired receipt twice. All 15 structurally valid changed
identity probes returned Unknown; the original mapping stayed unavailable,
and the stale Start was locally refused. Counts were one synthetic primary,
one title, and zero unknown or real model calls.

Replay with the external candidate and the recorded installed wheel:

```sh
EVENT_RECOVERY_CACHE="$(mktemp -d)"
EVENT_NATIVE_QUALIFIER="$PWD/scripts/qualify_native_bridge.py" \
  /private/tmp/event-native-dispatch-20261009/installed/bin/python -I -B -O \
  -X "pycache_prefix=$EVENT_RECOVERY_CACHE" \
  docs/native-bridge/durable-restart-v3-qualify.py \
  --binary /private/tmp/native-codex-p7-full-tree \
  --sha256 3e88bd929a8c1d6e29dd562c47c9264df5b8f5904847695b8b490ddcf492387c \
  --output /private/tmp/native-release-replay.json
rm -d "$EVENT_RECOVERY_CACHE"
```

Run from `packages/event-gateway`; the runner requires the exact recorded
qualifier/adapter/reader hashes. The artifact pair remains external to the
wheel. This proves neither bitwise build reproducibility, cloud settlement,
production admission, live wake, nor old-attempt no-start settlement. No owner
client was replaced or installed.

## Foreground launcher gate

A separate smoke of the promoted wheel
`3ad51947c3d04e28401a93fbe37228b21895e8bba7fee3f29133ef3023b57c5c`
accepted the candidate digest and opened its TUI, but failed before obtaining
a selected witness. The standalone CLI requires a complete background-server
package or `--no-daemon`; the launcher supplied neither. The captured failure
is recorded separately in the proof.

After adding `--no-daemon`, the earlier rebuilt wheel
`d11642c3ca2eb96f72f7ce192c422c60be174487cea418c243157d87fd1322a2`
passed the foreground smoke. The latest [foreground smoke](native-release-launcher-smoke.py)
passed against the dispatch wheel
`63c5ac411234f4a619540386c01183925e8bbdf84037734d95d08ea6bc251123`. It exercised
the installed CLI and `launch()` through a real PTY, accepted the candidate,
reported a selected session with attachment and automatic wake disabled,
returned its binding and fresh challenge-correlated witness, and removed its
control socket and stopped the backend after graceful `/quit` with exit code 0. No model requests
occurred. All 20 installed files match the dispatch wheel and source. Its reader
and adapter are byte-identical to the fresh two-TUI run. The restart runner uses
a directly supplied private bridge; these results do not prove live daemon
dispatch or production cloud wake.

```sh
/private/tmp/event-native-dispatch-20261009/installed/bin/python -I -O \
  docs/native-bridge/native-release-launcher-smoke.py \
  --package-source "$PWD/src/event_gateway" \
  --binary /private/tmp/native-codex-p7-full-tree \
  --output /private/tmp/native-release-launcher-replay.json
```

The smoke uses disposable configuration and homes and requires loopback
binding. It requires `-I`, verifies its interpreter and noneditable installed
wheel against the explicit source directory before importing gateway code,
checks all 20 packaged module/contract bytes and wheel RECORD hashes, and
records the preflight helper hash. Before importing gateway code, the parent
uses a fresh private bytecode cache with writes disabled. The foreground child
uses a separate fresh private cache via `-I -B -X pycache_prefix=...`; the smoke
checks that this cache starts and remains empty. This prevents previously
cached bytecode from bypassing verification of the installed source files.
Socket-bearing temporary directories use resolved Unix `/tmp` to fit macOS's
104-byte socket-path limit; the helper's import-only cache uses the resolved
platform temporary directory. Both remain private, including the 0700 child cache.
Native binary ownership, mode, and digest are checked on the same open descriptor
by the launcher's qualification function; the foreground proof rechecks after
exit. Execution still uses a pathname: a trusted same-user process could replace
it between verification and execution. This is not atomic descriptor execution
or remote artifact attestation.
All proof checks use explicit guards that
remain active under `-O`. Its PTY query detector is tested across all three
possible splits of the cursor query, without duplicate replies.
The earlier signal-termination run recorded exit 137; it is preserved separately
and is not the graceful-exit proof. Excluded startup-selection and input-burst
trials remain recorded with their logs.
