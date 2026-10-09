# Native release candidate runtime qualification

The preserved clean-build candidate `3e88bd929a8c1d6e29dd562c47c9264df5b8f5904847695b8b490ddcf492387c`
passed a fresh macOS ARM64 two-TUI restart qualification with the gateway wheel
built from `cc3630d3da726f7032b1d86062b0040aea57eb44`. The
[release proof](native-release-runtime-proof.json) records the binary, build
evidence, executed runner, qualifier, installed reader, wheel, and raw logs.

The preserved binary and build JSON match the earlier clean-build proof. All
48 patched source hashes match the current native source manifest; no Rust
rebuild was needed. The wheel SHA is
`09be6b33fbdb64224e4f008faa38703821d928c6594963f6c3312944e8294b7b`.
All 20 packaged modules/contracts match both the wheel archive and the base
commit. This is the **pre-promotion wheel**: the later launcher pin update is
separate from this reader/adapter runtime qualification.

The current runner verifies the qualifier, adapter, package initializer, and
extracted installed reader before loading them. It ran under Python 3.13.14
with `-I -O`; its three focused cleanup tests also passed. The first attempt
was denied loopback binding by the sandbox before native launch and is
excluded. The authorized loopback-capable retry exited successfully.

After the first TUI/backend stopped, a second TUI with a different selection
recovered the exact expired receipt twice. All 15 structurally valid changed
identity probes returned Unknown; the original mapping stayed unavailable,
and the stale Start was locally refused. Counts were one synthetic primary,
one title, and zero unknown or real model calls.

Replay with the external candidate and the recorded installed wheel:

```sh
EVENT_NATIVE_QUALIFIER="$PWD/scripts/qualify_native_bridge.py" \
  /private/tmp/event-native-release-setup/installed/bin/python -I -O \
  docs/native-bridge/durable-restart-v3-qualify.py \
  --binary /private/tmp/native-codex-p7-full-tree \
  --sha256 3e88bd929a8c1d6e29dd562c47c9264df5b8f5904847695b8b490ddcf492387c \
  --output /private/tmp/native-release-replay.json
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

After adding `--no-daemon`, the rebuilt wheel
`d11642c3ca2eb96f72f7ce192c422c60be174487cea418c243157d87fd1322a2`
passed the [foreground smoke](native-release-launcher-smoke.py). It exercised
the installed CLI and `launch()` through a real PTY, accepted the candidate,
reported a selected session with attachment and automatic wake disabled,
returned its binding and fresh challenge-correlated witness, and removed its
control socket and stopped the backend after graceful `/quit` with exit code 0. No model requests
occurred. All 20 installed files match the final wheel and source; its reader
and adapter are byte-identical to those in the two-TUI run.

```sh
/private/tmp/event-native-release-setup/standalone-installed/bin/python -I -O \
  docs/native-bridge/native-release-launcher-smoke.py \
  --binary /private/tmp/native-codex-p7-full-tree \
  --output /private/tmp/native-release-launcher-replay.json
```

The smoke uses disposable configuration and homes and requires loopback
binding. All proof checks use explicit guards that remain active under `-O`.
The earlier signal-termination run recorded exit 137; it is preserved separately
and is not the graceful-exit proof. Excluded startup-selection and input-burst
trials remain recorded with their logs.
