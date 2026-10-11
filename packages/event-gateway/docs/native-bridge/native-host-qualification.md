# Native code-mode host qualification

The metadata-qualified CLI requires its matching `codex-code-mode-host` beside
the executable. The earlier package omitted that helper: native admission and
input recording passed, but the real canary could not execute its source read.
The builder now accepts the pinned official local archive, publishes both
executables and evidence together, and rolls back only its own files on failure.
The launcher verifies both executables and rejects package layouts that could
select a different host from `codex-resources`.

The CLI remains pinned to
`362074bba4d43bbcc7e1e4162f67f8439106ef388670899309effd75cca65f27`.
The official `rust-v0.160.0` host, from the same upstream commit
`a956835d020762cb2b570053af06f643a11c0ecc`, is pinned to
`679eedaea70529aa1cffc9bc0a0788c186412663544fa76c09d63b57f383a65a`.
See the [build runbook](native-client-build.md) for the archive pin and handoff.

The [retained proof](native-host-launcher-proof.json) passed with an isolated
installed wheel: one Start, the actual file contents in the correlated tool
result, and `inputRecorded` for the same turn. Three synthetic provider requests
were observed: two for the main turn and one for the TUI title. Cleanup removed
the control socket and stopped the backend and owned process group.

## Repeat the installed-wheel proof

Build and install the wheel into a disposable consumer with locked dependencies.
Use an explicit absolute source directory for the wheel preflight, an owned
directory containing both pinned executables, and a new evidence path:

```sh
"$EVENT_PROOF_PYTHON" -I -B \
  docs/native-bridge/native-host-launcher-qualification.py \
  --binary "$EVENT_NATIVE_DIRECTORY/codex" \
  --package-source "$EVENT_PACKAGE_SOURCE" \
  --output "$EVENT_HOST_PROOF"
```

This Apple Silicon macOS fixture uses the actual installed launcher, real PTY,
native selection and one conditional Start. A loopback synthetic provider asks
the actual code-mode host to call `tools.exec_command` and read a fresh private
file. Its random contents are absent from the initial provider request and tool
program; they must arrive in the correlated tool output. The fixture requires
the matching durable `inputRecorded` receipt, unchanged executables/source,
socket removal and an empty owned process group.

All provider traffic is synthetic. The fixture accounts separately for the TUI's
automatic title request and the two main-turn requests. It copies no credentials
and uses a disposable Codex home. An outer `sandbox-exec` permits only the local
provider port and Unix sockets, and denies reads of the operator's Codex home.
The disposable inner configuration disables a second macOS sandbox because
nested Seatbelt application fails; the outer sandbox remains mandatory.

## Limits

This proves installed launcher/host integration and an actual local file read.
It does not prove a real model's choice of tools, GitHub source authorization,
cloud source rereading, or useful work after notification. Earlier build and
live wake/restart evidence remain historical and unchanged. No CLI rebuild,
trusted contract rotation, owner-client installation or cloud activation is part
of this packaging repair.
