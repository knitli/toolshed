# Codex native transport and client presence

Production Codex delivery is **blocked**. The transport is implemented; current
client attachment is not qualified. `CodexAdapter` refuses every production
presence check before native ingress. Its explicitly named test verifier is an
in-process fixture seam, never enrollment data or a command-line option.

## Verified on 2026-10-05

Installed CLI: 0.160.0. Running shared daemon: 0.160.1. Both exact executables
export experimental schemas with the methods used here. A disposable app-server
for each version, with a separate temporary Codex home and no credentials,
passed `initialize`, `server/diagnostics`, and `thread/loaded/list` through
`websockets.asyncio.client.unix_connect` 16.1.1 from the locked package environment. Diagnostics PID equaled the
launched child PID; loaded threads were empty. No model turns or active-session
writes occurred. Both disposable processes were terminated afterward.

This admits only those versions for **transport testing**, not client delivery.
The historical spike's native idle/busy queue canary covered 0.160.0; that is not
proof of the currently running mixed client/daemon combination.

The daemon-version command is read-only:

```sh
codex --version
codex app-server daemon version
codex app-server generate-json-schema --experimental --out /private/tmp/codex-schema
```

The shared native socket alias resolves into `/private/tmp/codex-daemon-501/`.
The adapter rejects symlinks, including ancestor components: enrollment must
explicitly identify the canonical socket under its user-owned mode-0700 parent.
The socket itself must be user-owned, mode 0600 or 0700. No socket permissions
or daemon settings on the user's shared runtime were changed during the probe.

## Protocol bounds

Each connection has one absolute ten-second deadline covering connect,
initialize, notifications, and the requested RPC. The maintained WebSocket
implementation bounds incoming messages to 4 MiB and the receive queue to eight
frames. Closing cannot extend the deadline. Server requests receive an error;
this connection never executes tools or grants approvals. Native error text is
not propagated into gateway diagnostics.

Calls are limited to `server/diagnostics`, `thread/read`, `thread/loaded/list`,
`thread/queue/add`, `thread/queue/list`, and `thread/turns/list`. Initialization
requests experimental APIs and sends the `initialized` notification.

Queue submission uses stable `deliveryId` as `clientUserMessageId`. The prompt
contains selected event metadata and fixed instructions to re-read the existing
authorized source. It supplies no new authority or external prompt body.
Reconciliation reads at most ten pages of fifty queue entries and ten pages of
fifty turns. A matching pending queue entry is submitted. A completed turn with
a matching native `userMessage.clientId` is observed only when the gateway also
supplies its persisted native submission receipt, even without a final text answer.
Turn history has no queue submission ID: if the add acknowledgment was lost and
the entry is no longer pending, correlation alone remains unknown; it cannot
complete the canonical acknowledgment or authorize replay. This is native delivery observation, not proof that source work finished.
Unrelated completed turns never qualify. Absence within the bounded scan is
unknown and never authorizes replay. Post-submission transport or presence
failure is ambiguous and must remain quarantined by the gateway ledger.

## Missing upstream contract

Neither 0.160.0 nor 0.160.1 exposes a current local TUI-to-thread binding API:

- `thread/loaded/list` means loaded in daemon memory, not visible in a live TUI.
- `thread/read.status` and `canAcceptDirectInput` describe runtime capability.
- `originator` and `cliVersion` describe creation, not the current client.
- `sessionId` is shared across a session tree.
- `remoteControl/client/list` has no local PID-to-thread mapping.
- `thread/attachment/*` manages stored attachments, not live UI connections.

A PID existence check plus any of those fields is insufficient. Even a matching
launch command proves only the initial selected thread: the TUI can later switch.
The local daemon PID metadata already records boot ID, kernel unique process
ID, microsecond start time, and executable digest. Such identifiers can protect
against PID reuse only when independently checked against the live process.
They still do not prove its selected thread.

Qualification requires an upstream native client binding/lease that identifies
the actual connected client instance and selected thread, binds the endpoint and
server instance, and changes or revokes on disconnect, thread switch, process
replacement, and client/daemon restart. Submission must reject stale binding
generations atomically; before/after presence checks alone leave a race. Native
revocation/expiry and a supported version contract must be testable. Until that
exists and passes live idle/busy/disconnect/replacement tests, existing Codex
clients remain unsupported as production delivery targets.

## Run the transport fixtures

```sh
PYTHONPATH=packages/event-gateway/src python3 -m unittest discover \
  -s packages/event-gateway/tests -p test_codex.py -v
```

The tests use disposable private Unix WebSocket servers. A sandbox that blocks
Unix socket bind/connect requires the normal local-test approval mechanism.

The reusable no-turn native probe runs with the locked package environment:

```sh
packages/event-gateway/.venv/bin/python \
  packages/event-gateway/scripts/probe_codex_transport.py \
  --binary /absolute/path/to/codex
```

See `transport-evidence.json` for the locked-environment results.
