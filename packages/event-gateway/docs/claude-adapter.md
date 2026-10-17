# Claude native socket qualification adapter

Status: implemented standalone transport, **not production-qualified and not registered
with cloud dispatch**. No owner session, configuration, credential store, or installation
was accessed or changed. The installed executable's static source was inspected.

## Verified support

The installed Claude Code **2.1.302** executable contains a native cross-session UDS
inbox (`--messaging-socket-path`), exporting `CLAUDE_CODE_MESSAGING_SOCKET` and
`CLAUDE_CODE_MESSAGING_TOKEN` to children. Its implementation accepts newline-delimited
JSON: an auth frame followed by a user frame. It rejects mismatched `session_id`,
accepts UUID `msg_id` with `msgV: 1`, and supports `now`, `next`, and `later` priorities.
This adapter chooses `next`: queue at the native boundary without forcing an interrupt.
Native `onEnqueue` supports wake, while hold/refuse policies can prevent delivery.

The token authenticates inbox access; it does **not** prove cloud authorization,
runtime binding, a trusted sender allowlist, or delivery. Claude separately checks
peer process provenance and applies native inbound policy. This adapter does not
forge sender identity, request child-token privileges, change policy, attach files,
or enable remote control. It supplies explicit session targeting on every message.

The inspected server returns no synchronous delivery acknowledgment. Held-message
status is routed separately to verified peer inboxes. Native queued messages and
those status messages do not satisfy Toolshed's durable receipt-v3 semantics.
Consequently `send` and `reconcile` always report `unknown`; `check` returns
`unavailable`, preventing accidental production Gateway activation.

The historical `apps/os/spikes/event-runtime` is a Codex socket spike; its README
explicitly excludes Claude qualification. It is not evidence for this transport.

[Official Channels documentation](https://code.claude.com/docs/en/channels-reference)
describes a separate session-local MCP stdio ingress. It has no notification ACK,
queues busy-session events, and requires an interactive development allowlist bypass
for custom channels. It is not this UDS protocol. No official public UDS contract was
found in the documentation search; the socket adapter is pinned to the inspected
installed version and must be revalidated before another version is accepted.

## Explicit disposable-session command

Prepare two owner-only mode-0600 JSON files in a mode-0700 directory from a deliberately
created disposable session. Do not select an existing owner session by scanning its
registry or reading its credentials. A launcher must independently verify the client
version and provide the socket identity and process PID. It must keep that trusted
process alive for the entire binding lifetime and discard the binding on exit; these
config assertions are not attestation. Never reuse a config after process exit: PIDs
can be reused. This manual qualification surface does not defend against code already
executing inside the trusted peer or a compromised launcher.

Binding file fields (all required, no extras):

```json
{
  "version": 1,
  "clientVersion": "2.1.302",
  "socketPath": "/private/disposable/claude.sock",
  "socketDevice": 1,
  "socketInode": 2,
  "peerPid": 12345,
  "sessionId": "11111111-1111-4111-8111-111111111111",
  "token": "DISPOSABLE_SESSION_TOKEN_ONLY",
  "journalDirectory": "/private/disposable/attempts"
}
```

Event files require exactly `eventId`, `deliveryId`, `source`, `sourceStateVersion`,
`canonicalSubject`, and `eventReference`. Validation projects those properties from
the pinned event contract: source is `manual` or `github`, the structured subject must
match that source (`manual` or `github_pr`), and the reference/revision/IDs must satisfy
the existing bounded schemas. Extra top-level or subject fields are rejected. The caller
must authorize/admit the event before sending. A stable native UUID derives from the
exact session and delivery IDs; the original IDs stay in the metadata. The payload
grants no tool or source authority.

```sh
python -m event_gateway.claude --config /private/disposable/binding.json --event /private/disposable/event.json
```

Exit 1 means input/local setup refusal. Exit 2 means unknown delivery, including a
successful socket write. There is deliberately no success exit status for delivery.
The command logs only safe reason codes, never credentials or event contents.

Before connecting, the adapter reserves an owner-only journal marker with exclusive
creation and fsync of file and directory. The same session/delivery cannot send again,
including across process restarts or after uncertain failures. Socket ownership,
permissions, symlinks and the pinned device/inode are checked before and after connect.
Those pathname checks alone do not prevent a swap-and-restore race. Before writing
auth or event bytes, the adapter verifies the connected kernel peer PID and UID
(Darwin `LOCAL_PEERPID`/`getpeereid`, Linux `SO_PEERCRED`) against the live launcher
binding and current user. Unsupported platforms fail closed. The socket parent must
remain owner-only; other code running as that owner and the trusted peer are outside
this manual qualification isolation boundary. Healthy writes close gracefully and
await buffer flushing within the send deadline; failure or timeout aborts.
Retain the journal: deleting it removes the no-replay boundary. Markers have no payload
or secret. This manual qualification journal is intentionally not auto-pruned.

## Evidence and remaining qualification

Protocol fixtures exercise real disposable Unix sockets: auth/wire shape, stable
session targeting, concurrent reservation, restart/no-replay, pre/post-connect socket
rotation, an actual other-process path-swap-and-restore race with a zero-byte witness,
graceful close/timeout, unsafe permissions, validation and safe CLI errors. They prove our adapter's
behavior, not Claude's processing or idle wake.

No live Claude/model run was attempted: an isolated authenticated disposable client,
verified native ingress availability, and a trusted observation of input/turn outcomes
are still required. Custom channel development bypass is not needed for native UDS,
but the installed client gates cross-session messaging independently. Do not bypass
that gate or borrow owner credentials. Production closure needs exact-session native
binding, observed idle/busy behavior, lost-write/restart reconciliation, and a durable
receipt contract that distinguishes input recorded, turn started, and terminal no-start.
