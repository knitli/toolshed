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

No successful native idle wake has been observed: an isolated disposable client,
verified native ingress availability, and a trusted observation of input/turn outcomes
are still required. Custom channel development bypass is not needed for native UDS,
but the installed client gates cross-session messaging independently. Do not bypass
that gate or borrow owner credentials. Production closure needs exact-session native
binding, observed idle/busy behavior, lost-write/restart reconciliation, and a durable
receipt contract that distinguishes input recorded, turn started, and terminal no-start.

## Dedicated-key idle-wake canary (not yet executed)

`qualify_claude_socket.py` is a separate opt-in run. In a terminal, with the gateway
installed in the selected Python environment, run this one command and enter a
**dedicated canary API key** at its hidden prompt:

```sh
python packages/event-gateway/scripts/qualify_claude_socket.py \
  --binary /Users/adampoulemanos/.local/share/claude/versions/2.1.302 \
  --model YOUR_AUTHORIZED_MODEL \
  --private-output /private/tmp/claude-canary-proof/proof.json
```

This invokes two small model turns and uses Claude's `$0.10` client budget guard
and a 90-second overall deadline. The guard is not an independent billing cap.
Do not pass a key on the command line, copy an owner token/configuration, or use
an existing owner session. No remote-provider model call was made during implementation.

The script pins the inspected executable digest and retains its own child handle.
It launches `--bare`, a fresh HOME/config/work/tmp, a closed environment, no tools,
no skills, empty MCP configuration and empty settings sources. Only the key entered
at the prompt enters the child environment. [Bare mode](https://code.claude.com/docs/en/headless)
explicitly avoids subscription OAuth and keychain credentials. A separate config
directory alone is insufficient: [authentication documentation](https://code.claude.com/docs/en/authentication)
notes that Console profile sign-ins can live outside it.

After native initialization confirms the exact session and zero tools, the script
requires a matching READY assistant message and successful result. It leaves stdin
open and writes no second stdin prompt. Following a one-second idle interval, it
reads only that child's exact freshly generated inbox key under its new config,
then submits unique synthetic metadata through `ClaudeSocketTransport`. The actual
connected peer must match the retained child. A matching WAKE assistant message and
successful result are required before any proof is published. Missing native
messaging support, native hold/refuse policy, authentication failure or unexpected
output fails closed; no hidden feature gate or permission bypass is enabled.

Only boolean/hash evidence is published atomically to a new private file. No raw
transcript or key is printed or stored by the harness. The disposable child is
terminated and awaited before deleting its state. If shutdown cannot be confirmed,
state is retained instead of deleting files under a live process. This is a trusted
client canary, not hostile-code process-tree containment. A successful headless wake
still does not prove TUI idle wake, busy queuing, receipt-v3, restart recovery,
production enrollment or release qualification. Unit tests check parsing/refusal and
isolation without executing Claude or manufacturing a native PASS artifact.

## Local synthetic-provider mode (native qualification incomplete)

A dedicated provider credential is unnecessary for the transport experiment. The
[official gateway connection contract](https://code.claude.com/docs/en/llm-gateway-connect)
supports `ANTHROPIC_BASE_URL` with an explicit `ANTHROPIC_API_KEY`. The inspected
2.1.302 binary constructs its SDK client with that base URL, posts to `/v1/messages`,
and consumes the standard `message_start`, content-block, `message_delta`, and
`message_stop` events described by the
[Messages streaming contract](https://platform.claude.com/docs/en/build-with-claude/streaming).
This establishes a plausible local protocol path; no actual native success is
inferred from inspecting code or replaying unit fixtures. Initial contained runs
ended before initialization because the client tried its shared per-user temporary
directory. The explicit `CLAUDE_CODE_TMPDIR` correction below is covered by unit
tests; a successful actual idle wake remains unproven.

After reviewing containment, the disposable macOS-only mode is:

```sh
python packages/event-gateway/scripts/qualify_claude_socket.py \
  --local-provider --local-port 43231 \
  --binary /Users/adampoulemanos/.local/share/claude/versions/2.1.302 \
  --model claude-local-fixture \
  --private-output /private/tmp/claude-local-proof/proof.json
```

The parent binds one fixed IPv4 loopback port, with no fallback on collision. The
server contains no upstream client or forwarding code. It accepts at most two
bounded streaming Messages requests authenticated by a fresh dummy key. It echoes
the initial READY marker from the client's system prompt; it emits WAKE only if a
new marker arrives in the actual client's subsequent latest user message. The
controller never passes that late marker to the server. Both native assistant/result
pairs remain mandatory, and stdin receives only the initial prompt.

The child gets a default-deny Seatbelt profile: its exact pinned executable,
platform libraries, and disposable scratch are readable; writes stay in scratch;
network output is limited to the one model port; UDS binding/listening is limited
to its generated inbox. Other executable paths and direct owner files are denied,
and keychain service lookup is denied. Bare mode, empty settings/MCP/tools, fresh
HOME, dummy credentials, and disabled nonessential traffic/updater remain explicit.
Both `TMPDIR` and `CLAUDE_CODE_TMPDIR` point inside scratch: this pinned client
otherwise ignores `TMPDIR` for its shared per-user Claude temporary directory.
The parent server closes after the child stops, including failed runs. Unsupported
platforms, occupied ports, unexpected provider calls, and malformed HTTP/SSE fail
closed. The dedicated-key mode above remains a separate opt-in choice.

Local evidence identifies `modelProvider: local-synthetic` and cannot establish
real-model behavior or production qualification. Native startup, sandbox
compatibility, the installed messaging gate, and idle wake must still be observed
in an actual contained run. Unit tests do not execute Claude.

### Offline busy probe (experimental)

Busy observation failures retain at most eight classified stdout envelopes in the
existing bounded `fixture.log`: event type/subtype from fixed allowlists, exact
expected session UUID (or null), parent monotonic timestamp, and sequence number.
Session-state events additionally retain only `running`, `idle`, or `unknown`.
Unexpected system events additionally classify the fixed `hook_started`,
`hook_progress`, `hook_response`, `status`, `session_metadata`, and `init_milestone`
subtypes. Their diagnostic includes only JSON type/absence labels for ten fixed
fields: subtype, metadata, status, hook_id, hook_event, message, stdout, stderr,
output, and exit_code. Field values and arbitrary field names are never retained.
These labels come from the pinned 2.1.302 executable's static source; they do not
identify the earlier failed run's redacted event or establish valid startup order.
Unknown labels, malformed JSON, and oversized reads retain no raw frame text.
This diagnostic is failure evidence only; init, native running, held-response,
identity and completion requirements remain unchanged. It does not prove admission.

`--busy-probe` requires `--local-provider` and uses the existing contained,
disposable launch. It explicitly enables experimental
`CLAUDE_CODE_EMIT_SESSION_STATE_EVENTS=1` only in the child environment and adds
`--replay-user-messages`. It needs no owner credentials or configuration and makes
no workflow changes. Add `--busy-probe` to the local-provider command above; this
section describes the probe contract, not an executed qualification result.

The probe continuously observes native stdout for the exact disposable session
and requires native `running` before creating the fresh BUSY nonce. The synthetic
provider holds its initial response until the socket write completes. Evidence
then requires ordered native READY and BUSY assistant messages and successful
results, plus a native user replay correlated by exact UUID and content. Ordering
uses host-observed monotonic timestamps, not inferred native admission times.

Delivery and native admission remain **unknown**. A replay can describe merged or
duplicate input and is not a durable receipt. Holding the response through the
write and observing an eventual second turn do not prove the native queue admitted
the input while busy. Restart recovery remains unqualified, and current selected
TUI identity remains unproven.

Audited [run `39037031558`](https://github.com/knitli/knitli-site/actions/runs/39037031558)
established a controlled synthetic two-turn,
same-session socket wake. Its completed first turn plus a one-second wait did not
independently establish native idle state. Earlier idle-wake wording describes the
canary's intent; it must not be read as independently observed native idle evidence.

### Reviewed hosted-VM qualification

`--trusted-hosted-vm --hosted-repository-id <immutable-id>` is a separate,
explicit mode and requires `--local-provider`. Use it only in a dedicated private
workflow after the client and canary changes have been reviewed and merged. The
runner must be a fresh GitHub-hosted macOS ARM64 VM, dispatched from protected
`main`, attempt 1. The guard checks the workflow identity and event's private
repository ID/name. These checks are operational guards, not remote attestation:
reviewed workflow code and the hosted VM are trusted.

This mode follows the existing reviewed native runner's network-only Seatbelt
policy: default filesystem/process access within the disposable VM, denied network
access except the fixed loopback model TCP port and exact inbox Unix socket. It
must never run on the owner's machine or a reused/self-hosted runner. The VM must
contain no production credentials, owner home, or unrelated sensitive data;
checkout credentials must not persist. Empty settings/MCP/tools, fresh HOME,
closed child environment, dummy provider key, pinned executable digest, and the
two real native assistant/result observations remain mandatory. The original
restrictive local mode is unchanged.

Hosted evidence marks `containment: trusted-hosted-vm-network-only`, with
`hostileSameUidIsolationProven`, `completeDescendantTerminationProven`, and
`vmDisposalObserved` all false. Scratch remains for provider-managed VM disposal,
including failed runs, to avoid deleting state while an unobserved descendant
might still use it. Audited private hosted run
[`39037031558`](https://github.com/knitli/knitli-site/actions/runs/39037031558),
attempt 1 on 2026-10-17, demonstrated a controlled synthetic second turn through
the authenticated socket in the same fresh headless session. It did not independently
witness native idle or busy admission. Subsequent busy-probe run
[`39042238469`](https://github.com/knitli/knitli-site/actions/runs/39042238469),
attempt 1, failed with `busy_native_missing_init` before emitting proof. A
same-session event preceded init, but its type was not retained. The bounded
failure diagnostics above support investigating that ordering without relaxing
the gate. Busy qualification, production admission, restart recovery, and
receipt-v3 remain false.

The [official 2.1.302 manifest](https://downloads.claude.ai/claude-code-releases/2.1.302/manifest.json)
records `darwin-arm64` SHA256
`5262ce9de86243fed0d21edc39b271555d56780d0112e2b194439fe1c6662d37`
and size 267956720 bytes. The
[official installer](https://claude.ai/install.sh) establishes the version/platform
URL pattern; the pinned artifact is
`https://downloads.claude.ai/claude-code-releases/2.1.302/darwin-arm64/claude`.
Initial preparation fetched only installer/manifest text; the audited hosted run
subsequently verified and executed the pinned client. Every qualification run must
verify downloaded bytes against the pinned hash before execution; it must not
execute an installer or select `latest`.
