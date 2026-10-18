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
System diagnostics recognize all 64 fixed system-schema subtype constants from
pinned Claude 2.1.302, plus the previously reviewed `init_milestone` constructor.
The [source manifest](claude-system-subtypes-2.1.302.json) records the binary and
schema-module hashes and absolute byte offsets for each fixed label. `init` and
`session_state_changed` retain their existing handling. Except for the narrowly
validated passive `ui_invalidate` hint below, the other labels change diagnostics
only. Their diagnostic includes only JSON type/absence labels for ten fixed
fields: subtype, metadata, status, hook_id, hook_event, message, stdout, stderr,
output, and exit_code. Field values and arbitrary field names are never retained.
These labels come from the pinned 2.1.302 executable's static source; they do not
identify the failed run `39055515172`'s redacted event or establish valid startup order.
That run still reported an unknown system subtype before init. Absent sampled
fields do not imply an otherwise empty envelope: fields such as content, tasks,
commands and title were not sampled. Static classification does not qualify
acceptance, and unlisted subtype strings remain `unknown`. Constructor-only labels
outside this reviewed schema (except retained `init_milestone`) are not included.
Unknown labels, malformed JSON, and oversized reads retain no raw frame text.
This diagnostic is failure evidence only; init, native running, held-response,
identity and completion requirements remain unchanged. It does not prove admission.

Hosted run `39063126919` failed on its first observed stdout frame: an exact-session
`system/ui_invalidate` before init. The observer stopped at that frame, so the
failure does not show whether init would have followed. The private artifact kept
the classified failure and no completion proof; evidence export remained incomplete.
The pinned schema describes this event as a fire-and-forget UI render invalidation.
The probe now ignores only its canonical shape: `event: "ui.render"`, string `uuid`,
the exact session, optional `prompts_screened: true`, and optional `instances` whose
`surface`, `component`, and `instance_id` are strings. Unlike the source schema's
object parsing, the fixture also rejects unknown top-level or instance fields.
The source manifest records the schema and string-alias offsets. The captured
diagnostic did not retain these additional fields, so it does not itself prove
that the failed frame meets this validator.

A valid hint changes no initialization, running, ready, replay or completion state.
Actual `system/init` with no tools remains mandatory, as do all later busy witnesses.
Repeated hints remain subject to the existing output cap and run deadline; hint-only
EOF or timeout fails. Unknown, malformed, error and wrong-session events still fail.
This observer change has offline coverage only; no subsequent native run is claimed.

Hosted run `39077401811` stopped at an exact-session `command_lifecycle`
frame before init. Its diagnostic retained neither command UUID nor lifecycle
state, so the phase is unknown; the failure does not establish that init would
never follow. Static inspection of the pinned binary shows that the local
transport enqueues these frames independently of the query generator's init,
and verbose stream-json writes them before its output bookkeeping filter.

The pinned lifecycle schema has `type`, string `command_uuid`, finite `state`,
string `uuid` and `session_id`, and optional literal-true `ran_ahead` (described
for repeated `queued` events). The fixture additionally requires canonical
native UUIDs, the exact session, no extra fields, and `ran_ahead` only for
`queued`. Command UUID must match the initial or prepared follow-up input,
and native event UUIDs cannot repeat. Before init, only `queued` and
`started` are passive; `completed`, `cancelled`, `discarded`, and `refused` clear
pending running evidence and fail. After init, `queued` and `started` remain
passive; `completed` requires the held response to have been released and the
corresponding successful result already observed. Folded completion cannot
substitute for the required separate second turn. Cancellation, discard, and
refusal fail the experiment.
These events never establish initialization, running, a held response, readiness,
or admission. Evidence retains only a fixed event label, finite state, and
monotonic observation time, under the existing observation cap. Genuine init,
native session running, and a held provider response remain mandatory. This
correction has offline coverage only and does not qualify another native run.

Busy run `39079656838` reached init, native running, the held initial response,
socket send and release, and two synthetic provider requests, then failed with
`busy_native_replay_mismatch`. Cleanup completed; no completion proof was exported.
The diagnostic did not retain which replay predicate failed. Static inspection of
the pinned local socket path establishes that it constructs a peer-origin prompt,
frames its content, and replays the constructed message. Comparing that message to
the unwrapped socket input is incompatible with the producer.

The observer now requires the known socket follow-up's exact fresh-turn peer
wrapper: fixed UTF-8 prefix/suffix lengths and SHA-256 digests, exact total byte
length, and unchanged expected middle bytes. The message must contain exactly
`role: "user"` and string `content`. It accepts neither plain follow-up text nor
substring, whitespace, or block-array normalization. Initial stdin replay still
requires the original message exactly. Native framing prose stays private; the
fixture carries only its lengths and hashes, tied to the fixed executable digest.
The same session, input UUID, literal replay flag, null parent and no-duplicate
checks remain mandatory, as do independent init/running/hold, both requests and
results, and final idle. Offline synthetic framing tests and a private check of
the actual pinned producer framing validate this matcher; they do not establish
that every predicate matched in the failed run or qualify native busy delivery.

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

Hosted run `39067519862` timed out at the four-minute fixture step with no
status or proof and an empty fixture log. Its exact startup phase is unknown.
A bounded Python 3.13 loopback reproduction confirmed that waiting for the
server to close before cancelling a held provider connection blocks cleanup.
Cleanup now closes the listener, settles provider connections and awaits
server shutdown independently within four seconds. A provider failure cannot
skip the server wait; the abort phase still allows server shutdown to finish. Failure aborts accepted clients and cancels
owned tasks with a further one-second bound. Cleanup failure retains scratch,
records a fixed failure label, and preserves the original run error. This fixes a demonstrated cleanup ordering defect; it does not
establish why the native witness failed to complete within the 90-second run
budget. Fixed lifecycle labels and bounded probe flags/counters are flushed to
the private log at startup, witness waits, timeout and cleanup, without payloads,
credentials, paths or session identifiers. Hosted run `39071583512`, attempt 1,
then failed promptly with `busy_native_missing_init` and completed cleanup.
Its bounded diagnostics showed a same-session canonical running notice before
init. Busy qualification remains unproven.

The pinned 2.1.302 startup queue can forward one canonical
`session_state_changed/running` before the separate init builder completes.
The probe buffers at most one such notice for its fresh owned session, validates
its exact envelope and canonical UUID, and reserves the UUID immediately. It
records the original observation time with `awaitingInit: true`; it does not
mark the session initialized or running, or permit sending, until a genuine
same-session init with empty tools arrives. A second lifecycle notice before
init, including idle or requires_action, fails the probe. Duplicate identities,
malformed envelopes, wrong sessions, and a missing init still fail closed.
Validated UI invalidation hints remain passive. This bounded ordering allowance
has only offline evidence; it does not establish native busy qualification.

Hosted run `39074877564`, attempt 1, accepted the buffered running notice,
then failed promptly with `busy_native_missing_init` on another same-session
pre-init event. Cleanup completed and no proof was emitted. The previous
diagnostic classified that event's top-level type as `unknown`, so its identity
cannot be recovered from that artifact and must not be inferred from ordering.

Diagnostics now name only the 19 fixed top-level types in the exact pinned
2.1.302 `StdoutMessage` union (binary byte offset 214655727), including its
`SDKMessage` union (214409742): `active_goal`, `assistant`, `auth_status`,
`autocompact_state`, `command_lifecycle`, `control_cancel_request`,
`control_request`, `control_response`, `conversation_reset`, `keep_alive`,
`prompt_suggestion`, `rate_limit_event`, `result`, `stream_event`, `system`,
`tool_progress`, `tool_use_summary`, `transcript_mirror`, and `user`.
These source anchors refer to the exact executable digest below, not a separate
SDK version. Other or non-string types remain `unknown`; arbitrary tags and
nested values are never copied. This changes failure diagnostics only: the
same pre-init event still fails, and initialization, readiness, stream limits,
cleanup and the 90-second budget are unchanged. Busy qualification remains
unproven.

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

## Same-live-session adapter recovery candidate (offline only)

`--adapter-reattach-probe` is a separate three-turn experiment and requires both
`--busy-probe` and `--local-provider`. It restarts Python adapter processes while
retaining the original native process handle, session UUID, socket device/inode,
peer PID, token and journal. The native command still uses
`--no-session-persistence`; this is not native-process restart or resume.

The private subprocess channel carries binding data through stdin, never argv or
logs. Actors use a closed environment and the same Python runtime. The existing
`ClaudeSocketTransport.send`, durable `_reserve`, kernel peer checks and
`reconcile` methods do the work; qualification-only barriers observe two cuts:

1. **After reservation, before connect:** the real marker file and directory have
   been fsynced. Kill/reap the paused actor. A new actor must preserve that marker,
   report unknown reconciliation and suppress the old attempt without connecting.
   A distinct delivery ID produces the sole fresh wire frame. This is the offline
   conservative-loss control, not proof of recovery after a write.
2. **After real write drain/close, before result delivery:** a wrapper awaits the
   real writer's `wait_closed`, signals the parent, and blocks before `send`
   returns. Kill/reap that actor. A new actor reports unknown reconciliation and
   suppresses the original delivery using the same journal. The offline socket
   fixture observes exactly one old frame and one fresh frame, with no old resend.

The proposed native scenario uses the second cut:

1. Observe exact-session init/running and hold the first synthetic response.
2. Prepare the old BUSY input, write it with the first adapter, then kill/reap only
   that adapter at the post-close barrier. Keep the native process alive.
3. Recreate the adapter against the retained binding and journal. Require
   `claude_native_receipt_unavailable` and `claude_attempt_already_reserved`.
4. Release the initial response. Require the existing unchanged two-turn busy
   witness: READY and old BUSY provider requests, exact replay, successful native
   assistant/results, and idle. Snapshot this witness before the third turn.
5. Prepare one distinct FRESH input and allow the restarted adapter to send it.
   Require a third synthetic provider request, exact UUID/content peer replay,
   native running, matching assistant and successful result, then final idle.
   Confirm the actor's write closure and exit before returning proof.

A separate `ReattachProbe`/`ReattachProvider` pair handles the third turn; existing
`BusyProbe` and `LocalProvider` behavior is unchanged. Fourth provider requests,
old/duplicate replay, missing witnesses, malformed identity and late failures
invalidate the result. Cleanup failure prevents proof; unconfirmed adapter
termination retains scratch even in local mode.

Both cuts keep admission and delivery `unknown`. The journal is a conservative
attempt quarantine, not a native receipt or the production Gateway ledger.
`ClaudeSocketTransport.check()` still returns unavailable and `reconcile()` never
claims consumption. Even an eventual successful native run would not establish
TUI-selected identity, durable admission, native restart, receipt-v3, complete
process-tree termination, VM disposal or production qualification.

Offline validation covers real Python actors and synthetic Unix sockets, plus
three-turn observer/provider and controller fixtures. No native client or model
was executed for this candidate. The Cloud workflow proposal is a new fixed
`adapter-reattach-live-session` choice mapping only to
`--busy-probe --adapter-reattach-probe`, with existing choices unchanged. It needs
a separately reviewed actual source squash pin, source hashes, scenario allowlist
and shell tests, fresh protected-main preflight, and an explicit single-run GO.
No workflow change or dispatch is included here.
