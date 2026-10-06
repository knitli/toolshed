# Codex bridge options

Follow-up: the [bounded stock-TUI spike](codex-bridge-spike.md) now provides live
evidence rejecting proxy-only selection authority. The investigation below is
the earlier planning record; its proposed spike has since been executed within
the documented no-turn limits. Production delivery remains disabled.

Investigation: 2026-10-05. **Production delivery remains disabled.** This document proposes research, not a supported native API or permission to enable delivery. Only this document was changed during the investigation; no active-client messages, model turns, daemon restarts, or configuration changes were performed.

## Decision

**Correct solution without a time constraint:** a supported native client-binding contract, implemented in the actual client UI and enforced by the daemon. It must bind an authenticated client instance, selected thread, server instance, and selection generation to submission **and eventual queue consumption**. A daemon-only list of subscriptions is insufficient: subscribed threads need not be selected in the UI.

**Recommended minimum safe step:** retain the disabled adapter and run a bounded, disposable controlled-client observation spike. Start with a launcher and protocol proxy to learn what the stock TUI exposes; treat it as instrumentation, never as presence authorization. If UI transitions are invisible, stop that approach and implement a small client-side witness in a pinned experimental CLI build, or a deliberately single-thread custom client. Neither is production-ready until the contract and negative tests below pass. Building a hook heartbeat does not remove the missing contract.

| Option | User experience | Can meet the requirement? | Relative difficulty |
| --- | --- | --- | --- |
| Existing CLI/app plus daemon diagnostics | Existing clients continue unchanged | No: no exact live-client/selected-thread evidence | Low effort, reject |
| Launcher running `codex resume <UUID>` | User opens a particular thread through a wrapper | Initial intent only; same PID can switch later | Low; useful instrumentation |
| Launcher plus dedicated protocol proxy | Stock TUI connects through a private endpoint | Observes connection and RPC transitions, not necessarily menus, local selection, or queue execution fencing | Medium spike; insufficient alone |
| Session hooks plus sidecar heartbeat | Plugin or local hooks accompany existing sessions | No: runtime lifecycle is not UI lifecycle; sidecar can outlive/detach from client | Low–medium; reject as authority |
| Actual client-side witness plus daemon fencing | Familiar TUI; bridge indicator disables on menu/switch/disconnect | Yes in principle, after implementation and proof | High: UI transition coverage, protocol, queue executor, release maintenance |
| Single-thread custom app-server client | Separate limited client, explicit attach/detach; no stock-client adoption | Can own selection and submission, but strict native queue semantics still need fencing | Medium–high; less UI coverage, new client UX |
| Upstream native binding API | Normal supported clients expose explicit enrollment/availability | Best durable solution; absent in inspected schemas | Highest coordination cost; removes ongoing fork maintenance |

Difficulty is engineering scope, not an elapsed-time estimate. A plugin is not assumed to have arbitrary access to the stock UI event loop.

## Evidence and limits

Local primary evidence was inspected before online documentation:

- Installed `codex --version`: `codex-cli 0.160.0`. Existing exact-binary schema exports: `/tmp/codex-client-probe-0160` and `/tmp/codex-client-probe-01601`; the prior transport probe identifies the running daemon as 0.160.1. See [client-presence.md](client-presence.md) for that probe's limits.
- Both `ClientRequest.json` surfaces expose diagnostics, stored thread attachments, and remote-control client listing/revocation; neither exposes local client selection/binding/lease operations. `ServerNotification.json` has thread status/closure but no local UI selection or menu event.
- `v2/ThreadLoadedListResponse.json` describes daemon-memory sessions. `ServerDiagnosticsResponse.json` has process ID and gauges. `RemoteControlClientsListResponse.json` exposes device/client metadata and last-seen time, not local process identity or selected thread.
- `ThreadQueueAddParams.json` takes `threadId`, `clientUserMessageId`, and input. Queue start/delete identify the thread/submission. None carries a client binding generation or expected live connection. Queue cancellation after detecting loss cannot retroactively prevent consumption.
- `HooksListResponse.json` lists runtime hook events, including session start/end, tool events, stop, and interrupt; no UI select/deselect event. `initialize.clientInfo` is client-declared, not proof of the enrolled client.
- Local `codex resume --help` supports an explicit UUID, `--remote unix://PATH`, `--remote-auth-token-env`, and `--no-daemon`. These are launch/routing controls, not attestation. `codex debug app-server --help` exposes `send-message-v2`; it was not invoked. Daemon restart/update/start controls are mutations, not presence diagnostics.

Current official OpenAI documentation confirms that session-end hooks are delayed after switching away/unsubscription; common hook fields identify runtime sessions, and subagent hooks use the parent session ID. Hooks can be disabled and their transcript format is unstable. These facts disqualify hooks as an exact UI witness. [Hooks](https://learn.chatgpt.com/docs/hooks)

The official app-server documentation describes Unix WebSockets and stdio, connection-scoped unsubscription with an inactivity grace period, and bearer authentication options. It explicitly calls app-server/WebSocket transport experimental and unsupported for production workloads. Protocol compatibility alone therefore cannot establish supported production readiness. [App server](https://learn.chatgpt.com/docs/app-server)

The documented CLI can route an interactive client to an explicit remote/Unix endpoint. This enables controlled instrumentation, not adoption of arbitrary existing clients. [Developer commands](https://learn.chatgpt.com/docs/developer-commands?surface=cli)

`notify` is documented as a notification command receiving a JSON payload; no selected-client lease is established by that setting. Project configuration cannot override it. It is not a bridge workaround. [Configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)

## Required contract and failure behavior

The following are proposed acceptance requirements, **not existing RPC names or fields**:

1. **Client identity:** create an unpredictable per-launch identity and bind it to an authenticated client channel, enrolled endpoint, and daemon incarnation. Validate OS process birth identity if a process is part of enrollment; PID or command line alone is never enough. Heartbeats prove responsiveness only when generated by the actual client event loop, not an independent surviving helper.
2. **UI selection:** one authoritative selection generation per enrolled client. Leaving the selected conversation, opening an ambiguous picker/menu, beginning a switch, or losing the UI connection invalidates it before accepting more external input. Returning to a thread creates a new generation. Define clearly which menus preserve an eligible selected thread; default ambiguous states to unavailable. This is client state, not daemon activity or window-focus inference.
3. **Atomic ingress and dispatch:** check the binding generation at the native acceptance boundary and again when a pending entry becomes a turn. Serialize revocation and dispatch at that authority. Gateway before/after checks cannot close this race. A switch after acceptance must hold or cancel unconsumed events; deleting a queue item asynchronously is not equivalent. Already-started turns remain submitted/ambiguous, never silently rerouted or replayed.
4. **Concurrent clients:** explicitly enroll one client instance. Another client displaying the same thread does not extend its lease. A process opening another thread must not steal enrollment; moving to another client requires explicit reenrollment.
5. **Crash/restart/reuse:** connection loss invalidates the channel; a bounded lease covers silent hangs. State the detection bound rather than claiming instantaneous crash detection. Process or daemon restart, PID reuse, socket replacement, and reconnect require a fresh generation and authentication. No automatic resurrection of old queued authority.
6. **Revocation:** disabling enrollment must block ingress and pending dispatch at the same enforcing authority. Retain delivery IDs and outcome evidence across restarts. Cancellation uncertainty stays quarantined; do not resend to a new thread.
7. **Transport:** private canonical Unix socket, owner-only directory, checked ownership/permissions and socket identity; independently authenticate the enrolled client. Filesystem ownership protects against other users, not all same-user processes. Use per-client capabilities and OS peer/birth validation where supported; define whether hostile same-user processes are outside the threat model. For remote transport use authenticated TLS. Never accept `clientInfo.name`, inherited environment markers, or an arbitrary signed sidecar assertion as sufficient proof of selection.

An in-client witness alone solves observation, not daemon queue fencing. A custom client could instead hold events outside the native queue until explicitly accepted in its UI; that changes delivery semantics and still requires a defined acceptance/revocation boundary. Do not call that automatic live-client delivery under the existing contract.

## Smallest next spike

No spike implementation or interactive launch was performed here. First reproduce the read-only inventory:

```sh
codex --version
codex app-server daemon version
codex resume --help
codex app-server --help
codex debug app-server --help
codex app-server generate-json-schema --experimental --out /private/tmp/codex-bridge-schema
```

Then, in a disposable credential-free home, run a dedicated app-server and a recording proxy on separate private endpoints. The following command shapes are for that future isolated harness, not the shared daemon; variables must point to newly created private directories. There is no recording proxy supplied by this investigation.

```sh
CODEX_HOME="$bridge_home" codex app-server --listen "unix://$bridge_backend_socket"
CODEX_HOME="$bridge_home" codex --remote "unix://$bridge_proxy_socket"
# With an existing disposable test thread, omit PROMPT to avoid initiating a turn:
CODEX_HOME="$bridge_home" codex resume "$bridge_test_thread_uuid" --remote "unix://$bridge_proxy_socket"
```

Record only message method, request ID, relevant thread ID, connection incarnation, and monotonic order. Do not capture prompts, tokens, or full RPC bodies. Inspect same-process thread switch, picker open/cancel, return to old thread, two simultaneous clients, ordinary exit, forced crash, reconnect, and backend restart. Compare UI observations with wire transitions. **Any UI transition with no corresponding authoritative signal disproves a proxy-only witness.** A successful sample does not prove complete coverage; inspect the exact pinned client's transition code before claiming it.

For a future native implementation, leave one runnable integration check that races selection revocation against ingress and queue consumption: stale-generation events must never start a turn, valid-generation events must retain their delivery ID, and ambiguous outcomes must never replay. Include busy queue then detach, revocation before drain, two clients on one thread, PID reuse, socket replacement, and delayed heartbeat. These tests need controlled native changes; transport fixtures alone cannot establish the result.
