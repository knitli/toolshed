# Stock client operations and qualification — 2026-11-04

This is the operator procedure for the existing Gateway controls, Messaging v2 handoff, and ambiguous stock recovery. The integrated E1/Gateway suite passes 377 tests across CLI, daemon, store, stock control, Gateway, listener, Cloud, V2 protocol/admission, journal, wire, Codex adapter/probe, and installer. The V2 contract is pinned to Cloud commit `e954904603b3467e30bbeaf7446977b61fbcb9ef`; its separate trusted-policy adoption must precede the consumer merge. Use these controls only from a reviewed, pinned, installed stock release. This validation does not establish installation, production activation, or live E3/E4 qualification; those remain separate release and evidence gates.

## Check current state

Use the installed Gateway entry point. Put the private state path before the subcommand:

```sh
knitli-event-gateway --state-dir "<PRIVATE_STATE_DIR>" status
knitli-event-gateway --state-dir "<PRIVATE_STATE_DIR>" runtime-status \
  --runtime-id "<RUNTIME_UUID>" --cloud-config "<PRIVATE_CLOUD_CONFIG>"
```

`status` reports local Gateway stage, dispatch state, and durable store counts. `runtime-status` reads cloud runtime authority and generation state. Neither proves a Codex client received input. Keep cloud config and credentials private.

## Assign or renew one Codex conversation

The stock profile names an existing canonical conversation UUID. Never infer one from a process, working directory, or latest-session listing. Initial assignment:

```sh
knitli-event-gateway --state-dir "<PRIVATE_STATE_DIR>" stock-control attach \
  --runtime-id "<RUNTIME_UUID>" --conversation-id "<CODEX_CONVERSATION_UUID>" \
  --cloud-config "<PRIVATE_CLOUD_CONFIG>"
```

The CLI reports the resulting runtime and attachment generations; record them with the assignment. Renew only that same assignment with the exact current pair:

```sh
knitli-event-gateway --state-dir "<PRIVATE_STATE_DIR>" stock-control renew \
  --runtime-id "<RUNTIME_UUID>" --conversation-id "<CODEX_CONVERSATION_UUID>" \
  --expected-runtime-generation "<RUNTIME_GENERATION>" \
  --expected-attachment-generation "<ATTACHMENT_GENERATION>" \
  --cloud-config "<PRIVATE_CLOUD_CONFIG>"
```

A replacement `attach` also requires both expected current generations; it advances them. If an operation outcome is unknown, read `runtime-status` and reconcile the exact same profile/generation pair. Do not send new conversation input to resolve uncertainty. The daemon renews an existing local stock mapping while running; it does not start, inspect, or reassign client sessions.

## Messaging route owner handoff (implemented in source; release pending)

The integration source implements `stock-control renew --messaging-handoff` and the CLI parser accepts the flag for `renew` only. It is not yet available in an installed release. After the reviewed release, check the installed command help; if the flag is absent, stop. This local import does not itself prove a current v2 route or E4 delivery.

Before handoff, the Messaging route owner must provide a fresh authoritative readback for the exact route and consumer. Verify its `namespace`, `principal`, `agent`, `agentIncarnation`, and `routeGeneration`, plus the consumer's `runtimeId`, `nodeId`, and generation tuple. The consumer tuple must match the already attached Codex runtime and canonical conversation profile, and `consumerGeneration` must equal `attachmentGeneration`. The Gateway CLI has no route-export/readback command; do not treat a handoff file as proof that the remote route is current or authorized.

The importer accepts a private JSON file with this shape:

```json
{
  "version": 1,
  "namespace": "<NAMESPACE>",
  "principal": "<PRINCIPAL>",
  "agent": "<AGENT>",
  "agentIncarnation": 1,
  "routeGeneration": 1,
  "consumer": {
    "nodeId": "<NODE_UUID>",
    "runtimeId": "<RUNTIME_UUID>",
    "nodeGeneration": 1,
    "runtimeGeneration": 1,
    "attachmentGeneration": 1,
    "consumerGeneration": 1
  },
  "runtimeProfile": {
    "profile": "assigned_stock_client",
    "client": "codex",
    "conversationId": "<CODEX_CONVERSATION_UUID>"
  }
}
```

Populate every value from the fresh owner readback and the exact current Gateway assignment. The file must be a regular owner-owned file with mode `0600`, one link, no symlink in its path, and a size no larger than 4 KiB. The JSON is unsigned route data: it is not owner approval, route authority, a cloud route readback, or proof that local compare-and-set import succeeded.

Use the exact generation pair from the current assignment and the private owner readback only after the Messaging v2 integration has been merged, pinned, released, and installed:

```sh
knitli-event-gateway --state-dir "<PRIVATE_STATE_DIR>" stock-control renew \
  --runtime-id "<RUNTIME_UUID>" --conversation-id "<CODEX_CONVERSATION_UUID>" \
  --expected-runtime-generation "<RUNTIME_GENERATION>" \
  --expected-attachment-generation "<ATTACHMENT_GENERATION>" \
  --cloud-config "<PRIVATE_CLOUD_CONFIG>" \
  --messaging-handoff "<PRIVATE_OWNER_READBACK_JSON>"
```

The operation renews the exact cloud stock assignment, checks the readback against that assignment, and asks the single local writer to store the Messaging mapping with the expected prior mapping. A successful CLI result reports `localMapping: stored`; this proves the local write returned successfully, not independent remote route authority or E4 event delivery. If the outcome is ambiguous or the result reports `cloud_committed_local_mapping_failed`, stop and reconcile the exact generations with the route owner before another operation. Do not replace the file with guessed values or retry under a new assignment.

## Stop future submissions

Stop the Gateway daemon through its existing foreground/supervisor lifecycle: Ctrl-C for a foreground `run`, or the supervisor's normal stop/SIGTERM for its exact process. There is no separate `pause` or `stop` CLI subcommand. Then fence the local runtime mapping:

```sh
knitli-event-gateway --state-dir "<PRIVATE_STATE_DIR>" detach "<RUNTIME_UUID>"
```

The daemon's SIGINT/SIGTERM handler stops accepting dispatch and shuts down workers. `detach` fences new submissions for that local runtime and expires its local mapping. It does **not** cancel input already accepted into Codex's queue or an active turn; Codex owns cancelling/removing accepted queued input and cancelling an active turn. Detach/reassignment does not recall already accepted input. Check the exact assigned client directly through its supported controls before claiming cancellation. No Gateway command confirms client receipt, removes Codex queue input, interrupts a turn, or cancels cloud work.

## Reconcile an unknown stock submission

Never replay an ambiguous client submission. For V2 stock rows, the recovery identity hash binds the entire validated historical envelope and admission, including source, profile, permit, destination, and generation fields. Abandonment uses that exact hash as a compare-and-set guard; it grants no authority, does not settle the remote obligation, and does not make retry safe. Inspect the durable record:

```sh
knitli-event-gateway --state-dir "<PRIVATE_STATE_DIR>" stock-recovery list
knitli-event-gateway --state-dir "<PRIVATE_STATE_DIR>" stock-recovery list \
  --delivery-id "<DELIVERY_ID>"
```

If the first output reports truncation, use the exact delivery ID to retrieve the row. For unresolved ambiguity, an operator may annotate a local abandonment using the exact values from that row:

```sh
knitli-event-gateway --state-dir "<PRIVATE_STATE_DIR>" stock-recovery abandon \
  --delivery-id "<DELIVERY_ID>" --attempt-id "<ATTEMPT_ID>" \
  --expected-identity-sha256 "<IDENTITY_SHA256_FROM_LIST>"
```

This is local annotation only. The machine state remains `unknown`, cloud obligation remains unresolved, and retained evidence and budget charge remain. It does not confirm receipt, cancel cloud work, release a slot, or permit retry. There is no Gateway CLI operation for cloud confirmation/cancellation. Preserve the record and escalate through the existing authority/recovery owner; do not invent an API or mark it complete.

A `command_accepted` ACK means the stock CLI exited successfully and Gateway journaled that acceptance. It is not independent proof that Codex durably recorded the input, started a turn, or completed work. Lost cloud ACK recovery reuses the stored ACK; uncertain submissions stay unknown and are not resent.

## Client support matrix

| Client/version | Evidence and operating decision |
| --- | --- |
| Codex CLI 0.166.0 | Bounded synthetic loopback evidence supports explicit persisted UUID targeting, idle queue+`--resume`, TUI-closed/daemon-alive continuation, and the tested 0.163.0→0.166.0 same-home saved-thread upgrade. Busy behavior qualifies only for a documented daemon-connected TUI: `codex --no-alt-screen resume --include-non-interactive --remote unix://<private daemon socket> <A UUID> -C <PRIVATE_HOME>`; the exact production queue command is `codex queue --thread <A UUID> --message <REF> --resume`, without `--remote`. The held turn completed, and the next A history contained the exact held response and unique queued ref; an extra request was classified as background title generation. The reviewed core gate passes; the original V6 harness verdict `passed: false` is preserved because that harness also required the external ref to render in the TUI. The TUI remained Working and displayed the held answer with no cancellation signal, but did not display the queued ref. The default embedded-TUI route remains unqualified. Duplicate queueing is possible; no independent durable client receipt, turn-start, or task-completion proof. Gateway tests cover its own journal behavior. The underlying E1 qualification and sanitized busy-evidence artifacts are maintained separately from this E5 document copy. |
| Claude Code 2.1.318 | Disabled; no trial. Preview MCP Channels require a running session and provide no documented exact-session binding, busy policy, independent receipt, persisted reconciliation, or stop contract. An authenticated session would have been needed for the documented channel trial. Keep disabled until an inert no-credential test proves these properties. See [Claude adapter audit](claude-adapter.md) and [official Channels docs](https://code.claude.com/docs/en/channels). |
| Muse Code 1.4.14 | Offline echo/MSP probe established same-host session lifecycle, restart/resume, and same-command dedupe. A separate documented peer UUID ingress exists (`muse session-message send --target <session-uuid-or-name>`), but the installed CLI returned `external_agent_ingress_closed` with an isolated echo TUI alive; no peer message was sent. The gate prevented E5 qualification. MSP's single-host ownership limit applies only to MSP sessions and does not rule out this separate peer-messaging path. Keep disabled until the supported ingress is available and verified. Active stop/cancel was not tested. See [client breadth qualification](stock-client-breadth-qualification-2026-11-04.md) and [Muse ingress audit](muse-ingress-spike.md), [official MSP session and turn docs](https://dev.meta.ai/docs/muse-code/sessions-and-turns/), and [official session messaging docs](https://dev.meta.ai/docs/muse-code/session-messaging). |
| Native Workshop | Disabled. Existing exact client/thread/server witness contract and an explicit supported event ingress/receipt path are not qualified. See the accepted event-alignment plan's native-admission gate. |

## Evidence boundary

The E1 stock Codex result is bounded client-interface evidence, not live Cloud delivery or a deployed route. Local Gateway tests establish persistence, fencing, duplicate, and ambiguous-recovery behavior under the tested cases. They do not prove E3 live idle wake or E4 canonical Messaging delivery/settlement; neither stage is declared complete here. The handoff and V2 recovery implementation and its tests do not establish an installed release or deployment qualification. Source/client evidence is not deployment evidence.

Existing shared Messaging grants and wake-budget rules remain authoritative. This runbook introduces no new limits, budget service, retry permission, or authority. Remote Execution remains an optional Messaging-to-Execution handoff under its existing grants, approval, run lifecycle, limits, and cancellation; it is not an Event executor or a prerequisite for local wake. Memory remains governed by its existing grants and policies; event delivery creates no automatic memory writes.
