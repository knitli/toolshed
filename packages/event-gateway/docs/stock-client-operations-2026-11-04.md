# Stock client operations and qualification — 2026-11-04

This is the operator procedure for the existing Gateway controls, Messaging v2 handoff, and ambiguous stock recovery. The stock-only installer and Messaging v2 consumer are merged in protected main; the protected-main installer has been verified, and an owner-private qualification install exists. This does not claim public wheel promotion, selection of an active/default client, agent attachment, production activation, or live E3/E4 qualification. Use these controls only from a reviewed, pinned, installed stock release. The V2 contract remains pinned to Cloud commit `e954904603b3467e30bbeaf7446977b61fbcb9ef`; the trusted policy and Gateway consumer are merged, but a local handoff does not prove a current production route or delivery.

## Check current state

Use the installed Gateway entry point. Put the private state path before the subcommand:

```sh
knitli-event-gateway --state-dir "<PRIVATE_STATE_DIR>" status
```

`status` reports local Gateway stage, dispatch state, durable store counts, and aggregate `stockWatchRenewal` association/pending/failure/capacity counts. The daemon renews only watches returned by the owner-scoped cloud list for the exact assigned runtime and conversation; it does not infer watches from PR labels or TUI state and cannot create or reattach one. Watch renewal uses its stored operation ID for exact readback and only retries after an explicit unresolved response. A listing failure is diagnostic and does not settle a pending renewal. Neither these counts nor runtime-status proves that the Codex client received input or started a turn. Keep cloud config and credentials private.

Watch renewal runs in at most eight runtime workers, with at most eight watch-renewal operations in flight per runtime. The durable association limit is 32 across the Gateway state directory; status reports when that fail-closed limit is full. Detached or expired local mappings do not prove what happened to an ambiguous Cloud operation. Preserve its exact pending request until supported owner-side reconciliation settles it; do not edit the database to reclaim capacity.

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

A replacement `attach` also requires both expected current generations; it advances them. If a stock `attach` or `renew` outcome is unknown, `runtime-status` may expose generic stored generations when its native-admission canary gate allows, but its readback omits the assigned-stock profile and conversation, so it cannot authoritatively reconcile stock identity. Preserve the `unknown` result and have the authority owner reconcile the current runtime, exact profile, conversation, and generation pair using a supported authoritative path. A same-generation renewal retry alone does not distinguish a committed request from an unknown outcome. Do not blindly retry, choose new generations, or send new conversation input to resolve uncertainty. If no supported owner readback is available, stop and hand off for reconciliation. The daemon renews an existing local stock mapping while running; it does not start, inspect, or reassign client sessions.

If the authority owner confirms that an `attach` committed but the CLI reports `cloud_committed_local_mapping_failed`, do not retry from the old pair. Reconcile the current cloud identity and generation pair first, then issue a replacement `attach` using that confirmed pair. The local writer can advance an exact detached Messaging mapping across the reconciled generation gap and clears its old route metadata; new Messaging delivery still requires a separate owner CAS and handoff.

## Messaging route owner handoff (merged; check the installed profile)

Protected main implements `stock-control renew --messaging-handoff`, and the CLI parser accepts the flag for `renew` only. An owner-private qualification install exists for the stock-only package; this is not a claim that the wheel was promoted to the public package index or that other installed releases contain the flag. Check the installed command help before use; if the flag is absent, stop. This local import does not itself prove a current v2 route, production activation, or E4 delivery.

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

Use the exact generation pair from the current assignment and private owner readback only when the installed command help confirms the handoff flag and the v2 integration is present in that reviewed installation:

```sh
knitli-event-gateway --state-dir "<PRIVATE_STATE_DIR>" stock-control renew \
  --runtime-id "<RUNTIME_UUID>" --conversation-id "<CODEX_CONVERSATION_UUID>" \
  --expected-runtime-generation "<RUNTIME_GENERATION>" \
  --expected-attachment-generation "<ATTACHMENT_GENERATION>" \
  --cloud-config "<PRIVATE_CLOUD_CONFIG>" \
  --messaging-handoff "<PRIVATE_OWNER_READBACK_JSON>"
```

The operation renews the exact cloud stock assignment, checks the readback against that assignment, and asks the single local writer to store the Messaging mapping with the expected prior mapping. A successful CLI result reports `localMapping: stored`; this proves the local write returned successfully, not independent remote route authority or E4 event delivery. If the outcome is ambiguous or the result reports `cloud_committed_local_mapping_failed`, stop and reconcile the exact generations with the route owner before another operation. Do not replace the file with guessed values or retry under a new assignment.

For canonical content reads, configure the assigned client's existing Messaging MCP connection as the same principal and agent. Messaging stock notifications include the canonical message ID and ask the client to call `read` with that ID; the opaque event reference is not a message ID. The tool still enforces current mailbox access and provenance. Queue acceptance does not prove the read happened.

## Stop future submissions

Stop the Gateway daemon through its existing foreground/supervisor lifecycle: Ctrl-C for a foreground `run`, or the supervisor's normal stop/SIGTERM for its exact process. There is no separate `pause` or `stop` CLI subcommand. Then fence the local runtime mapping:

```sh
knitli-event-gateway --state-dir "<PRIVATE_STATE_DIR>" detach "<RUNTIME_UUID>"
```

The daemon's SIGINT/SIGTERM handler stops accepting dispatch and shuts down workers. `detach` fences new submissions for that local runtime and expires its local mapping. It does **not** cancel input already accepted into Codex's queue or an active turn. The inspected Codex CLI 0.166.0 top-level help lists `queue` and `delete`; `delete` is described as permanently deleting a saved session. It exposes no queue-cancel or queue-clear command, and the E1 trials did not qualify removal of an accepted queued input. Do not use session deletion or Gateway detach as proof that queued input was removed. Check the exact assigned client directly before claiming cancellation; if exact client-side removal or readback is unavailable, preserve the ambiguous submission as `unknown`, stop automatic replay, and escalate to the existing owner/recovery authority. No Gateway command confirms client receipt, removes Codex queue input, interrupts a turn, or cancels cloud work.

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

This is local annotation only. The machine state remains `unknown`, cloud obligation remains unresolved, and retained evidence and budget charge remain. It does not confirm receipt, cancel cloud work, release a slot, or permit retry. The only documented Gateway recovery actions here are read-only `list` and local `abandon`; there is no Gateway CLI operation for client queue removal or cloud confirmation/cancellation. Preserve the record and escalate through the existing authority/recovery owner; do not invent an API, treat abandonment as confirmation, or mark it complete.

A `command_accepted` ACK means the stock CLI exited successfully and Gateway journaled that acceptance. It is not independent proof that Codex durably recorded the input, started a turn, or completed work. Lost cloud ACK recovery reuses the stored ACK; uncertain submissions stay unknown and are not resent.

## Client support matrix

| Client/version | Evidence and operating decision |
| --- | --- |
| Codex CLI 0.166.0 | Bounded synthetic loopback evidence supports explicit persisted UUID targeting, idle queue+`--resume`, TUI-closed/daemon-alive continuation, and the tested 0.163.0→0.166.0 same-home saved-thread upgrade. Busy behavior qualifies only for a documented daemon-connected TUI: `codex --no-alt-screen resume --include-non-interactive --remote unix://<private daemon socket> <A UUID> -C <PRIVATE_HOME>`; the exact production queue command is `codex queue --thread <A UUID> --message <REF> --resume`, without `--remote`. The held turn completed, and the next A history contained the exact held response and unique queued ref; an extra request was classified as background title generation. The reviewed core gate passes; the original V6 harness verdict `passed: false` is preserved because that harness also required the external ref to render in the TUI. The TUI remained Working and displayed the held answer with no cancellation signal, but did not display the queued ref. The default embedded-TUI route remains unqualified. Duplicate queueing is possible; no independent durable client receipt, turn-start, or task-completion proof. E1 did not test or qualify removal of an accepted queued input; top-level help exposes no queue-cancel/clear command. Gateway tests cover its own journal behavior. The underlying E1 qualification and sanitized busy-evidence artifacts are maintained separately from this E5 document copy. |
| Claude Code 2.1.318 | Disabled; no trial. Preview MCP Channels require a running session and provide no documented exact-session binding, busy policy, independent receipt, persisted reconciliation, or stop contract. An authenticated session would have been needed for the documented channel trial. Keep disabled until an inert no-credential test proves these properties. See [Claude adapter audit](claude-adapter.md) and [official Channels docs](https://code.claude.com/docs/en/channels). |
| Muse Code 1.4.14 | Offline echo/MSP probe established same-host session lifecycle, restart/resume, and same-command dedupe. A separate documented peer UUID ingress exists (`muse session-message send --target <session-uuid-or-name>`), but the installed CLI returned `external_agent_ingress_closed` with an isolated echo TUI alive; no peer message was sent. The gate prevented E5 qualification. MSP's single-host ownership limit applies only to MSP sessions and does not rule out this separate peer-messaging path. Keep disabled until the supported ingress is available and verified. Active stop/cancel was not tested. See [client breadth qualification](stock-client-breadth-qualification-2026-11-04.md) and [Muse ingress audit](muse-ingress-spike.md), [official MSP session and turn docs](https://dev.meta.ai/docs/muse-code/sessions-and-turns/), and [official session messaging docs](https://dev.meta.ai/docs/muse-code/session-messaging). |
| Native Workshop | Disabled. Existing exact client/thread/server witness contract and an explicit supported event ingress/receipt path are not qualified. See the accepted event-alignment plan's native-admission gate. |

## Evidence boundary

The E1 stock Codex result is bounded client-interface evidence, not live Cloud delivery or a deployed route. Local Gateway tests establish persistence, fencing, duplicate, and ambiguous-recovery behavior under the tested cases. They do not prove E3 live idle wake or E4 canonical Messaging delivery/settlement; neither stage is declared complete here. The handoff and V2 recovery implementation and its tests do not establish an installed release or deployment qualification. Source/client evidence is not deployment evidence.

Existing shared Messaging grants and wake-budget rules remain authoritative. This runbook introduces no new limits, budget service, retry permission, or authority. Remote Execution remains an optional Messaging-to-Execution handoff under its existing grants, approval, run lifecycle, limits, and cancellation; it is not an Event executor or a prerequisite for local wake. Memory remains governed by its existing grants and policies; event delivery creates no automatic memory writes.
