# Claude Channels interface qualification — E1 evidence toward E5 — 2026-11-10

**Result: bounded local stock-client Channels interface evidence; E5 remains unqualified and production remains disabled.** This was the official fakechat Channels trial with stock Claude Code 2.1.322 and explicit per-session channel opt-in. It is not a Knitli Messaging or Event Gateway integration, and does not qualify a production route.

## Evidence identity and scope

- Client: stock Claude Code 2.1.322; channel: `plugin:fakechat@claude-plugins-official`.
- Exact supplied session UUIDs: `34497ae9-0c39-4da1-b380-acb94c716fe5` (initial idle event, then busy event with a contradictory foreground instruction), `c5fd813d-fdb8-475e-8ce1-0044f31af2a6` (idle reply), and `7a654161-b81e-4087-8b83-d28bf34742aa` (busy-timed trial and resume check).
- Sanitized evidence: [Claude Channels qualification record](evidence/claude-channels-2.1.322-qualification.json). Raw Claude API request transcripts and authentication material are excluded.
- Each trial had a 120-second guard, at most two messages and three operator turns, no attachments, only `sleep 15` plus a manual fakechat text reply, and a 512-token maximum output per request. No other tools were called; the guard required manual denial of other tool requests.

All times below are 2026-11-11 UTC, corresponding to the local evening of 2026-11-10.

## Observations

| Trial | Evidence | Classification |
| --- | --- | --- |
| `34497ae9-0c39-4da1-b380-acb94c716fe5` | An initial idle event was timestamped 02:40:41.847Z, before `sleep 15` started at 02:41:16.509Z. A second event arrived at 02:41:20.601Z during sleep, but the foreground prompt explicitly prohibited using other tools, so Claude refused the fakechat reply. | **Initial event is idle evidence; busy reply is invalidated by the conflicting prompt.** This trial cannot qualify busy reply behavior. |
| `c5fd813d-fdb8-475e-8ce1-0044f31af2a6` | `sleep 15` ran from 02:43:48.486Z to 02:44:04.534Z; the event arrived at 02:44:15.430Z and the exact fakechat reply tool ran at 02:44:17.610Z. | **Idle reply confirmed.** The late event does not establish busy delivery. |
| `7a654161-b81e-4087-8b83-d28bf34742aa` | `sleep 15` ran from 02:46:55.466Z to 02:47:11.383Z. The synthetic submit at 02:47:02.047Z returned HTTP 204; its matching channel event was timestamped 02:47:02.058Z (body SHA-256 `e6e0a363b14fee1bf6b66516784353b710cc73db9ee6ae701acb86cc8cfaf4e6`) and appeared in the next Claude API request at 02:47:11.417Z, after sleep completed. At 02:47:13.654Z Claude invoked fakechat reply targeting that message with exact text `CLAUDE_BUSY_7A654161`; the reply tool returned a successful `sent` result at 02:47:36.613Z. The browser snapshot at 02:48:17.218Z independently showed the exact reply. | **Bounded queue-and-after-busy-reply slice observed:** the event was queued during sleep and appeared in the next model request after the Bash tool completed; Claude then replied. This does not show delivery to the model while the tool was still running, a native Claude acknowledgement, or a turn-start/durable receipt. |

The first trial contains both an idle event and a later busy-timed event, but the contradictory foreground instruction invalidates its reply result. The second trial’s event was too late to show busy handling. Only the third supports the bounded queue-and-after-busy-reply observation. The fakechat HTTP 204 and fakechat receipt/UI are observations of that test service, not a Claude Channels delivery acknowledgement.

## Resume and stop boundary

Resuming the same busy-trial session produced no new messages or assistant records, and no replay was observed. The assistant-record ID set was unchanged; the whole transcript file hash changed, so no full-file immutability claim is made. After the listener stopped, the port refused connections; no input was sent and no offline queue behavior was claimed. Final cleanup found no owned processes, no fakechat outbox, and the port free. An earlier guard cleanup reported a lineage mismatch during a Ctrl-D race; the independent post-run checks establish quiescence only.

## Contract and disposition

The [official Channels reference](https://code.claude.com/docs/en/channels-reference) describes Channels as a research preview with session opt-in. It states that Claude Code does not acknowledge notifications: the notification write resolving means only that data reached the transport, while busy events are queued for a later turn. Thus this trial does not establish client acknowledgement, durable receipt, turn start/completion, recovery reconciliation, or stopped-session queueing. Local development opt-in for custom channels is preview testing, not production qualification.

**Disposition: E5 and production remain disabled / unqualified.** This narrow local fakechat result does not qualify Knitli Messaging, Event Gateway, authentication or authorization behavior, or any production path.
