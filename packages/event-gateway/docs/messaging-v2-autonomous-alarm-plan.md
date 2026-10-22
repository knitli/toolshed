# Autonomous alarm proof: prepared execution plan

Status: method and controls only; point-in-time results are recorded in the
[final 9503 qualification receipt](messaging-v2-source-admission-9503-final-qualification.json).
Scope: private local fixture, one after-reserve SIGKILL per fresh fixture, actual
persisted workerd alarm, production coordinator alarm implementation. No native
client, provider, deployment, production attachment, or external messaging.

## Frozen sequence

1. Review and hash the Python test/helper, broker, worker, observer, runtime pin,
   process child/helpers and pinned production source before any execution.
   Include `messaging-autonomous-observer.mjs` and its inert test in the source
   manifest; these broker-side modules are outside the worker bundle closure.
   `messaging-workerd-inputs.json` contains the exact 353-input freeze for
   merged Cloud source 9503. Its compile preparation is retained at
   [the corrected 9503 preparation receipt](messaging-v2-source-admission-9503-reduced-env-preparation.json);
   the executed results and full hashes are in the
   [final 9503 qualification receipt](messaging-v2-source-admission-9503-final-qualification.json).
   This plan documents method and controls; it is not itself the execution record.
2. Set the existing pinned `FIXTURE_NODE`, `FIXTURE_MINIFLARE`, and
   `FIXTURE_CLOUD_SOURCE` paths and `FIXTURE_ABRUPT_CLOUD_CRASH=reviewed`.
3. Run exactly `test_messaging_autonomous_alarm.MessagingAutonomousAlarmTests`
   once for each separately selected `FIXTURE_AUTONOMOUS_ALARM` mode:
   `positive`, `no-super`, `delete-alarm`. Use fresh broker/storage per run.
4. The fixture seeds synthetic state, arms after-reserve, starts the existing
   synthetic gateway child, and kills only the captured owned workerd child.
   The pre-kill barrier captures the real persisted alarm, coordinator instance
   nonce, attempt ID and coordinator state. Preserve native claim timestamps;
   do not age deadlines or explicitly invoke recovery.
5. From the kill through completion, poll only
   `/fixture/autonomous-observation`. This endpoint immediately returns broker
   memory: `proof`, `barrier`, `completion`, `elapsedSinceKillMs`, and
   `observationTimeout`; proof remains null until restart evidence completes.
   Each observation HTTP request has a one-second timeout.
   No readiness read, health request, coordinator read, or explicit alarm dispatch
   may wake the replacement during this interval. Broker dispatch is blocked
   until completion or 25 seconds since kill. Python also bounds observation
   polling with a 25-second monotonic deadline after the gateway child returns.
6. Only after completion or broker-confirmed timeout, perform one diagnostic
   `/fixture/read`. It cannot establish autonomous recovery; the out-of-band
   completion state is the positive oracle. If positive or no-super reaches the
   timeout without completion, retain that first diagnostic state and fail with
   `wake-on-access limitation`. Never fall back to a manual alarm invocation.
7. Retain mode, exact file hashes, command, duration, exit code, skips, assertions,
   and cleanup outcome in a separate result receipt. Failure or a skipped test
   is not qualification. Do not edit this plan into a passing-result claim.

## Required outcomes

- Positive: a distinct coordinator instance nonce reports actual alarm execution,
  bound to the exact attempt and scheduled time. Production recovery changes
  only the reserving claim/attempt to unknown and reservation state to unknown.
- No-super: alarm completion still proves a replacement instance executed, but
  state stays reserving/pending. The positive recovery oracle must reject it.
- Delete-alarm: barrier observes the scheduled alarm then deletes it before kill.
  No completion occurs during the full 25-second observation window; state
  remains reserving/pending. A diagnostic request cannot repair this result.
- All modes: one captured child kill/replacement, original broker survives,
  storage identity stays fixed, one exact reservation charge, no permit,
  unchanged deliveries/slot intents, held local history, one uncertain claim,
  no retry, no native call and no outbound provider call.

Existing bounded owned-process cleanup and pipe limits remain mandatory.
Static checks and inert unit tests validate preparation only. Actual scheduling
and restart behavior require the separate reviewed local execution.
