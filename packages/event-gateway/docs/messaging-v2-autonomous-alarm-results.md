# Persisted alarm recovery after workerd SIGKILL

All three current guarded-fixture cases passed on 2026-10-17 with the frozen test sources in
[messaging-v2-autonomous-alarm-result.json](messaging-v2-autonomous-alarm-result.json).
The [preparation plan](messaging-v2-autonomous-alarm-plan.md) remains the historical
pre-execution plan. These results add executed evidence without changing it.
The current fixture explicitly rejects a missing observer binding before state
reads or production alarm effects. All three cases were rerun after this guard
and its bundle/source pins changed. The prior pre-guard baseline also passed
once per mode; its original receipts, logs and hashes remain recorded separately.

| Mode | Observed assertion outcome | Test duration | Passed / skipped |
| --- | --- | --- | --- |
| positive | Replacement instance autonomously completed the production alarm; reserving/pending became unknown/unknown | 11.657 s | 1 / 0 |
| no-super | Replacement alarm signaled, but reserving/pending remained; positive recovery oracle rejected that state | 11.406 s | 1 / 0 |
| delete-alarm | No completion for the full 25-second observation interval; subsequent diagnostic retained reserving/pending | 26.481 s | 1 / 0 |

The positive case recorded the production-scheduled persisted alarm before the
owned after-reserve SIGKILL. During restart and recovery, the test polled only
broker-owned memory. Its first postrestart Durable Object read followed the
completion signal from a distinct coordinator instance. It did not age deadlines,
manually invoke recovery, rearm an alarm, or use a readiness request to wake the
replacement. The production coordinator source was unchanged.

Each case asserted two distinct workerd PIDs, one kill, one automatic restart,
a surviving broker and the same persistence directory identity. The reservation
and budget charge remained exactly one; no permit appeared; deliveries and slot
intents stayed unchanged. Local uncertain history stayed held, with one HTTP
claim, no resend and zero native/provider calls. Cleanup completed before
fixture storage removal.

The runtime was Node 24.21.0, Miniflare 5.20261001.0-alpha and workerd 1.20261001.1
on darwin/arm64. The result records executable/source hashes, relative test
commands, completion timestamps, unittest durations, total command durations,
and log/receipt basenames and hashes. Raw process/storage/state snapshots were
asserted during execution and were not retained separately. Logs record passing
tests, rather than replayable state traces.

Adjacent default/manual behavior was reviewed and checked without another live
run: 16 Python safety tests, 29 Node mock tests and two mocked launch cases
passed. The sanitized child environment does not forward an ambient autonomous
mode to default/manual launches. Manual alarm helpers remain available, and the
automatic alarm override remains disabled without the explicit fixture binding.
After the guard change, two tests executing the actual alarm method passed
(missing binding and default mode), alongside three repeated observer tests.

This establishes autonomous persisted-alarm discovery for the pinned local
runtime after an actual process kill. It does not qualify production hosting,
power-loss durability, native clients, provider execution, production attachment,
or real idle-session wake. Each mode has one current guarded run and one retained
pre-guard baseline run; these timings do not establish a reliability or latency
distribution.
