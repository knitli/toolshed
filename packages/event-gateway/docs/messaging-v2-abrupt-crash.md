# Messaging in-flight workerd crash matrix

Status: the approved local three-case matrix passed on 2026-10-17. One unittest
executed all three subtests in 6.412 seconds with exit code 0 and no skips. The
preparation base is reviewed PR #153, commit `1a66233e2ae957e3015c84e188be6725a63a8cf9`.
PR #153 has since merged as `4182c8e593a70c8f752b812a45494dcbf693484c`.
This work is rebased onto fresh main `291fbead344e33be99851e1238dfbcf3bafcbaf2`
with the executed fixture bytes preserved. Root content review approved publication.

The [derived result receipt](messaging-v2-abrupt-crash-result.json) records the
successful root execution against preparation freeze SHA-256
`c415cd9cc2c1b58488543648123a80616e9bd520f5c29b37785ca2956520a292`;
all eleven frozen file hashes matched before the run. The evidence is the frozen
assertions and successful execution result. Temporary fixture directories were
cleaned; raw per-case PID and storage-identity values were asserted during the
run but were not retained as separate artifacts. No provider or native client ran.

The [existing restart proof](messaging-v2-process-restart.md) remains orderly
Miniflare teardown/recreation, including Miniflare's internal SIGKILL. This new
fixture exercised unexpected in-flight workerd death and automatic replacement;
it does not turn the earlier orderly proof into crash evidence.

## Three passing cases

Each case creates a fresh broker, storage directory, synthetic authority and
held Python ledger. The private broker arms exactly one causal barrier:

| Barrier | Asserted post-restart cloud state | Local result |
| --- | --- | --- |
| Before `EventAuthority.reserveMessageAttempt` calls its production implementation | Coordinator reservation intent; zero shared-budget charges; no permit | Held, uncertain claim; no automatic resend |
| After that production method returns `reserved`, before returning to the coordinator | One durable message-bound budget charge; coordinator intent; no permit | Held, uncertain claim; no automatic resend |
| Broker consumes the admitted claim response, before forwarding it to Python | One budget charge and the exact admitted permit in both coordinator records | Held, uncertain claim; no automatic resend |

The fixture wraps the real Messaging-specific method; generic native status or
reservation fallback fails the crash case. Pinned cloud
`99655360630ca0e3f222d1e73d841aaf456378a7` routes Messaging admission through
`reserveMessageAttempt` in `event-runtime/src/coordinator.ts`. The authority
awaits `Mailbox.reserveEventMessageAttempt`, whose transaction writes the
message attempt and shared wake budget before its RPC response leaves the DO.
The middle barrier relies on the platform's
[storage output gate](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/):
outgoing responses wait for prior writes to be confirmed flushed. The
[output-gate explanation](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/)
also covers discarding outgoing messages after storage failure. No fixture
pre-read, manual flush, production transaction edit or durability bypass is
inserted before the crash. The actual local restart/readback assertions passed
for all three cases; this is not power-loss evidence.

## Ownership, limits and cleanup

The opt-in broker verifies the Miniflare module/version and the platform-specific
workerd version/binary SHA-256 in `messaging-workerd-runtime.json`. Before loading
Miniflare, it captures `child_process.spawn`, accepts only the canonical approved
binary and the closed serve/loopback/pipe argument shape, and retains the actual
returned `ChildProcess`. Extra spawns fail before execution. It never finds a
target by process name or sends a signal to an arbitrary supplied PID.

One `child.kill('SIGKILL')` injection must produce an observed old-child exit with
that signal, one distinct replacement child, and exactly one Miniflare automatic
restart-completion callback. The original broker `Popen` must remain alive, and
its PID must match the proof. The storage directory's canonical path, device and
inode must match before and after. A bounded read through the replacement then
checks readiness. Immediately before injection, the broker observes the original
claim socket and response still open. Only after the owned kill succeeds does it
write a one-shot marker. Python samples that marker before returning from the
claim transport, binding the observation to the phase, broker and old child;
missing, wrong or oversized evidence fails. A later crash cannot repair that
earlier sample. This is ownership evidence, not a claim of race-free OS PID
containment. Normal final Miniflare disposal may send SIGKILL to the replacement;
that cleanup is separate from the single unexpected crash injection.

- Broker startup retains the existing 60-second parent handshake deadline and
  1 MiB handshake limit. Gateway startup is 15 seconds with a 64 KiB handshake.
- Crash exit and automatic restart share a four-second deadline. Replacement
  readiness uses a one-second request signal; parent HTTP requests are bounded
  to five seconds and 8,192 response bytes. The causal marker is capped at 1 KiB.
- Abrupt mode sends broker stderr through the existing pipe drainer, retaining
  at most 8,000 bytes. Overflow fails the fixture and requests owned-group
  shutdown. Gateway stderr has the same cap. The orderly fixture's regular log
  file behavior is unchanged; its retained diagnostic tail is not a write cap.
- Process-group cleanup keeps the existing ten-second TERM and five-second KILL
  deadlines and preserves the primary failure. Drainer joins are bounded.
  Failure stops the pending restart waiter and restores the spawn capture.

After the crash, two local history calls must return the same unknown outcome.
A fresh Python process repeats them against the same ledger without HTTP resend,
new native calls, native receipts, pending/reconcilable work, another budget
charge, another permit or another workerd replacement. Message attempt identity,
delivery/slot state and the held envelope remain unchanged. External Worker
egress must remain zero. Automatic cloud alarms remain suppressed as in the
original fixture, so alarm recovery is outside this matrix.

All these assertions passed. The reserved cases additionally required one
`reserved` decision with `recordedAt = reservedAt = wakes[0] = pendingSince` and
the exact `event:<attemptId>` pending token. The unreserved case required empty
attempt/wake records and null or absent pending fields. The admitted case required
a nonempty valid UUID permit matching both coordinator records and the consumed
admission response.

## Checks and reproduction

`messaging-workerd-crash.test.mjs` uses only synthetic EventEmitter children. It
checks ownership, binary/argument rejection, wrong exit signal, missing callback,
extra spawn/callback, storage identity changes, kill failure and waiter cleanup.
Python safety tests mock the overflow kill and ensure missing execution opt-in
is rejected before a subprocess starts. Neither suite executes a workerd child
or sends a real signal. The offline checks passed: 26 Node mock tests and six
Python safety tests, including positive and negative budget/permit assertions.

The build-only update retains all 334 Cloud/dependency input hashes and the
335-input closure; only the fixture worker hash and compiled bundle hash change.
The worker hash is
`1f68afde1484e391ee76b615f4ce7f2d5263d0ddce8ce2c6511f82de05d5c43d` and the bundle
hash is `164bb39a7b1fb1b0fbc1a1aff9abf41418ebb6d03d676c08fb228a59be93b76b`.
No production runtime or upstream pin changes accompany this fixture.

For a separately approved reproduction, configure the three explicit fixture
paths in [the interoperability guide](messaging-v2-workerd.md): Node 24.21.0,
the pinned cloud checkout above, and Miniflare 5.20261001.0-alpha. The reviewed
darwin/arm64 runtime uses workerd 1.20261001.1 and the checked-in runtime hashes.
Set `GATEWAY_PYTHON` to the existing gateway Python interpreter. From the fixture
checkout, select the same single test class used by the successful run:

```sh
FIXTURE_ABRUPT_CLOUD_CRASH=reviewed \
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=packages/event-gateway/src:packages/event-gateway/tests \
  "$GATEWAY_PYTHON" -m unittest \
  test_messaging_abrupt_cloud_crash.MessagingAbruptCloudCrashTests -v
```

Do not widen the run to the whole integration suite or treat a skip as a pass.
That class contains exactly three fresh crash subtests. The pass qualifies the
local pinned Miniflare/workerd boundaries above. Deployment, machine power loss,
automatic cloud-alarm recovery, native/provider execution, native completion,
durable ACK, settlement and unattended wake remain unqualified. No install,
recurring monitor or production activation is included.
