# Messaging in-flight workerd crash matrix

Historical crash-only result: the approved local three-case matrix passed on 2026-10-17. One unittest
executed all three subtests in 5.260 seconds with exit code 0 and no skips. The
preparation base is reviewed PR #153, commit `1a66233e2ae957e3015c84e188be6725a63a8cf9`.
PR #153 has since merged as `4182c8e593a70c8f752b812a45494dcbf693484c`.
This work is rebased onto fresh main `291fbead344e33be99851e1238dfbcf3bafcbaf2`
with the executed fixture bytes preserved. Root content review approved publication.

The [derived result receipt](messaging-v2-abrupt-crash-result.json) records the
successful root execution against preparation freeze SHA-256
`1beb36e89e86e88ac7c335838eaf3c6899cda4d45c0628abeaec004296c1070e`;
all twelve revised frozen file hashes matched before the latest run. The original
6.412-second pass is preserved in the result history. The repeated pass covers the
constructor dependency grouping and equivalent JSON integer PID validation. The evidence is the frozen
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
The original run contained three fresh crash subtests; the extension below now contains twelve. The pass qualifies the
local pinned Miniflare/workerd boundaries above. Deployment, machine power loss,
automatic cloud-alarm recovery, native/provider execution, native completion,
durable ACK, settlement and unattended wake remain unqualified. No install,
recurring monitor or production activation is included.

## Crash followed by production alarm composition

The extended fixture runs twelve fresh owned-workerd crash cases: the three
original barriers followed by the real production `AgentCoordinator.alarm()`,
eight unadmitted cases (before/after reservation crossed with consumer, route,
source and key changes), and one positive same-attempt replay after reservation.
The fixture endpoint ages only claim deadlines (`updated_at` for reserving and
`permit_until` for admitted) before invoking the production alarm. Automatic
platform alarm scheduling remains suppressed. This proves the alarm method's
post-crash composition, not autonomous scheduling or power-loss recovery.

The first two phases become `unknown`; admitted claims become `ambiguous`.
Snapshots require the exact attempt identity, budget ledger, message attempt,
slot obligation and permit ID to survive. A second alarm must be idempotent.
A reopened Python process must retain its exact held, uncertain attempt, with
no automatic HTTP resend or native call. No native receipt, ACK or settlement
is generated. The admitted deadline is deliberately aged; no claim is made
that its timestamp is unchanged or that historical lookup was retested.

The eight fencing probes explicitly replay the original unadmitted Cloud attempt
with a fresh node proof after the alarm. Consumer/route/source changes return
HTTP 409 `conflict`; key deactivation returns HTTP 403 `denied`. The Cloud
snapshot must remain unchanged, with no permit or additional budget charge.
The positive unchanged-consumer replay returns one valid permit for the original
attempt while preserving the already charged ledger. This explicit probe is
separate from local gateway custody, which remains uncertain and never resends.
Admitted historical lookup intentionally retains its original permit; blanket
refusal after consumer/source changes would contradict that production contract.

Source trace on pinned Cloud `99655360630ca0e3f222d1e73d841aaf456378a7`:

- `coordinator.ts:2275`: the alarm ages reserving claims to unknown and expired
  admitted claims to ambiguous; it does not retry admission.
- `coordinator.ts:1446` and `:2477`: new admission refreshes the source fence;
  its local check compares runtime attachment generation against the delivery.
- `messaging/delivery-authority.ts:26`: preparation is reread and must match
  the retained source snapshot; route changes or revoked source grants conflict.
- `event-authority.ts:146` and `coordinator.ts:1422`: active agent credentials
  are rechecked; deactivated keys are denied before reservation.
- `coordinator.ts:1550`: explicit same-attempt recovery checks Messaging status
  before considering reservation; generic reservation/status remains forbidden.

`coordinator.ts` is byte-identical at the fixture pin and reviewed Cloud
`ba9824bc17c3b37464a1142cdb34253bf6198354`. All 334 upstream/dependency input
hashes and both Cloud pins remain unchanged. Only the fixture worker input and
compiled bundle hash rotate; the closure still has 335 inputs.

Causal negative controls remove the fixture's production-alarm invocation
(all twelve cases fail) or suppress the consumer/revocation stimulus
(all eight refusal cases fail because admission succeeds). The latter is a
stimulus control, not deletion of a production fence. Exact fixture source and
pin bytes were restored and matched the final positive-run source freeze. No upstream
source was mutated. The derived JSON receipt records the final run, source
freeze, logs and these limits. Root independently repeated all twelve crash
cases and six safety tests: seven unittest tests passed in 21.050 seconds with
zero skips. The original executable freeze matched that run. Root approved signed PR
publication; CI, automatic Codex review and root merge gates remain pending.

A later review correction extracts shared child configuration and Cloud client
construction into the existing test helpers. Scenario assertions and runtime
fixture bytes remain unchanged. A separately reviewed three-module run passed
26 tests in 48.853 seconds with zero skips, including all twelve actual crash
cases. The JSON receipt preserves the original run and records this newer run's
three changed source hashes separately. Root reviewed the exact extraction and
hashes and ran extended lint and diff checks; the bounded test agent executed
the 26-test run. This adds no production qualification.
