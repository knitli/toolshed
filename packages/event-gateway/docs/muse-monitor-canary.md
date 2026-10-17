# Disposable Muse monitor wake canary

Status: owner-observed controlled idle wake on 2026-10-17, alongside offline
fixture checks. The owner confirmed that the native notification reached the
idle session and that a subsequent model response treated it as inert data.
This fixture emits one nonsecret random marker; it cannot establish delivery
authority, a durable acknowledgment, source permission, or a production binding.

The owner-reported monitor contract accepts a shell `command`, a `description`,
and `wake_delay_ms=0`. Omitted settings use its reported defaults:
`persistent=false`, `timeout_ms=300000`, `show_lines=false`. Every stdout line is
an asynchronous machine notification, and process exit ends the watch. The
controlled idle observation below has limited scope. The script does not call
the monitor tool. Only the owning eligible Muse session can register it through
that session's native tool.

## Controlled idle observation (2026-10-17)

The owner reported that the session was idle before the trigger and observed
native monitor start and end, notification receipt, and a subsequent model
response treating the notification as inert data. This establishes an
owner-confirmed controlled idle wake; no durable native completion receipt was
captured.

The interval from fixture readiness to trigger was 44.442808 seconds, within the
90-second fixture deadline. This is readiness-to-trigger timing, **not wake
latency**; it does not measure notification delivery or model response time.

Busy-session behavior, crash/restart recovery, durable delivery, explicit read/ACK
semantics, independent session binding, and production integration remain
unqualified. The offline checks below retain their fixture-only scope.

## Prepare without starting Muse

Use an explicitly selected Python interpreter and this reviewed checkout:

```sh
python packages/event-gateway/scripts/muse_monitor_canary.py prepare
```

The result contains `directory` and a `monitor` object. Keep the exact object; its
command quotes the interpreter, script, and unique private directory. The script
creates the directory with mode 0700 and files with mode 0600. No marker appears
in the preparation output or command; it lives in that directory's manifest.
The marker is nonsecret, but avoid putting it in an ordinary model prompt because
that would contaminate the later wake observation.

No command copies credentials, discovers a session, starts a provider, or installs
anything. The caller must trust the selected Python interpreter and checkout.
Private filesystem permissions isolate other users, not hostile code running as
the same operating-system user. Each record first claims a persistent exclusive
reservation, then writes and fsyncs a private temporary file in the same directory.
After rejecting any existing final path (including symlinks), rename publishes
complete bytes at once without a transient extra hard link. Reservations exclude
competing writers using this fixture and remain after failure or crash. This is a
cooperative-writer boundary: the absence-check/rename pair cannot prevent a
hostile same-UID actor from inserting a final path between those operations.
Do not edit or reuse the generated records or reservations.

## Owner-run idle phase

1. Select a disposable eligible Muse session and record its exact identity and
   process/session generation independently. Do not infer identity from this
   fixture's random `runId`; that identifies only the fixture run.
2. Inside that session, invoke the native monitor tool using the returned
   `monitor` object. Retain native tool evidence that the monitor was installed.
   The script writes `ready.json` privately and stays silent on stdout. A ready
   file alone does not prove native monitor registration or session idleness.
3. Finish the setup turn. The owner must confirm that the same session is idle
   before the orchestrating agent triggers the canary. Read `ready.json` to check
   that the command started. No synchronous monitor response counts as delivery.
4. Within the fixture's 90-second deadline, the orchestrating agent runs:

   ```sh
   python packages/event-gateway/scripts/muse_monitor_canary.py trigger --directory /EXACT/PREPARED/DIRECTORY
   ```

   Trigger success means only that a private file was created. It does not prove
   that the source is still running, that Muse read a line, or that a turn started.
5. Observe the **native machine-notification event** in the same session. Compare
   its complete JSON line against the private manifest: `kind` must be
   `muse-monitor-canary`, and `runId`, `marker`, and `phase` must match exactly.
   A model repeating the marker in assistant text, a successful trigger command,
   or a transcript FEED cell alone is not proof of idle wake. Retain independently
   observed session state before the trigger and native notification/turn state
   after it, including ordering and timestamps. Do not label an assistant response
   as a native event receipt.

The source exits after flushing its one line. Native monitor cleanup and event
visibility must be observed, not assumed from the source's successful exit. No
polling service or acknowledgment command exists in this fixture. Missing or
ambiguous observations remain unproven; do not retry the same directory.

## Optional busy phase, stop, and crash

Busy behavior is a separate run prepared with `--phase busy`. Register that new
monitor in the same independently identified disposable session. Trigger only
while a separately authorized ordinary turn is demonstrably active, then record
whether the native notification steers, queues, waits, or is lost. This fixture
neither starts that turn nor authorizes tool execution. Do not call an idle result
a busy-queue result, and do not reuse one run's marker as evidence for another.

Before triggering, the owner may stop the watch with its native `muse.work_stop`
operation, close its source, or end the disposable session. Record what actually
happens. A crash or stop after `ready.json` can leave stale files; those files do
not attest liveness. The fixture checks its monotonic 90-second deadline while
waiting and emits no line on timeout. Ordinary filesystem operations are local;
it does not claim to bound a hung operating system or native monitor shutdown.

A `started.json` record is created before readiness and retained even after a
crash or timeout. A second `wait` refuses that run, and `trigger` refuses an
existing trigger. This conservative no-replay behavior can lose a canary after
an uncertain write; it is not exactly-once delivery. Create a fresh run for any
retry. Remove only the explicitly created disposable directory after the source
has exited and the native watch has stopped. The script performs no automatic
cleanup or deletion of owner state.

## Offline checks and remaining gates

`test_muse_monitor_canary.py` covers private preparation, exact command quoting,
no output before readiness/trigger, one line after a matching trigger, deadline,
wrong/premature triggers, symlink refusal, stop/crash replay refusal, and a real
Python subprocess. A separate publisher process is paused after writing half a
record: readers see no final record until publication, a competing writer is
refused, and killing the publisher retains its reservation. Tests also preserve
preexisting final files and symlinks. These tests execute only the fixture, never Muse. They cannot
prove monitor installation, idle wake, busy handling, restart fencing, native
receipts, gateway attachment, durable ACK, or production acceptance. A future
session-owned pull service still requires independent session binding, explicit
read/ACK semantics, and isolation from native push dispatch.
