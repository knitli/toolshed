# Messaging v2 admission across Python process crashes

`tests/test_messaging_process_restart.py` kills a real Python gateway child with
SIGKILL, waits for its owned process group to exit, then starts a fresh interpreter
against the same SQLite ledger. The original three barriers keep the reviewed Messaging workerd broker alive
across the two gateway processes. Additional cases also replace the workerd
process against retained Durable Object storage before the Python restart.

The three deterministic barriers stop the child:

- After its claim-intent transaction commits, before HTTP: restart retains the
  uncertain attempt, sends no claim and leaves the cloud budget uncharged.
- After actual HTTP admission returns, before local response persistence: restart
  retains the uncertain attempt, sends no claim and preserves the cloud's single
  budget charge and permit.
- After its local admission transaction commits: restart returns the exact stored
  admission and permit, with no claim resend or additional cloud charge.

The barriers wrap the real methods and stop only after they return, outside SQLite
transactions. They emit one bounded JSON handshake before blocking; the parent
uses fixed startup/exit deadlines and always cleans up owned process groups.
Stdout permits one JSON handshake (64 KiB maximum) and is checked for trailing
bytes after process exit. A dedicated pipe drainer retains at most 8,000 stderr
bytes; overflow kills the owned process group and fails the test. Diagnostic and
cleanup errors do not replace an existing primary failure. A host-only regression
checks the stderr bound, overflow shutdown and preservation of the primary error.
A denied process-group liveness probe remains “possibly alive” within the existing
shutdown deadlines; only an absent-group result proves exit. Host regressions cover
transient denial followed by disappearance and persistent denial failing cleanup.
Shutdown failures identify the process-group ID.
HTTP-send and native-factory entry markers are appended and fsynced before the
operation so a killed process or swallowed exception cannot erase those attempts.
Every case checks held state, unchanged attempt/envelope history, no pending or
reconcilable work, null native requests/receipts, no native calls and zero external
Worker egress. Recovery invokes the history path twice to verify stable results.

Run with the same three explicit local paths documented in
[messaging-v2-workerd.md](messaging-v2-workerd.md):

```sh
PYTHONPATH=packages/event-gateway/src:packages/event-gateway/tests \
  packages/event-gateway/.venv/bin/python -m unittest discover \
  -s packages/event-gateway/tests -p test_messaging_process_restart.py -v
```

## Workerd replacement against retained storage

The broker uses Miniflare's `resourcePersistencePath` inside the existing private
fixture temporary directory. Its secret-gated `/fixture/restart` disposes the old
Miniflare instance and creates another with the same compiled bytes, synthetic
keys and storage path. The Node broker stays alive; workerd does not. Tests use
`/usr/bin/pgrep` to observe its direct workerd child PIDs, require replacement PIDs,
and require every old PID to be absent. The existing five-second HTTP deadline
and owned-process-group shutdown bounds apply to a stalled restart too. This is
orderly Miniflare teardown/recreation; Miniflare internally sends SIGKILL to
workerd. It does not exercise unexpected in-flight death, a partial cross-Durable
Object commit, or machine power loss.

Both Python crash boundaries after cloud admission are repeated with workerd
replacement. The real Mailbox/coordinator readback preserves the exact attempt,
permit ID, delivery/slot state and single shared-budget charge. A fresh Python
process recovers exact stored admission history or preserves its uncertain
intent, sends no further claim, and creates no native adapter. A separate case
confirms a current consumer can still claim after replacement. Fixed fixture
state rotations increment either the coordinator runtime's attachment generation
or the Mailbox route generation before replacement; both stale deliveries are
refused through the real authenticated claim path without a permit or budget
charge. These are fixture SQL rotations, not production consumer-transfer APIs
or owner-client authority evidence.

The 335-input manifest retains all 334 Cloud/dependency hashes from cloud
`99655360630ca0e3f222d1e73d841aaf456378a7` and upstream
`949ee3cfa79121919cb8dced13971c6bec857df0`. Only the fixture worker input changes
for the fixed consumer rotation. Its new SHA-256 is
`1ae28f422e20805539fd4898ee84777a8770056cd82481f7c0ad7937cbacabbe`; the pinned
compiled bundle is `dee843b7d11d1a9b88dbd361c0aa20ac26737b1ef6cb6b84256d4f06112d7d6b`.
A build-only scratch copy computed these hashes before worker execution; normal
fixtures still verify the exact input closure and compiled bytes before startup.

Scratch mutations remove the actual restart or its persistence path. The first
fails the PID replacement assertion; the second fails authoritative readback
because retained coordinator tables are absent. Neither mutation changes source
pins or production files. The ordinary three-barrier tests remain intact.

This proves local Python process-crash recovery and orderly Miniflare replacement
at admission boundaries. It does not qualify deployed transport,
provider/native execution, settlement, ACKs or unattended wake. Cloud approval,
keys, routing and native binding remain synthetic seeded prior state. No production
activation, runtime changes, dependency installation or CI wiring is included.
