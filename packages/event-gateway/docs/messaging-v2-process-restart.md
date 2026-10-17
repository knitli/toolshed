# Messaging v2 admission across Python process crashes

`tests/test_messaging_process_restart.py` kills a real Python gateway child with
SIGKILL, waits for its owned process group to exit, then starts a fresh interpreter
against the same SQLite ledger. The reviewed Messaging workerd broker stays alive
across the two gateway processes. Its exact 335 input hashes and compiled bundle
checks remain unchanged.

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

This proves local Python process-crash recovery at admission boundaries. It does
not simulate machine power loss, a cloud-worker restart, deployed transport,
provider/native execution, settlement, ACKs or unattended wake. Cloud approval,
keys, routing and native binding remain synthetic seeded prior state. No production
activation, runtime changes, dependency installation or CI wiring is included.
