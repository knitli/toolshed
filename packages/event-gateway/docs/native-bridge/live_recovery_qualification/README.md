# Native live recovery orchestration fixture — NOT_READY

This is a private, offline qualification slice. It has no network, credential loader, publisher, native process owner, automatic dispatcher, daemon restart supervisor or production configuration hook. Passing these tests grants no live execution authority.

The phase journal records the seven-case order `A1, B1, C1, C2, C3, B2, A2`, one durable publication intent per case (including an unresolved or ambiguous attempt), four native Start *attempts*, a separate maximum of four accepted Start outcomes, and three one-use restart tokens. Unknown or ambiguous Starts consume their attempt. There is no refund, cap increase or generic release operation. The journal also retains exact submitted/observed ACK request hashes and correlation IDs, the accepted response witness, replay identity and process-generation-aware reattach facts. C3's binding and event hash are latched from the reattach record; C2's old event and binding remain immutable.

The native Core-busy gate is intentionally closed. `nativeBusySignal` must remain null: a caller-provided boolean, source name or hash cannot qualify the native bridge. Consequently C2 cannot begin, be queued, or authorize R3 in this slice, and the seven-case matrix is not ready. The fixture also reports missing production Store readback, owned OS restart supervision, fresh deployed provenance and live approval as blockers. Reattach validation permits either native counter to stay the same, requires neither to decrease, requires at least one to advance, and requires the Cloud runtime and attachment generations to equal the observed CAS successor. This is fixture validation of supplied readback fields, not a live Cloud readback.

## Production seams and integration coverage

The production path is `Gateway._ack_native` → `Store.persist_native_ack` → `CloudClient.acknowledge` → `CloudClient._post` → its injected `send` port. The accepted response returns through `Store.complete_native_ack`. On recovery, `Gateway.reconcile` loads the same immutable ACK from Store and calls the same client path again. `client_runtime` supplies the installed `_send_https` transport to the production CloudClient; this fixture does not patch an installed client or daemon.

`tests/test_live_recovery_qualification.py` adds one integration test using the checked-in production `Gateway`, `Store`, `CloudClient` and `NativeBridgeAdapter`. The Cloud authority and native bridge are local fakes. The injected Cloud send verifies the NodeProof signature and transport bounds. The test independently reads SQLite through a second connection before each ACK send, confirms the committed immutable ACK and native receipt, lets the fake authority return a valid success, then holds that reply. It closes and reopens SQLite, calls the real `Gateway.reconcile`, and proves the same ACK body is retried with a new NodeProof and credentials. It does this for submitted and observed ACKs.

That test simulates a Store reopen only. It does not run `daemon.serve`, `client_runtime._send_https`, an OS-owned process kill/reap/restart, Cloudflare, a native Core busy signal, or live Cloud admission. The older transport tests use injected callbacks too. Neither test group qualifies the complete live harness.

## Tests

Run from `packages/event-gateway`:

```sh
uv run --frozen python -m unittest discover -s tests -p test_live_recovery_qualification.py -v
```

The ordinary `event-gateway` workflow discovers this file as part of its full suite. The current local test environment may require its pinned dependency cache to be available; the phase-only tests use Python's standard library.
