# Direct native input observation

The [disposable native checkpoint](https://github.com/knitli/toolshed/pull/45)
returns `inputRecorded` only through read-only receipt lookup after Core records
the exact user-message input. Registration remains `started`. This consumer
retains the full request and actual receipt; it does not fabricate a queue ID or
a weaker Started receipt when only InputRecorded was recovered.

```text
actual Started or InputRecorded → durable submitted DTO → confirmed submitted ACK
actual InputRecorded          → durable observed DTO  → confirmed observed ACK
lost response                 → same persisted DTO; fresh node proof
missing native evidence       → no observation, no new native start
```

The observation correlation is closed:
`{kind:"native_input_recorded",permitId,turnId,itemId}`. The item comes from the
identity-bound native receipt, not the turn ID. Both phases keep their own
immutable acknowledgedAt and body. Observation is sent only after the cloud
confirms submitted registration. Exact submitted replay after observation cannot
demote completion or reopen pending work.

Once registration is confirmed, reconciliation polls the original native request
without issuing another start or requiring a new eligibility lease. A changed
attachment, unknown receipt, missing native ledger or malformed outcome cannot
authorize observation or a new claim. After retaining InputRecorded, retries of
either ACK need no further native call.

SQLite schema 4 adds nullable input-recorded receipt and observed-ACK columns.
Existing Started receipts, submitted DTOs and queue records remain intact. The
confirmed observed CAS marks the delivery observed and releases its local byte
reservation; cloud observation commits its own original slot-release intent.
Retained evidence remains until normal terminal cleanup.

Stop the daemon before changing binaries. Older schema readers refuse version 4;
restore a compatible dual-phase reader or roll forward while retaining the private
database. Disabling new work must retain both ACK parsers and replay phases.
Deleting evidence or lowering the schema version is not a rollback path.

Tests use injected authority and native peers. Canonical wire and installed-package
proof must use the separately reviewed immutable cloud contract and trusted policy.
Those checks do not establish deployed Access/Mesh routing, native restart
convergence or the owner's client. Production binding and automatic wake remain
disabled.
