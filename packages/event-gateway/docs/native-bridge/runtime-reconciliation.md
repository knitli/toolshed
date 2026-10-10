# Retained native commit reconciliation

Use this when an attach or renew has retained `.native-pending` evidence and its
original launcher or receipt window can no longer support exact replay. Preserve
that file. Its historical outcome remains unknown even after a successor attaches.
Transfer reconciliation is unsupported and fails closed without changing evidence.

This requires a deployment containing the runtime-status API from cloud PR #723.
An older deployment returning an unavailable route is an error, never `missing`.

Read stored cloud authority without a live TUI:

```sh
knitli-event-gateway --state-dir "$state" runtime-status \
  --cloud-config "$state/cloud.json" --runtime-id "$runtime"
```

The authenticated HTTPS response to a signed request distinguishes `missing` from
`present`, with `observedAt`.
A present record includes stored generations, node identity, lease, qualification,
and optional native binding. This does not establish live presence, lease validity,
or current dispatch eligibility. Denial, transport failure, and invalid responses
are errors; they never become `missing`.

Launch a fresh qualified native client, obtain its different session ID, then run:

```sh
knitli-event-gateway --state-dir "$state" reconcile \
  --operation attach --original-session-id "$original_session" \
  --session-id "$successor_session" --cloud-config "$state/cloud.json"
```

Use `--operation renew` when the retained original operation was a renewal.
The original evidence supplies the runtime ID and cloud identity. The first
reconciliation reads authoritative generations and creates an immutable private
`.reconcile.json` link beside the original artifact before any successor lifecycle
request. The link pins the original file's exact SHA-256, identity, current public
key, runtime, successor session, observed authority, and successor attach intent.
Only an explicit `missing` response supplies null CAS generations. A replaced or
unauthorized node key is rejected by the signed status request. A successor session
reserved by any other retained reconciliation link cannot be reused.

An ambiguous authority-read failure returns `reconciled: null` with its concrete
error reason (such as `request_timeout` or `unavailable`); a definite failure returns
`reconciled: false`. The status read is safe to retry: no successor commit has
started, and `originalHistoricalOutcome` remains `unknown`.

The successor performs the normal challenged attach to that same runtime. Its own
pending artifact is durable before the commit is sent; local persistence uses the
existing daemon writer. After the validated cloud result is stored, the command
reads the mapping back through that writer and requires an exact match. A direct
Store read is used only when the daemon socket is absent or its listener is
definitely gone; a timeout or unknown failure does not open a second writer.

Before clearing the successor's pending attach, the command writes an immutable
private `.reconcile.completed.json` record. It binds the original link's exact
SHA-256, successor session, cloud identity, node public key, actual validated cloud
result and matching mapping readback. Its generations come from that result.
The record and containing directory are synced under the pending-directory lock.
Readback or sync failure retains pending evidence and reports local unavailability;
an identical retry re-syncs an existing completion record before pending cleanup.
The original pending artifact and `.reconcile.json` reservation remain unchanged.

After completion, use ordinary `renew` with the completed runtime's returned CAS
generations and the same successor session. Renewal must match the completion
record's cloud identity, node key, runtime, native binding and generations, and the
current writer mapping must match every recorded field except `leaseExpiresAt`.
That exception allows subsequent lease extensions; it does not permit a different
binding, session or runtime. The permanent reservation still blocks another
original's reconciliation, unrelated attach intent and transfer from reusing this
successor. Completion does not establish the original attempt's historical outcome.

No model input or automatic turns are enabled by this command. A concurrent
authority change produces a conflict rather than guessed replacement generations.

Retry the exact reconciliation command. A saved link reuses its original intent
and generations; an existing successor pending commit uses normal exact replay.
Changed identity, key, session, or binding is refused. A closed successor receipt
window remains unknown. Once completion is recorded and the successor's pending
attach is cleared, repeating `reconcile` still uses the original attach intent; it
may conflict rather than return the earlier success. Use ordinary renewal to
extend the completed attachment's lease. Inspect the reported result and stored
status; do not delete evidence or rewrite either record to force a new attempt.
A new recovery decision requires a separately reviewed fresh successor, not silent
rebasing of this retained intent.

The completion tests cover mapping-readback and injected file/directory-sync
failures with retained-evidence retries. They do not prove recovery after an
operating-system crash or physical power loss.
