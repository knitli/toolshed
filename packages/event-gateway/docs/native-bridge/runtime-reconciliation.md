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

The successor performs the normal challenged attach to that same runtime. Its own
pending artifact is durable before the commit is sent; local persistence uses the
existing daemon writer. No model input or automatic turns are enabled by this
command. A concurrent authority change produces a conflict rather than guessed
replacement generations.

Retry the exact reconciliation command. A saved link reuses its original intent
and generations; an existing successor pending commit uses normal exact replay.
Changed identity, key, session, or binding is refused. A closed successor receipt
window remains unknown. A link can remain after a successful local write, so a
later retry may conflict instead of returning the earlier success. Inspect the
reported result and stored status; do not delete evidence or rewrite the link to
force a new attempt. A new recovery decision requires a separately reviewed fresh
successor, not silent rebasing of this retained intent.
