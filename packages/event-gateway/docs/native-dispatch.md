# Explicit native dispatch

The default `run` command serves private local control only. To qualify delivery,
provide a mode-600 dispatch configuration alongside the existing cloud config:

```json
{
  "version": 1,
  "cloudConfig": "cloud-config.json",
  "listenHost": "100.64.0.10",
  "listenPort": 8787,
  "transportKeys": {
    "event-v1": "REPLACE_WITH_CANONICAL_BASE64URL_ED25519_PUBLIC_KEY"
  }
}
```

Use the provisioned node's explicit private Mesh address and the cloud Event
transport's public verification key. The configuration accepts no wildcard bind
address or public address. The signed recipient audience is the enrolled node ID
from the cloud config. The cloud identity and credentials retain their existing
validation and refresh rules; this command creates no keys or enrollment grants.

```sh
chmod 600 /private/path/dispatch-config.json
knitli-event-gateway --state-dir /private/path/gateway-state run \
  --dispatch-config /private/path/dispatch-config.json
```

Launch and select the reviewed native client separately, then use `attach` with
its exact printed session ID. New native attachments retain that session ID and
the cloud-confirmed native binding. Old mappings without this route cannot
dispatch; explicitly reattach rather than guessing a client from a thread or PID.

The listener verifies signed bytes before durable acceptance. HTTP 202 means
accepted into the spool. It does not mean a native turn started or was observed.
The worker reconciles durable attempts and dispatches queued deliveries using
the existing cloud claims, budgets, generation fences and acknowledgments.

Only the launcher owns the native bridge. Conditional Start obtains fresh
eligibility and checks the exact binding under its lock immediately before
submitting the already-persisted request. Presence polling cannot grant Start.
An uncertain Start outcome is recovered by an exact read-only receipt lookup;
recovery never generates a replacement request or blindly repeats Start.

Stop the daemon before upgrading. Restart preserves pending claims, receipt
lookups and immutable acknowledgments. Keep the original launcher alive for
daemon-only restart recovery. A new launcher session requires explicit
reattachment. Lease renewal remains the explicit `renew` command.

Local readiness reports configuration and worker availability. It does not
prove deployed admission, Mesh reachability or live wake. Keep production scope
and source activation disabled until the reviewed release and canary evidence
pass their separate gates.
