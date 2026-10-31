# One-Mac device-profile proxy trial

This is an operator-only, fixed-canary qualification seam. It is not native admission or a deployment recommendation. Automatic turns stay disabled.

## Why a separate controller is needed

The owner Mac's enrolled WARP client rejected `warp-cli mode proxy` with `Invalid setting for this account type.` Both guarded live attempts independently verified healthy original `warp+doh` state and completed restorer shutdown. `allow_mode_switch=true` and the CLI help listing `proxy` did not prove that the enrolled account permits local mode mutation. Do not retry that mutation as root or bypass the refusal.

Cloudflare's supported Local proxy setup uses a device profile with `service_mode_v2: {mode: "proxy", port: 40000}` and MASQUE. A new disabled profile copies the existing Mac profile's writable settings, changing only its canary name/description, exact owner email + Mac + OS-version matcher, precedence, and service mode. The original default, Mac, BYOD, and Mesh profiles remain outside this controller's authority. Before activation, enumerate registrations and confirm the matcher selects only the reviewed Mac; repeat the check immediately before enabling it.

The fixture `scripts/fixtures/device-profile-rollback.mjs` pins one account, the new canary profile ID, its name, and its exact match expression. It has a scheduled handler and no HTTP handler. Deploy it without public routes, workers.dev, previews, Logpush, or application logs, with only its dedicated `STATUS` KV binding. It never accepts commands, URLs, profile IDs, or token values from requests.

## Credential and lease limits

`CF_TOKEN` is a Worker secret, never a source/config value or operator stdout. Its minimum API permission is **Zero Trust Write on the one account**; Cloudflare's token resource model does not scope that permission to an individual device profile. The code restricts network calls to the fixed canary profile. Do not describe the credential itself as profile-scoped.

Create and inject that child token inside one trusted control-plane execution, returning only its ID and expiry. The token must expire no more than 20 minutes after issuance. The non-secret `LEASE_SPEC` binding is JSON with exactly `issuedAtMs`, `rollbackAtMs`, and `tokenExpiresAtMs`. Its cleanup deadline is at most 12 minutes after issuance and at least two minutes before token expiry. Missing or malformed bindings cannot produce an armed receipt. Token expiration does not disable the device profile.

The connected OAuth session can manage profiles but currently cannot call account-token management: `Account API Tokens Write` was not granted. User-token management also rejects OAuth. Do not activate this trial while token injection is unavailable. An owner authentication/grant or an equivalently narrow supported credential route is required; do not print or request the secret in chat.

## Admission and proof order

1. Create/read back the canary profile **disabled**; preserve the original profile snapshot and exact request/readback hashes. No client-mode change is part of staging.
2. Deploy the source-pinned rollback fixture unarmed, with no token or lease, and a new dedicated KV namespace. Configure a once-per-minute Cron schedule. Observe a fresh actual scheduled `unarmed` receipt through KV before arming; require `latest` to match its corresponding `observations/<scheduledAtMs>` value byte-for-byte. The observation is written first and `latest` last as the commit marker; an isolated observation is not a complete scheduled proof. Schedule configuration alone is insufficient. Allow for Cron propagation, which can take several minutes.
3. Before activation, qualify the cleanup path against the still-disabled profile using a valid short lease whose deadline has elapsed. Require an actual scheduled `disabled` receipt and independent API `enabled:false` readback. This proves the fixed endpoint/schema/credential path without a mode change. Revoke that qualification token before issuing the actual-trial token.
4. Issue/inject the actual-trial token and fresh bounded lease. Observe a fresh `armed` scheduled receipt matching the pinned profile and the exact lease deadline. Bind the deployed source/settings and receipt to the admission record, and repeat the unique-device/profile drift checks. Only then enable the canary.
5. Poll bounded readbacks for the exact active profile ID, healthy proxy mode, MASQUE and the fixed root-owned local listener. Then make one guarded Event runtime-status request over the explicitly configured localhost transport. Require the existing authenticated `409 native_binding_unqualified` response. It proves transport authentication, not node-proof validation or native admission; do not enable automatic turns.
6. Disable the canary immediately after the observation, even on failure. Independently, at/after its deadline the Cron handler GETs only the pinned profile, checks its saved ID and boolean enabled state, PATCHes only `{enabled:false}` if necessary, and verifies the same ID and `enabled:false` with a separate GET. Mutable name, match, or service settings never veto disabling this owned temporary ID; those fields are admission checks, not cleanup authority. API, timeout, response-size, or malformed-identity failures never establish successful cleanup. Later Cron invocations retry cleanup; no retry re-enables anything.
7. Require independent API-disabled readback, the client's original profile/mode and healthy status, unchanged enrollment config/key, and complete child cleanup. Preserve failed/partial records. Then revoke the child token, remove its secret, stop the schedule, and delete only the temporary Worker, its KV namespace and the disabled canary profile. Verify absence; retain the original profile snapshot and immutable local evidence.

Cron execution and device-policy propagation are best effort. The cleanup deadline triggers rollback attempts; it is not a guarantee that the client has restored by that instant. If a fresh receipt or independent API/client readback is missing, the run is unqualified and requires recovery rather than another activation.

## Boundaries and validation

API requests use one fixed HTTPS URL, reject redirects, have five-second abort deadlines, and stream responses under a 16 KiB cap. Receipts contain only fixed identifiers, times, statuses, counts, and safe error codes; no credentials, raw errors, policy contents, or request bodies. KV records are observations, not an admission authority or an append-only audit log. Preserve separately fetched local evidence with hashes.

Fixture tests run in Linux and macOS CI. They must detect early cleanup, wrong target/schema, missing post-PATCH readback, unbounded response bodies, auth/transport failures, and token disclosure. Test causal checks use scratch copies, preserve the actual source, and verify red assertions followed by green restored source.

This host-only profile trial does not start a VM. The later guest route test requires a reviewed combined lifecycle that stops/reaps guest networking before restoring host full-tunnel mode. The older local CLI restorer cannot provide that control for this account, and its 45-second trigger cannot simply be stretched around a VM readiness phase that may consume 60 seconds.

## Primary references

- [Cloudflare client modes](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/modes/#set-up-local-proxy-mode)
- [Device profiles and selectors](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/device-profiles/)
- [Cron triggers](https://developers.cloudflare.com/workers/configuration/cron-triggers/)
- [Workers KV writes](https://developers.cloudflare.com/kv/api/write-key-value-pairs/)
