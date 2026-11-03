# Protected provisioning downloads

The Softnet controller's `--provisioning-downloads` mode runs only the fixed
provisioning downloader in a measured macOS 15 ARM64 guest. It acquires the
120 files in `native-workspace-provisioning-assets.json` as data. It does not
extract them, install tools, fetch Cargo dependencies, compile, or qualify a
native runtime. Both `prepared` and `qualified` remain false.

## Admission

The existing protected `admission.plist` uses kind
`softnet-provisioning-download-admission-v1`, retaining the owner, Tart home,
fresh VM identity, and complete pre-run disk/config/NVRAM measurement. It adds:

- `provisioningManifest`: the exact pinned manifest bytes.
- `provisioningBundleSha256`: the digest of the complete stdin bundle.
- `provisioningCaSha256`: the reviewed public CA file digest.
- `provisioningDnsMap`: all admitted IPv4 answers for the five manifest-derived hosts.
- `provisioningDeniedIPv4`: the known account destination addresses.
- `provisioningInventorySha256` and `provisioningInventory`: the digest and raw
  bytes of the trusted operator's destination inventory snapshot.

The snapshot has exact fields `kind`, `accountId`, `observedAtUnixNs`,
`deniedIPv4`, `accountReadbackSha256`, and `originReadbackSha256`. Its kind is
`native-provisioning-destination-inventory-v1`; its account is the fixed Knitli
account. The denied list must agree with the admission, and the observation must
be at most 20 minutes old and not in the future when the controller admits it.
The two source hashes identify the retained account and DNS/origin readbacks.
The reviewed operator must collect those readbacks; a digest alone does not
establish that an external account inventory is complete. No account API token
or owner identity is sent to the guest.

The CA pin identifies the reviewed public trust file containing 128 roots,
without the known Gateway CA. Each candidate address must be globally routable,
outside the published Cloudflare IPv4 front-door ranges and the known account
destination list. After validating the bundle and clone, the owner resolves each
of the five manifest-derived hosts once with IPv4 and IPv6 enabled, validates
the complete answer set (at most 32 resolver records and 1–8 unique safe IPv4
addresses per host), and publishes the numerically sorted IPv4 snapshot in both
the admission and rebuilt bundle. IPv6 answers are observed but never admitted. The controller
consumes that frozen protected admission without resolving DNS again.

The protected admission directory also contains `provisioning-bundle.json`.
The controller opens it without following symlinks, validates its complete
digest, exact source and manifest pins, CA bytes, and DNS binding, then retains
that read-only descriptor through child cleanup. These checks precede run
reservation and host preference changes.

## Guest action and recovery

Only each hostname's first admitted IPv4 answer is allowed by Softnet, matching
the downloader's fixed selection. All other IPv4 destinations are blocked;
Softnet drops IPv6 frames. This is an IP boundary for this trusted client, not
a general hostname-aware policy for arbitrary guest programs.

The fixed Tart command drops to guest `admin:staff`, clears its environment,
and invokes the guest Homebrew Python with `-I -B`. Its bounded stdin contains
only the reviewed downloader source, manifest, public CA bytes, and address
map. The receiver checks the guest runtime before reading input or writing
files, creates a fresh private directory, and executes only the pinned
downloader source. Downloaded assets remain unopened data files. The existing
owned-process supervision cancels the guest command if its VM, helper, or log
drainer fails; its outer command limit is 1,830 seconds.

The controller validates the complete bounded 120-asset receipt before
publishing `provisioning-download.json`. The run journal binds that receipt to
the original manifest, bundle, CA, and address map. Completion requires its
digest, proven VM/helper stop and reap, and original preference restoration.
Missing or invalid receipts leave an incomplete run subject to the existing
retained-failure recovery gate. A download failure still runs the existing
stop/reap/conditional-restoration sequence.

A terminal provisioning failure retains `command-failure.plist` with its fixed
phase, stable error code, exit status when available, and at most 4 KiB from
each command output stream. It records no command arguments or environment.
Readiness retries that later succeed produce no failure record. The record is
root-owned, validated and included in failed-run disposition hashes; a run
containing it cannot become complete. Diagnostic write failure still runs
cleanup and leaves the run failed.

Failed-run disposition binds the provisioning manifest, bundle, CA and frozen
DNS map to the retained admission. Its read-only observer may validate an
expired destination inventory while checking current VM, process and original
preference state. Future timestamps and all static policy and digest failures
still fail validation. New provisioning and DNS snapshots continue to require
an inventory no more than 20 minutes old; disposition permits no retry.

## Operator and later phases

This source mode does not provide a ready-to-run privileged installer or
authorize an unreviewed wrapper. Its owner package must bind the exact installed
module closure, collect fresh readbacks, clone the reviewed stopped base, publish
the protected admission and bundle, and retain bounded evidence. Preserve the
base and historical runs. After a successful data download, stop and measure
the changed clone into a separate downloaded-only receipt before any later
offline installation. A pre-run disk measurement is not the post-download
frozen artifact.

Offline tool installation, dependency staging, capacity qualification, the full
Rust suite, and native runtime admission are separate gates described in
[native workspace staging](native-workspace-staging.md). Source tests and a
completed download journal establish none of those later results.
