# Guest SCPreferences API qualification

The opt-in `--scpreferences-api` flag on `qualify_offline_macos_vm.py` extends the
existing fixed NIC-drop canary. It runs only after the existing guest platform,
loopback, Unix socket, nested Seatbelt, and observed external-frame checks pass.
The default canary does not load or stage this probe.

The host bundles exactly four current scripts with SHA-256 hashes: the offline
canary, typed preferences, recovery primitive, and fixed guest API probe. A fixed
loader verifies the bounded bundle and writes the modules into a new root-only
guest directory. Tart's existing guest agent runs the loader through noninteractive
sudo and the guest's `/usr/bin/python3 -I`. No helper or host preference API runs.

Inside the disposable macOS 15 arm64 guest, the probe exercises the fixed
InternetSharing bootpd domain: capture its typed original value, write the fixed
600-second/ignore-client-identifier target, accept commit/apply, synchronize,
read from a fresh session, reject another process's nonwaiting lock request,
restore, and read the original value from another fresh session. Only
`kSCStatusPrefsBusy` (3002) counts as cross-process contention. A later successful
cleanup cannot turn a failed operation into a passing result. Reports contain
fixed status codes, booleans and source hashes; they do not export original
preference values.

The host accepts only the exact report schema, eight passing checks, matching
source hashes, `apiQualified: true` and `effectiveDaemonQualified: false`.
Source hashes and capped raw stdout/stderr are included in the existing evidence
manifest. Guest staging is removed after execution. The guest recovery journal
exists during the test; normal canary cleanup disposes of the owned clone, so its
reported path is not a retained host recovery artifact.

This proves API acceptance and typed persistence/readback only. It does not prove
InternetSharing/bootpd consumed the change, a real daemon failure path, privileged
host installation, crash reconciliation, Softnet network policy or full native
qualification. Those gates remain separate. No host installation, native pair
promotion, attach or automatic turns are enabled by merging this opt-in probe.

Apple references: [nonwaiting lock contention](https://github.com/apple-oss-distributions/configd/blob/585b7f2fca293f4642d21d15c5daf187f63c4796/SystemConfiguration.fproj/SCPLock.c#L494-L520)
and [SystemConfiguration status codes](https://github.com/apple-oss-distributions/configd/blob/585b7f2fca293f4642d21d15c5daf187f63c4796/SystemConfiguration.fproj/SystemConfiguration.h).
