# Softnet startup controller (not installed or qualified)

`scripts/qualify_softnet_macos_vm.py` is a separate, opt-in startup/shutdown
canary. It owns the root recovery journal and starts the pinned Softnet helper
directly. All Tart commands run as the admitted nonroot account, with that
account's primary group, no supplementary groups, a private Tart HOME and a
fixed environment. There is no SUID setup, Softnet self-escalation, general
command option, dependency download, workspace build, VM deletion or promotion.
The existing NIC-drop canary and its network behavior stay unchanged.

The fixed canary starts one previously prepared disposable VM, runs only
`/usr/bin/true` through its guest agent, observes the typed Softnet preference
target, then stops both children and restores preferences. It connects Tart's
`--net-fd` attachment to an independently supervised Softnet process. Softnet gets
only `--block=0.0.0.0/0`, the exact VM MAC and privilege-drop account; no allow,
exposed port, control socket or caller-supplied helper arguments are accepted.
This permits Softnet's ARP/DHCP bootstrap, not general IPv4 traffic. The
[pinned frame parser](https://github.com/openai/softnet/blob/28bb29df4aa5935cc2899712f8d0feb08fda4e83/lib/proxy/vm.rs)
rejects other Ethernet types, including IPv6. This source inspection is not a
live network-policy qualification. Public-download preparation remains separate.

## Admission

The command takes only `--admission-dir`. That existing directory and the fixed
`/private/var/db/knitli-event-qualification/softnet-runs` state directory must be root-owned
`0700`, outside Tart storage, with protected ancestry and no mutating ACLs.
All admissions share this fixed state directory, so a different admission path
cannot bypass an unresolved run. `admission.plist` is an immutable,
root-owned `0600`, single-link regular file containing exactly:

```text
kind: softnet-startup-admission-v1
ownerUid: <nonroot local account UID>
tartHome: <absolute private Tart home owned by that account>
vmName: softnet-canary-<32 lowercase hex digits>
macAddress: <exact lowercase unicast VM MAC>
measurement:
  configSha256, configBytes
  diskSha256, diskBytes
  nvramSha256, nvramBytes
```

The measurement covers the selected clone's complete `config.json`, `disk.img`
and `nvram.bin`. Saved-memory state is refused. Configuration must identify
macOS/arm64 and the admitted MAC. The VM must already be stopped. This admission
is a local operator record, not independent OCI provenance or evidence of a
credential-free guest. Its prepared guest and admitted local account must remain
quiescent; this does not contain a hostile host owner or concurrent Tart user.

Executable paths are fixed, root-owned and mode `0555`, with protected ancestry:

- `/usr/local/libexec/knitli-event-qualification/tart-2.41.1/tart.app/Contents/MacOS/tart`
  with SHA-256 `6d3a455456979c138387d0660af8e956a054018f7516bd0e8bcd175382973823`.
- `/usr/local/libexec/knitli-event-qualification/softnet-0.22.1/softnet`
  with SHA-256 `1584af036b6d6d11319b2a3766d1be212534c525e3805bc566180aec7a1b2a0e`.

The controller refuses Python older than 3.13 or a missing non-reaping `waitid`
before opening run state or preferences. This Mac's Apple Python 3.9.6 has no
`os.waitid`; it cannot run this controller.

Any eventual privileged installation must also protect the Python 3.13+ interpreter,
controller, imported modules and parent directories. Running a user-writable
checkout as root is not a supported installation. This change does not install
anything, create root directories, or grant sudo access.

## Recovery and interruption

One permanent `controller.lock` is held nonblockingly for admission, launch,
shutdown, restoration and publication. Every retained run is checked before a
new run can begin. A new random run directory binds the exact admission digest,
VM identity and pinned executable hashes before preference capture. A failed or
interrupted run remains a gate against another run. Unknown/malformed records,
symlinks, snapshot changes and a standalone `restored` marker cannot clear it.

Both children have independent owned sessions/process groups. The supervisor
uses non-reaping `waitid(...WNOWAIT)` and retains each leader PID while signaling
its group and checking a bounded process-table snapshot. Only a group containing
its expected leader and no live members can proceed to log-drainer completion
and `wait()` reaping. An unsuccessful or ambiguous probe retains the journal.
The fixed pinned programs must not escape their sessions; this is not general
containment for arbitrary processes. Logs are drained continuously and capped
at 64 KiB per stream.

Cleanup always fetches the exact VM's stopped state again, including when launch
failed early. Restoration requires both children reaped, `Running: false` and
`State: stopped`, and no cleanup/log errors. The immutable controller completion
record binds the run identity, snapshot, restoration marker and stop evidence.
A startup error is still reported as failure even when cleanup restored the
preferences; it leaves an unresolved run for explicit reconciliation. Journals,
logs and the disposable VM are retained. No automatic stale-PID recovery, journal
pruning or boot-time recovery is implemented.

## Live gates

Tests use fake preferences and executables, plus an ordinary owned Python child
for process cleanup. They do not open host SCPreferences or run Tart/Softnet.
Before host installation or invocation, qualify the real SCPreferences
commit/apply/readback and error paths in a disposable macOS environment and
review the concrete installation and recovery procedure with the owner.
Apply acceptance is asynchronous; neither startup success nor a readback proves
effective daemon completion. Full Rust qualification, native pair promotion,
attach, and automatic turns remain held.
