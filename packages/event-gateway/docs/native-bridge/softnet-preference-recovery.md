# Softnet preference recovery (preparation only)

Softnet 0.22.1 overwrites the complete `bootpd` value in
`com.apple.InternetSharing.default.plist` with a dictionary containing
`DHCPLeaseTimeSecs` (CFNumber, 600) and `dhcp_ignore_client_identifier`
(CFBoolean, true). It commits and applies the change without restoring it.
See the [pinned source](https://github.com/openai/softnet/blob/28bb29df4aa5935cc2899712f8d0feb08fda4e83/src/main.rs).

`scripts/softnet_preferences.py` accesses only this fixed preference/key through
Apple's SCPreferences API. It holds a non-waiting preferences lock and preserves
the complete original value as a binary CoreFoundation property list, including
its types, nested contents, or absence. Comparisons check nested CF type identity
before equality because CFEqual alone can treat a boolean as an equal number,
or an integer as an equal real. Binary plist serialization normalizes integer
storage widths; comparisons distinguish plist node types, not integer widths. It never reads/writes the preference
file directly. `scripts/softnet_recovery.py` provides `capture` and `restore` for
the separate [startup controller](softnet-startup-controller.md). Neither module offers a privileged CLI or starts
Softnet, Tart, or a VM; existing canary behavior is unchanged.

## Journal and failure contract

The controller must supply a fresh root-owned `0700` directory outside the
VM's disposable storage. Its ancestry is opened without following symlinks,
validated for ownership, permissions and mutating macOS ACLs; root-owned sticky
temporary parents are allowed. Records are root-owned `0600` single-link regular
files with bounded reads. An exclusive advisory lock on the permanent `reserved`
file excludes cooperating capture/recovery processes.

| Record | Meaning |
| --- | --- |
| `reserved` only | Capture failed/interrupted; no permission to launch. |
| `snapshot.plist` | Original presence/value and fixed target were atomically published and fsynced before helper launch may be considered. |
| `restored` | Preference restoration committed and read back; apply request accepted. Retain both records for audit. |

Records are published with atomic no-replace rename (macOS `renameatx_np`
with `RENAME_EXCL`; Linux fixture tests use `renameat2` with `RENAME_NOREPLACE`).
Missing APIs or unsupported filesystems fail closed. This preserves the
single-link invariant even if the process dies immediately after publication.
A failed attempt consumes its directory. The controller must never infer launch readiness from directory
or snapshot existence alone: `capture` must return successfully, and all other
controller gates must pass. Journals are not deleted automatically.

`restore` opens a fresh locked preference session. If the current value equals
the saved original, it commits/applies again to recover a previous interrupted
or failed application. If it equals the known Softnet target, it restores the
complete original value (or removes only `bootpd` if originally absent), commits,
applies, synchronizes, and verifies the value before publishing `restored`.
Any other value causes refusal without a preference write; preserve the journal
for owner reconciliation. A completed journal refuses a later changed value,
including another Softnet target, so it cannot roll back a subsequent run.

False API results, snapshot/publication errors, lock contention, and failed
readback are failures, not evidence that the host is unchanged. A commit may
have succeeded even if apply failed; retry with the same unfinished journal
and a fresh session after proving the helper stopped.
[Apple's apply implementation](https://github.com/apple-oss-distributions/configd/blob/585b7f2fca293f4642d21d15c5daf187f63c4796/SystemConfiguration.fproj/SCPApply.c#L634-L640)
posts the apply notification even without a staged Set/Remove, matching the
[API contract](https://developer.apple.com/documentation/systemconfiguration/scpreferencesapplychanges%28_%3A%29). Never discard the snapshot
on these paths. SCPreferences and the journal are separate persistence systems;
there is no atomic transaction between them. Apply success accepts a notification
request; it does not prove synchronous completion by the configuration daemon.
The marker records preference readback and an accepted apply request; effective
runtime configuration still requires disposable-environment qualification.

## Remaining gates

This code is preparation, not live qualification or authorization for host setup.
Unit tests use fake preference sessions; macOS tests exercise real CoreFoundation
serialization only, without opening SCPreferences. No system preferences are
changed by those tests. The startup controller now binds each run, gates unresolved journals and owns
helper/VM cleanup. Its live gates remain:

1. Qualify the real commit/apply/error paths and effective runtime configuration
   in a disposable macOS environment,
   then obtain authorization for concrete protected controller/helper installation and its exact invocation.
2. Validate the fixed helper arguments and non-TTY Tart invocation on the
   actual host; preserve the existing offline canary separately.

The conditional check cannot distinguish a separate actor writing the identical
value. Softnet itself can overwrite a change made after capture; recovery cannot
reconstruct that lost intervening value. Host Internet Sharing configuration must
remain quiescent throughout the controlled run. Physical power-loss durability
and boot-time automatic recovery have not been qualified; a surviving journal
must block further preparation until recovery is explicitly reconciled.

Apple references: [SCPreferences](https://developer.apple.com/documentation/systemconfiguration/scpreferences-ft8),
[locking](https://developer.apple.com/documentation/systemconfiguration/scpreferenceslock(_:_:)),
[commit](https://developer.apple.com/documentation/systemconfiguration/scpreferencescommitchanges(_:)),
and [CFEqual](https://developer.apple.com/documentation/corefoundation/cfequal(_:_:)).
