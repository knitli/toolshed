# Offline macOS VM boundary canary

This runbook qualifies one narrow property: a guest can use IPv4/IPv6 loopback,
Unix-domain sockets, and nested Seatbelt while its Ethernet frames have no
forwarding path to the host network. It does not run the Rust workspace and is
not full native-suite qualification.

**Status:** controller and fake Tart tests are implemented, but the real VM
canary has not been run. No guest boundary or native workspace qualification
is claimed yet.

The controller runs a fixed guest script. It does not accept a guest command,
install Tart, pull an image, change host firewall rules, or forward packets.
The host receives Ethernet datagrams through Tart's `--net-fd` endpoint and
only drains and discards them. The test sends nonce-bound IPv4 and IPv6 UDP
frames to documentation-only addresses; both must be observed by the host.
There is no send operation or NAT fallback. A passing canary proves the
controller observed the two expected guest frames and the guest reported its
local socket and nested-sandbox checks. It does not prove the whole VM is free
from hypervisor defects.

## Pinned inputs

- Tart `2.41.1`, source commit
  `543453404cd1b15c1338b6b70e162d000c8ba5e2`.
- Signed macOS package size: `22,959,557` bytes.
- Package SHA-256:
  `e680a734febccfce7d4e910c1f7f13fc3b00f19a181c945e2d746de3214c32c2`.
- Reviewed `tart` executable SHA-256:
  `6d3a455456979c138387d0660af8e956a054018f7516bd0e8bcd175382973823`.
- Guest base image:
  `ghcr.io/cirruslabs/macos-sequoia-base@sha256:eee659985b01e4df2a6c0754bd8d25e54969933c43fdcd4edef8bea337b3d354`.
- Compressed OCI image size: `25,458,766,500` bytes. The imported VM's
  expanded disk can be much larger.

The exact Tart package and OCI digest were reviewed before this runbook was
written. Recheck the release signature, package digest/size, and OCI manifest
before acquiring them. Do not substitute a mutable `latest` tag.

## Host and base-VM preparation

An authorized host owner must do these steps outside the canary controller:

1. Confirm Apple Silicon, supported macOS/Virtualization.framework setup,
   host disk/RAM capacity, installation authorization, and Tart's required
   packaged-app/helper setup. The controller intentionally does not bootstrap
   host software or request privilege.
2. Acquire the pinned Tart package and image. Verify the package SHA-256 and
   signature, and verify the OCI manifest resolves to the pinned digest before
   import. Keep credentials out of the canary environment.
3. Prepare one local macOS 15 base VM and confirm the Tart guest agent is
   installed/configured for `tart exec`. Configure the guest so the fixed
   `/usr/bin/sudo -n` operations used by the canary succeed. Do not put
   credentials or owner data in the guest.
4. Shut the VM down cleanly. Do not save or restore guest memory state. Keep
   the base VM immutable during qualification. Confirm its local Tart storage
   contains regular `config.json`, `disk.img`, and `nvram.bin` files under
   `<TART_HOME>/vms/<base-name>/` and no `state` file.
5. Create a receipt for the prepared base. The receipt binds the actual bytes
   of those three local files (not a self-reported digest) to the pinned Tart
   package/executable. The OCI digest is an operator-declared source label in
   this receipt; the controller does not cryptographically bind the local VM
   disk back to registry bytes. Preserve a separate trusted import/acquisition
   record if provenance from the OCI manifest is required. Use this schema:

   ```json
   {
     "kind": "offline-macos-vm-base-receipt-v1",
     "baseVmName": "prepared-macos15",
     "tartVersion": "2.41.1",
     "tartPackageSha256": "e680a734febccfce7d4e910c1f7f13fc3b00f19a181c945e2d746de3214c32c2",
     "tartBinarySha256": "6d3a455456979c138387d0660af8e956a054018f7516bd0e8bcd175382973823",
     "ociBaseDigest": "ghcr.io/cirruslabs/macos-sequoia-base@sha256:eee659985b01e4df2a6c0754bd8d25e54969933c43fdcd4edef8bea337b3d354",
     "preparedSnapshot": {"sha256": "<disk.img SHA-256>", "bytes": 1},
     "storageMeasurement": {
       "configSha256": "<config.json SHA-256>", "configBytes": 1,
       "nvramSha256": "<nvram.bin SHA-256>", "nvramBytes": 1
     }
   }
   ```

   Replace `tartBinarySha256` with the verified local executable hash above,
   and replace every byte-count/digest placeholder with measurements from the
   actual files. The
   `bytes` examples above are schema examples, not valid measurements. Store
   the receipt read-only and protect it as local evidence.
6. Check free space on the filesystem containing Tart storage. The controller
   requires free bytes at least equal to the measured logical `disk.img` size
   plus 512 MiB headroom before it creates a clone. This deliberately budgets
   a full disk-sized clone and avoids relying on APFS copy-on-write behavior.
   The 150 GiB figure discussed for the later full-source/full-suite setup is
   only a planning estimate; it is not a canary admission constant.

## Run the canary

Use a private, empty evidence directory and the exact local base name. Example
command shape (run only after host-owner authorization and independent code QA):

```sh
umask 077
mkdir -m 700 /private/tmp/offline-macos-vm-evidence
export TART_HOME=/opt/coder/toolshed/.local-artifacts/offline-macos-vm-20261027/tart-home
python3 packages/event-gateway/scripts/qualify_offline_macos_vm.py \
  --base-vm prepared-macos15 \
  --receipt /private/tmp/offline-macos-vm-base-receipt.json \
  --evidence-dir /private/tmp/offline-macos-vm-evidence \
  --tart-home "$TART_HOME" \
  --tart /opt/coder/toolshed/.local-artifacts/offline-macos-vm-20261027/tooling/tart-2.41.1/tart.app/Contents/MacOS/tart
```

`--tart-home` defaults to the `TART_HOME` environment variable and then
`~/.tart`. The selected Tart home must be owned by the current user with mode
0700; its `vms` and prepared-base directories must be owned by that user and
not writable by group/other. Symlinked Tart homes, VM directories, and base
directories are rejected.

The controller hashes the installed Tart binary and the actual base files,
checks capacity, clones to a random local VM name, starts only that clone with
the inherited `--net-fd` socket, runs the fixed guest script, and attempts to
stop/reap Tart before deleting only that clone. It sets
`TART_NO_AUTO_PRUNE=1`; it never deletes the prepared base. If it cannot prove
the Tart process exited, it retains the exact owned clone and marks the
evidence `tainted` instead of deleting a potentially active VM. Cleanup
sends SIGTERM to the owned Tart process group and escalates to SIGKILL after a
bounded wait. A tainted
result is a failed canary requiring owner cleanup review.
If Tart fails during clone creation, the controller cannot prove that the
random name belongs to this invocation; it retains the partial path and marks
the result `tainted`. The manifest records the exact `cloneVmName` for owner
inspection. Do not delete that path automatically.

## Evidence and interpretation

The controller creates `offline-macos-vm-canary.json` with exclusive,
no-follow creation in the empty mode-0700 evidence directory. It records the
pins, source/storage hashes and byte counts, selected deduplicated
`hostCommandTemplates`, fixed guest script hash, bounded guest/Tart output
hashes, received frame count/bytes,
matched nonce frame hashes and their exact two raw frame files,
`hostTransmitted: 0`, guest-reported macOS build/architecture, status, and
cleanup outcome.
The command templates are not an exhaustive invocation trace: repeated
readiness calls are represented once, with their exact argv and attempt count
in `readinessProbe`.
The JSON is capped at 64 KiB and written mode 0600. Capped raw guest stdout and
stderr and Tart run stdout and stderr are also retained as four exclusive
mode-0600 files beside it; their byte counts and SHA-256 values are recorded
in the JSON. Each output stream is limited to 16 KiB for guest output and 64
KiB for Tart run output. Exceeding a cap fails the canary and terminates the
owned Tart run process. If the complete result exceeds 64 KiB, the controller
writes a bounded `tainted` fallback containing the primary error, cleanup
errors, and exact base/clone names so the result remains reviewable.

The guest reports `/usr/bin/sw_vers` ProductVersion and BuildVersion and
`platform.machine()`. The controller accepts only macOS 15.x on `arm64` and
retains the parsed runtime values plus the raw JSON. IPv6 transmission waits
until binding the fixed source address succeeds, then binds the actual UDP
probe to that same source address so DAD and source selection are explicit.
The readiness probe has its own 60-second budget; after it passes, the canary
gets a separate 90-second budget.

Only the two nonce-matched UDP frames are retained as `frame-ipv4.bin` and
`frame-ipv6.bin`, mode 0600 and capped at 2 KiB each. Their hashes are bound to
the manifest. No unrelated guest Ethernet packets are written to evidence.

- `passed`: both expected nonce frames were observed, every fixed guest check
  succeeded, and owned-VM cleanup completed.
- `failed`: a required check or command failed; inspect the stable error code
  and bounded evidence. Missing frames do not by themselves prove denial.
- `tainted`: cleanup or ownership could not be confirmed. Treat this as a
  failed qualification and do not reuse the clone.

Clone deletion is gated on both reaping the owned Tart run process and reading
the exact Tart `get --format json` stopped-state fields (`Running: false` and
`State: "stopped"`, lowercase). If either check is missing or disagrees, the controller
retains only its random-named clone and marks the result tainted.

The test makes no assertion about general Internet availability or arbitrary
protocols. It demonstrates only that the canary's two IPv4/IPv6 UDP frames
reached the host drop controller and were not forwarded by that controller.
Guest loopback and Unix sockets remain local to the guest. Tart's guest-agent
control channel is an intentional host-to-guest command channel and remains in
the trusted computing base; guest output is never converted to a host command
or a host path.

## Next qualification gate

This boundary canary does not contain the upstream Rust source, build
dependencies, workspace tests, or full-suite logs. Keep those fixtures on hold
until the canary code receives independent review, the owner approves the
prepared host/image, and the canary itself passes. A later full-suite run must
separately pin and stage source/toolchain inputs, run offline, preserve the
entire test log, report exact scope and exit status, and retain the ephemeral
VM cleanup evidence.

## References

- [Tart 2.41.1 `Run.swift`](https://github.com/openai/tart/blob/543453404cd1b15c1338b6b70e162d000c8ba5e2/Sources/tart/Commands/Run.swift)
- [Tart 2.41.1 `NetworkFD.swift`](https://github.com/openai/tart/blob/543453404cd1b15c1338b6b70e162d000c8ba5e2/Sources/tart/Network/NetworkFD.swift)
- [Tart 2.41.1 `VM.swift`](https://github.com/openai/tart/blob/543453404cd1b15c1338b6b70e162d000c8ba5e2/Sources/tart/VM.swift)
- [Tart 2.41.1 release](https://github.com/openai/tart/releases/tag/2.41.1)
- [Tart Quick Start](https://tart.run/quick-start/)
- [Tart guest agent](https://github.com/openai/tart-guest-agent)
