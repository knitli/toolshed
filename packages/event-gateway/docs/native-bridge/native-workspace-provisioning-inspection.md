# Native workspace provisioning inspection

This read-only route starts a fresh offline clone of the stopped downloaded-only base VM, then inspects the clone's pinned provisioning files and local Homebrew state. It never boots the downloaded base in place, extracts archives, installs packages, runs downloaded programs, or qualifies the VM. A root-host attester/PIV action is not part of this probe.

The host requires the exact downloaded-only owner receipt and binds the probe bundle to its source base VM, guest root, manifest digest, and post-download measurement. The controller separately names the fresh offline clone used to run the probe. The untrusted owner receipt binds a measured source state; it does not establish original root-journal provenance. The guest accepts no caller-supplied command. Every exact asset is opened through a pinned downloads directory descriptor and hashed before archive inspection or local commands; any mismatch aborts the probe.

## Rootless invocation

Use the existing offline canary's base receipt, which records the pinned Tart executable/package and OCI source label under the schema in [offline-macos-vm.md](offline-macos-vm.md). The canary physically remeasures the stopped VM's config, disk, and NVRAM files, then binds that measurement to the downloaded-only owner receipt's `postDownloadMeasurement`. This checks the local measurement; it does not prove root-journal provenance back to the OCI image.

```sh
umask 077
mkdir -m 700 /private/tmp/native-workspace-inspection-evidence
python3 packages/event-gateway/scripts/qualify_offline_macos_vm.py \
  --base-vm "softnet-canary-<downloaded-vm-id>" \
  --receipt /private/tmp/offline-macos-vm-base-receipt.json \
  --evidence-dir /private/tmp/native-workspace-inspection-evidence \
  --tart-home /private/tmp/offline-macos-vm-tooling/tart-home \
  --tart /private/tmp/offline-macos-vm-tooling/tart-2.41.1/tart.app/Contents/MacOS/tart \
  --native-workspace-provisioning-inspection \
    /private/tmp/event-provisioning-ready/owner-result.json
```

Run this as the owner of the private Tart home and evidence directory; it uses no root/PIV step. The usual base-receipt path, ownership, permissions, and pinned-Tart conditions in [offline-macos-vm.md](offline-macos-vm.md) still apply. The canary clones the stopped downloaded VM for inspection and never boots that base in place.

Gzip and XZ tar scanning is read-only and uses a 512 MiB compressed per-asset cap, 2 GiB expanded per archive, 8 GiB expanded across the asset set, 512 MiB per member, 100,000 members, 64 KiB extension headers and a 4 MiB report. A streaming header pass rejects oversized PAX/GNU metadata before `tarfile` parses it. Homebrew metadata and Rust installer descriptors have a 64 KiB cap; the pinned Rust channel TOML has a separate 1 MiB cap. The report carries a digest of each complete archive header inventory, member and byte counts, top-level roots, relevant Homebrew receipts/formula metadata, Rust installer components and manifests, and required `opt/` link targets. Symlink targets are recorded literally and never followed. Capped or malformed archive or local state is marked incomplete; no content is extracted. This is inspection evidence only: `qualified` and `prepared` remain false.
