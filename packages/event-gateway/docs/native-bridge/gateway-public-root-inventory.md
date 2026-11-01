# Gateway public root inventory

The opt-in `--gateway-public-root-inventory` flag on
`qualify_offline_macos_vm.py` records the selected guest Python's default TLS
trust-root observations after the existing NIC-drop canary passes. This is a
read-only collection run. It does not prepare the guest, qualify the gateway
route, or change the prepared base VM.

The fixed guest collector uses `ssl.create_default_context()` with hostname
checking enabled and `CERT_REQUIRED`, with no `cafile`, `capath`, or `cadata`
arguments. It rejects `SSL_CERT_FILE` and `SSL_CERT_DIR` in its clean fixed
environment. The command has no user-selected guest command, CA path, or
network option; the collector opens no sockets and invokes no subprocesses.

`publicRoots` contains distinct DER fingerprints from
`SSLContext.get_ca_certs(binary_form=True)`. Python can leave `capath` roots
lazy-loaded until a connection is made. Since this inventory makes no
connection, the report is explicitly scoped to materialized default CA roots;
it cannot show that capath is empty or enumerate roots Python has not loaded.
An empty materialized root set is rejected. The canonical digest is SHA-256 of
the sorted unique lowercase DER SHA-256 fingerprints joined by LF, with no
trailing LF. No certificate DER bytes are retained in the report.

The report also records selected Python path/version/platform, public paths
from `ssl.get_default_verify_paths()`, hostname and verification flags, and
bounded cafile whole-file hash/stat provenance. Cafile bytes are read through
one descriptor with a 2 MiB limit and matching before/after `fstat` identity.
The platform cafile path may be a symlink, as permitted by the TLS loader; the
inventory follows it and records the opened regular target's hash and metadata.
This provenance does not establish that the file was the context's trust source;
the separately validated materialized context roots provide that observation.
The guest output and each captured stream are capped at 64 KiB; stderr must be
empty. The shared report validator reserves 257 bytes within that cap for the
fixed transport envelope, including when the standalone collector uses it. The controller preserves both raw captures in `rawEvidence` and binds
the probe source and compressed bundle hashes in the separate
`gatewayPublicRootInventory` metadata.

The report records the interpreter it observed; this collection does not
qualify an interpreter version. The live caller must separately verify the
selected guest image runs Python 3.9.6 and bind the observed executable path to
the exact base-image receipt. The inventory result alone cannot establish
either condition.

Use a private, empty evidence directory and the exact local base name described
in [the offline VM guide](offline-macos-vm.md). Add the opt-in flag to that
guide's fixed controller invocation:

```sh
--gateway-public-root-inventory
```

The result is inventory evidence only. Root fingerprints require review against
the exact guest image before any future route-admission decision; this report
alone is not that review or admission proof.
