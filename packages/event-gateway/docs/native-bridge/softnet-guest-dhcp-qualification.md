# Guest Softnet DHCP behavior qualification

The opt-in `--softnet-dhcp-binary /absolute/private/path/softnet` argument on
`qualify_offline_macos_vm.py` extends the fixed NIC-drop canary with one DHCP
experiment inside its disposable macOS 15 arm64 clone. The default canary does
not load or stage this probe. The existing platform and network checks must pass
first; `--scpreferences-api` can also run before this experiment.

The host accepts only a private, owner-held regular helper file, at most 64 MiB,
matching Softnet 0.22.1's fixed binary digest:

```text
release commit: 28bb29df4aa5935cc2899712f8d0feb08fda4e83
archive SHA256: 1093be6f77b0c7a75b31cf651ff46844a81d73568184e807494f555280684644
binary SHA256:  1584af036b6d6d11319b2a3766d1be212534c525e3805bc566180aec7a1b2a0e
binary bytes:   14158248
```

Keep the host copy nonexecutable (mode 0600). The arm64 slice has a valid linker
signature; this is not a Developer ID or notarization claim. The reviewed hash is
the payload pin. The fixed root guest loader receives bytes over Tart's stdin,
checks the digest before making its private guest copy executable, and verifies
four bounded, hashed source modules. No guest external download is needed.

The guest starts only that helper with a fixed unicast MAC, a Unix datagram
socket, explicit admin/staff privilege drop, and `--block=0.0.0.0/0`. It waits for
fresh typed readback of the helper's fixed bootpd preferences. Two bounded
DISCOVER/OFFER/REQUEST/ACK exchanges hold the MAC constant and change option 61.
Passing requires 600-second OFFER and ACK leases and the same address for both
client IDs. The full validated guest report, including exact capped frames and
helper logs, is retained in `softnet-dhcp-stdout.bin`; the main manifest binds
that file by byte count and SHA-256 in `rawEvidence`. It carries a bounded
`reportSummary` with scalar exchange results and frame/log byte counts and
hashes, avoiding a second embedded copy of the base64 payloads. Source and
binary hashes remain in the manifest. The host validates the report against the
raw frames. Failure and cleanup failure remain failures.

This is a compatibility experiment: vmnet Shared mode may be unavailable inside
the guest. A startup failure does not establish a DHCP defect. Matching behavior
also does not uniquely prove which preference store the daemon consumed; defaults
or lease state can yield the same result.

The host continues draining and discarding every external guest NIC frame. It
stops and disposes of only its owned clone after the experiment. Preference
restoration is qualified separately by the guest API probe; this experiment does
not add another recovery controller for a VM that will be discarded. The guest
helper is signaled before its leader is reaped, but this does not qualify the
host controller's descendant supervision.

This does not install a host helper, open host preference APIs, promote a native
pair, attach a runtime, enable automatic turns, or qualify the Rust workspace.
A passing DHCP report always retains `fullNativeQualified: false`.

References: [pinned Softnet release](https://github.com/openai/softnet/releases/tag/0.22.1),
[DHCP identity checks](https://github.com/openai/softnet/blob/28bb29df4aa5935cc2899712f8d0feb08fda4e83/lib/proxy/vm.rs),
[DHCP snooping](https://github.com/openai/softnet/blob/28bb29df4aa5935cc2899712f8d0feb08fda4e83/lib/dhcp_snooper.rs),
[DHCP](https://www.rfc-editor.org/rfc/rfc2131), and
[BOOTP minimum packet size](https://www.rfc-editor.org/rfc/rfc1542#section-2.1).
