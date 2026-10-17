# Dormant reviewer HTTPS adapter prototype

Dependency: artifact-transport PR #158 at `cc714cc45fbc8bb2be80ff0d98f9980c485cf8a5`.
This directory is an unactivated prototype. No CLI, credential discovery, host
admission, contract/pin changes elsewhere, listener, or production integration.
The existing transport's download-host set remains empty. Every non-API origin
is refused, including an artifact URL carrying an Authorization header.

`request = adapter.bind(trusted_physical_node_path)` creates the transport's
four-argument `request(url, headers, maximum, deadline)` seam using a fixed Node
child. The trusted caller supplies an absolute physical runtime path; relative
paths, symlinks and mismatched runtime bytes fail closed. No PATH/environment
discovery or machine-specific publication path is used. The immutable Node hash
remains enforced on every call; portability across locations does not qualify a
different runtime build. The caller supplies the existing
`transport` module on Python's trusted import path; the adapter imports that
module's exact `Response` class, as required by the transport's nominal check.
The composed offline test exercises bound request and the real transport call,
using an inert fixture runtime with its test digest and faking child execution.
A full bundle cannot succeed with the deliberately
empty download-host policy.
The caller supplies the existing
absolute monotonic deadline. A one-second cleanup reserve is subtracted from
that deadline; it is never added to the transaction. A deadline with less than
that reserve fails before spawning. Pin reads, spawn, I/O, exit, cleanup and
decoding are checked against that deadline. OS scheduling, process creation,
filesystem calls and SIGKILL delivery cannot promise hard real-time completion;
late completion fails and a failed bounded reap is an explicit cleanup failure.
When cleanup also fails after a primary refusal, the primary fixed code is
retained with the fixed `https_cleanup_failed` exception note.

The selector supervisor bounds stdin to 16 KiB, response metadata to 32 KiB,
body to the caller's ceiling (at most 3 MiB), and discarded stderr to 4 KiB.
It closes every pipe and kills the owned process group while the leader remains
unreaped, then reaps within the original deadline. No poll/early wait can release
the leader PID before the signal. Environment contains only private HOME and C
locale; cwd is a private temporary directory. URL/token go only through stdin,
never argv/environment/error text. The private `_run` function accepts fake
commands for offline tests; the public request uses only pinned runtime/child.

Node resolves only `api.github.com`, with IPv4-only `lookup(all=true,family=4)`;
every answer must pass the conservative special-purpose CIDR denial list before
any connection. It connects to the selected numeric IP with original SNI, Host,
and certificate hostname verification, refuses any second lookup, and checks
the connected peer address and TLS authorization. No IPv6 qualification claim.
The denylist covers non-global/reserved entries in the
[IANA IPv4 special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry/)
plus multicast; globally reachable exceptions inside denied ranges are also
denied. Reviewed against registry last-updated 2025-10-09, accessed 2026-10-17.

Explicit `ca: tls.rootCertificates` uses Node's immutable bundled Mozilla store,
not ambient system/additional roots. Node documents that this store is a
[release-fixed snapshot](https://nodejs.org/download/release/v24.20.0/docs/api/tls.html#tlsrootcertificates).
`pins.json` records runtime hash, child hash, and SHA-256 of the UTF-8
`JSON.stringify(tls.rootCertificates)` array (121 roots). The child checks this
CA digest before resolution. TLS >=1.2, certificate validation, no fallback,
pooling, proxy configuration, retries, cookies, redirect following or decoding.
Raw duplicate headers, excessive header fields/bytes, CL/TE ambiguity,
unsupported encoding, truncated/oversized bodies and changed peers fail closed.

Offline verification (no socket/listener/DNS calls):

```sh
python3 -B -m unittest -v test_adapter
"/absolute/physical/path/to/pinned-node" --test test_child.mjs
```

These tests exercise real local fake-child processes and injected HTTP/DNS
objects. They do not qualify actual TLS, Node wire parsing, real DNS, provider
traffic, artifact download, auth stripping on admitted storage hosts, or native
SDK completion. Future steps require separate frozen review and execution GO:
local TLS/parser fixtures, exact API-only redirect-host observation, explicit
host-policy change, and bounded actual transport acquisition. No source/runtime
hash mismatch or new storage hostname is auto-enrolled.
