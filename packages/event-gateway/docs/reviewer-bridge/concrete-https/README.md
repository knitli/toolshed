# Dormant reviewer HTTPS adapter prototype

Dependency: artifact-transport PR #158 at `cc714cc45fbc8bb2be80ff0d98f9980c485cf8a5`.
This directory is an unactivated prototype. No CLI, credential discovery, host
admission, contract/pin changes elsewhere, listener, or production integration.
The existing transport's download-host set remains empty. Every non-API origin
is refused, including an artifact URL carrying an Authorization header.

The public adapter is intentionally unavailable. `adapter.bind(node_path)` and
its internal `_request` entry point always raise
`https_runtime_authority_unavailable` before inspecting a runtime path, reading
pins, serializing credentials, loading native code or spawning a process. No
configuration, environment variable or callback can enable them. The former
path-check-then-spawn branch has been removed: matching file hashes could not
prevent executable or script replacement before process creation.

The private `_run` supervisor and `_decode` parser remain trusted-fixture
utilities. They do not establish production runtime authority and must not be
exposed as a request interface. The composed transport test supplies an explicit
fixture response; it does not claim a successful public adapter binding. The
adapter retains the existing `transport` module's exact `Response` class for
that nominal protocol test.

For private supervisor fixtures, the caller supplies the existing
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
never argv/environment/error text. The private `_run` function accepts commands only for explicitly trusted
offline fixtures; public requests never call it.

The standalone child fixture resolves only `api.github.com`, with IPv4-only `lookup(all=true,family=4)`;
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

Production prerequisite: a separately reviewed, independently trusted immutable
host/native-helper distribution and owner-provisioned runtime hierarchy must
exist before any public launch path is added. The helper must not be loaded from
a user-writable path and used to authenticate its own authority. A future
implementation must validate protected runtime ancestors and capture verified
child bytes once for a fixed bootstrap, without reopening the script pathname.
It also needs bounded private source/request pipes and qualified cleanup.

This change disables the unsafe public execution path; it does not implement or
qualify that future guarded launcher. Native helper pinning, provisioning,
loader qualification and actual protected-launch acceptance remain outstanding.
Functional TLS/parser evidence belongs to explicitly trusted private fixtures
and cannot establish production launcher or transport readiness.

## In-memory HTTP framing proof

Run the additional fixture with the existing pinned Node executable:

```sh
"/absolute/physical/path/to/pinned-node" --test test_wire_parser.mjs
```

The fixture uses Node's real HTTP parser over an in-memory Duplex through the
existing trusted request seam. It fragments response bytes, retains the child's
header limits, and checks fixed-length, chunked and close-delimited bodies;
ambiguous framing, truncation, malformed chunks, excessive headers/body,
informational responses and redirects. Each case has a timeout and destroys its
agent/streams on completion or test cleanup. Network socket connection attempts
throw, and DNS answers are supplied directly by the fixture.

Only HTTP framing is exercised. The fixture deliberately uses an HTTP agent
instead of HTTPS, with synthetic authorization and peer-address properties.
It does not establish TLS authentication, DNS, live network behavior, deadline
supervision, protected launch authority, artifact acquisition or reviewer
completion. The child, pins, public binding refusal and empty download-host
policy are unchanged.

## Bounded anonymous HTTPS observation

On 2026-10-18, a separately approved trusted fixture used the unchanged
`child.mjs` and private `adapter.py::_run` from Toolshed `0cafb025` with the
existing pinned Node executable and bundled CA roots. One anonymous
`GET https://api.github.com/zen` returned HTTP 200, 19 bytes, in 0.267 seconds.
The body SHA-256 was
`e926db51cb9dd0b0c7d548b7e9d2fd34534ac1b44066db30450d9cd9295bca7a`.
The fixture retained only status, length, digest and fixed diagnostic fields;
it discarded raw response body and headers. Owned-child cleanup was confirmed,
with no cleanup failure observed.

An earlier separately approved request returned HTTP 415; its cause remains
unknown and its evidence is preserved. The second experiment changed only its
private location and the literal headers from `Accept: text/plain` and
`X-GitHub-Api-Version: 2026-03-10` to `Accept: application/vnd.github+json` and
`X-GitHub-Api-Version: 2022-11-28`, matching the existing artifact transport's API
profile. Two requests were authorized individually; neither experiment retried.
Both used a 256-byte body ceiling, an 18-second child timer and a 20-second
parent budget from entry, including preflight and cleanup reserve. There were
no credentials, redirect following or application-level address fallback.

This records one successful trusted-fixture DNS/TLS/read path. It does not
qualify protected launch, independent runtime authority, credentialed requests,
artifact acquisition, production transport or reviewer completion. Pathname
replacement races and hard real-time bounds remain outside the proof; cleanup
confirmation covers the owned child, not all possible descendants. Public
`bind()` and `_request()` still refuse unconditionally, and the download-host
allowlist remains empty.
