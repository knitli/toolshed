# Controlled native admission qualification

**PASS, 2026-10-09.** [Recorded proof](admission-workerd-proof.json) passed with
native binary SHA-256 `3e88bd929a8c1d6e29dd562c47c9264df5b8f5904847695b8b490ddcf492387c`
and the final installed wheel SHA-256
`d11642c3ca2eb96f72f7ce192c422c60be174487cea418c243157d87fd1322a2`.
The proof SHA-256 is
`82a7e0dd7f6ac7a08b6a95448e18c00b75ac38543f65a4712e889b98c3a4af48`.
It records 16 wire requests and exact cloud source hashes, including the scoped
canary admission gate and RPC error mapping changes in the working tree.

The first mismatched-client run exposed a cloud RPC boundary bug: workerd
serialized `EventApiError`, causing a definite `native_binding_unqualified`
refusal to become `503 unavailable`. The cloud API now maps known serialized
codes; the final run observes the expected `409` and clears the denied local
pending record. An earlier sandbox listener refusal and a corrected fixture
entrypoint error are not passing qualification evidence.

`admission-workerd.py` runs the installed wheel's CLI lifecycle, private launcher
control handler, native reader, and daemon writer against the production cloud
API/registry/coordinator in disposable workerd. It does not insert runtime rows.
The native qualifier launches two separate disposable TUIs using the supplied
hash-checked binary and an isolated HOME with a loopback mock model.

The assertions cover:

- Real native binding and fresh challenge-correlated witness admission.
- Two lost successful attach replies, persisted exact pending body, and recovery
  using a newly loaded CloudClient after witness expiry. All three commit bodies
  match; node-proof nonces differ; cloud runtime/challenge/binding rows do not
  change on the third request. Recovery obtains presence preflight but no new
  challenge-correlated witness.
- A real daemon process holds the exclusive Store writer lock while CLI commands
  persist mappings through its Unix socket. Readback uses read-only SQLite.
- Successful renewal; stale CAS, disabled admission gate, mismatched canary scope,
  and a different genuine native client binding are refused. Gate negatives
  exercise the API boundary; they do not prove direct-RPC rollback behavior.
- The second genuine client attaches a replacement runtime. Transfer updates its
  attachment generation and revokes the source in cloud and local storage.
- Neither native process submits a model request.

Access edge identity, Messaging identity, owner enrollment approval, and loopback
transport are explicit fixtures. Native startup is owned by the qualifier; the
production `NativeClient` and `_control` handler are connected using a fixture-owned
private session socket. This does not exercise the production foreground `launch`
entrypoint. The cloud admission flag and exact owner/agent canary scope are enabled
only in disposable workerd. Production admission remains unproved.

## Reproduce

Prerequisites: a noneditable installed gateway wheel, the qualified native binary,
current `scripts/qualify_native_bridge.py`, Node 24.19.0, esbuild and Miniflare package
directories, and the cloud event-runtime source directory. No dependency installation
or deployment is performed. Loopback listeners and a disposable PTY are required.

```sh
"$EVENT_PYTHON" admission-workerd.py \
  --qualifier "$EVENT_QUALIFIER" \
  --binary "$EVENT_NATIVE_BINARY" \
  --binary-sha 3e88bd929a8c1d6e29dd562c47c9264df5b8f5904847695b8b490ddcf492387c \
  --node "$EVENT_NODE" \
  --cloud-source "$EVENT_CLOUD_SRC" \
  --esbuild "$EVENT_ESBUILD_PACKAGE" \
  --miniflare "$EVENT_MINIFLARE_PACKAGE" \
  --output "$EVENT_PROOF_OUTPUT"
```

The output records exact local source hashes, installed distribution provenance,
cloud bundle/source hashes, native bindings, wire bodies, response statuses, and
cloud/local readback. Synthetic credentials and ephemeral node proofs are fixture
artifacts. The sibling `.broker.log` records broker/daemon diagnostics.
