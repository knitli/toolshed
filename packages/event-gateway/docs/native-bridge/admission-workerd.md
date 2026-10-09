# Controlled native admission qualification

**PASS, 2026-10-09.** [Recorded proof](admission-workerd-proof.json) passed with
native binary SHA-256 `3e88bd929a8c1d6e29dd562c47c9264df5b8f5904847695b8b490ddcf492387c`
and the final installed wheel SHA-256
`d11642c3ca2eb96f72f7ce192c422c60be174487cea418c243157d87fd1322a2`.
The proof SHA-256 is
`17757225fd87555d7da7023ffdd2c24f89c51e102f2e9fe8f77b8ed6f5106471`.
It records 16 wire requests and exact cloud source hashes, including the scoped
canary admission gate, RPC error mapping, and extracted synchronous native runtime store.
The final run used Python `-I -O`; explicit qualification guards remain active.

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
hash-checked binary, explicit `--no-daemon`, and an isolated HOME with a loopback
mock model.

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

## Installed artifact checks

Before importing any gateway module, the shared `qualification-installed.py`
checks the installed wheel's RECORD and all 20 Python module/contract files against
explicit `--package-source` (`src/event_gateway`, with sibling `contracts/event-v1`).
It rejects editable/source installs, import shadows, extra files, and changed
module or contract bytes. Source is trusted local operator input; these checks
are not remote or signed build attestation.

The parent and Python daemon require `-I` and independently use new private
bytecode-cache directories with bytecode writes disabled. This prevents a valid
old `.pyc` from bypassing the verified `.py` bytes. Cache ownership lasts until
process exit. Node and the actual Python executable must be owned, regular,
executable files with safe ancestors; normal verified venv interpreter symlinks
are supported. Node receives a closed synthetic environment.

Eight guard tests passed with `-I -O`, including changed module and contract bytes
with both stale and rewritten RECORD, wrong import paths, editable/source installs,
unsafe executable paths, and a valid poisoned timestamp `.pyc`. The bytecode test
first observes the poisoned value, then observes the verified source value after
preflight and garbage collection of the helper module.

## Reproduce

Prerequisites: a noneditable installed gateway wheel, the qualified native binary,
current `scripts/qualify_native_bridge.py`, Node 24.19.0, esbuild and Miniflare package
directories, and the cloud event-runtime source directory. No dependency installation
or deployment is performed. Loopback listeners and a disposable PTY are required.

```sh
"$EVENT_PYTHON" -I -O admission-workerd.py \
  --package-source "$EVENT_PACKAGE_SOURCE" \
  --qualifier "$EVENT_QUALIFIER" \
  --binary "$EVENT_NATIVE_BINARY" \
  --binary-sha 3e88bd929a8c1d6e29dd562c47c9264df5b8f5904847695b8b490ddcf492387c \
  --node "$EVENT_NODE" \
  --cloud-source "$EVENT_CLOUD_SRC" \
  --esbuild "$EVENT_ESBUILD_PACKAGE" \
  --miniflare "$EVENT_MINIFLARE_PACKAGE" \
  --output "$EVENT_PROOF_OUTPUT"
```

The output records all verified installed module and contract hashes, qualification
script hashes, installed distribution provenance,
cloud bundle/source hashes, native bindings, wire bodies, response statuses, and
cloud/local readback. Synthetic credentials and ephemeral node proofs are fixture
artifacts. The sibling `.broker.log` records broker/daemon diagnostics.
