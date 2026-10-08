# Packaged reader and combined restart recovery

PASS, 2026-10-07: the installed wheel's private socket reader recovered an expired
Core receipt through a new native TUI/backend, then settled the real coordinator
in disposable workerd. The [proof](packaged-recovery-proof.json) records exact
Python sources, the cloud bundle, and all 129 bundled input hashes. This remains
fixture-qualified integration, not production admission or a client installation.

The native reader moved unchanged from the qualification script into
`event_gateway.native_reader` (executable AST equality checked against Toolshed `9e54800`; new docstrings
are excluded from the comparison).
The wheel exposes `NativeBridge`; the existing `NativeBridgeAdapter` remains the
cloud-admission/recovery boundary. Callers supply a qualified connected Unix
stream. Version 2 stays the default; durable version 3 is explicit. The reader
never discovers clients, launches processes, enables wake, or restores selection.

## What the combined run proves

1. A real signed delivery and claim produce one Started turn and submitted ACK.
   The real registry retains one slot, and no observed watermark exists yet.
2. A private native receipt independently confirms the genuine Core input item.
   The local gateway has persisted only the original request and submitted receipt.
3. After permit expiry, the first TUI and backend stop. A different TUI, backend,
   server identity, and selected thread start against the disposable StateDB.
   The original attachment remains unavailable.
4. Reopening the local store and reconciling through the installed reader recovers
   the exact InputRecorded identity from the new native process. No fresh native
   Start or cloud claim occurs. The real coordinator accepts the observed ACK,
   releases the actual registry slot, and advances the current source watermark.
5. The observed ACK reply is deliberately lost after workerd commits. A second
   Store/CloudClient restart replays identical ACK bytes with a fresh node nonce.
   Cloud readback is unchanged and local pending capacity reaches zero. Exactly
   four cloud requests succeed; mock-model counts are primary=1, title=1, unknown=0.

InputRecorded proves durable Core observation, not model success or transcript
materialization. The run does not prove old-attempt terminal no-start settlement;
`oldStartNoStartSettlementProven` remains false. Unknown outcomes retain their
fence. Existing no-start gateway tests remain separate evidence. Qualified runtime
setup, Access/Messaging identity and budget, manual publication, queue metrics,
and loopback transport remain explicit fixtures. No deployment or user service
was installed, and no owner client or production binding was changed.

## Reproduce

Build/install the wheel into a disposable Python 3.13 environment. Supply the
retained native binary (SHA below), current qualifier, current cloud source, and
existing Node 24.19.0, esbuild 0.28.1, and Miniflare 5.20261001.0-alpha packages.
From this directory, with those paths set:

```sh
"$EVENT_PROOF_PYTHON" -I -O coupled-workerd.py \
  --installed --restart-native --package "$EVENT_LOCAL_PACKAGE" \
  --qualifier "$EVENT_QUALIFIER" --binary "$EVENT_NATIVE_BINARY" \
  --binary-sha 0fb3a5de06ab2ccb8dcc20c11cb71cad1f0c1b85fbfa3a5c6fd16ca1f57d22de \
  --node "$EVENT_NODE" --cloud-source "$EVENT_CLOUD_SRC" \
  --esbuild "$EVENT_ESBUILD_PACKAGE" --miniflare "$EVENT_MINIFLARE_PACKAGE" \
  --output "$EVENT_PROOF_OUTPUT"
```

`--installed` rejects editable source distributions. The harness still supports
its earlier source mode when that flag is absent. The binary is an external
prototype prerequisite, not shipped in the wheel; fresh-checkout native builds
and supported owner-client packaging remain unqualified. User-service lifecycle
is a separate follow-up.

## Checks and causal evidence

All 228 gateway tests passed; the installed-wheel reader suite runs outside the
checkout in CI (26 passing tests). Reader extraction preserves the prior executable reader AST; docstrings differ.
Two new assertions failed against the original qualifier before the change:
reader ownership pointed to the script, and cleanup never signaled the owned
process group. Both restored green. A third regression models a backend that
survives SIGTERM after its leader exits: KILL clears it, and later cleanup must
send no signals even if the old PID reappears. Before the completed-cleanup guard,
this assertion failed at four signals versus two; it now passes. A scratch
mutation removing that guard reproduced the same semantic failure.

The pre-restart live runner passed its old scope but failed the explicit combined
requirement `nativeProcessRestarted is True`. The new run passed that assertion,
including under `-O`; runtime guards use explicit checks. The old passing run is
not counted as combined proof. Ruff and offline contract checks passed. The
[manifest](packaged-recovery-manifest.json) records hashes for retained test logs,
wheel, binary, and proof. The native patch and canonical contract snapshots did
not change.

Review corrections bound every resolved esbuild input to the explicit cloud OS
checkout or fixture directory before any content read. A Node regression rejects
sibling-prefix, traversal, and symlink escapes; the original unbounded reader
failed this assertion, and the bounded version passes. Process-liveness permission
denial now conservatively counts as alive, with its own assertion-red/green pair.
Restart, bounded ACK polling, and observed-settlement helpers preserve the prior runtime assertions.
The combined proof was rerun with the rebuilt wheel after these changes; the
source manifest includes the hashing helper and the corrected semantic driver
as separate provenance (the driver is not wheel content).
