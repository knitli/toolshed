# Packaged reader and combined restart recovery

PASS, 2026-10-07: the installed wheel's private socket reader recovered an expired
Core receipt through a new native TUI/backend, then settled the real coordinator
in disposable workerd. The [proof](packaged-recovery-proof.json) records exact
Python sources, the cloud bundle, and all 130 bundled input hashes. This remains
fixture-qualified integration, not production admission or a client installation.
The current cloud source pin is `807f398a7da62d9107e858c63dbec92c8d8145f7`;
the synthetic authority fixture supplies a canonical 43-character thumbprint
to exercise the stricter production response validator.

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
"$EVENT_PROOF_PYTHON" -I -B coupled-workerd.py \
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

## In-flight fault checkpoint (controlled run passed — 2026-10-13)

Add `--restart-inflight` to the installed `--restart-native` command above to
stop the old TUI/backend after durable InputRecorded and permit expiry while the
single synthetic primary model response remains held. The runner checks that
both old processes have stopped before releasing that response. Explicit response
lifecycle state and the unchanged 30-second hold deadline must still report held
both before stopping and after confirmed shutdown; timeout or response transmission
refuses the proof even when the release event remains unset. The runner then uses the
existing new-process read-only receipt recovery and exact lost-ACK replay checks.
The default restart scenario still waits for idle before stopping native.

The [sanitized proof](native-inflight-recovery-proof.json) records a fresh
installed-package run against cloud `03a2911f`, using the protected-main native
binary `763e5e2b…3717b`. Both in-flight proof fields are true. The original exact
Core receipt was recovered after permit expiry through rotated native identities;
one claim and one primary model request produced identical observed-ACK replay
bytes with a fresh nonce. Capacity was released and the budget charged once.
Independent evidence review passed. Supervision exited 0 in 9.126 seconds with
unchanged inputs and no owned processes, listeners or sockets remaining.

Attempts 1–3 remain failed: unsafe scratch ancestry, incomplete bundle resolution,
and an obsolete synthetic manual scope. None was relabeled as a pass. The final
run reports an expected synthetic BrokenPipe after deliberate client death.
`interruptedTurnCompletionProven` stays false: recovering InputRecorded proves
Core observation, not model completion,
a useful response, or permission to start a replacement turn. No reattachment,
lease-renewal service, automatic queue drain, or live rollout is introduced.

Use a fresh private wheel/environment matching the current package source,
explicit qualified native artifacts and qualifier, a pinned clean cloud source,
and the existing bounded external supervisor. Retain failed-run logs separately;
the historical packaged-recovery proof above does not qualify this new checkpoint.

The disposable broker supplies the current cloud manual-publication guard with
only `fixture-manual-source`, expiring five minutes after broker setup. This
scope is a fixture binding, never a production guard override. The shared
three-session runner explicitly selects a separate six-subject fixture profile
with sequential exact scopes and the same immutable expiry; see
[three-session acceptance](three-session-acceptance.md#current-manual-canary-fixture-profile).
Its historical proof does not transfer to that current profile.

## Narrow Core Busy checkpoint (2026-10-13)

The [sanitized proof](native-core-busy-20261013-proof.json) records an independently
reviewed offline run using a diagnostically instrumented gateway candidate based
on `98c87baa`, with unchanged installed native binary and code-mode host pins.
A synthetic provider used no owner/model credentials or real model calls while
a real owned tool ran. Two native Start RPCs produced one accepted Start and one
exact fresh `terminalNotStarted/busy` receipt. After barrier release, read-only
recovery returned InputRecorded for the immutable original request, and that
exact thread and turn completed. Before obtaining fresh authority and probing,
the fixture used a fixed two-second schedule of eight read-only observations.
These samples do not prove continuous stability or authority; this is neither
a quiescence guarantee nor a production delay requirement.
Inputs stayed unchanged; supervision exited 0
with no owned processes, listeners, or sockets remaining. This public projection
hashes retained private evidence; its helpers and raw journal remain private, so
it is not a standalone runnable qualification fixture. The Busy receipt exists
in fixture evidence; retained StateDB has the original InputRecorded record but
the probe remains pending. Native Busy receipts are process-local by
[contract](terminal-no-start-checkpoint.md). The gateway persists terminal
receipts before cloud settlement, as covered by the separate
[coupled no-start checkpoint](coupled-no-start.md); this launcher-only run does
not exercise that persistence handoff. Loss before gateway persistence followed
by native restart leaves the outcome unknown and fenced, with no retry.
Native Busy persistence, gateway terminal-receipt persistence, restart replay,
and durable terminal no-start settlement remain unqualified by this run.
This does not qualify the
unmodified production gateway, live Mesh, OS crash recovery, same-binding C2
drain, the seven-case harness, or all of Stage 1. Earlier proofs remain unchanged.

## Gateway terminal Busy handoff checkpoint (2026-10-13)

The [sanitized handoff proof](native-gateway-handoff-20261013-proof.json) records
an independently reviewed offline v6 run of the production Gateway listener,
dispatch, and Store paths from candidate `98c87baa`, with gateway diagnostic
instrumentation and the cloud HTTPS transport replaced by an offline fake.
This is a pinned historical candidate, not qualification of the latest production
source or installed gateway. The native binary and code-mode host pins were
unchanged. Synthetic provider requests used no owner/model credentials; the
fake cloud used fixture credentials and verified signed node requests.

One signed delivery, one claim, and one granted permit produced one actual fresh
Core `terminalNotStarted/busy` receipt while the original owned tool was running.
The gateway committed the exact Busy receipt and receipt UUID before the fake
cloud committed settlement. After losing that response, the fixture SIGKILLed
and reaped the first gateway daemon, then started a new daemon with the same
configuration, key, and durable state. Replay sent the identical settlement body
with a fresh signed nonce, received HTTP 200, and reached local `settled` state
before SIGTERM and clean exit. The attempt remained unchanged after exit.
There was no replacement claim, replay native Start, or replay native receipt
lookup. Across the run, two native Starts produced one accepted original and
one Busy refusal. The native process stayed alive through the gateway restart.
The fixture repeated the fixed two-second schedule of eight read-only observations
before probing; these samples establish neither continuous authority nor global
quiescence and are not a production delay requirement.

After releasing the tool barrier with the matching nonce, read-only recovery
returned InputRecorded for the immutable original request, and the exact original
thread and turn completed. Two primary and one title request reached the synthetic
provider; real model and live Mesh calls were zero. Supervision exited 0 in
8.749918 seconds, with the v6 inputs unchanged and no owned processes, listeners,
or sockets remaining. Private journal, proof, supervision, diagnostics, and frozen
manifest hashes bind this projection to retained evidence; raw identities, keys,
prompts, paths, and fixture helpers remain private. It is not a standalone runnable
qualification fixture.

This qualifies gateway persistence and daemon-crash settlement replay only for
this received terminal-Busy handoff. Native terminal Busy receipts remain
process-local; native restart and loss before gateway persistence are not covered.
The fake cloud does not establish production cloud settlement or live Cloud/Mesh
behavior. Installed deployment, same-binding C2 drain, global idle, the seven-case
harness, and all of Stage 1 remain unqualified. The earlier v5 false start remains
a retained blocked run (supervisor exit 1): its fixture expected two challenges where the production path
required three; it did not establish a production bug. Earlier proofs are unchanged,
and the v6 input check makes no claim about all historical scratch bytes.

## Disposable hosted recovery scenario

The hosted runner now pairs three-session qualification with this fixture's
`--installed --restart-native --restart-inflight --trusted-hosted-vm` mode.
Use `-I -B`, never `-O`; assertions must stay enabled. Hosted mode requires
`--cloud-commit` and model/entry/loopback/broker ports 43125/43121/43122/43123.
It checks inherited kernel network denial before the broker and every native
launch, with no filesystem isolation claim. The wrapper checks source identity
and both scenario proofs before reporting completion pending independent audit.
See [hosted admission](native-hosted-admission.md). No new native run or
production qualification is claimed by adding this execution path.
