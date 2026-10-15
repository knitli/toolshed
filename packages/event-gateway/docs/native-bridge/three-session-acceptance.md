# Three-session acceptance runbook

**Status: controlled local run passed; live qualification remains open.** The
[current public proof projection](three-session-20261013-proof.json) records the
result and raw-proof provenance without private paths or session IDs. The
[runner](three-session-workerd.py) writes a separate mode-0600 raw proof only
after its assertions and cleanup succeed. This evidence does not qualify
production admission, deployment, or a live user wake.

## Scenario matrix

Three real native CLIs share one production gateway daemon and have separate
session, client, thread, and runtime identities. Production cloud event-runtime
code runs in disposable workerd.

| Scenario | Required local evidence |
| --- | --- |
| Admission and idle selection | Three distinct native attachments; each CLI initially selected, idle, and unattached before fixture admission. |
| A-only event | A receives one native Start and reaches observed; B and C receive none. |
| B-only event | B receives one native Start and reaches observed; A remains at one and C at zero. |
| Submitted A across daemon restart | Stop the daemon after submission, let A finish, then recover its native receipt through daemon reconciliation. |
| Lost observed ACK reply | Workerd commits A's observed ACK before simulated reply loss; restart the daemon and replay identical ACK body bytes with a fresh node-proof nonce, without another native Start or changes to the compared workerd readback. |
| Busy C | Hold C's first synthetic model request open; accept a second signed delivery into the local durable queue and observe production dispatch return `client_unavailable_or_busy` backed by a fresh, current-binding native challenge with `nativeCoreTurnState: busy`. Unavailability alone cannot satisfy this gate. The fixture creates a transport-attempt row before delivery; prove it stays in its original unreserved state, with no native claim or additional native Start. |
| Queued C across daemon restart | Stop and restart the daemon while C remains held; confirm C2 stays queued with its original unreserved transport-attempt state and unchanged stored envelope, with no native claim or Start. |
| Binding change and explicit reattachment | After C1 completes, compare the settled launcher binding with its original attachment. Run the production `attach` CLI against synthetic Workerd using current runtime/attachment generations and a fresh native challenge. Prove C2 becomes locally `stale` with `attachment_detached`, retaining its unchanged envelope and Workerd transport row, with no claim or Start. |
| Fresh C3 after reattachment | Publish a new synthetic C3 event only after the explicit fixture attach. Require one current-generation Workerd claim, one native Start on C, and observed settlement. Record post-turn binding-field changes. This does not prove automatic draining of C2 or successive unattended events. |

The production daemon does not refresh attachment identity automatically. A changed
binding fences queued C2; the fixture's explicit attach and new C3 prove the normal
CAS/challenge path and post-attach delivery only. They do **not** establish
busy-to-idle queue draining, an owner-authorized production reattachment, or
completion of any rollout stage.

## Current manual-canary fixture profile

The runner explicitly enables a broker profile containing only its six existing
synthetic subjects: `three-session-route-a`, `three-session-route-b`,
`three-session-route-c`, `three-session-c-busy-first`,
`three-session-c-busy-second`, and `three-session-c-after-attach`.
Each setup call selects one exact subject under the Durable Object concurrency
barrier, invokes the production manual-publication guard, and restores the
original scope in `finally`. All selections retain the broker's original
five-minute expiry; setup never extends it. Unknown subjects fail closed.

This models sequential synthetic deployment scopes, not production authority for
multiple subjects. Production principal/agent and expiry guards remain active.
Source rows and delivery identities are preserved: reusing a single subject would
deduplicate C1/C2 or conflict across A/B and post-attach generations. The default
coupled recovery broker still admits only `fixture-manual-source`.

The controlled provider now holds only a main request, checks that the hold has
not expired through daemon restart, and uses separate tool-call identities per
session and C phase. Proof requires exactly two successful main requests for each
source-read turn and native idle settlement, with provider errors checked after
cleanup. These are fixture correctness checks, not live useful-response evidence.

The 2026-10-13 controlled run below qualifies this fixture profile within its
stated local scope; historical proofs remain separate.

## Latest controlled evidence

Attempt 03 on 2026-10-13 passed in 26.244 seconds with exit 0, unchanged frozen
inputs, and no remaining owned processes, listeners, or sockets. The
[dated proof projection](three-session-20261013-proof.json) records source commit
`a22a40fd123784c7cf870a688f226f22bceb3840`, cloud source
`e6196b5d2d714f71fce6c06812563c0360a2b551`, all 20 verified installed package files,
the exact native binary and Workerd bundle, and the raw-proof and supervisor hashes.
The run used the verified outer sandbox with the short private scratch path.
Its frozen guard queried the existing outside directory; the current runner
now requires denial for a fresh outside child path. The dated proof
remains evidence for its recorded source revision.

A and B each received one native Start. C1 stayed busy across the daemon restart;
C2 remained queued without a claim or Start, then became stale after binding
rotation and explicit fixture attachment. Fresh C3 received one claim and Start,
completed its source read, and settled observed. The lost observed ACK reply was
retried with identical body bytes and a fresh proof nonce.

Independent review checked the frozen assertion chain, artifact hashes, retained
aggregate proof, and cleanup. **Raw model requests, hold timestamps, signed wire
bodies, and complete native/gateway/ledger histories were not retained**, so these
cannot be independently replayed from the surviving artifacts. The private causal
sidecar retains only C1/C3 nonce hashes and their non-reuse assertion. This is
controlled runtime-assertion qualification with an evidence-retention limitation.

The daemon's `serve` coroutine restarted inside the harness process; this was not
an OS process crash or power-loss test. C2 was fenced after binding rotation, so
this run does not demonstrate deferred C2 delivery under an unchanged binding.
Production admission, owner Access, Mesh, manual canary, automatic queue draining,
and live user wake remain unqualified. Attempt 01 failed before selection because
nested sandbox application and process enumeration were denied. Attempt 02 failed
before selection with an overlong Unix socket path. Neither wrote a proof; their
supervisor hashes remain in the dated projection. The historical proof below is
unchanged.

## Earlier CI artifact evidence

The protected-main CI artifact rerun passed with CLI `763e5e2b…3717b` and a
fresh matching wheel. See [CI qualification](native-ci-qualification.md) and its
[five-proof projection](native-ci-qualification-proof.json) for exact artifact
identity, hashes, inputs and results. The unchanged runner produced raw proof
`51f8acaae227fa943ee51d76e545d96be50e084bdfdf4b5b09582e7db3dc711e`.
This repeats the complete scenario matrix; it does not qualify the live gates.
Use absolute command arguments and set runner cwd to the same private directory
as `TMPDIR`, because the broker emits build input paths relative to that directory.

## Historical restored-candidate evidence

The 2026-10-12 run used the offline-qualified, held promotion candidate from
[PR 81](https://github.com/knitli/toolshed/pull/81). Its native binary SHA-256 is
`62eac2a58bdac388850948aa82bf341c376e8653010d628de12ba642a2e343a3`. The private package
also includes the Store fix from [PR 84](https://github.com/knitli/toolshed/pull/84).
The exact package source revision is `9721e3945d0665e8eae2b237d5b61e8339238b63`: native
candidate base `206fcde88551f83bd86df9bc612890e39f60d204` plus the Store fix. A fresh
non-editable wheel matches that complete source; this is not the old PR 81 wheel.
The clean Workerd source commit is `df7cf5b1e4ac3fb40de664c594c934abdda730de`. The proof
projection contains the exact runner, fixture, helper, installed-package, and
Workerd bundle hashes. CI artifact provenance remains pending PR #82; this run
does not treat the held candidate as a main-pinned or production release.

The run observed isolated A/B routing; C2 retained unchanged while C was busy
and through daemon restart; binding rotation after C1; explicit fixture attach
advancing both generations; stale C2 fencing; one observed C3 claim/Start; and
identical observed-ACK replay after daemon restart. All three native launcher
groups, backends, and control sockets closed, as did the Workerd process group
and fixture ports. The public projection maps each summary field to its raw
proof field. Raw proof SHA-256:
`c8e4d1e080c725b59ac0d00bbac947cb574e6504f6d489c3c3ec72a083a097c6`.
R18 and diagnostic R19 failed the stricter full-history assertion: reattachment
rewrote the observed C1 attempt's fence, reason, and timestamp. Neither wrote a
proof. R20 passes with the Store fix and verifies C1 is observed locally/remotely
before attach and its complete history is unchanged afterward. The earlier R17
state-only projection is superseded and retained in Git history; its original
raw evidence remains private. No failed run was relabeled as PASS.

The separate private causal sidecar keeps only C1/C3 source-nonce hashes and
their non-reuse assertion; the public artifact carries event labels and the
boolean assertion only.

## Prerequisites and inputs

Use explicitly selected, verified artifacts; the runner installs nothing:

- Apple Silicon macOS with PTYs, Unix sockets, `sandbox-exec`, and permission for
  disposable loopback listeners and child processes. Scratch uses a private
  temporary directory; native child launch uses the existing host qualifier's sandbox.
  Set `TMPDIR` to an existing owned mode-0700 directory whose resolved path is at
  most 30 filesystem-encoded bytes on macOS (for example, `/private/tmp/et3-03`).
  The runner checks this before starting the broker: its generated gateway socket
  suffix needs 73 bytes plus the terminating NUL within macOS's 104-byte limit.
  Native and gateway scratch
  stay beneath this directory so the external supervisor can bound their writes.
- Python 3.13+ in a private environment containing a non-editable
  `knitli-event-gateway` wheel and its dependencies. Run with `-I -B`.
  Installed preflight verifies interpreter ownership, wheel RECORD, import path,
  exact trusted Python/contracts bytes, and a fresh import cache.
- The package checkout including `src/event_gateway`, `contracts/event-v1`, and
  this documentation directory's runner, broker, Worker fixture, installed
  preflight, native-host qualifier, launcher smoke helper, and their dependencies.
- The qualified `codex` executable and sibling `codex-code-mode-host`.
  `--binary-sha256` must equal the installed launcher's `QUALIFIED_SHA256`;
  the companion must match `QUALIFIED_CODE_MODE_HOST_SHA256`. A supplied hash
  cannot override those pins. See [native host qualification](native-host-qualification.md).
- Explicit Node executable and installed esbuild/Miniflare package directories
  resolvable by Node, including their transitive dependencies and workerd binary.
  Nearby coupled qualification uses Node 24.19.0, esbuild 0.28.1, and Miniflare
  5.20261001.0-alpha; record the actual selected artifacts for this new run.
- A cloud checkout whose source path ends at
  `apps/os/packages/event-runtime/src`, with bundle dependencies available.
  Supply its exact HEAD as `--cloud-commit`; the runner checks equality.
  HEAD alone does not certify a clean tree: retain input hashes and checkout state.
- A new absolute proof filename in an existing directory owned by the invoking
  user with mode `0700`. The runner checks this before starting any subprocess
  and rechecks the held directory during publication. Both it and its
  siblings `<proof-stem>.private-causal.json` and `<proof-stem>.private-evidence.jsonl` must be absent, including dangling
  symlinks; the runner checks all three paths before starting any subprocess. Choose separate
  stdout/stderr paths and retain failed
  run diagnostics without relabeling them as proof.
  Keep the output directory and its ancestors under exclusive trusted control.
  No untrusted concurrent writer, including an unsandboxed process with the same
  UID, may modify the artifacts from creation through consumer verification.
  This is an operator/environment precondition: the native sandbox profile does
  not establish output-directory write isolation. Mode `0700` restricts POSIX-mode
  access; ACLs and privileged access must also preserve exclusive trusted control.
  It does not isolate processes sharing the owner's UID.

The seven loopback ports are Workerd entry `49732`, internal loopback `49733`,
broker `49734`, gateway listener `49735`, and model providers A/B/C
`49736`/`49737`/`49738` in the example below. All supplied ports must be distinct
integers between 1024 and 65535. `--outer-contained` requires `--listener-port`
and exactly three `--model-ports`; the default per-native profile still supports
an omitted listener/model selection using dynamic ports.

Port shape is validated before artifact inspection or Git subprocesses. After
artifact and Git validation and the containment checks, every selected port must
be closed before the evidence archive is created or the broker/native sessions
start. Git validation therefore still precedes occupancy probes. These probes
are not reservations: a later bind can fail if another process takes a port.
Cleanup also requires every selected port to be closed after the native providers,
daemon, and broker have stopped; a remaining listener refuses PASS.
The old four-port recovery profile cannot be reused unchanged. Audit the outer
profile for the seven selected ports before execution; do not supply operator
credentials or real model configuration.

## Command

Set every variable below to an existing explicit artifact or the new output path.
`EVENT_PACKAGE_SOURCE` ends at `src/event_gateway`; package module directories
for esbuild/Miniflare are not their parent `node_modules` directory. Run from the
package root:

```sh
"$EVENT_PROOF_PYTHON" -I -B docs/native-bridge/three-session-workerd.py \
  --package-source "$EVENT_PACKAGE_SOURCE" \
  --binary "$EVENT_NATIVE_BINARY" \
  --binary-sha256 "$EVENT_NATIVE_SHA256" \
  --node "$EVENT_NODE" \
  --cloud-source "$EVENT_CLOUD_SOURCE" \
  --cloud-commit "$EVENT_CLOUD_COMMIT" \
  --esbuild "$EVENT_ESBUILD_PACKAGE" \
  --miniflare "$EVENT_MINIFLARE_PACKAGE" \
  --entry-port 49732 --loopback-port 49733 --broker-port 49734 \
  --listener-port 49735 --model-ports 49736 49737 49738 \
  --output "$EVENT_PROOF_OUTPUT" \
  > "$EVENT_RUN_STDOUT" 2> "$EVENT_RUN_STDERR"
```

An independently qualified external supervisor must enforce a hard deadline and
terminate the whole owned process tree; this fixture has no standalone hard bound.
The 30-second observer-drain deadline refuses qualification without cancelling the
actual executor join. State, native scratch, and archive descriptors remain live
until that join completes. A timed-out run still fails after workers finish; only
then may cleanup remove scratch. If the join itself fails or workers never finish,
the runner retains these resources for supervisor termination instead of unwinding
cleanup or publishing PASS. Cancelling the waiter cannot authorize cleanup.
Retain
source/artifact hashes before and after execution. See the
[coupled recovery preflight](coupled-workerd-recovery-preflight.md) for staging
and supervision principles, not a directly interchangeable command/profile.

## Explicit outer containment on macOS

The default command retains the mandatory per-native `sandbox-exec` profile,
which permits each native process's own model port and Unix sockets. An already
sandboxed supervisor cannot apply another seatbelt profile to its descendants.
For an independently audited outer profile, add `--outer-contained` to the
command above, retaining all seven explicit ports. This fixture option changes no production launcher behavior.

Before starting the broker and before each native launch, the option checks the
kernel sandbox is active, creates an owned scratch-only positive control, and
requires permission-query denials for the real-user home, its `.codex`, the verified installed
venv's sibling `codex-home`, creation of a fresh child path beneath `/private/tmp`, and
unqualified inbound/outbound network operations. Query errors, missing API
support, an inactive sandbox, and permissive results refuse execution. It never
opens owner-state files or contacts an external endpoint. Every owner-state read-denial probe must be an existing directory, verified using metadata
only. The outer profile must permit metadata inspection of those exact directory
roots while denying their contents; missing or inaccessible probe metadata refuses
execution. Root identities are also checked by the independent supervisor preflight.

Only after those checks does it remove the exact `sandbox-exec -f <profile>`
prefix from the original verified launch argv. The outer profile permits the seven selected
loopback ports for disposable services and the required Unix sockets; its audited bytes
must deny other network access, protect all owner state, and restrict writes to
one attempt directory. The kernel's unqualified network query does **not** prove
all address-specific rules. Retain the exact outer-profile hash and external
supervisor audit with the proof; `executionContainment` records this limitation.

The sandbox-presence query follows [Chromium's seatbelt implementation](https://chromium.googlesource.com/chromium/src/+/master/sandbox/mac/seatbelt.cc),
and the permission-query ABI and PATH filter follow [WebKit's sandbox SPI declarations](https://github.com/WebKit/WebKit/blob/main/Source/WTF/wtf/spi/darwin/SandboxSPI.h).
Darwin cleanup enumerates processes using bounded `libproc` calls and checks each
process group directly, avoiding setuid `/bin/ps` under containment. Permission
errors and incomplete/saturated process lists fail closed. Other platforms keep
the existing bounded `ps` path; outer-contained mode itself requires macOS.

## Reading the result

Require exit 0, the fresh JSON proof, and the stdout `result: PASS` summary.
The [public projection](three-session-acceptance-proof.json) provides stable
session labels and an exact mapping from summary fields to raw proof keys. Retain
the mode-0600 raw proof, private causal sidecar, and execution logs with the input
manifest; do not publish private paths, session IDs, or nonce hashes. No proof
file or a nonzero exit means that run has not passed.

The retained descriptors and sequential identity, metadata, and byte checks
validate each artifact at its check points; they are not an atomic snapshot of
all files at PASS. Keep the trusted-writer precondition in force while reading
and retaining the result. Independently reread the archive and compare its
SHA-256 and byte count with the proof before accepting it. A mismatch or any
untrusted concurrent modification invalidates the attempt; another final check
cannot provide isolation from a hostile writer.

New runs also retain `<proof-stem>.private-evidence.jsonl`, a mode-0600 raw causal archive containing provider exchanges, native receipts/observations, cloud wire/readbacks, and local database checkpoints before scratch cleanup. Keep it private with the input manifest and logs, including failed-run evidence. Records are capped at 4,100,000 bytes and the archive at 64 MiB; exceeding either bound fails qualification. Appends and hashing use the original file descriptor, with file and parent identity checks. Native executor work drains and provider handlers join before sealing; the archive and its parent directory are flushed before cleanup and final hashing. After resource cleanup finishes, the PASS proof records the final archive SHA-256 and byte count. Verify both against the retained file before accepting the run. This retention does not change the historical runs described above. New runs require a fresh matching challenge, an unexpired authoritative Core-busy witness, and a nonce not previously accepted for C2 on each counted busy dispatch, including after daemon restart. The archive retains these observations as `c2CoreBusy`; the final proof reports their distinct nonce count as `privateEvidence.coreBusyNonces`. C2 must still have zero native claims and zero native Starts while its original transport attempt remains unchanged. The integrated gate has not yet been exercised against real native sessions. The scenario remains bounded to four native Starts and five daemon starts.

This PASS is controlled integration evidence only. Access identity,
Messaging identity/budget, owner manual publication, queues/metrics, and model
responses are fixtures; loopback replaces Mesh. Actual daemon, listener,
SessionNativeBridge, Gateway, and cloud runtime paths execute with fixture
transport and instrumentation. Native CLIs stay alive across daemon restarts:
this procedure does not prove native-process restart recovery. `realModelCalls: 0`
is a fixture configuration claim, not independent network-capture evidence.

## Remaining live gates

Do not promote local PASS into live acceptance. Keep the emitted
`productionAdmissionProven`, `liveOwnerAccessProven`, `liveMeshProven`,
`liveManualCanaryProven`, and `idleDispatch.liveUserWakeQualified` false until
separate evidence establishes the corresponding live behavior:

Automatic busy-to-idle draining is also unqualified. C2 became stale when the
native binding changed; the local recovery required explicit fixture attach and
a fresh C3 delivery. The acceptance run does not authorize unattended rebinding
or retarget stale deliveries.

1. Real owner/Access authorization, enrollment, and runtime admission on the
   intended deployed surface, including unauthorized-request rejection.
2. Authenticated Mesh delivery to the intended installed daemon with actual
   routing and capacity accounting.
3. An owner-authorized manual canary reaching the intended idle user session,
   producing correlated native input and a useful response/source read, with
   durable receipt and cloud ACK evidence.
4. Live A/B isolation, busy-session retention and eventual authorized recovery,
   plus restart/retry evidence under the actual deployment's failure conditions.
5. Successive turns on one native session: determine whether the app-server
   binding rotates after every completed turn and provide an authorized,
   generation-safe path to resume the retained queue. This local fixture does not
   prove automatic busy-to-idle drain or retarget stale deliveries.

The [continuity source spike](native-continuity-spike.md) identifies candidate
turn-correlation signals and the missing causal authority contract. It supplies
research for gate 5, without qualifying that gate.

Record the exact deployed revision, executable/package hashes, session/runtime
bindings, and redacted causal evidence for each live gate. GitHub ingestion and
source authorization require their own evidence; this manual fixture does not
qualify them.
