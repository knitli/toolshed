# Three-session acceptance runbook

**Status: controlled local run passed; live qualification remains open.** The
[public proof projection](three-session-acceptance-proof.json) records the
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
| Busy C | Hold C's first synthetic model request open; accept a second signed delivery into the local durable queue and observe production dispatch return `client_unavailable_or_busy`. The fixture creates a transport-attempt row before delivery; prove it stays in its original unreserved state, with no native claim or additional native Start. |
| Queued C across daemon restart | Stop and restart the daemon while C remains held; confirm C2 stays queued with its original unreserved transport-attempt state and unchanged stored envelope, with no native claim or Start. |
| Binding change and explicit reattachment | After C1 completes, compare the settled launcher binding with its original attachment. Run the production `attach` CLI against synthetic Workerd using current runtime/attachment generations and a fresh native challenge. Prove C2 becomes locally `stale` with `attachment_detached`, retaining its unchanged envelope and Workerd transport row, with no claim or Start. |
| Fresh C3 after reattachment | Publish a new synthetic C3 event only after the explicit fixture attach. Require one current-generation Workerd claim, one native Start on C, and observed settlement. Record post-turn binding-field changes. This does not prove automatic draining of C2 or successive unattended events. |

The production daemon does not refresh attachment identity automatically. A changed
binding fences queued C2; the fixture's explicit attach and new C3 prove the normal
CAS/challenge path and post-attach delivery only. They do **not** establish
busy-to-idle queue draining, an owner-authorized production reattachment, or
completion of any rollout stage.

## Latest controlled evidence

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
- A new absolute proof filename whose parent already exists. Both it and its
  sibling `<proof-stem>.private-causal.json` must be absent, including dangling
  symlinks; the runner checks both before starting any subprocess. Choose separate
  stdout/stderr paths and retain failed
  run diagnostics without relabeling them as proof.

The three workerd ports must be distinct and between 1024 and 65535. Defaults
are entry `49732`, internal loopback `49733`, and broker `49734`. Native model
providers and the gateway listener use dynamically selected loopback ports;
there is no `--model-port` option. The older four-fixed-port recovery profile
cannot be reused unchanged for this procedure. Establish suitable execution
containment and supervision for these listeners before running; do not supply
operator credentials or real model configuration.

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
  --output "$EVENT_PROOF_OUTPUT" \
  > "$EVENT_RUN_STDOUT" 2> "$EVENT_RUN_STDERR"
```

Use an external bounded supervisor that tracks and cleans up owned descendants;
individual harness timeouts do not provide a global execution deadline. Retain
source/artifact hashes before and after execution. See the
[coupled recovery preflight](coupled-workerd-recovery-preflight.md) for staging
and supervision principles, not a directly interchangeable command/profile.

## Reading the result

Require exit 0, the fresh JSON proof, and the stdout `result: PASS` summary.
The [public projection](three-session-acceptance-proof.json) provides stable
session labels and an exact mapping from summary fields to raw proof keys. Retain
the mode-0600 raw proof, private causal sidecar, and execution logs with the input
manifest; do not publish private paths, session IDs, or nonce hashes. No proof
file or a nonzero exit means that run has not passed.

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
