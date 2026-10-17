# Hosted native fixture qualification

The controlled Core-idle candidate remains **UNEXECUTED / UNPROMOTED** until a
reviewed private-cloud workflow dispatch produces independently verified proof.
`run_hosted_native_qualification.py` supplies the execution step; it does not
acquire artifacts, approve candidate bytes, or promote a release.

## Execution contract

This fixture trusts the reviewed, hash-pinned native code and trusted harness
inside one disposable GitHub-hosted macOS ARM64 VM. It tests real native scenario
behavior against synthetic model, authority and cloud services. It is not a
hostile-code isolation assessment. The VM contains no installed owner client or
owner credentials. Checkout must disable persisted credentials, and acquisition
must use only the job's read-only token before execution.

The runner rejects unprotected/non-main, automatic, self-hosted, wrong-platform and rerun
attempts. It supplies a closed child environment, explicit descriptor closure,
a fresh short private scratch path, and an exclusive evidence directory. The
whole fixture inherits a network sandbox with seven fixed host-local TCP ports
and Unix sockets. Its distinct `--trusted-hosted-vm` fixture mode verifies an
active kernel sandbox and default bind/inbound/outbound network denial before
broker startup and each native launch, then omits the nested sandbox wrapper.
The older `--outer-contained` mode retains its filesystem checks and cannot be
combined with the hosted mode. Neither hosted mode nor VM disposal proves
filesystem isolation. `localhost`
means host-local addresses, not literal loopback. Broad Unix access and trusted
same-user processes are explicit assumptions; this does not claim hostile IPC
isolation or endpoint authentication. No production network call is permitted.

Each scenario has a 240-second subprocess timeout. The timeout kills the direct fixture process on expiry;
it does not prove every descendant exited. Scratch remains until VM disposal,
avoiding deletion races with residual writers. The private workflow must use a
bounded job timeout, no retry and no cancellation replacement. Ultimate lifetime
containment relies on the provider's disposable-VM contract. Neither job
completion nor the result file is an observed VM destruction receipt.

The runner executes three-session followed by installed in-flight native recovery
(`coupled-workerd.py --installed --restart-native --restart-inflight`), each in
its own private evidence directory. Both use `-I -B`; optimization is forbidden
because the native qualifier relies on assertions. Ports must be released before,
between and after scenarios; occupied ports abort without fallback. The recovery
fixture checks default kernel network denial before its broker and each native
launch. Its temporary adapter restores the original qualifier helper on exit;
it changes no production launcher and removes no sandbox prefix.

The runner separately checks both proof identities, scenario outcomes, source
hashes, recovery receipts, native identity rotation, exact lost-ACK replay,
settlement and cleanup evidence. It also checks three-session private evidence
and causal-sidecar hashes/nonces. Only both successful scenario checks produce
`FIXTURE_COMPLETED_PENDING_INDEPENDENT_VERIFICATION`, never automatic PASS.
Timeout, nonzero exit, malformed or mismatched evidence remains INCOMPLETE.
Independent audit of the raw evidence and archive is still required. These
checks are an acceptance filter for reviewed fixture code, not an independent
observer of hostile code.

Three-session retains four native Starts and five daemon coroutine invocations.
Coupled recovery adds genuine native TUI/backend replacement while the synthetic
response remains held, and exact durable receipt recovery in the new process.
Neither proves OS gateway-daemon crash recovery, interrupted-turn completion,
production admission, or observed VM destruction.

## Private workflow integration

The private-cloud repository owns dispatch, acquisition and evidence upload.
Use reviewed immutable Toolshed main plus the exact reviewed candidate overlay;
do not check out an older candidate branch as the trusted harness. The overlay
updates the launcher/helper native pins and provenance without promoting them.
Verify native build/run/artifact identity, archive digest and both executable
digests before extraction. Build a non-editable wheel from that exact source,
install into a fresh Python 3.13+ environment with frozen dependencies, and retain
wheel/overlay/source hashes. The fixture verifies installed wheel RECORD and
source bytes before importing the gateway.

Stage the exact cloud Git checkout and esbuild/Miniflare package directories.
Use real, absolute Node executable paths. The runner command is:

```sh
python3 packages/event-gateway/scripts/run_hosted_native_qualification.py \
  --repository-id "$CLOUD_REPOSITORY_ID" \
  --python "$VENV/bin/python" \
  --package-root "$TOOLSHED/packages/event-gateway" \
  --binary "$NATIVE/codex" --binary-sha256 "$REVIEWED_NATIVE_SHA256" \
  --node "$NODE" --cloud-source "$CLOUD/apps/os/packages/event-runtime/src" \
  --cloud-commit "$REVIEWED_CLOUD_SHA" \
  --esbuild "$ESBUILD_PACKAGE" --miniflare "$MINIFLARE_PACKAGE" \
  --output-dir "$NEW_PRIVATE_EVIDENCE_DIRECTORY"
```

Workflow constants must supply these inputs, not arbitrary dispatch commands.
The output directory must not already exist. Fixed ports 43121–43127 cover entry,
Miniflare loopback, broker, daemon and models A/B/C. Occupied ports abort without
fallback. The fixture rejects ports inside the host's ephemeral range.

Retain `hosted-result.json`, `network.sb`, `three-session/proof.json`, its private
causal and evidence sidecars, and `native-recovery/proof.json`, plus bounded private
logs from each directory. The recovery proof contains raw synthetic native identities
and wire bodies; it is private evidence. Update the cloud workflow export allowlist
for both directories before enabling this runner. Archive only an explicit allowlist
with size limits; never upload whole scratch or public raw evidence. Cancellation
or incomplete archive retention cannot produce qualification PASS. The workflow
must record its immutable execution SHA, Toolshed/overlay/cloud identities,
wheel/native hashes and runner image alongside the runner result.

This contract deliberately replaces the earlier local supervisor's impossible
complete-descendant/five-second ownership promise for hosted runs only. It does
not modify or authorize the old local supervisor. Synthetic hostile-parent/Mach
isolation experiments are not prerequisites for this trusted-code fixture scope.

Native compatibility, actual hosted sandbox compilation and full scenario
completion remain untested until the reviewed dispatch. Even a verified
controlled PASS does not prove deployed Mesh delivery, installed owner wake,
production admission, release promotion or activation.
