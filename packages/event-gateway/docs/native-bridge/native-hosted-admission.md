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

The runner rejects non-main, automatic, self-hosted, wrong-platform and rerun
attempts. It supplies a closed child environment, explicit descriptor closure,
a fresh short private scratch path, and an exclusive evidence directory. The
whole fixture inherits a network sandbox with seven fixed host-local TCP ports
and Unix sockets; existing per-native sandboxes remain enabled. `localhost`
means host-local addresses, not literal loopback. Broad Unix access and trusted
same-user processes are explicit assumptions; this does not claim hostile IPC
isolation or endpoint authentication. No production network call is permitted.

The 240-second subprocess timeout kills the direct fixture process on expiry;
it does not prove every descendant exited. Scratch remains until VM disposal,
avoiding deletion races with residual writers. The private workflow must use a
bounded job timeout, no retry and no cancellation replacement. Ultimate lifetime
containment relies on the provider's disposable-VM contract. Neither job
completion nor the result file is an observed VM destruction receipt.

Existing fixture cleanup, four native Starts, five daemon invocations, causal
assertions, input hashes and private evidence checks remain authoritative.
A zero exit with proof becomes
`FIXTURE_COMPLETED_PENDING_INDEPENDENT_VERIFICATION`, never automatic PASS.
Timeout, nonzero exit or missing proof remains INCOMPLETE. Independent proof and
archive verification must precede any qualification or candidate promotion.

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

Retain `hosted-result.json`, `network.sb`, proof and its referenced private causal
and evidence files, plus bounded private logs. Archive only an explicit allowlist
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
