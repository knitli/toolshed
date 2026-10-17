# Historical SDK process-protocol proof

Attempt 6 passed with the current packaged source. The actual hash-pinned Claude Agent SDK 0.3.209 passed four in-memory process
protocol cases with the unchanged `runReview` driver from knitli/.github revision
`e516ab4803311cd58fc860f57371aedb0fb24f4d`. This directory preserves historical
source and evidence; it is **not runnable from this repository path**.

## Result and evidence

[Final receipt](final-receipt.json) records exit code 0, three-page success,
early-terminal rejection, EOF-without-terminal rejection, and timeout/abort
cleanup. Unexpected subprocess and fetch counts were zero. Outside-scratch
reads and loopback access were denied, scratch writes succeeded, and the parent
verified the outside canary unchanged. Captured output totals 4,900 bytes.

[Raw stdout](capture-qpp9s1g8/stdout.bin), [raw stderr](capture-qpp9s1g8/stderr.bin),
[capture metadata](capture-qpp9s1g8/capture.json), and the
[parent attempt log](actual-attempt-6.log), and [parent result](actual-attempt-6-result.json) retain the exact evidence hashed by the
receipt. Abort events are stdin EOF → SIGTERM → exit → forwarded abort → a second
SIGTERM. No exactly-once kill claim is made.

[Prior attempts](failed-attempts.json) records startup failure, empty-output
failure, and the merged-stream parser failure. These attempts establish no
protocol PASS. Full historical startup probes are not packaged. Attempt 5's exact source,
manifest, receipt, log and captures are preserved in the immutable
[historical attempt 5 archive](historical-attempt-5.tar.gz). The final receipt
lists its archive hash and exact ten-member allowlist with individual hashes
and sizes. Members are regular files only, without absolute/traversal paths or
links. This forensic archive is not current source or an executable entrypoint.
Those archived bytes describe
prior behavior and are never imported or executed by the current launcher.
Attempt 4 remains a brief hash reference in that provenance. Attempt 6 reran the
proof after the three fixture review fixes and explicit historical-path preflight.
The unchanged
[runtime manifest](manifest.json) intentionally retains its pre-run state and
private evidence paths; the final receipt records the later passing outcome.

## Historical sources and external inputs

[fixture.mjs](fixture.mjs), [launch.py](launch.py), [profile.sb](profile.sb), and
manifest.json are byte-exact copies of the executed sources. They are bound to
`/private/tmp/reviewer-sdk-process-protocol-20261017` and the manifest's exact
macOS Node 24.21.0 binary. The SDK and driver are **not vendored**. The historical
layout expects these two externally provisioned inputs:

| Input | SHA256 |
| --- | --- |
| `frozen/sdk.mjs` — Claude Agent SDK 0.3.209 | `7b3577a1078660a3ec43471e6738c730ca1b172070ddcf3f9a9384bcb68bd3ca` |
| `frozen/reviewer-completion-driver.mjs` — revision above | `4ff7c66588d16f33f67ca89670b5efe4540170bf5708d28cea7b19a2d0298eee` |

Hydration must provision those exact bytes externally and verify both hashes;
it must not substitute a newer SDK or driver. Hydration alone does not make this
copy runnable: the launcher now explicitly rejects other paths before reading
the manifest or creating resources. Another path or runtime requires separately reviewed staging,
a newly rendered exact-path profile and manifest, and a fresh qualification
receipt. No acquisition, execution, portable launcher, or automatic staging is
included here. Private source paths in the immutable manifest are provenance,
not repository links or permission to read those paths.

## Containment and capture

The historical sandbox denies default access, network and process fork, and
permits only the exact Node executable for initial handoff. Code reads are exact
fixture/module/Node paths; runtime reads cover system libraries, random/null
devices, ancestor metadata, and literal root directory data. Scratch alone is
writable. No owner home subtree, repository tree, credentials directory, native
cache or Docker socket is allowed. Node addons are disabled.

The launcher verifies hashes, supplies a closed environment, enforces a
20-second deadline, and reads stdout/stderr fairly under a shared 65,536-byte
cap. Stdout must be exactly one PASS JSON document. Stderr cannot supply
acceptance. Raw streams, parsed diagnostics and warnings survive parser failure.
The fixture has a bounded 15-second keepalive and counted subprocess/fetch guards
installed before SDK import. Its synthetic credential is not usable.

## Permission warning and limits

Four `CLAUDE_SDK_CAN_USE_TOOL_SHADOWED` warnings are preserved. The pinned SDK's
`G5`/`bC` code warns that the driver's bare
`allowedTools: ['mcp__frozen__read_next']` entry auto-approves that tool before
`canUseTool` is consulted. The denial callback is therefore **not a per-call
authorization gate** for this allowlisted read-only tool. The warning also notes
that settings allow rules can shadow the callback. No permission code was changed.

This is an actual-SDK/in-memory-process protocol proof with synthetic data.
It does not qualify native permission enforcement, production safety, a Docker
adapter or process owner, provider completion, hosted handoff, or any proposed
owner lifecycle interface. The fake process has no PID and starts no OS child.
No native client, Docker or provider execution occurred in this proof. No
production code or deployment behavior is changed by this package.
