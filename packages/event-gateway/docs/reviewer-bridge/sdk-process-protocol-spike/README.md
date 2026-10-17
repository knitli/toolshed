# SDK process-protocol proof

Attempt 7 passed the pinned Claude Agent SDK 0.3.209 with an in-memory fake
process, using the unchanged `runReview` driver from
`knitli/.github` revision
`e516ab4803311cd58fc860f57371aedb0fb24f4d`. This is a protocol and containment
proof with synthetic data; it does not qualify a native client or a production
owner lifecycle.

## Attempt 7 result

The controlled run completed at 2026-10-17 17:34:56–17:34:59 UTC with exit code
0 and 4,900 captured bytes. All four cases passed: three-page success, early
terminal rejection, EOF without a terminal result, and abort cleanup. The
launcher retained separate stdout and stderr under the shared 65,536-byte cap,
accepted exactly one PASS JSON document from stdout, and preserved diagnostics
and warnings in the raw capture.

The run passed three containment controls: an outside-scratch read was denied,
loopback access was denied, and scratch writes succeeded. Two causal guards
proved that unexpected subprocess and fetch requests are refused; both counters
remained zero. The root receipt records no remaining owned processes and no
remaining canaries.

[Final receipt](final-receipt.json) binds the executed source hashes, manifest,
profile, capture, results, and exact historical archive. [Root receipt](root-attempt-7.json),
[launcher log](actual-attempt-7.log), and [full result](actual-attempt-7-result.json)
retain the run summary and diagnostics. The bounded [capture metadata](capture-x6843ioa/capture.json),
[stdout](capture-x6843ioa/stdout.bin), and [stderr](capture-x6843ioa/stderr.bin)
contain the accepted PASS frame and the four SDK warnings.

## Executed sources and qualification boundary

[fixture.mjs](fixture.mjs), [launch.py](launch.py), and [manifest.json](manifest.json)
are the exact bytes used by attempt 7; their hashes are in the final receipt.
[profile.sb](profile.sb) is byte-identical to attempt 6. The manifest pins the
external Claude Agent SDK 0.3.209 and the completion driver by hash; neither is
vendored here. Its recorded private paths are provenance, not links or permission
to read those paths. Its state field records the pre-run staging state; the
receipts record the completed run while preserving the exact manifest bytes the
launcher consumed.

The launcher and manifest retain the exact absolute Node 24.21.0 path used for
this local qualification. That literal path is part of the sandbox authorization:
the profile allows only the pinned executable, and the copied launcher rejects
other paths. Redacting or templating it would produce a different source and
sandbox profile. A different host or path needs its own rendered profile,
manifest, hashes, and qualification run. This package is a host-specific
forensic artifact, not a portable launcher.

## Historical evidence

[Historical attempt 6 archive](historical-attempt-6.tar.gz) preserves the exact
13 regular files published at the attempt-6 head, including its source, receipt,
capture, and attempt-5 archive. It contains no SDK or driver bytes and has no
links, absolute paths, or traversal members. The root
[attempt-5 archive](historical-attempt-5.tar.gz) remains unchanged.
[Failed attempts](failed-attempts.json) records the runs that did not establish
a PASS.

## Mock regression tests

The fixture test calls `FakeProcess.emitFrame` extracted from the promoted
`fixture.mjs` and checks an astral character split across UTF-8 byte chunks,
JSON reconstruction, and the 64 KiB bound. The launcher tests exercise late
readiness and exit observation, fair stream reads, and retained-byte accounting
after aggregate overflow. They use fakes and do not run the SDK or launch a
child.

    /Users/adampoulemanos/.local/share/mise/installs/node/24.21.0/bin/node --test tests/fixture-attempt7.test.mjs
    python3 -B tests/test_launch_attempt7.py

## Permission warning and limits

The SDK emitted four `CLAUDE_SDK_CAN_USE_TOOL_SHADOWED` warnings. The pinned
SDK warns that the driver's bare `allowedTools: ['mcp__frozen__read_next']`
entry auto-approves that tool before `canUseTool` is consulted. The callback is
therefore not a per-call authorization gate for this read-only tool; settings
allow rules can also shadow it. No permission code was changed or qualified.

The run used the actual pinned SDK with an in-memory fake process. The fake
process has no PID and starts no OS child. No native client, Docker, provider,
or owner credential was used. The proof does not establish native runtime
qualification, production permission safety, provider completion, hosted
qualification, or Docker adapter compatibility.
