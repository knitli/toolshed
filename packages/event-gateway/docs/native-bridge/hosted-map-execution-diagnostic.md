# Hosted mapping and execution diagnostic

This fixed diagnostic distinguishes a rejected executable mapping from an accepted
mapping whose bytes can actually execute. It does not qualify the CLT runtime,
a native client, production admission, or release promotion.

Toolshed owns the parent and child scripts and their mock tests. The private Cloud
repository owns the protected-main workflow, immutable Toolshed revision pin,
hosted containment and evidence export. A Toolshed merge does not authorize a
hosted run; the Cloud integration must pin the actual reviewed merge before a
separate execution approval.

## Fixed experiment

The payload is exactly `40058052c0035fd6`: little-endian arm64 `mov w0,#42; ret`.
It returns integer 42 without a syscall, memory access, argument or external call.
The input file contains those eight bytes followed by zeros to 65,536 bytes, with
mode 0600. It is never compiled, signed, modified through a mapping, or marked
executable. No MAP_JIT, signing changes, entitlements or fallback are used.

Three profiles run in order: control-before, a single literal
`deny file-map-executable` addition, and byte-identical control-after. All cases
use the same input inode. Each profile has six bounded child operations:

- Ordinary read and private R/RW mappings.
- Initial RX mapping followed by the fixed call.
- R→RX and RW→RX protection upgrades followed by the fixed call.

Both positive controls must return exactly 42 for all three execution routes.
Data operations must succeed everywhere. The denial case must reject initial RX
at mmap and upgrades at mprotect with EPERM/EACCES. Only this complete matrix can
report `SYSCALL_AND_CONTROL_MATRIX_PASS`, with `qualified: false`.

A returned callback under denial is `FAIL_EXECUTION_ALLOWED`, even if another
control fails or a later output line is truncated. PASS requires strict complete
receipts. A signal, timeout, failed positive control, unexpected architecture or
uncertain cleanup remains inconclusive. An accepted mprotect alone is neither
execution evidence nor evidence that execution is prevented.

## Launch and evidence contract

The parent admits only the fixed private Cloud repository, exact protected-main
workflow ref, explicit workflow_dispatch, attempt 1, GitHub-hosted macOS ARM64,
Python 3.13.14, matching workflow/source SHA and recorded run/image identities.
The Cloud workflow must separately enforce private visibility and pin these
scripts from the actual Toolshed merge. Its runtime is trusted; observed tool
hashes are retained for audit, not presented as independently preapproved bytes.

Use the documented `macos-15` runner label with the runtime ARM64 checks; the
current standard-runner table lists it as ARM64 for private repositories.
`macos-15-arm64` is an image name, not a documented standard workflow label.
See the [GitHub runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#standard-github-hosted-runners-for-private-repositories).

The parent gives each fixed child ten seconds, reserving two for kill/reap, and
caps combined output at 16 KiB. It retains the unreaped direct-child identity
until cleanup. The fixed child and callback cannot launch descendants; this is
not a general process-tree supervisor. Unconfirmed cleanup stops further cases.
An uninterruptible kernel operation is not claimed bounded.

Children receive only PATH, LANG, LC_ALL, HOME and TMPDIR, with closed inherited
descriptors, null stdin and output pipes. Their default-deny profile permits
reads from fixture/runtime/system paths, but no network or filesystem writes.
Core dumps are disabled. No owner credentials or native client are staged.
Profile/runtime compatibility remains subject to the hosted positive controls.

The parent binds source/tool/profile/input identities around every launch and
unlinks the stub input at the end. Only the allowlisted `result.json` may be
exported privately after type/size checks; no whole-scratch or executable upload.
The Cloud job must retain the immutable workflow/Toolshed identities, image,
hashes and raw receipts. Missing evidence cannot pass. VM disposal is a provider
lifecycle assumption, not an observed destruction receipt.

The fixed command, after a separately approved Cloud integration, is:

```sh
python -I -B packages/event-gateway/scripts/probe_hosted_map_execution.py --go
```

This command intentionally rejects ordinary local environments. Do not change
admission variables, weaken profiles or retry a failed attempt to force a pass.
Pre-opened descriptors, aliases, other mapping forms, dynamic loading and actual
CLT runtime closure are outside this diagnostic's claim.

## Mock verification

The normal Event Gateway workflow discovers `tests/test_hosted_map_execution.py`
and lints both scripts. These tests mock libc, function pointers, subprocesses and
host identity. They verify the fixed bytes, profile delta, evidence classification,
closed environment and ownership cleanup without mapping or executing the stub.

```sh
python -I -B -m unittest discover -s packages/event-gateway/tests \
  -p test_hosted_map_execution.py -v
```
