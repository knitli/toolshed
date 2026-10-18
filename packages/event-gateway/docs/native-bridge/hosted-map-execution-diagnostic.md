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

The `--startup-only` mode schedules only the existing `control_before:read` case.
It verifies and reads the same fixture under the existing control profile, without
loading libc, mapping memory or invoking the fixed callback. Even a healthy read
remains `INCONCLUSIVE`, with `qualified: false`, because the full matrix is absent.

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

The child emits these exact newline-terminated stderr markers in order:

```text
startup:script_entry
startup:ctypes_imported
startup:imports_complete
startup:platform_checked
startup:limits_set
startup:fixture_opened
startup:fixture_verified
```

Raw stderr is retained. An exact shorter prefix can locate the last completed
startup phase but is never healthy; reordered, repeated or additional lines are
invalid. A healthy receipt requires all seven markers, zero exit status,
confirmed cleanup and no execution or cleanup error. A complete trace alone
does not establish matrix success.

The full-matrix command, after a separately approved Cloud integration, is:

```sh
python -I -B packages/event-gateway/scripts/probe_hosted_map_execution.py --go
```

The separately approved startup-only command is:

```sh
python -I -B packages/event-gateway/scripts/probe_hosted_map_execution.py --startup-only
```

These are source capabilities. The Cloud workflow's fixed invocation and
reviewed pin are a separate integration change; adding this source mode does not
change that workflow or authorize execution. Both modes retain the same admission,
profiles, bounds and cleanup. `--go` continues to select the full matrix.

Both commands intentionally reject ordinary local environments. Do not change
admission variables, weaken profiles or retry a failed attempt to force a pass.
Pre-opened descriptors, aliases, other mapping forms, dynamic loading and actual
CLT runtime closure are outside this diagnostic's claim.

## Private startup discriminator candidate

The diagnostic-only `--site-startup-only` mode selects a fixed interpreter-version
control and two marker-only child launches. All three use the same existing
`control_before` profile and closed environment. The marker launches differ only
by adding `-S` to `-I -B`; the child emits a fixed marker and exits before its
extension imports, fixture access or mapping code. No sandbox permissions change.

The fixed case order is `site_startup:version`, `site_startup:enabled`, then
`site_startup:disabled`. Both marker cases emit exactly
`startup:site_startup_marker` followed by a newline on stderr. The version case
uses `-I -B --version` without a script or module.

The version control tests whether the executable reaches its version-reporting
path. It does not establish full interpreter initialization. The normal marker
includes automatic site initialization; the `-S` marker omits it. Interpret the
raw receipts as follows, requiring zero exit status, the exact expected output,
and confirmed cleanup before treating a control as successful:

| Result | Supported conclusion |
| --- | --- |
| Version succeeds, both markers fail | Early interpreter entry works; the shared later initialization/script path remains suspect. |
| Only the `-S` marker succeeds | The difference involves automatic site initialization or its effects; no specific denied operation is established. |
| Only the normal marker succeeds | Startup behavior depends on configuration; this does not support blaming site initialization. |
| Both markers succeed | Both minimal script paths work in this attempt; the prior abort is not reproduced or explained. |
| Version and both markers fail | Launcher, process-image loading and early interpreter failure remain unresolved. |

No outcome qualifies the runtime or constitutes mapping/execution-matrix evidence.
The mode always reports `INCONCLUSIVE` with `qualified: false`; raw receipts remain
the evidence. A failed control does not suppress later controls when cleanup is
confirmed, but uncertain cleanup stops further launches. Default full-matrix and
startup-read modes retain their existing behavior.

Adoption requires a separate Cloud integration pinned to the actual reviewed
Toolshed merge, with a separate closed discriminator receipt set in the exporter.
The mapped-matrix receipt set and PASS requirements must remain unchanged.
No candidate preparation, merge or pin update authorizes a hosted execution.

## Fixed version launch comparison

The diagnostic-only `--version-launch-only` mode compares exactly two launches:

1. `version_launch:direct`: the exact frozen interpreter with `-I -B --version`.
2. `version_launch:sandboxed`: the unchanged sandboxed version command, using
   `sandbox-exec -f control_before.sb` followed by that same interpreter and flags.

Both launches use the same closed environment, working directory, null stdin,
captured output pipes, new session, closed inherited descriptors, time/output
bounds and owned-child cleanup. The direct control is outside the sandbox, but
its only admitted command prints the interpreter version and exits: no script,
module, variable code, fixture read, mapping or callback is selected. The sandbox
profile remains unchanged. Each fixed command is attempted at most once; uncertain
cleanup stops the remaining case. Every outcome is `INCONCLUSIVE` with
`qualified: false`, including two successful version outputs.

| Result | Supported conclusion |
| --- | --- |
| Direct succeeds, sandboxed fails | The added launcher/profile path accounts for the observed difference; this does not identify a denied operation or failing executable image. |
| Both fail | The shared launch context remains suspect; sandbox policy is not established as the cause. |
| Both succeed | The earlier abort is not reproduced in this attempt; no runtime qualification follows. |
| Direct fails, sandboxed succeeds | The contrast does not support the proposed sandbox-specific failure; retain the raw evidence without attributing a cause. |

Success here requires zero exit status, the expected version output and confirmed
cleanup. Parent/helper success under their ordinary launch environment is not a
substitute for this direct control. Cloud receipt validation, an actual reviewed
merge pin and separate execution approval remain required before a hosted run.
Existing full-matrix, startup-read and site-startup modes keep their behavior.

## Mock verification

The normal Event Gateway workflow discovers `tests/test_hosted_map_execution.py`
and lints both scripts. These tests mock libc, function pointers, subprocesses and
host identity. They verify the fixed bytes, profile delta, evidence classification,
closed environment and ownership cleanup without mapping or executing the stub.

```sh
python -I -B -m unittest discover -s packages/event-gateway/tests \
  -p test_hosted_map_execution.py -v
```

### Version-pair crash observation

The version-only pair additionally records parent-owned child PID, parent PID, UID,
and paired UTC/monotonic launch and exit observations. After both children are
reaped, a best-effort observer waits once for 29 seconds, then examines at most
four new Python/sandbox-exec `.ips` candidates in the runner user's physical
`~/Library/Logs/DiagnosticReports` directory, baselined before the pair. The total
availability deadline is 30 seconds: the final scan has the remaining one-second
budget after that wait, with deadline checks and no retries. Local regular-file
reads and JSON parsing are bounded by size but are not hard real-time interruptible.

A match requires the owned PID/parent PID, file owner, exact frozen interpreter or
sandbox-exec path, and report event times inside the owned UTC interval; the
report-arrival allowance never widens that identity interval. Clock disagreement,
missing/private/malformed identity, ambiguous incidents, changed files, symlinks,
hardlinks, directory/candidate overflow, or unavailable reports yield the fixed
`unavailable` status. Reads are capped at 1 MiB per candidate and 2 MiB total.
Only executable class, a closed termination namespace classification and numeric
code, report SHA-256, and byte count survive parsing. No raw reports, paths,
frames, symbols, images, exception text, or other free-form crash data are saved.

These observations never change case return codes, cleanup truth, the fixed pair,
control profile, environment, or qualification. The result remains `INCONCLUSIVE`
and `qualified: false`; unavailable evidence does not show that no crash occurred.
