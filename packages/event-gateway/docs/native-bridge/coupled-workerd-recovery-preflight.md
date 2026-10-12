# Offline coupled recovery: candidate qualification

**PASS, 2026-10-12 UTC (October 11 in America/New_York).** The installed gateway,
explicit native candidate, and disposable Workerd completed one controlled
native-process restart and lost-observed-ACK recovery. The exact receipt survived
native restart; after permit expiry and a local Store/CloudClient restart, the
same observed ACK recovered with a fresh proof nonce and no additional native start.
The cloud attempt, delivery, and claim became observed; the source watermark
advanced and the actual registry slot was released. Mock model counts were
primary=1, title=1, unknown=0; real model calls were zero.

[Exact proof](coupled-workerd-recovery-proof.json) SHA-256:
`2ad93e0b27bc1a6b4d37e67710da43b3113d8b903d14915c3bf7d76358163b62`.
[Supervision and integrity evidence](coupled-workerd-recovery-attempt-three.json)
records exit 0 in 8.49 seconds, no timeout, no surviving owned process groups,
and unchanged 2,266 staged files, 47 confined links, and 887 prior-venv files.
Absolute paths in these unmodified evidence files identify historical inputs;
reproduction does not require those locations.

This is candidate-only evidence with synthetic authority and a manual source.
Production admission, production GitHub ingestion, and deployment/promotion are
not proved. Terminal no-start settlement passed in a separate mode below. No launcher pin changed. Earlier proof
files retain their historical scope.

| Executed input | Pin |
| --- | --- |
| Fixture source before documentation/rebase | `e219af0e9a609217d987b4a9d3194dae2a1c428b` |
| Gateway source base | `d76fa4bcab64d416b6b83c415ec558c7954a922c` |
| Cloud source | `c436b3efcb81b1ac6aadcbb6e6f81795e822720a` |
| Native candidate SHA-256 | `62eac2a58bdac388850948aa82bf341c376e8653010d628de12ba642a2e343a3` |
| Companion host SHA-256 | `679eedaea70529aa1cffc9bc0a0788c186412663544fa76c09d63b57f383a65a` |
| Outer four-port profile SHA-256 | `543b805aae12a71f9f9300b9685be50ed48b777f732846955faae65ea1de4051` |

Two failed fixture attempts remain preserved as
[attempt one](coupled-workerd-recovery-attempt-one.json) and
[attempt two](coupled-workerd-recovery-attempt-two.json). The first targeted
`node:http2` instead of the dependency's actual `node:http` listener and failed
before native startup. The second reached actual admission but asserted an
nonexistent envelope `nodeId` before dispatch. The corrected check compares four
envelope/admission identity fields and separately requires the attached node and
signed transport audience to match the local node. Neither failure is counted as
recovery evidence; each retry received separate review with the same network profile.

The runner now enrolls the synthetic node, calls the real runtime challenge API,
obtains a fresh witness through `NativeClient`, and calls the real attach API before
publishing a manual delivery. Empty runtime/binding tables are checked before
admission and one persisted runtime/binding afterward. The local injected adapter
uses the admitted native binding, generations, and lease. `fixtureAdmission` keeps
the challenge, native evidence, attach response, two wire calls, and readback
separate from the existing four dispatch/ACK calls. No runtime SQL is seeded.

Access/Messaging identity and budget, admin enablement, manual publication, queue,
and loopback transport remain explicit fixtures. The local Store is still opened
by this fixture rather than the daemon control flow. `productionAdmissionProven`
remains false; this does not qualify production GitHub ingestion or deployment.

`--installed` now requires `python -I` and runs the shared
`qualification-installed.py` checks before any gateway import. That checks the
wheel RECORD, exact trusted source/contracts, import location, interpreter, and a
fresh bytecode-cache location. `--package` still names the package directory;
the trusted Python source is its `src/event_gateway` child. The explicit candidate
binary hash remains a qualification input, not a change to production launcher
pins. Freeze the companion executable separately before running.

## Separate terminal no-start settlement

**PASS, same frozen candidate and fixture payload.** A separately reviewed,
180-second-bounded `--terminal-no-start` run completed in 8.44 seconds. The native
backend actually refused the expired permit with `terminalNotStarted` /
`permitExpired`; the fixture lost that reply before local persistence. Read-only
native recovery returned the exact terminal receipt. Workerd committed no-start
settlement before its reply was also lost, and identical settlement replay with a
fresh node proof retired the original attempt and permit. Exactly one fresh
replacement attempt then started. Mock model counts were primary=1, title=0,
unknown=0; real model calls were zero. Both owned process groups exited, and the
2,266 staged files and 47 links remained unchanged.

[Exact no-start proof](coupled-workerd-recovery-no-start-proof.json) SHA-256:
`237535909e72971f8792a2cc3772cf8041fa9a610dede8e48b50313e0ea47e5c`.
[No-start supervision](coupled-workerd-recovery-no-start-supervision.json) SHA-256:
`296171d1eed6f93230a2dcdacbd94c8cce37a054992643195ed19c3b273e43be`.

This is a separate mode from the native-restart recorded-input proof above.
It sets `oldStartNoStartSettlementProven: true` but does **not** restart the native
process or prove terminal-receipt survival across native restart. Production
admission remains false in both modes. Reproduce it with the same bounded command
and frozen inputs below, replacing `--restart-native` with `--terminal-no-start`
and choosing a fresh exclusive output directory. Do not combine those flags.

## Rebase and final offline checks

The branch was rebased onto `bfb9700f5e90504bf9074d5d638e758e80a3692c`
(PR #74) after execution. That change affects README, the event-control-v1
export/fixtures/manifest, and two consumer test files. It changes no executed
Python module, native fixture, or packaged event-v1 contract. All 21 proof source
hashes and 20 installed-package hashes still match; all 143 cloud bundle input
hashes match the frozen stage. The installed preflight checks `src/event_gateway`
and `contracts/event-v1`, so the event-control-v1 corpus change does not alter
its inventory. The original proof was retained without relabeling its source
commit or repeating the native run.

Validation before the review fixes: **479 Python tests, four Node fixture
tests, Ruff, contract synchronization check, and `git diff --check` passed**.
The Python suite ran with external networking denied and local test sockets
allowed. The native proof used the stricter four-fixed-port profile below.

Review fixes subsequently declared the runner configuration globals, changed an
invalid-listener test to a second loopback address, and replaced test-only source
evaluation with a direct TypeScript import using scoped dependency hooks. Positive
installed-preflight ordering and settlement-integrity mutation tests were added.
These changes were checked offline; the archived native runs retain their original
source hashes and were not rerun. The global declarations change the current Python
runner hash, so those historical proofs do not certify its exact current bytes.
Final review-fix checks passed: 481 Python tests, four Node tests, Ruff including
the runner, contract synchronization, and diff validation.

## Fixed execution ports

| Listener | Flag | Default |
| --- | --- | --- |
| Synthetic native model | `--model-port` | 49731 |
| Miniflare entry | `--entry-port` | 49732 |
| Miniflare internal HTTP loopback | `--loopback-port` | 49733 |
| Python-facing broker | `--broker-port` | 49734 |

All four must be distinct integers from 1024 through 65535. All bind to
`127.0.0.1`. No port discovery or fallback to an ephemeral listener is allowed.
The pinned Miniflare lacks a public internal-loopback-port option, so the broker
intercepts exactly one HTTP `listen(0, '127.0.0.1', callback)` call during startup,
substitutes the fixed port, and restores the prototype on success or failure.
Unexpected calls or dependency drift fail startup. Failed startup restores the
prototype without replacing the original readiness error. This interception has stubbed
causal tests; the first staged startup failed before native launch because the old interceptor
targeted `node:http2`, while the bundled name `import_node_http2` actually resolves
to `node:http`. That failed attempt is preserved. The corrected interceptor ran in the passing
third attempt under the unchanged four-port profile.

Current cloud `api.ts` reaches `github/client.ts`, which imports `node:crypto`.
The bundle therefore retains this builtin import. The fixture retains production's
compatibility date `2026-10-05` without adding a compatibility flag: the installed
Wrangler/Miniflare effective-configuration audit resolves that date and an empty
flag list to Node compatibility mode `v2` (automatic since `2026-08-04`). No cloud
configuration change is needed. This configuration check is not runtime proof.

The fixture sets `cf:false`: the frozen Miniflare `setupCf` false branch returns
placeholder request metadata immediately, avoiding its default outbound fetch of
`https://workers.cloudflare.com/cf.json`. The four-port sandbox is unchanged.

## Inputs to stage and freeze before execution

Use a fresh owned `$TASK` directory, with private `home`, `tmp`,
`state`, and `proof` children. Stage only these inputs, retaining relative module
resolution paths and recording SHA-256 for every regular file plus symlink targets:

- `fixture/`: this runner, broker, Worker, `coupled-workerd-source-hashes.mjs`,
  `qualification-installed.py`, and the independently selected native qualifier.
- `package/`: exact `src/event_gateway` Python sources and `contracts/event-v1`
  corresponding to the installed wheel. Freeze the wheel provenance and the
  installed environment, including third-party dependencies, separately.
- `candidate/`: the explicitly reviewed `codex` and sibling
  `codex-code-mode-host`; no installed application discovery or shipping pin edit.
- `runtime/node`: the reviewed Node executable; esbuild 0.28.1, Miniflare
  5.20261001.0-alpha, workerd 1.20261001.1, their installed transitive package
  closure, and the matching darwin-arm64 esbuild/workerd executables. Preserve
  package-local resolution links inside the staged tree. Do not install packages.
- `cloud/`: the explicitly selected cloud commit's bundle input closure, retaining
  its `apps/os` hierarchy and required package manifests/resolution links. A
  compile-only esbuild metafile identifies the inputs; it does not freeze them by
  itself. Reject links that escape the staged tree.

The executed cloud source ends at `apps/os/packages/event-runtime/src`, commit
`c436b3efcb81b1ac6aadcbb6e6f81795e822720a`; Node is 24.19.0. Freeze the
complete input closure again before any new run. The proof is for the recorded
bytes, not arbitrary later revisions.

The executed outer Seatbelt profile denies all networking except Unix sockets and exact
loopback ports 49731–49734. Keep the established system/Python runtime reads and
literal `/` loader read, but allow task data reads only in the staged tree and the
exact verified venv. Writes are only private task scratch and necessary devices.
Set `HOME`, `TMPDIR`, `TMP`, and `TEMP` to task scratch via `env -i`; supply no
operator tokens, proxies, loader overrides, or application state. The broker
inherits only its explicit synthetic environment. Node gets no external network
permission. Existing single-port 49731 authorization is insufficient for this run.

Review the final staged file manifest, interpreter/venv path, four-port profile,
output paths, and exact command together before running. The executed command
shape is below. Set the variables to explicit verified
artifacts; no private checkout path is required. The exact native artifacts and
macOS sandbox are external prerequisites, so this is not a self-contained test.
Run this argv only through a reviewed supervisor with a 180-second hard deadline,
exclusive output creation, tracked descendant identities/process groups, TERM/KILL
cleanup of owned groups, and post-run input rehashing. The archived attempt-three
evidence records that bound and the resulting group cleanup. A shell timeout alone
does not replace descendant supervision; the native restart owns separate groups.

```sh
/usr/bin/sandbox-exec -f "$REVIEWED_PROFILE" /usr/bin/env -i \
  PATH=/usr/bin:/bin HOME="$TASK/home" TMPDIR="$TASK/tmp" TMP="$TASK/tmp" TEMP="$TASK/tmp" \
  "$VERIFIED_VENV/bin/python" -I -B "$TASK/fixture/coupled-workerd.py" \
  --installed --restart-native --package "$TASK/package" \
  --qualifier "$TASK/fixture/qualify_native_bridge.py" \
  --binary "$TASK/candidate/codex" --binary-sha "$REVIEWED_CANDIDATE_SHA256" \
  --node "$TASK/runtime/node" --cloud-source "$TASK/cloud/apps/os/packages/event-runtime/src" \
  --esbuild "$STAGED_ESBUILD_PACKAGE" --miniflare "$STAGED_MINIFLARE_PACKAGE" \
  --model-port 49731 --entry-port 49732 --loopback-port 49733 --broker-port 49734 \
  --output "$TASK/proof/attempt/recovery.json" \
  > "$TASK/proof/attempt/run.stdout" 2> "$TASK/proof/attempt/run.stderr"
```

The fixture is not responsible for approving or broadening its outer sandbox.
