# Offline coupled recovery: pending runtime review

This fixture repair has unit, type, and bundle checks only. No fresh native/Workerd
qualification has run. Historical proof JSON files remain historical.

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

## Concrete port proposal

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
to `node:http`. That failed attempt is preserved. The corrected interceptor has
not been exercised by another whole-harness run.

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

Use a fresh owned directory such as
`/private/tmp/native-workerd-recovery-qualification`, with private `home`, `tmp`,
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

For the current read-only inspection, the cloud source is
`/private/tmp/knitli-github-live-qualification/apps/os/packages/event-runtime/src`,
commit `c436b3efcb81b1ac6aadcbb6e6f81795e822720a`. Node is 24.19.0. These are
explicit proposal inputs, not a claim that the runtime has passed.

The outer Seatbelt proposal denies all networking except Unix sockets and exact
loopback ports 49731–49734. Keep the established system/Python runtime reads and
literal `/` loader read, but allow task data reads only in the staged tree and the
exact verified venv. Writes are only private task scratch and necessary devices.
Set `HOME`, `TMPDIR`, `TMP`, and `TEMP` to task scratch via `env -i`; supply no
operator tokens, proxies, loader overrides, or application state. The broker
inherits only its explicit synthetic environment. Node gets no external network
permission. Existing single-port 49731 authorization is insufficient for this run.

Review the final staged file manifest, interpreter/venv path, four-port profile,
output paths, and exact command together before running. The command shape is:

```sh
"$VERIFIED_VENV/bin/python" -I "$TASK/fixture/coupled-workerd.py" \
  --installed --restart-native --package "$TASK/package" \
  --qualifier "$TASK/fixture/qualify_native_bridge.py" \
  --binary "$TASK/candidate/codex" --binary-sha "$REVIEWED_CANDIDATE_SHA256" \
  --node "$TASK/runtime/node" --cloud-source "$TASK/cloud/apps/os/packages/event-runtime/src" \
  --esbuild "$STAGED_ESBUILD_PACKAGE" --miniflare "$STAGED_MINIFLARE_PACKAGE" \
  --output "$TASK/proof/recovery.json"
```

The fixture is not responsible for approving or broadening its outer sandbox.
