# Controlled native / local gateway / workerd qualification

**PASS, 2026-10-07.** One real native input-recording receipt was carried through the production local gateway and production cloud coordinator/registry in disposable workerd. An observed ACK committed before its reply was deliberately lost; after permit expiry and a Store/CloudClient restart, the exact ACK recovered successfully without another native start.

This is fixture-qualified integration evidence. Production admission is **not proved**. The native process was **not restarted**. No deployment occurred.

## Recorded evidence

[Historical proof](coupled-workerd-proof.json) is the original JSON, copied byte-for-byte. Its absolute paths identify the historical inputs, not required checkout locations. The separately parameterized [Python runner](coupled-workerd.py), [broker](coupled-workerd-broker.mjs), and [Worker fixture](coupled-workerd-worker.ts) retain the original assertions and authority mocks. Only paths, output location, and module resolution were rebound. One reproduction of these exact exported sources passed, exit 0.

| Input | Pin |
| --- | --- |
| Local gateway | `ef16ac7375b2feac0081cb4d6ba2be5ff025443b` |
| Cloud event runtime | `ed23882eac491e26e070e3ef26cf8c0e9e702b38` |
| Native qualifier launcher | `c60b5373c238763b1476350c6589b2527cb690eb` |
| Native executable SHA-256 | `26226b229488bc06b3f0f5e2c0623d4760af58d54c7cb729861692403418877a` |
| Qualifier file SHA-256 | `a91a33276c89035ea1e57f02170a2bb31eae5724adc6e10c597e48c335d94e31` |
| Historical proof SHA-256 | `2e1d1e985d0064c3bf15afe1abe6a07ef62f90bf4381501c8a344caf16589c90` |
| Exported-source reproduction SHA-256 | `d79375aeb36cf86f90df4ae82990db43973cdbbe4fdc3d12badadcc218a00af2` |

The independent source/artifact audit closed with no blocking finding within this declared scope. Audit SHA-256: `790d4e033bddca87e1be511e7221d7254253a89f627c70331ed1addb4b130324`. Its local artifact is `/private/tmp/event-coupled-native-workerd-independent-audit.md`; it did not rerun the native process. All 15 historical source hashes and the native binary matched; 14 cloud source files matched their manifest and pinned commit.

## What passed

Both historical and exported-source runs exercise these assertions:

- A real registry enrollment signature and real raw-body-bound node proofs reach production `eventFetch`; the broker forwards the Python CloudClient body bytes without JSON reconstruction.
- A real signed transport envelope reaches Gateway; production claim returns a permit. Native `Started` leads to submitted state, one actual registry slot, and no observed source watermark.
- The native private-FD receipt contains the full request identity and actual `inputRecorded` turn/item correlation. Its v7 item ID differs from the turn ID.
- The first observed ACK receives actual workerd HTTP 200/status observed before the harness raises its simulated lost-reply timeout. Local state remains pending.
- Production attempt, delivery, and claim become observed; immutable observed ACK and current source watermark are stored. The actual registry slots fall from one to zero and slot intents empty. Synthetic budget usage remains one.
- After permit expiry, reopening the same Store and constructing a fresh CloudClient sends identical ACK bytes with a fresh node-proof nonce. Readback is unchanged, local pending becomes zero, and bridge nonce/attempt tracking shows no repeated native operation.
- Exactly four CloudClient calls return HTTP 200: claim, submitted ACK, observed ACK, observed retry. Both runs record mock-model counts primary=1, title=1, unknown=0.

“Unchanged readback” covers six coordinator tables (`attempts`, `deliveries`, `native_claims`, `native_correlations`, `manual_sources`, `slot_intents`), registry slots, and synthetic budget. It does not cover every database table: fresh node-proof nonces necessarily affect the registry replay ledger. No universal Core deduplication or native-process restart guarantee follows from this retained-receipt recovery.

## Fixture and authority boundaries

The fixture inserts a qualified runtime row directly and creates a trusted enrollment challenge; it bypasses human admin/runtime qualification. Access edge handling accepts an exact synthetic token, Messaging identity and idempotent budget are in-memory mocks, manual publication is invoked through trusted fixture setup, queue metrics/backlog are mocked, and loopback replaces Mesh delivery. Actual registry capacity accounting is not mocked. Public runtime admission remains unavailable; `productionAdmissionProven` is false.

The native launcher creates temporary HOME/CODEX_HOME, strips inherited credentials/proxies, disables telemetry/update checks, and selects only the loopback mock model. The broker uses two loopback listeners guarded by a fresh private per-run secret, fixed POST routes, bounded requests, and cleanup on exit. The `realModelCalls: 0` field reflects this configuration and model counters; no independent network-capture claim is made.

An earlier setup attempt returned 403 because the fixture helper omitted its synthetic credentials. That failed run is excluded from passing causal evidence. The correction supplies only the declared fixture credentials; it does not bypass production node-proof validation. The old standalone phase-1 README/result used generated native IDs and is not evidence for the coupled native run.

## Reproduce with the exported sources

Prerequisites are deliberately external: the exact frozen native executable, qualifier script from its separate pinned commit, local and cloud source checkouts at the pins above, Python 3.13 with the gateway dependencies, Node 24.19.0, esbuild 0.28.1, and Miniflare 5.20261001.0-alpha with its installed workerd. No installation or deployment is performed by the runner. In particular, the qualifier script in the local gateway commit is older and does not support `input_recorded`; do not silently substitute it. The binary is not included here, so this is reproducible when those pinned artifacts are available, not a self-contained fresh-checkout test.

Set these paths to existing verified artifacts, then run from this documentation directory. `EVENT_CLOUD_SRC` ends at `apps/os/packages/event-runtime/src`; the package paths are module directories resolvable by Node `require`, not their parent node_modules directory. The output parent must exist. The runner verifies the supplied binary hash; verify the other source pins before running. Execution requires permission for disposable loopback listeners and launching the frozen binary.

```sh
"$EVENT_PYTHON" coupled-workerd.py \
  --package "$EVENT_LOCAL_PACKAGE" \
  --qualifier "$EVENT_QUALIFIER" \
  --binary "$EVENT_NATIVE_BINARY" \
  --binary-sha 26226b229488bc06b3f0f5e2c0623d4760af58d54c7cb729861692403418877a \
  --node "$EVENT_NODE" \
  --cloud-source "$EVENT_CLOUD_SRC" \
  --esbuild "$EVENT_ESBUILD_PACKAGE" \
  --miniflare "$EVENT_MINIFLARE_PACKAGE" \
  --output "$EVENT_PROOF_OUTPUT"
```

The output is fresh proof JSON plus `<output>.broker.log`. A passing run exits 0 and prints `result: PASS`, `productionAdmissionProven: false`. Fresh IDs/timestamps/signatures make the output hash run-specific. Retain its exact source hashes rather than expecting the historical proof hash to repeat.

The single exported-source reproduction used `/private/tmp/event-native-observed-corrected-wheel-consumer/venv/bin/python` (3.13.14), the existing pinned checkouts, and the existing Node/package paths. Its full result is `/private/tmp/event-coupled-workerd-reproduction.json`; its source trace is `/private/tmp/event-coupled-workerd-reproduction-manifest.json`. These local paths are archival references, not bundled prerequisites.

## Exported source hashes

| File | SHA-256 |
| --- | --- |
| `coupled-workerd.py` | `55f95ec736f9c874699099697f23a701efb32630eb59ef6defb69139f478c4d6` |
| `coupled-workerd-broker.mjs` | `b67aebc75bff36dfaac8ffd941bd2fecbd7cb262a145ff8ae3b691f2303b61f6` |
| `coupled-workerd-worker.ts` | `da3d53f6683c7cb3ac1e7cbda3cdbd107ed65939d0319ad8239b8759b470084b` |

The proof JSON contains each local Python module hash. The reproduction manifest additionally records the 14 cloud module hashes from the independently checked cloud manifest. Source checks passed after the reproduction; no product source was modified.

## One harness-assertion mutation check

A scratch copy of the exported harness changed only `FixtureRegistry.fixtureRead()` from returning the actual `SELECT * FROM slots` result to returning `[]`. Production claim and submitted ACK still ran; the exercise then failed at `AssertionError: retained slot` (exit 1). This is the expected assertion failure, not an authentication, tool, or runtime error.

Restoring the exact original Worker fixture bytes produced PASS (exit 0), using the same pinned native/local/cloud inputs. The exported repository files were never mutated. This demonstrates sensitivity of the retained-slot harness assertion; it is **harness-assertion mutation coverage**, not a product-causal mutation test or full harness coverage. Product-causal checks are separate evidence.

The scratch artifacts are under `/private/tmp/coupled-harness-assertion-check/`. Source hashes match the exported-source table above. The exact mutation is reproducible by replacing the registry method body with `return [];` while leaving the coordinator readback unchanged.

| Artifact | SHA-256 |
| --- | --- |
| `Mutated Worker` | `abc380a2c676ac13371db9f66e801393a3a31e242402c334ee4dbb3f78550755` |
| `red.log` | `fcbc3ce1e526589be0639fac380093a583d8c7c607957e50ac10d59a0f0f2599` |
| `Restored Worker` | `da3d53f6683c7cb3ac1e7cbda3cdbd107ed65939d0319ad8239b8759b470084b` |
| `green.log` | `f53949af1756e66ea8a5569b7049d71adf132cedb28db46ffc942d42cf4d9efc` |
| `green.json` | `e6b076210b7b5b36cb36e57726140289115b85e5035ee7c29ece0afab8e64907` |
| `manifest.json` | `9c09b4a3d1d059f98f40792fd7e48ea1f7cb6a80ae772b3d74c63a6996d4e5d8` |
