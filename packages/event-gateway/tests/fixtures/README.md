# Trusted contract fixtures

`trusted-contract-families.zip` contains immutable Git blob bytes for all fifteen
contract families. Tests read members with `ZipFile.read`; nothing is
extracted or executed, and tests require neither network access nor Git history.

`metadata.json` freezes the policy entries, including revision labels and all
seven snapshot hashes. It records these snapshot commits or prepared-export identifiers:

| Family | Snapshot commit or prepared export |
| --- | --- |
| legacy | bd46ecbc6d65e64f075be1ed2b9f8dde325f03f9 |
| no-start | 4d4418231d1c5c3492c52b173b118476d9b780fb |
| native-start | af1d569560f637407357829a92276c999a7cd3af |
| native-input-recorded | 83bd9751b4616298563f8e633bb71520f0dbf347 |
| native-admission | 3baeb6d5e8fa0fddceacc0c8c7151cdae4fe59c4 |
| native-runtime-status | d979c715aec6ad00d3d40f622249e9a46bdc179f |
| github-source-readback | 7c1c27ce5dbbdfc1af786a9f261da9cc7e22d43c |
| github-source-control | prepared-export:c25ade9233013d97d56ed0fdfddf75453071066b |
| github-watch-control | prepared-export:ccdb861eb9126ccd8319d50da5cd6689f91435dd |
| github-watch-owner-rpc | prepared-export:59940bde10db5584247c8648c985f246f546226f |
| github-pinned-history-read | prepared-export:49122dd4ac2a358d87e8cd727fd8e817ae183dac |
| cloud-guard-baseline-messaging-v2-dispatch | prepared-export:7b63bee97395a70e05ffb08ee214e8351f6dda06 |
| github-initial-custody | prepared-export:3ad64222999bc2aaa60f50623120e302edc5f8bd |
| github-initial-plan-material | prepared-export:5d3c326677bab6cb8ac3115dcbc65e7956676ba9 |
| github-material-page-parity | prepared-export:5d3c326677bab6cb8ac3115dcbc65e7956676ba9 |

Every snapshot matched all seven authorized raw SHA-256 values before inclusion.
The identifiers distinguish committed Toolshed snapshots from prepared exports.
Source members
were copied from `knitli/knitli-site` at the native family's event revision
`ed23882eac491e26e070e3ef26cf8c0e9e702b38` (four sources) and control revision
`038716741534afe804fb75b9eab15dba6ddbee11` (nine sources). Every source was matched
to its manifest SHA-256. The runtime-status family adds control revision
`7675f40a4053795de03458c2741da4e3a475ce29` (eleven sources, including
`native-runtime-store.ts` and `native-admission-gate.ts`), retaining the same four event sources. Member paths
retain the repository paths and revision.

The separate `assigned-stock-control` archive pins cloud commit
`e12da5feb121eecba3c0b3b578e0e4341cb2a2dc`: 58 control sources and four event
wire sources form 60 unique source paths. Each archived file is the exact Git
blob for its recorded path and revision, checked against the manifest SHA-256.
The stock archive freezes its complete member list and archive digest; the
historical family archive remains a separate byte-for-byte unchanged fixture.

Source provenance tests are separate from runtime authorization: the trusted
verifier authorizes exact snapshot bytes, not source code evaluated from a PR.
When deliberately authorizing another family, retain existing fixtures and
review new source bytes, snapshot bytes, and policy metadata together.

The GitHub source-readback family pins merged cloud `7d738a387cdbaab795e1538a240c1b85b6b7a0f7`
with 23 control sources covering the readback schema, delegated authorization and
deadlines, GitHub host/client/admission, grants, retained pagination and shared
identity helpers. Its request/result vectors cover the emitted metadata boundary;
the existing event sources and all previous family hashes are retained. The
Unicode length fix ships with this authorization; the consumer snapshot rotation
follows after the trusted-main policy merges. These pins
preserve the local read path; they do not qualify the external authority service,
GitHub API or platform runtime. The snapshot commit is the reviewed consumer
candidate, not an assertion that it is deployed or live-qualified.

The `github-source-control` family is a prepared export of cloud commit
`c25ade9233013d97d56ed0fdfddf75453071066b`, using Node 24.19.0 and the deployed
lockfile's Zod 4.6.5. Its metadata snapshot identifier is `prepared-export:` plus
that cloud commit; no consumer snapshot commit exists at authorization time.
The separate consumer rotation will copy these exact reviewed bytes.

Its 32-source inventory adds source-control, watches, manual-canary and scope,
native-admission-canary, admin-api and admin-types, and shared auth/admin-security
to the prior 23-source readback inventory. Each source was read with `git show`
at the immutable cloud commit and checked against its manifest hash. All four
transport source blobs match the retained `ed23882` pin byte-for-byte; control
fixture bytes also remain unchanged. All seven previous policy entries and
archive source/snapshot bytes are retained. Tests check the entire new family,
all required snapshot mutations/omissions, all 32 source hashes and omissions,
and the exact source inventory. This is provenance authorization, not deployment
or source activation, publication, native delivery, or live qualification.

The `github-watch-control` family records cloud commit
`ccdb861eb9126ccd8319d50da5cd6689f91435dd` as a `prepared-export:` snapshot,
using Zod 4.6.5. Its 34-source inventory adds `github/watch-store.ts` and
`github/watch-control-internal.ts` to the source-control inventory. Each source
blob is read at the pinned commit and checked against the manifest hash.
The four event source blobs retain the `ed23882` revision, and the control
fixture corpus is unchanged. All eight prior families and their source/snapshot
bytes remain intact. Tests check the complete family, every snapshot mutation or
omission, all 34 source hashes and omissions, and the exact source inventory.
This fixture records provenance only; it does not enable the public watch kernel,
rotate the consumer snapshot, or qualify deployment, native delivery, or recovery.

The `github-watch-owner-rpc` family uses actual event merge
`59940bde10db5584247c8648c985f246f546226f` and control merge
`b152b1b92fec860354cacd406b0d72274a97713c`. Its `prepared-export:` identifier
uses the event revision. Four event sources include the embedded 45-case semantic
corpus; 36 control sources add `github/watch-kernel.ts` and
`github/watch-owner-proof.ts`, with Zod 4.6.5. Every source hash was independently
checked against its immutable revision; all 36 control sources also match the
event revision. The control fixture bytes are unchanged. All nine prior policy
entries and archived members are retained. Tests cover authorization, every
required snapshot and source-hash mutation/omission, closed provenance, all 45
semantic verdicts, and a changed verdict with a self-rehashed event manifest.
This authorizes exact bytes only; consumer rotation and runtime qualification
remain separate.


The `github-initial-custody` family pins the actual #902 merge
`3ad64222999bc2aaa60f50623120e302edc5f8bd` for its 55 control sources, using
Node 24.19.0 and Zod 4.6.5. Its snapshot identifier is `prepared-export:` plus
that control revision. The private exporter verified every selected source hash
before evaluating the reviewed DTO/proof modules. The control fixture bytes are
unchanged; the control manifest records the expanded, merged-source provenance.

All five event-v1 files retain their exact bytes and event revision
`7b63bee97395a70e05ffb08ee214e8351f6dda06`, including all 45 semantic verdicts.
The historical metadata source map at that revision remains the original
41-entry union. All 315 historical archive payloads, twelve policy entries,
snapshot mappings, and source maps are preserved; the archive adds seven
snapshot members and 55 source members. Tests freeze historical payload and
metadata digests, check the exact new source inventory and event-source subset,
and reject snapshot/source-hash omissions, mutations and a self-rehashed
semantic-verdict change.

The sixteen additional sources cover GitHub initial conversion, manifest and
watch custody, reconciliation, material access, source references, and
quarantine inventory. This is selected GitHub/initial-custody provenance, not
whole-runtime dependency closure. It does not adopt the consumer snapshot or
exporter, deploy services, activate delivery, or release acknowledgments.


The `github-initial-plan-material` family pins control revision
`5d3c326677bab6cb8ac3115dcbc65e7956676ba9` with 57 sources. It adds
`github/reconciliation-planner.ts` and `github/initial-plan-material-read.ts`
to the initial-custody inventory. The control fixture corpus and all five event
files remain unchanged, including the 45 semantic verdicts.

The `github-material-page-parity` family retains that control revision and all
57 source hashes. It adds only the `githubMaterialRead` fixture corpus: 11 request,
15 result, and seven page-binding verdicts, plus the canonical signed-path proof.
The control manifest records the new fixture digest; all other control manifest
fields, previous fixture entries, event files, and historical archive members
remain unchanged. No new source revision or source hash is introduced. These
vectors check producer/consumer DTO and page-binding compatibility; native model
consumption, delivery, and production qualification require separate evidence.
