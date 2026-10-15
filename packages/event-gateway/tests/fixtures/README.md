# Trusted contract fixtures

`trusted-contract-families.zip` contains immutable Git blob bytes for all nine
contract families. Tests read members with `ZipFile.read`; nothing is
extracted or executed, and tests require neither network access nor Git history.

`metadata.json` freezes the policy entries, including revision labels and all
seven snapshot hashes. It records these `knitli/toolshed` snapshot commits:

| Family | Snapshot commit |
| --- | --- |
| legacy | bd46ecbc6d65e64f075be1ed2b9f8dde325f03f9 |
| no-start | 4d4418231d1c5c3492c52b173b118476d9b780fb |
| native-start | af1d569560f637407357829a92276c999a7cd3af |
| native-input-recorded | 83bd9751b4616298563f8e633bb71520f0dbf347 |
| native-admission | 3baeb6d5e8fa0fddceacc0c8c7151cdae4fe59c4 |
| native-runtime-status | d979c715aec6ad00d3d40f622249e9a46bdc179f |
| github-source-readback | 7c1c27ce5dbbdfc1af786a9f261da9cc7e22d43c |

Snapshots were copied from `packages/event-gateway/contracts/` with `git show`
and matched against every approved raw SHA-256 before inclusion. Source members
were copied from `knitli/knitli-site` at the native family's event revision
`ed23882eac491e26e070e3ef26cf8c0e9e702b38` (four sources) and control revision
`038716741534afe804fb75b9eab15dba6ddbee11` (nine sources). Every source was matched
to its manifest SHA-256. The runtime-status family adds control revision
`7675f40a4053795de03458c2741da4e3a475ce29` (eleven sources, including
`native-runtime-store.ts` and `native-admission-gate.ts`), retaining the same four event sources. Member paths
retain the repository paths and revision.

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
