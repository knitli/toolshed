# Trusted contract fixtures

`trusted-contract-families.zip` contains immutable Git blob bytes for all six
approved contract families. Tests read members with `ZipFile.read`; nothing is
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
| native-runtime-status | 6ed20e3bf62665cf1ecbe618e8cc1ae277878a78 |

Snapshots were copied from `packages/event-gateway/contracts/` with `git show`
and matched against every approved raw SHA-256 before inclusion. Source members
were copied from `knitli/knitli-site` at the native family's event revision
`ed23882eac491e26e070e3ef26cf8c0e9e702b38` (four sources) and control revision
`038716741534afe804fb75b9eab15dba6ddbee11` (nine sources). Every source was matched
to its manifest SHA-256. The runtime-status family adds control revision
`7675f40a4053795de03458c2741da4e3a475ce29` (ten sources, including
`native-runtime-store.ts`), retaining the same four event sources. Member paths
retain the repository paths and revision.

Source provenance tests are separate from runtime authorization: the trusted
verifier authorizes exact snapshot bytes, not source code evaluated from a PR.
When deliberately authorizing another family, retain existing fixtures and
review new source bytes, snapshot bytes, and policy metadata together.
