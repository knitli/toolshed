# Native provenance fixtures

These are test data, not native build or qualification evidence.

`native-legacy-v1-inputs.json.gz` freezes the reviewed legacy builder, producer,
and build-workflow bytes as base64 JSON values keyed by repository path. The
legacy manifest and patch remain the checked-in immutable assets; their hashes
are bound by the registered legacy tuple. The fixture test confirms that it never
reads the three mutable current files and that the resulting complete five-input
tuple matches the registry.

`native-v2-producer-receipts.json.gz` contains core-idle57 and terminal-query71
receipts returned by the actual `produce_native_ci_artifact.produce` from the
frozen builder worktree at
`/opt/coder/toolshed/.worktrees/native-recipe-builder-v2-20261017`.
The fixture also freezes that builder, producer, workflow, and registry as base64
blobs. The selected manifest and all selected recipe assets are read from their
pinned checked-in paths. Tests hash the actual fixture blobs at fake immutable
HEAD/BUILD/MAIN revisions; they do not substitute claimed hashes for bytes.

Generation mocked only `package_native_client.package`, producer `command`, and
producer `environment`. The package mock writes tiny ARM64 Mach-O-header test
payloads and returns the recipe/source evidence fields defined by the actual
builder, including exact patches, source map, canonical before/after inventory
hashes, and archive scope. No compilation, native execution, provider call, or
GitHub request occurred. The producer itself performs its input/output checks
and writes each receipt. Stub run identity is run123/attempt2, head `cccccccccccccccccccccccccccccccccccccccc`;
it does not identify a real build.

The one-off generation script is retained for this implementation session at
`/private/tmp/native-v2-verifier-qa/generate.py`. It initially freezes all legacy
inputs; the final legacy bundle retains only the three mutable files described
above. No general generation command is added to production.

Frozen v2 input identities for core-idle57:

| Input | SHA-256 |
| --- | --- |
| `builderSha256` | `b444846aee2848dcb4db7d72898a0a3a32d4a722503f558cea618a44c4ede89c` |
| `producerSha256` | `b1538b6e42be51c18112d91c80ed1a0b5c383daba8f46df1a1a1ef81d8c5e7db` |
| `registrySha256` | `b037bed7567079b3a36523ae052fb608e4cfad69fcb43a747acd4179514d4b0f` |
| `sourceManifestSha256` | `8c6f136f215deb4dca30b4d230eede5eaf8e65c1850635b199b62457a7759924` |
| `workflowSha256` | `908a68c05231247b36b8a5ab7af90590440d7023c6d24d0ab9b7ccda412b682f` |

Terminal-query71 uses the same four program/policy blobs and its registered
manifest hash `19519a2d017b3c62726d13f620cecaa3a37a34cd3fb0f414e3754e210dcb9269`.
The JSON additionally records producer/builder hashes and mocked function names.

Inspect either bundle without executing its content:

```sh
python3 -c 'import gzip,json,sys; print(json.dumps(json.load(gzip.open(sys.argv[1], "rt")), indent=2))' tests/fixtures/native-v2-producer-receipts.json.gz
```
