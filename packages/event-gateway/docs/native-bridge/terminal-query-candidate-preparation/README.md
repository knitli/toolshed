# Inactive terminal-query source preparation

This directory records a source recipe only. It does not authorize a candidate,
build, native execution, installation, promotion, or deployment. Existing release
pins, active builders, producer exports, evidence policy, and owner execution gates
are unchanged.

The recipe starts at upstream commit
`a956835d020762cb2b570053af06f643a11c0ecc`, followed by these seven patches in order:

1. Core-idle implementation.
2. Terminal-history cumulative implementation.
3. Public-query patch `01`.
4. TUI terminal-query patch `02`.
5. Generated protocol patch `03`.
6. Generated SDK patch `04`.
7. Terminal-query recovery repair patch `05`.

`manifest.json` pins the existing parent manifests and each patch by path, byte
length, and SHA-256. Its final map contains the **71 selected source files** after
SDK generation and recovery repairs. The verifier independently composes the
parent maps through the 57, 66, and 71-file stages and checks the final result.
The upstream `codex-rs/app-server/tests/suite/v2/mod.rs` supplement is pinned to
its bytes at the upstream commit; its final patched bytes are in the selected
map. This supplement records a replay prerequisite, not an extra patch.

Run the standard-library-only verifier from the repository root:

```sh
python3 packages/event-gateway/docs/native-bridge/terminal-query-candidate-preparation/verify.py
python3 packages/event-gateway/docs/native-bridge/terminal-query-candidate-preparation/verify.py --source-root /path/to/existing/patched/source
```

The first command authenticates the manifest, ordered patch assets, and parent
maps. The optional source argument reads and hashes the 71 selected files from
an existing source tree. Neither command applies patches, invokes subprocesses,
builds, or executes native code. Input sizes are bounded; unsafe paths, symlinks,
unexpected preparation-directory entries, and altered assets are rejected.

Successful output always reports `authorization: none` and
`coverage: selected_source_only`. `sourceFilesChecked: 0` means metadata only;
`71` means the selected source files also matched. Unlisted files in a source
checkout are outside this proof. These hashes do not establish whole-tree
authenticity, build reproducibility, binary provenance, runtime behavior, or
native acceptance. No new provenance family is defined here.

Any future integration must first establish the trusted recipe and release-policy
contract, separately review builder/producer integration and release pins, and
satisfy the owner's existing full-suite and native execution gates. This inactive
preparation is not permission to perform those steps.
