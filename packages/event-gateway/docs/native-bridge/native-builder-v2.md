# Native builder v2 candidates

The builder defaults to `core-idle-v1`, revision 1 (57 selected source files).
`--family terminal-query-v1 --revision 1` explicitly selects the inactive 71-file
recipe. Both families produce schemaVersion 2 CI receipts. The workflow offers
only those family choices and passes the choice through a quoted environment
variable; revision remains 1. Existing v1 artifacts require the verifier's
separate registered historical-tuple compatibility path.

The package evidence and receipt carry the same `recipe` object:
`family`, integer `revision`, and `manifestSha256`. Receipt `inputs` contains
exactly `builderSha256`, `producerSha256`, `workflowSha256`, `registrySha256`,
and `sourceManifestSha256`. The manifest digest equals the recipe digest.
`appliedPatches` records ordered `{path, bytes, sha256}` descriptors, including
all seven terminal patches. No singular patch digest represents that family.

The registry authenticates the selected manifest, parents, and patches. The
builder applies authenticated patch contents to a fresh full archive of the
pinned upstream commit. It checks the terminal base prerequisite in that archive
before applying patches. It verifies every selected source hash before and
after compilation, preserving the legacy byte-size checks and bounding terminal
source reads to 2 MiB per file. Inventory hashes use sorted UTF-8 paths followed
by NUL and the raw SHA-256 digest for each file. The producer checks recipe
assets and implementation input hashes before and after packaging and correlates
package identity with the selected recipe before writing the receipt.

This integration must follow merged v2 verifier policy. Source-only and mocked
checks do not qualify a native binary. No dispatch, installation, pin promotion,
provider/client execution, or activation is authorized by this change. The
previous failed full native workspace run remains failed and unwaived; terminal
candidates require separate exact-candidate qualification.
