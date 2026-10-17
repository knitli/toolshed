# Native recipe registry

`scripts/native_recipe_registry.py` records two fixed source families using
frozen records and a read-only mapping:

| Family | Revision | Selected source entries | Registry selection |
| --- | --- | --- | --- |
| `core-idle-v1` | 1 | 57 | Default |
| `terminal-query-v1` | 1 | 71 | Explicit only |

The trusted provenance verifier supports registered legacy schema version 1
artifacts and schema version 2 recipe identities. It loads the registry from a
fixed sibling file in its trusted checkout, including under Python isolated mode;
candidate and build-head registry code is never run. Builder/producer adoption
follows this verifier policy separately. Direct production consumers are limited
to the verifier and builder; the producer accesses the registry through the
builder. This policy does not change launcher pins or authorize a build.

## API

- `recipe(family='core-idle-v1', revision=1)` returns the immutable registered
  recipe without reading assets. Unknown families or revisions are rejected.
- `validate_recipe(family='core-idle-v1', revision=1)` reads the fixed registered
  manifests, parent manifests, and ordered patches. It checks their pinned identity
  and manifest structure, then returns frozen `RecipeEvidence` with an immutable
  `file_sha256` map. It does not read source files or apply patches. Callers cannot
  supply replacement paths or reconstruct a recipe from an arbitrary manifest.
- `matches_historical_inputs(family, revision, inputs)` requires exactly
  `builderSha256`, `producerSha256`, `workflowSha256`,
  `sourceManifestSha256`, and `patchSha256`, with canonical SHA-256 values. It
  matches all five values against one complete registered historical tuple;
  independently valid hashes from different tuples cannot be combined.

Validation evidence explicitly reports `authorization="none"`,
`coverage="selected_source_only"`, and `source_files_checked=0`. The selected
hashes describe manifest entries, not verified source-file contents.

`terminal-query-v1` has **no historical input tuples**. Its registered source
assets describe preparation, not a qualifying historical build.

## Authority and evidence

A tuple match alone authorizes no artifact or binary. It bypasses none of the
current launcher, protected-main, or provenance checks. Source registration does
not establish successful native builds, full test coverage, installed-client
qualification, or permission to promote pins.

For legacy changed-pin candidates, the five candidate build-input files and registry
bytes must equal current main. The artifact's five build-head hashes must match
one complete registered legacy tuple, with the fixed legacy manifest and patch
identities. A later current-main tuple is not automatically accepted under v1.
The receipt must attest those authenticated historical inputs, even when current
builder, producer, or workflow bytes have changed. Registry freshness is checked
before publishing pending, success, or failure statuses. Unchanged current pins
retain their no-artifact fast path; both reviewed launcher transitions remain.
The v1 selection remains strict and cannot carry a recipe identity or 71-family
inputs.

Schema version 2 adds the exact recipe object `{family, revision, manifestSha256}`
to selection, receipt, and builder evidence. Those objects must equal the selected
protected recipe; the recipe object itself has no `schemaVersion`. Its manifest
digest also equals `inputs.sourceManifestSha256`. The complete v2 input tuple is
`builderSha256`, `producerSha256`, `workflowSha256`, `registrySha256`, and
`sourceManifestSha256`. Candidate and build inputs must match current main, and
selected manifests, parents, and ordered patches must match protected pinned
assets. There is no historical v2 fallback.

Builder evidence must contain the exact ordered patch descriptors and complete
selected source map/count. Each before/after inventory digest independently
matches SHA-256 over sorted UTF-8 paths, each followed by NUL and its raw digest,
from the protected map. Equality of the two observed inventories alone is
insufficient. The authenticated builder checks upstream prerequisites in a fresh
archive of the pinned upstream commit before applying patches; prerequisites are
upstream files, not additional documentation assets.

All new registry-dependent builds, including the default 57-entry family, must
emit v2 receipts after builder adoption. Historical v1 tuples remain unchanged.

The existing full-suite run failed. Six targeted reruns passed; those results do
not replace the failed full-suite result or establish acceptance. Future builder adoption
must retain the existing checks and separately establish the required build,
provenance, and qualification evidence.
