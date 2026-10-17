# Native recipe registry

`scripts/native_recipe_registry.py` records two fixed source families using
frozen records and a read-only mapping:

| Family | Revision | Selected source entries | Registry selection |
| --- | --- | --- | --- |
| `core-idle-v1` | 1 | 57 | Default |
| `terminal-query-v1` | 1 | 71 | Explicit only |

The trusted provenance verifier adopts only the registered `core-idle-v1`,
revision 1 historical build-input tuples for legacy schema version 1 artifacts.
It loads the registry from a fixed sibling file in its trusted checkout, including
under Python isolated mode; candidate and build-head registry code is never run.
The builder and producer do not import the registry. The 71-entry family remains
inactive, and launcher pins and receipt schemas remain unchanged.

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

For changed-pin candidates, the five candidate build-input files and registry
bytes must equal current main. The artifact's five build-head hashes must match
one complete registered legacy tuple, with the fixed legacy manifest and patch
identities. A later current-main tuple is not automatically accepted under v1.
The receipt must attest those authenticated historical inputs, even when current
builder, producer, or workflow bytes have changed. Registry freshness is checked
before publishing pending, success, or failure statuses. Unchanged current pins
retain their no-artifact fast path; both reviewed launcher transitions remain.
Schema version 2, recipe selection fields, and 71-family artifacts are rejected.

The existing full-suite run failed. Six targeted reruns passed; those results do
not replace the failed full-suite result or establish acceptance. Future builder adoption
must retain the existing checks and separately establish the required build,
provenance, and qualification evidence.
