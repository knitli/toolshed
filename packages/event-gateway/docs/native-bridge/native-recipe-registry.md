# Inactive native recipe registry

`scripts/native_recipe_registry.py` records two fixed source families using
frozen records and a read-only mapping:

| Family | Revision | Selected source entries | Registry selection |
| --- | --- | --- | --- |
| `core-idle-v1` | 1 | 57 | Default |
| `terminal-query-v1` | 1 | 71 | Explicit only |

The registry is an inactive foundation. No production code imports it. The active
builder, workflow, producer, verifier, launcher, release pins, and receipt schemas
remain unchanged. Adoption by protected main is a separate future change.

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

The existing full-suite run failed. Six targeted reruns passed; those results do
not replace the failed full-suite result or establish acceptance. Future adoption
must retain the existing checks and separately establish the required build,
provenance, and qualification evidence.
