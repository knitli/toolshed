# CI provenance for native candidates

The main-only `Native client candidate build` workflow builds a new candidate
from the pinned upstream commit and selected registry recipe. The default is
`core-idle-v1`, revision 1 (57 selected source files); `terminal-query-v1`, revision 1
(71 files), requires explicit selection. The workflow forwards the enumerated family
through a quoted environment variable and fixes revision 1. It does not change
the production launcher pin, install a client, dispatch itself, or establish live
qualification. Its receipt is CI provenance, not a cryptographic attestation or
a claim that another machine will reproduce identical bytes.

The producer requires repository ID `1200860702`, the main ref, the expected
workflow path, an exact checked-out head SHA, and an arm64 macOS runner. Actions
are pinned to commits. The workflow has read-only contents permission, uses no
repository secrets, and starts fresh Cargo/Rustup directories without restoring
PR caches. Rust 1.95.0, the upstream commit, and official host archive are pinned;
the builder validates the archive and host digest before using it.

`--prime-dependencies` explicitly permits dependency metadata resolution and
fetching before compilation. The builder checks that Cargo.lock changes only the
159 expected local package versions, records the normalized lockfile digest,
and performs the actual build with `--offline --locked`. Cargo concurrency is
fixed at two in the sanitized environment. Default packaging remains offline.
The runner image, SDK, and linker are observed and recorded; they are not claimed
to be immutable or identical to the historical local build environment.

The immutable artifact is named `native-client-<runId>-<runAttempt>` and contains
exactly `codex`, `codex-code-mode-host`, and `build-receipt.json`. Retention is 90
days. Every new schema version 2 receipt has kind `native-client-ci-build`,
repository, run, attempt, and head identity; the selected recipe; hashes for the
builder, producer, workflow, registry, and source manifest; the observed build
environment; and builder evidence with independently computed executable hashes.
Historical schema version 1 receipts retain their original manifest-and-patch
input tuple. The artifact ID and archive
digest come from GitHub after upload and appear in the workflow summary. They
are external to the receipt because an artifact cannot contain its own final
archive digest.

Promotion requires the separate trusted-main verifier to check the successful
producer run and exact attempt, approved recipe inputs, artifact API identity,
archive digest, and actual executable bytes. A JSON receipt alone is insufficient.
The verifier must read candidate PR files as data and must not execute candidate
code. Ordinarily, the candidate launcher AST must match protected main except
for the two digest literals, preventing indirect pin overrides or weakened hash
checks. Other launcher code changes require a separately reviewed trust-policy
update before promotion.

Legacy schema version 1 promotion accepts only complete historical five-input
tuples registered for `core-idle-v1`, revision 1, with its fixed manifest and
patch identities. The verifier loads this policy from a fixed sibling registry
in the trusted checkout, never from candidate or build-head code. Candidate
build-input files and registry bytes must equal current main, while the artifact
receipt must match its authenticated historical build inputs. This permits reuse
of a reviewed legacy artifact after shared builder, producer, or workflow changes;
it does not automatically admit later current-main tuples. Registry changes
trigger provenance refresh and participate in policy freshness checks before
status publication. The strict nine-field schema version 1 selection remains:
additional recipe fields and 71-family inputs are not accepted under v1. Both reviewed
launcher transitions and the unchanged-pin no-artifact path remain available.

Schema version 2 uses the existing selection fields plus exactly
`recipe: {family, revision, manifestSha256}`. Selection and receipt use integer
`schemaVersion: 2`; the recipe object and builder evidence do not gain a schema
field. Selection, receipt, and builder recipe identities must exactly equal the
protected registered recipe, and its manifest digest must equal
`inputs.sourceManifestSha256`. Unknown identities, extra fields, boolean revisions,
and cross-family combinations fail.

The v2 receipt binds exactly five inputs: `builderSha256`, `producerSha256`,
`workflowSha256`, `registrySha256`, and `sourceManifestSha256`. All five candidate
and build inputs must equal current main. Selected manifests, parents, and patches
are authenticated against the protected recipe; ordered `appliedPatches` and the
complete `patchedFileSha256` map and `patchedFileCount` must match it. Both
`patchedSourceInventoryBeforeBuildSha256` and
`patchedSourceInventoryAfterBuildSha256` independently equal the canonical digest
of that map: SHA-256 over sorted UTF-8 paths followed by NUL and each raw digest.
The authenticated builder checks upstream prerequisites in a fresh archive of the
pinned upstream commit before applying patches in order. The verifier does not
rebuild source or treat an upstream prerequisite as a documentation asset.

The builder and producer use the registry for both families, and every new build
emits v2, including the default `core-idle-v1` family. The producer hashes all
implementation inputs and selected recipe assets before and after packaging.
Legacy artifacts retain the separate registered v1 path; v2 has no historical
tuple fallback. Adoption checks include source-only replay and mocked packaging;
they do not produce an actual 71-family binary or establish native qualification.
Recipe support does not establish native qualification or authorize dispatch,
installation, or pin promotion. The failed full-suite result remains a hold;
six targeted passes do not waive it.

The explicit exception for [PR #89](https://github.com/knitli/toolshed/pull/89)
authorizes only the raw launcher bytes at
[`98c87baaaf88ea3a65d2ffea980066a1a69f606c`](https://github.com/knitli/toolshed/blob/98c87baaaf88ea3a65d2ffea980066a1a69f606c/packages/event-gateway/src/event_gateway/launcher.py),
introducing read-only native observations with their original request deadline,
against the launcher at main baseline `8af65e449a2ea54d45280909e6f3520cc407cd3f`:

| Exact transition component | SHA-256 |
| --- | --- |
| Main launcher bytes | `fbe251ff9f50af21157902813e60651aac8b2c84513485fe9e4148d1e624edcd` |
| Candidate launcher bytes | `ec9225a2bc907646d3e81898c61e45706cb81df27d95d7c23387075681d8bd12` |
| Unchanged native binary pin | `763e5e2b574f60b766d0d1b73b74ecc32d09d46479afe24e164299ca3633717b` |
| Unchanged code-mode host pin | `679eedaea70529aa1cffc9bc0a0788c186412663544fa76c09d63b57f383a65a` |

All four values must match and both literal pins must equal protected main.
Raw-byte authorization is independent of Python's AST representation. A later
launcher edit, including a comment or pin change, cannot use this exception;
a different logic transition requires another reviewed main-policy update.
The ordinary AST-equality path and its complete changed-pin artifact verification
remain unchanged. The running verifier comes from trusted main: editing a
candidate's verifier cannot authorize that candidate. Current-head/main and
trusted-policy freshness checks still apply before publishing the status.
Merge this separate policy before revalidating the observation PR. This exception
does not establish Codex approval, native runtime qualification, installation or
deployment; the observation PR retains its independent review and CI gates.

The `Event Gateway / native provenance` status must be required in repository
rules before relying on platform merge enforcement. Workflow and token-permission
changes also need protection: a status context identifies the GitHub Actions app,
not a unique issuing workflow. This foundation changes no repository rules.
Expired or deleted artifacts cannot authorize a new
promotion verification; preserve the release artifact before its retention window ends.
An hourly trusted-main sweep revalidates open PRs, replacing stale success with
pending and then failure or error if the selected artifact has expired, was
deleted, or is unavailable. Immutable source bytes are cached by exact commit
and path only within a sweep; artifact metadata is always read again. The
main-only manual verifier dispatch can repair a stale status without a push.
Gateway CI completions refresh only current PRs matching that run's head and
repository; native build completions and scheduled sweeps refresh all open PRs.
Sweeps request only PR numbers and head OIDs. Ancestry uses a minimal comparison
of exact build/main OIDs and status, excluding PR bodies, commit messages and
file patches. A changed main OID invalidates verification before publication.
Scheduled jobs can be delayed, so this is periodic invalidation rather than an
instant deletion notification. Immediately before merging a pin promotion,
rerun the trusted-main verifier and require its current-head success as well as
the ordinary review gates. Repository rules and merge automation must enforce
that freshness requirement before relying on unattended platform enforcement.
Unchanged protected-main launcher code and pins remain accepted without an
artifact download, so artifact expiry cannot block unrelated work.

The builder reads the production launcher digest as a literal AST value, without
importing the launcher. Changing that digest therefore does not change the build
recipe file. Candidate builds can produce a different digest with
`launcherQualified: false`. For an explicit existing-release verification, pass
`--verify-release`; a mismatch fails before any package outputs are published.
A matching digest alone still does not prove runtime or live qualification.

The release sequence is: merge the producer/verifier foundation; dispatch the
producer on main; independently verify and download its immutable artifact;
qualify those exact executable bytes locally; then propose the new launcher pin
and artifact provenance pointer. Historical artifacts and their original evidence
remain unchanged.
