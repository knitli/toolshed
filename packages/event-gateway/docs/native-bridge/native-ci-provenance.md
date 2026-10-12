# CI provenance for native candidates

The main-only `Native client candidate build` workflow builds a new candidate
from the reviewed upstream commit, patch, and source manifest. It does not change
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
days. The schema version 1 receipt has kind `native-client-ci-build`, repository,
run, attempt, and head identity; hashes for the builder, producer, workflow,
manifest, and patch; the observed build environment; and the builder evidence
with independently computed executable hashes. The artifact ID and archive
digest come from GitHub after upload and appear in the workflow summary. They
are external to the receipt because an artifact cannot contain its own final
archive digest.

Promotion requires the separate trusted-main verifier to check the successful
producer run and exact attempt, approved recipe inputs, artifact API identity,
archive digest, and actual executable bytes. A JSON receipt alone is insufficient.
The verifier must read candidate PR files as data and must not execute candidate
code. It also requires the candidate launcher AST to match protected main except
for the two digest literals, preventing indirect pin overrides or weakened hash
checks. Other launcher code changes require a separately reviewed trust-policy
update before promotion.

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
