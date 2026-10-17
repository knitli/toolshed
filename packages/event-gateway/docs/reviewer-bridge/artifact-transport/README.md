# Dormant reviewer artifact transport

This offline qualification module prepares transport inputs for unchanged
`knitli/.github@711e265cc280cad7c4a44ba6d2d72f40a1378fec`
`scripts/reviewer-host-acquisition.mjs`. It does not authenticate signed evidence,
execute artifacts, call a verifier, publish evidence, or activate a workflow.

`transport(policy, token, request, parent)` is a context manager. Its trusted,
injected HTTP seam accepts a fixed GET URL, headers, byte ceiling and absolute
monotonic deadline; it must enforce TLS authentication, no automatic redirects,
no cookies/proxies/ambient credentials, bounded headers/body and cancellation by
that deadline. The module independently checks response URL/status/body length
and deadline. There is deliberately no live HTTP adapter or CLI in this slice.
A dishonest or indefinitely blocking injected seam is outside this offline proof.
Root owns later concrete HTTP/TLS/DNS/cancellation qualification.

The fixed API origin is `https://api.github.com`; paths are constructed from
closed trusted policy, never response URL fields or Link headers. Calls are only
completed run/attempt metadata, bounded run-artifact listing, selected immutable
artifact metadata and their ZIP redirects. Latest run attempt, private repository,
head, workflow and completed/success state are checked before and after transfers.
Unique names include run and attempt. Metadata is compared across listing,
individual reads, and a fresh bounded enumeration after transfer, including IDs,
owner/head, sizes, expiry and SHA-256. Artifacts lack an attempt field: exact names
and latest-attempt/run fencing provide transport selection only; signed handoff
and existing acquisition enforce the authoritative attempt identity.

The production download-host allowlist is **empty**. Offline tests patch its
private constant to one synthetic host. No public argument, artifact field,
environment variable or workflow input can add a host. A later controlled run must
observe and freeze the exact GitHub-issued storage host before a reviewed change
can admit it. GitHub documents `*.blob.core.windows.net` for artifact traffic, but
that suffix includes other Azure accounts and is not treated as qualified trust.
Only a single authenticated API 302 may supply the signed HTTPS URL; download
headers omit Authorization, and a second redirect fails. URLs are never retained
in output or errors.

Both ZIPs must match authenticated metadata size and SHA-256 before parsing.
Archive/entry count, compressed and decompressed sizes are bounded. Only fixed
flat filenames and stored/deflate compression are accepted. ZIP64, extra fields,
comments, prefixes/trailers, encryption, unsupported flags/types, duplicate paths,
symlinks, traversal and CRC/size failures are refused. The strict parser also accepts the exact pinned upload-artifact bundled writer's
compression-level-zero output in a controlled offline run. Hosted output and
other writer configurations remain unqualified; compatibility must not silently
broaden it.

The context yields an absolute directory with exactly the three producer files
(64 KiB each, 128 KiB combined), separate handoff bytes (4096 maximum) and
attestation bytes (2 MiB maximum). The fresh private directory is removed on any
failure and after context exit; it never overwrites caller paths. A future trusted
Node bridge converts the byte buffers and invokes the existing acquisition API
inside this lifetime, retaining its signature, job, step and final composition
checks. Output remains unavailable / missing-review-step / unverified / unknown.
This Python slice does not duplicate or wire that bridge.

Source contracts inspected directly at the immutable commit above:
`reviewer-host-acquisition.mjs`, `reviewer-host-handoff.mjs`,
`reviewer-host-source.mjs`, and inactive `acquire.yml.template`.

Primary references, checked 2026-10-17: [GitHub artifact API](https://docs.github.com/en/rest/actions/artifacts)
(metadata digest, run identity, list/get and short-lived download redirect) and
[runner communication requirements](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#communication-requirements-for-github-hosted-runners).

## Offline proof

Run from the repository root with the package's Python 3.13 environment:

```sh
python -m unittest discover \
  -s packages/event-gateway/docs/reviewer-bridge/artifact-transport \
  -p test_transport.py -v
```

Twenty-two tests exercise actual metadata selection, bounded ZIP parsing and private
file creation using an offline HTTP seam. Positive cases include deflate,
streamed ZIP data descriptors and paginated metadata. Negatives cover metadata
and latest-attempt drift, expiry at final publication, duplicate identities,
credential stripping, redirect refusal, dishonest response sizes/digests,
traversal, symlinks, CRC errors, oversized expansion, hidden central records,
ZIP64, and cleanup. Removing digest, expiry or central-record guards makes the
corresponding tests fail.

The repeatable composition regression uses those committed synthetic ZIPs with
unchanged upstream `acquireQualificationEvidence` at `711e265`. It exports only
seven fixed source modules from an existing local Git repository at that exact
commit with `--no-replace-objects`; it never imports the upstream working tree.
A disposable bare repository borrows upstream objects read-only and installs a
replacement ref locally: ordinary `git show` returns the poisoned bytes, while
the actual exporter must retain the original bytes. The upstream repository is
never mutated. No fetch is performed.
Provide a trusted absolute Node 24 executable and the local upstream repository:

```sh
REVIEWER_ACQUISITION_REPOSITORY=/absolute/path/to/knitli-dot-github \
REVIEWER_ACQUISITION_NODE=/absolute/path/to/node \
python -m unittest discover \
  -s packages/event-gateway/docs/reviewer-bridge/artifact-transport \
  -p test_transport.py -v
```

Without the repository variable, both upstream-dependent tests explicitly skip;
a skip is not composition evidence. With it, all 24 tests must pass with zero skips.
The Node fixture runs with an empty environment and a 15-second timeout. Its
explicit **TEST ONLY verifier stub** fabricates identity evidence; the real
signature verifier, GitHub requests, SDK and provider are never invoked. This is
trusted fixture execution, not an OS sandbox or cryptographic qualification.

The test checks exact producer/handoff/placeholder-attestation bytes and invokes
acquisition while the transported directory exists. Success retains the four
synthetic distinctions: `unavailable / missing-review-step / unverified / unknown`.
A second case throws from the final source read after acquisition has staged its
result. Both cases require transport-directory and acquisition-stage cleanup;
the failing case must publish no result. No runtime artifact is executed.

## Host filesystem and hosted sample gates

The caller supplies a physical absolute directory owned by the current UID with
mode 0700. Symlink aliases are refused. Ancestors must be root/current-UID owned
and not group/world writable, except the fixed root-owned sticky system temporary
roots `/private/tmp` and `/tmp`. This follows the gateway launcher boundary and
does not defend against an adversarial process with the same UID. The transport
never changes a shared directory's permissions.

Run snapshots currently compare the complete decoded API objects before/after.
GitHub may change non-authority fields during that interval and cause a safe
refusal. This behavior remains intentional pending an actual controlled sample;
no fields are silently dropped to obtain hosted success. Hosted format acceptance,
latest-attempt sampling, exact redirect-host freezing and the concrete HTTP seam
remain distinct gates before any transport activation.

## Exact bundled writer compatibility

The two small [synthetic ZIP fixtures](fixtures/README.md) were generated offline
by the actual `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02`
bundled ZIP writer, with compression level zero. The normal transport test checks
both archive hashes and all five extracted file hashes, then confirms private
directory cleanup. It uses the existing offline HTTP seam; production download
hosts remain empty. This proves writer/parser compatibility for these bytes,
not a live upload/download, TLS, signature verification or hosted acquisition.
