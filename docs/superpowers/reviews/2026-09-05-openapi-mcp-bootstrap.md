# OpenAPI MCP bootstrap publication and OIDC transition

**Version 1.0.0** · Knitli · 2026-09-05

## AI reading instruction

Read `[SPEC]` and `[BUG]` blocks for verified facts and release requirements.
`[NOTE]` records context; `[?]` records settings reported by the owner but not
independently verified. This record does not authorize a new publication.

## 1. Verified bootstrap

**[SPEC]**

- Package: `@knitli/openapi-mcp@0.0.0`, public, dist-tag `bootstrap`.
- Source commit: `4f39c6c541568328b8566329c8eaa23fac1c52a0` on `main`.
- Workflow: `knitli/toolshed/.github/workflows/release.yml`; environment: `npmrelease`.
- Run: [33977232028, attempt 1](https://github.com/knitli/toolshed/actions/runs/33977232028).
- Named owner approval: [bootstrap scope recorded on PR #23](https://github.com/knitli/toolshed/pull/23#issuecomment-5552963096).
- Tested artifact: `openapi-mcp-bootstrap-tested-33977232028-1`, artifact ID `9972685133`.
- Tarball: `knitli-openapi-mcp-0.0.0.tgz`.
- Tarball SHA-256: `5a08830a006091bc0d4c371ab9530b91c0c506cf811a37a5b23f48cb6a93bca5`.
- Tarball SHA-512: `e346a9357baceccd9cd529af4c56f0554f129207c95a6ddc047792b5fba677fd753cf75932d0561f18fa2fe646420520376ee2c50699fb275f34e12993318337`.
- Publication completed at `2026-09-05T16:15:56Z`; [publish job](https://github.com/knitli/toolshed/actions/runs/33977232028/job/101336147561).
- No stable `latest` release, semantic-release Git tag, or OS deployment is established by this bootstrap.

## 2. Verification after registry propagation

**[SPEC]**

- A fresh public installation of exact version `0.0.0` passed without npm credentials and with lifecycle scripts disabled.
- `npm audit signatures --json --include-attestations` exited zero, with no invalid or missing evidence.
- `verify-audit` bound the verified provenance to the exact CI-tested tarball, package/version, source commit, repository, workflow path/ref, run ID, and attempt above.
- The installed Node consumer passed runtime, public MCP read, rejected-admission recovery, rollback, and CLI checks.
- Verification used Node `24.19.0`, matching the release workflow.
- Retained local evidence: `/private/tmp/openapi-bootstrap-verification-3l6HHy/`; raw audit: `npm-audit-signatures.json`.
- Raw audit SHA-256: `a6a76157126cd943ab2aea20b08cadfb32d0a7d9c02922d745af66e356b10f36`.
- These were subsequent local checks, not a green rerun of the failed CI job. The local evidence directory is not a durable hosted artifact.

**[BUG] Immediate registry lookup after publication**

- Symptom: the publish step succeeded, but the public install returned `E404` approximately 0.68 seconds later; the workflow remained failed.
- Cause: the package listing was not yet visible to that lookup. A later exact-version request succeeded while a package-listing request still returned `404`.
- Fix: poll the same public package listing used for installation with bounded requests before installing. Do not retry `npm publish`, waive cryptographic checks, or treat an uploaded artifact as proof that verification finished.

**[NOTE]**

The run also uploaded `openapi-mcp-bootstrap-registry-evidence-33977232028-1`
(artifact ID `9972692303`), but installation failed before its audit and consumer
commands ran. Its existence alone is not completed registry verification.

## 3. Transition status and remaining gates

**[SPEC]**

- GitHub's `npmrelease` environment secret listing was empty after the owner removed `OPENAPI_MCP_BOOTSTRAP_TOKEN` on 2026-09-05.
- This cleanup removes the bootstrap dispatch and jobs from the workflow while retaining the adapter's rejection of token wiring.
- `OPENAPI_MCP_OIDC_READY` was unset at inspection; this PR does not set it or start a release.
- The bootstrap owner/enablement repository variables were still present at inspection. They are unused once the bootstrap workflow path is removed and can be retired separately.
- Before enabling the first regular release, confirm the exact trusted publisher: owner `knitli`, repository `toolshed`, workflow filename `release.yml`, environment `npmrelease`, permission to publish.
- Confirm revocation of the bootstrap npm token, not merely removal of its GitHub secret, before enabling regular publication.
- GitHub must issue the standard issuer `https://token.actions.githubusercontent.com`; the earlier bootstrap attempt was rejected for the enterprise-specific `/knitli` issuer.
- After cleanup is merged and external setup confirmed, an operator may enable `OPENAPI_MCP_OIDC_READY`. A successful OIDC-authenticated publication and its public verification are still required to establish the first regular release.
- The native OS integration retains its separate stable-release and API approval gates.

**[?]**

- The owner reports configuring npm trusted publishing and disabling the token/publication route. Public `npm trust list` returned `E401`, so the exact publisher fields and npm token revocation were not independently inspected.

## 4. Changelog

**[NOTE]**

1.0.0 records the successful bootstrap, subsequent public verification, registry
propagation failure, and the remaining OIDC transition gates.
