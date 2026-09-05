# OpenAPI MCP Phase 2 final review record — 2026-09-05

## External PR feedback closure checkpoint

Three subsequent PR #23 findings are addressed in reviewed implementation snapshot `c7413d88d28c3a0365183e2605b346a331026319`: every exact policy is compiled before any generation admission; parser/provider profile validation shares a side-effect-free validator; credential redaction sanitizes untrusted response values before serialization while preserving protocol metadata and continuation tokens. Independent scoped review found no new fix-diff defect. Historical RED runs are implementer-reported because raw output was not retained; fresh controller GREEN logs and regression source were independently inspected.

Fresh full-repository results: **997 passed, one known skip, zero failures; 4,823 assertions across 40 files**. Actual Node transport20/20, stdio/TLS1/1, four installed consumers, build, root/generated validation and whitespace passed. Full-package Biome passed with **18 warnings and two infos**, superseding earlier diagnostic counts. Tested tarball SHA256: `5a08830a006091bc0d4c371ab9530b91c0c506cf811a37a5b23f48cb6a93bca5`. Supporting scoped verdict: retained local `/private/tmp/toolshed-pr23-feedback-fix-verdict.md`; logs `/private/tmp/toolshed-pr23-feedback-controller-{suite,node_transport,node_stdio,validate,biome}.log`. These local results do not substitute for corrected-head hosted CI or publication.

## Subsequent delivery and CI checkpoint

[PR #23](https://github.com/knitli/toolshed/pull/23) is open; this supersedes the pre-submission checkpoint wording below. The first hosted validation used ambient Node 22.23.2, outside the declared Node 24.16–24.x support range, and failed the installed Node consumer on SQLite serialization. A separately reviewed, four-line workflow correction selects Node 24.19.0, matching the release jobs; compiler code and test assertions remain unchanged.

The exact repository-wide `bun test` command independently passed on Node 24.19.0: **986 passed, one known skip, zero failures; 4,729 assertions across 40 files**. Its tested tarball hash matches the final package evidence below. Hosted checks for the corrected commit must be read from the PR; local success is not a claim that hosted CI passed. No publication or deployment is implied.

## Verified disposition and delivery status

All five original Important findings (I1–I5) and the subsequent Important FIFO-race finding (R1) are addressed. No Critical finding was confirmed. This records local implementation and review acceptance; remaining delivery and external gates are pending.

- Final verified source tree: `5bca2b89c787af490c09404adf02c106348535de`.
- Signed transport checkpoint: `78a1264321315a57b794184d868b9b3ee716013c`, with Git signature status `G`. The user restored a working signing agent; earlier signing-blocker notes are historical.
- Signed integration checkpoint: `921c312a34dd566aa477ca7dd9a092e08c97ba5d`, with Git signature status `G`; its tree equals the final verified source tree above. Signing and source checkpoints are complete. PR submission remains pending.
- No publication, publisher setup, external variable/secret provisioning or revocation, or deployment was performed by this work.

Scope is governed by the [runtime plan](../plans/2026-09-03-openapi-mcp-runtime.md) and [runtime specification](../specs/2026-09-03-openapi-mcp-runtime-design.md). The gitignored progress ledger at `.superpowers/sdd/2026-09-03-openapi-mcp-runtime/progress.md` is retained local evidence. The Phase 1 v3 compiler/CLI is baseline functionality, not newly delivered Phase 2 work.

## Final findings and verification

| Finding | Addressed scope and evidence |
| --- | --- |
| I1 — startup admission | Prove every configured executable release completely before any startup generation transition; reauthenticate and reprove after lost CAS. Preserve both prior catalog states and retained public reads when a later candidate fails. Public manifest-only admission retains its narrower contract. |
| I2 — publication completion | Local v5 executable ingress requires matching bounded manifest/signature sidecars and complete signed inventory. Interrupted publication, mismatches, oversized or symlink sidecars, manifest-last success, and historical-v4/v5 compatibility have behavioral coverage. |
| I3 — shared search limits | One multiplexed search runtime enforces shared candidate/proof/store/work/output budgets, API filtering, ranking, and final active-generation filtering. Budget-charged candidate lookup preserves ninth-catalog selective-query reachability, including within one API namespace. Full successful MCP result sizing includes wrappers and warnings. |
| I4 — OAuth resource parity | Provider and configuration validation share the approved absolute-resource-URI contract, including URNs. Credential/token destinations retain HTTPS checks. |
| I5 — uncertain action receipt | Modern and legacy MCP paths expose only stable code/message, forced `retryable: false`, and an own-property 64-hex prepared-call digest for unknown outcomes. Hostile extra details are excluded; actual Node/TLS coverage checks independently authorized disconnects without retrying the uncertain invocation. |
| R1 — sidecar FIFO race | Add `O_NONBLOCK` to the existing no-follow sidecar open. Deterministic manifest and signature regular-file-to-FIFO swaps first reproduced native-open timeouts, then promptly returned `MANIFEST_INVALID`; six regression cases passed. Existing type, identity, bounds, decoding, envelope, and final-path checks remain. Independent re-review found R1 addressed with no new breakage. |

Fresh controller verification on the final source tree:

| Check | Result |
| --- | --- |
| Combined package/release-helper suite | **973 passed, 1 known Graph skip, 0 failed; 4,707 assertions across 38 files** |
| Actual Node transport | **20 passed, 0 failed** |
| Actual Node stdio/TLS | **1 passed, 0 failed** |
| Installed consumers | **Four passed**, covering the retained Node/Bun/Worker consumer configurations |
| Build; root validation/generated synchronization; whitespace | Passed |
| Full-package Biome | Passed, with **17 fixture warnings and 2 infos**, no errors |
| Exact tested tarball SHA-256 | `7b531f129db169212bd35869058aa1c3e0d717a84a84060b70b9a832b7b2e868` |

## Review history and evidence limits

Tasks 1–7 have retained implementation/test commit-to-tree mappings and collective reviewed-baseline evidence, including 670 passes, one intentional Graph skip, and a passing TypeScript build. No independent per-task verdict transcripts were recovered. Committed tests and plan instructions saying “Expected PASS” are not execution transcripts. PR #14/current main is too late to serve as the whole-Phase-2 baseline because Tasks 1–5 were already merged there.

Task 8's [tracked authorization review](2026-09-05-openapi-mcp-action-authorization.md) records six authorized negative controls killed and restored; an initially surviving control prompted direct-consume call/grant regressions. Its package checkpoint was 747 passes, one skip, zero failures, and 3,564 assertions. The initial restoration checksum output was not retained intact, so exact pre/post checksum equality is not claimed.

Task 9 retained implementation/fix reviews and subsequent PR feedback cover reserved API-key headers, token-write rollback, and owned cleanup; its controller checkpoint was 778 passes, one skip, zero failures, and 3,730 assertions. Node callback smoke evidence used mocked token responses. Task 10 retained transport/fingerprint repair and restoration evidence includes actual Node transport checks; its restored package checkpoint was 834 passes, one skip, zero failures, and 3,926 assertions.

Task 11 retained modern/legacy MCP fixes and nine negative controls around enumeration, framing, revalidation, ordering, and replay. One indentation-only restoration discrepancy was corrected and the original hash confirmed. Its checkpoint was 940 passes, one skip, zero failures, and 4,449 assertions. Later scoped repairs did not claim to rerun every historical mutant.

Task 12's initial package/release-helper checkpoint was 945 passes, one skip, zero failures, and 4,503 assertions. Its independent review required a successful installed public `read` after rejection of a newer release candidate. The fix demonstrated that orchestration against signed SQLite and persistent generation state; four consumers passed with 32 harness assertions plus fixture assertions. The outbound response was injected, so this is not network-adapter parity evidence.

The first whole-Phase-2 review rejected tree `92043b0ac7c425608ff6555920174d45f8611c98` for I1–I5 and an unresolved formatter gate. One scoped repair review of `c5108144b819ad22c3633601f48c67332fb63629` closed I1–I5 but identified R1. The controller initially withheld approval under the one-wave cap; the user then authorized one extra narrow R1 fix/re-review. That final re-review closed R1. Earlier “not ready,” failed-lint, old tarball, and signing-blocker statements remain historical evidence, superseded by the final results above.

Limits remain explicit: generation CAS is per group, not a cross-group transaction on later storage-I/O failure; preproof observes a bounded inventory rather than a durable filesystem/database snapshot. Search returns a deterministic bounded ranked sample within eight authenticated candidate-release/proof slots, not exhaustive global relevance. An impossibly small success cap yields a separately bounded `RESPONSE_LIMIT_EXCEEDED` control error; no arbitrary outer JSON-RPC/full-wire bound is promised. Stdio rollback activation lacks a host rollback-envelope input despite lower-level rollback API coverage. Cancellation cannot undo upstream work already dispatched; provider revocation and JavaScript-buffer erasure are not established by local cleanup. Auth-module decomposition remains follow-up maintenance work.

Actual Node checks emit experimental-transform-types warnings. An intermediate listener run failed with sandbox `EPERM` and had a masked shell status; it is excluded from passing evidence, superseded by direct-status actual Node runs. Output compression required narrow lexical/structured reads; no lossless every-line historical replay or recovered Tasks 1–7 transcript set is claimed. An unavailable TypeScript AST helper was a review diagnostic limitation, not a package test failure.

## Rulings I made

The following preserves all 26 historical decision/cost entries and the subsequent delivery ruling in recoverable task progression; ordering within a task is not independently timestamped. Later dispositions explicitly supersede earlier ones.

1. Add operator-owned profiles and immutable credential snapshots for stable identity/live bindings. **Cost:** pre-publication contract adjustment if wrong.
2. Separate secret-free preparation from credential retrieval through `bindingResolver`. **Cost:** consumer adapters; combining paths risks secrets during preparation.
3. Treat v1 revocation as local forgetting/grant invalidation. **Cost:** upstream grants can remain usable until provider-side revocation; a protocol adapter needs its own contract/tests.
4. Keep `auth-required` portable and adapt it to MCP in stdio. **Cost:** adapter maintenance and direct-provider consumer mapping.
5. Accept absolute resource URIs, including URNs, as configured audience metadata. **Cost:** bad metadata can reject or misstate targeting; digest binding does not verify token audience.
6. Add digest-bound pagination tokens in unpublished PreparedCall v2. **Cost:** consumers regenerate prepared calls; revisit versioning if publication evidence changes.
7. Support standard Link `rel=next` only. **Cost:** body-only pagination needs a future explicit extraction contract.
8. Pair local broker and transport internally. **Cost:** callers must use paired construction.
9. Block action redirects without replay; permit policy-compliant read redirects. **Cost:** mutation-redirect APIs need explicit adaptation.
10. Classify action failures after connection attempts as outcome-unknown unless pre-connect failure is known. **Cost:** some failures with no application bytes sent still require reconciliation.
11. Require owned close/abort cleanup and trusted signed-manifest origin-membership callbacks. **Cost:** hosts supply lifecycle/policy hooks; the generic transport interface stays unchanged.
12. Carry preserved transport work onto rebased authorization history before review. **Cost:** local branch recovery and retained-reference separation if wrong; no remote history rewrite.
13. Enforce default deny through valid consumed receipts, with explicit per-call confirmation by default. **Cost:** pre-publication operator UX adjustment; no silent authorization bypass.
14. Continue independent stdio work behind the immutable pending transport index. **Cost:** possible local branch/review separation repair; no signing bypass.
15. Use the installed SDK's actual `ServerOptions.requestState.verify` hook. **Cost:** incorrect registration breaks continuation verification; modern/legacy tests cover it.
16. Use boolean elicitation wire fields while requiring literal-true consent in the authorizer. **Cost:** boundary drift can weaken consent; accepted-false denial tests are required.
17. Replace only OpenAPI's npm prepare/publish lifecycle with a tested repository-owned adapter. **Cost:** maintaining lifecycle integration and exact artifact/version/OIDC identity checks before publication.
18. Add push-only guards to unrelated release jobs when adding manual bootstrap dispatch. **Cost:** routing corrections before release; manual-versus-push behavior needs tests.
19. Gate publication/public audit on explicit OIDC readiness while keeping build/test/validate mandatory. **Cost:** delayed publication or routing repair; the flag is not publisher/provenance evidence.
20. Initially defer inherited formatting diagnostics to final review while repairing Task 12's missing public-read proof. **Cost:** a later formatter pass or an explicitly unresolved lint gate; scoped passes cannot establish full lint success.
21. Supersede that deferral with nine-file formatting cleanup and discovery wording correction; defer auth decomposition. **Cost:** continuing auth maintenance debt or later extraction; residual diagnostics remain visible.
22. Require one shared stdio search port backed by a multiplexed runtime/store. **Cost:** unpublished local host/consumer option adjustment; portable contracts/versions stay unchanged.
23. Prove every configured release before startup admission, then retain per-group CAS. **Cost:** retry/recovery after later storage-I/O failure or a future transaction contract; no cross-group atomicity claim or state reset.
24. Count the whole successful stdio result against its cap; use a bounded control error when no valid result fits. **Cost:** clearer data/control-budget specification or caller adjustment; no impossible full-wire promise.
25. Refine shared search with budget-charged internal candidate lookup, superseding fixed-first-eight source selection while retaining the shared-port requirement. **Cost:** coordination complexity and explicit bounded omissions/future continuation design; no silent later-source exclusion or unbounded work.
26. Initially retain R1 as unresolved Important and withhold ready-to-merge approval under the one-final-fix-wave cap; preserve evidence and request one extra narrow fix/re-review plus signing recovery. **Cost:** delayed completion for a local-write-access availability defect. The user subsequently authorized that extra pass; `O_NONBLOCK` regression evidence and independent re-review now close R1, and signing recovery produced the transport commit above. This did not authorize automatic further waves, unsigned bypass, merge, publication, or deployment.

27. Submit the remaining Phase 2 work as one PR with logically separated signed commits because final ingress/search/consumer changes must land together. The user authorized PR(s), not a mandatory three-PR stack. **Cost:** a larger combined review surface or a later independently validated split; no unsafe intermediate stdio PR.

## Pending delivery and Phase 3 gates

PR submission and fresh PR/review/CI verification are pending. Signed source checkpoints and the final source-tree-to-commit mapping are recorded above. Historical PR merge observations are not refreshed live status. The retained main release audit observed `EINVALIDNPMTOKEN`; local release-adapter tests do not establish repaired registry credentials or successful release CI.

Publication requires explicit operator OIDC readiness, exact trusted-publisher/workflow identity, and any required named-owner/protected-environment bootstrap approval. Bootstrap `0.0.0` is not stable `latest`. Public exact-version installation, cryptographic registry-signature/provenance verification bound to package integrity/source/workflow/run, bootstrap-token cleanup/revocation, and real release/tag evidence remain external gates. Helper field-binding checks do not replace npm cryptographic audit.

Phase 3 exact API/presentation re-approval remains **unapproved**. Stable-latest publication/provenance and an upstream Gatekeeper pin are prerequisites. The intended integration target is `apps/os/packages/gatekeeper-openapi`, outside the pinned cloudflare-os submodule. No native OS implementation or deployment is claimed.

## Retained scratch evidence

The controller retains `/private/tmp/toolshed-phase2-final-evidence-draft.md`, `/private/tmp/toolshed-phase2-final-review-verdict.md`, `/private/tmp/toolshed-phase2-final-fix-verdict.md`, and `/private/tmp/toolshed-fifo-race-fix-verdict.md`, plus final `toolshed-fifo-controller-{suite,node_transport,node_stdio,validate,biome}.log` logs, baseline mappings, task reports/review and mutation/restoration evidence, exact artifact/consumer results, CI audit, and Phase 3 approval draft. These are supporting local artifacts, not published evidence.
