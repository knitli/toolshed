# Reviewer terminal-signal spike

Read-only investigation, 2026-10-07. Base: Toolshed `9e54800`.
Scope: provider evidence and deterministic replay only. No review requests,
workflow edits, runtime changes, canonical contract changes, or activation.

**Result:** useful attention signals exist for all three providers. None of the
inspected surfaces alone proves the complete stage-3 review-round predicate.
Keep GitHub attention independent of this missing terminal contract.

## Provider evidence

| Provider | Invocation / terminal evidence available | Missing proof / interpretation |
|---|---|---|
| Codex Code | Authored summary row gives status, short commit, completion timestamp and trigger label. Submitted reviews, when present, carry `commit_id`. | Trigger label is not an invocation ID; short SHA is not exact candidate identity. `Completed` can coexist with findings. A posted review/comment is not proof all provider work finished. |
| Codex Security | Separate summary row; observed hidden `codex-security-review:v1` JSON carries repository, PR, full `headSha`, `status`, threshold and merge-gate flag. | Observed format, not a documented stable terminal API in the sources inspected. No invocation/attempt/base/policy binding. `mergeGateEnabled:false` and threshold are not proof of no findings. Never borrow Code's head or timestamp. |
| Knitli Agent | Caller workflow/pinned reusable workflow, Actions run ID/attempt, actual review job and step outcomes. Comments/reviews use a separate bot identity. | Successful gate/sanitize/workflow is not review success. Current reusable workflow can skip or mask review failure. Summary header is model-authored prose, with no required machine candidate/invocation terminal manifest. |

Original-post `+1` by the Codex actor is a useful owner-facing signal. Its API
object has actor, ID, content and timestamp, but no reviewed SHA or invocation.
It cannot certify a current round, distinguish Code from Security, or establish
that a same-head rerun completed. An `eyes` reaction indicates activity, not an
enumerable set of running invocations. Missing reactions/runs and quiet time
remain unknown. Partial comments can already contain actionable findings without
establishing terminal review state.

## Captured live observations

These are bounded observations, not a claim about later PR state. Raw finding
text is deliberately absent from the replay fixtures.

- [knitli-site#683 summary6030899494](https://github.com/knitli/knitli-site/pull/683#issuecomment-6030899494), actor ID `199175422`: Code completed at `2026-10-07T18:18:53.937567Z` on short SHA `e9dbe58`; Security completed at `2026-10-07T04:30:05.446745Z` on full SHA `3aaedc306640631e49001b99d02cba589eaebc4a` in its hidden marker. Read-back head was `e9dbe58a05b7342398be179afe489709199a31d5`, base `33d253b4257cfbb4982df1b5324b00fb76c4cf6f`. Security was stale despite the updated Code row.
- The same PR's original-post reaction `551874848` was `+1`, actor `199175422`, created `2026-10-07T18:18:57Z`. It coexisted with the different Security SHA. The paginated submitted-review endpoint returned no Codex reviews for this PR; absence does not refute the summary or prove failure.
- [toolshed#45 summary6032507650](https://github.com/knitli/toolshed/pull/45#issuecomment-6032507650): both Code and Security reported completed on `bb49271`; Security marker expands this to `bb49271b1df0709f5703abcc20578c76de91ef49`. A separate [finding6032555726](https://github.com/knitli/toolshed/pull/45#issuecomment-6032555726) existed for that revision. Completed-with-findings is not an execution failure and does not authorize another review request.
- [toolshed#45 run37685095724](https://github.com/knitli/toolshed/actions/runs/37685095724), attempt 1, `pull_request`, head `27ad6438e932e06fb1e0667cb2b88b5a07299e53`: actual review [job113011163346](https://github.com/knitli/toolshed/actions/runs/37685095724/job/113011163346) was `completed/cancelled`; its step list was empty. CI gate and input scan were successful. Earlier Knitli submitted reviews referenced older heads. The check app ID was `15368` (`github-actions`), not the review-comment bot.

## Pinned Knitli contracts differ by repository

The cloud implementation plan's stage 3 points to the OS caller pinned at
[`880dae35`](https://github.com/knitli/.github/blob/880dae35e7f2dfdd099f88c5fc55ccbfd8e4022c/.github/workflows/claude-pr-reviewer.yml).
The OS caller inspected at `origin/main` triggers PR `opened` only. Its
issue-comment condition reads `event.pull_request` instead of
`event.issue.pull_request`; its submitted-review condition reads `comment`
instead of `review`. The reusable workflow does not handle `pull_request_review`
in its review-job condition either. No workflow fixes are included here.

Toolshed's caller at this spike base includes `synchronize` and other PR events,
with a CI gate, and pins
[`dcae9400`](https://github.com/knitli/.github/blob/dcae94003fadba215b451f4232a0b5e41b95755a/.github/workflows/claude-pr-reviewer.yml).
That reusable workflow has `continue-on-error` on both review job and Claude
review step. Freshness/provider-availability conditions can skip the review;
provider outages can finish successfully without reviewing. Both pinned versions
ask for a prose summary and fetch current PR data, without a final immutable
head/base/run/attempt-bound completion record. Thus even a successful actual
review step is execution evidence, not a certified complete review round.

## Proposed fields for the GitHub lane

Preserve source evidence rather than precomputing `clean`:

- Repository ID/PR; provider enum (`codex_code`, `codex_security`, `knitli_agent`);
  authenticated actor/app ID; workflow path and pinned source revision where applicable.
- Evidence kind, object ID/URL, created/updated/fetched timestamps and body digest;
  full reviewed head when available, otherwise separate short-head field.
- Trigger event/comment ID, provider invocation ID, run/check/job ID and attempt.
  Missing IDs stay null; timestamps and trigger labels never synthesize them.
- Candidate head/base/tested-merge revision, policy revision, reconciliation epoch;
  preserve whether the source actually binds each field.
- Raw status/conclusion, actual reviewer step outcome, findings-present evidence;
  complete pagination/read status for each source, not a blanket successful HTTP flag.

Latest-attempt selection must include same-head reruns; recheck candidate/base/
policy after asynchronous reads. Older findings remain unresolved until an
authorized disposition, regardless of newer completion signals. Distinguish
failed/cancelled execution, no invocation observed, incomplete reads, stale
candidate, and reported completion with findings. The replay intentionally
returns `round_complete:false` for every observation.

The smallest production prerequisite for Knitli is a trusted final manifest
binding actual reviewed candidate, invocation/run/attempt, outcome and finding
inventory, emitted only after successful review and reread. Codex needs an
authenticated provider task/invocation terminal mapping or an explicitly adopted
and verified supported contract; the sampled summary alone does not supply it.
Until then keep completion unknown/manual. This spike does not add either system.

## Runnable proof and limits

From the repository root:

```sh
python3 packages/event-gateway/scripts/replay_reviewer_signals.py
```

[Fixtures](reviewer-signals/replay.json) contain 30 cases: curated live
projections and clearly labeled synthetic edge cases. The script accepts an
optional fixture path. It is an offline classifier, not an authenticated API
normalizer, polling service, provider parser or full stage-3 implementation.
No existing provider terminal classifier was found in the gateway/scripts;
`scripts/wait-for-ci.sh` is a CI gate, not a reviewer terminal contract.

[Proof](reviewer-signals/proof.json): nine in-memory source mutations each reached
an assertion failure, followed by restored GREEN for all 30 cases. Mutations cover
actor spoofing, partial reads, stale heads, same-head attempts, reactions,
findings, skipped/failed steps and accidental completion authority. This proves
the bounded classification logic, not live webhook completeness, provider
availability, verified normalization, or production clean completion.

Read-only refresh examples (no review invocation):

```sh
gh api --paginate repos/knitli/knitli-site/issues/683/comments
gh api --paginate repos/knitli/knitli-site/issues/683/reactions
gh api repos/knitli/toolshed/actions/runs/37685095724
gh api repos/knitli/toolshed/actions/jobs/113011163346
```

## Primary references

- [OpenAI GitHub review documentation](https://developers.openai.com/codex/integrations/github/): separate Code/Security review and configured automatic triggers; does not establish the sampled hidden marker as a stable completion API.
- [GitHub check-run API](https://docs.github.com/en/rest/checks/runs): app identity, head SHA, status/conclusion and check identity.
- [GitHub workflow-job API](https://docs.github.com/en/rest/actions/workflow-jobs): job/run/attempt and step outcomes.
- [GitHub reactions API](https://docs.github.com/en/rest/reactions/reactions): reaction identity, actor, content and timestamp.
