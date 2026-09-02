#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Knitli Inc.
#
# SPDX-License-Identifier: MIT OR Apache-2.0

# scripts/wait-for-ci.sh — Poll for the "CI" workflow's run on a commit and
# report its conclusion.
#
# Used by .github/workflows/knitli-agents.yml's `wait-for-ci` job to gate the
# auto-fire Claude review: reviewing a commit before CI has judged it wastes
# an LLM call on code that may not even build, and re-reviewing every
# intermediate push in a fix-iterate cycle is exactly the review-on-every-push
# cost the 2026-08 CI-usage audit flagged. Waiting for `ci.yml` to conclude
# collapses a burst of pushes to (at most) one review per PR: `ci.yml`'s own
# `cancel-in-progress` concurrency group means every push but the last gets
# its CI run cancelled (conclusion != success), so this script reports a
# non-success conclusion for those and the review is skipped for them too.
#
# Never exits non-zero — a network hiccup or an unfound run should not paint
# this job red when the actual signal (CI's own conclusion) is what matters.
# The caller reads the `conclusion` GITHUB_OUTPUT instead:
#   success   — CI's latest run for $SHA completed successfully; review.
#   failure / cancelled / etc. — CI's own conclusion string; skip review.
#   not_found — no "CI" run ever appeared for $SHA within the wait budget.
#   timeout   — a run was seen but never reached `status: completed`.
#   draft     — CI succeeded, but the PR is (now) a draft; skip review.
#
# Required env: GH_TOKEN, REPO ("owner/repo"), SHA, PR_NUMBER, EVENT_TIME
#   (ISO 8601 — the triggering pull_request event's timestamp, e.g.
#   github.event.pull_request.updated_at; the caller passes a no-op
#   (epoch) value for event types that never produce a fresh ci.yml run
#   for an unchanged SHA — see EVENT_TIME note below)
# Optional env: WORKFLOW_NAME (default "CI"), POLL_INTERVAL_SECONDS (default
#   20), MAX_WAIT_SECONDS (default 3300 — 55 min, leaves margin under the
#   caller job's 60-minute timeout so a real timeout is reported as
#   `conclusion=timeout` rather than the job being killed mid-poll with no
#   output set at all).
#
# EVENT_TIME matters for one specific race: a draft PR marked ready without a
# new commit keeps its head_sha, and ci.yml's draft-time run for that SHA
# already completed with conclusion=success (its slow jobs were skipped, not
# failed, by the draft-skip guards — skipped doesn't fail a run). Without a
# freshness filter, a poll landing before ci.yml's new ready_for_review run
# is even created would grab that stale success and wave the review through
# before the slow jobs the transition just unblocked have run at all. Runs
# older than EVENT_TIME are ignored so the script keeps waiting for the run
# this actual trigger produced. The caller
# passes an epoch EVENT_TIME (a no-op filter) specifically for a title/body-
# only `edited` event, since that PR event (no head change) never gets its
# own ci.yml run at all — filtering there would starve the poll for the full
# MAX_WAIT_SECONDS looking for a run that will never arrive (review finding
# on #2142). A base-branch-retargeting `edited` event never reaches this
# script at all — the caller's `if:` excludes it entirely (a different
# review finding on #2142), since ci.yml doesn't validate the new base
# either and reusing a CI result that only validated the old one would be
# wrong, not just stale. Every other action ci.yml itself triggers on
# (opened, reopened, synchronize, ready_for_review) gets the real filter.
#
# A final live check: right before reporting `success`, re-fetches the PR's
# CURRENT draft state (not the value from when this job started) and
# downgrades to `draft` if it's now a draft — a PR marked ready, then
# reverted to draft while this script was still polling, must not still get
# reviewed just because CI eventually passed (review finding on #2142; no
# `converted_to_draft` trigger exists to cancel the in-flight wait, so this
# job re-checks for itself instead). Fails closed: if that final check
# itself fails, `success` is also downgraded — an unconfirmed draft state is
# treated the same as a confirmed one.

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN required}"
: "${REPO:?REPO required}"
: "${SHA:?SHA required}"
: "${PR_NUMBER:?PR_NUMBER required}"
: "${EVENT_TIME:?EVENT_TIME required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT required}"

WORKFLOW_NAME="${WORKFLOW_NAME:-CI}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-20}"
MAX_WAIT_SECONDS="${MAX_WAIT_SECONDS:-3300}"

# No clock-skew buffer here (review finding on #2142): a stale run that
# happened to start just before EVENT_TIME would still pass a "started
# within the last N seconds" filter, which is exactly the race this
# threshold exists to close. EVENT_TIME and every workflow run's timestamp
# come from the same GitHub infrastructure clock — the triggering event
# necessarily precedes the run it triggers — so an exact `>=` bound (no
# subtraction) is both correct and sufficient; a run legitimately created
# by this event cannot be timestamped before the event itself.
not_before="${EVENT_TIME}"

elapsed=0
conclusion="not_found"
seen_run=false

while [ "$elapsed" -lt "$MAX_WAIT_SECONDS" ]; do
    # `if ! run_json=$(...)` (not a bare assignment) is load-bearing under
    # `set -e`: a bare `run_json=$(gh api ...)` would abort the whole script
    # the moment `gh api` hit a transient failure (network blip, secondary
    # rate limit, a momentary 5xx) — never reaching the GITHUB_OUTPUT write
    # below, so the job goes red with a bash error instead of reporting the
    # documented `timeout`/`not_found` conclusion. Treat an API failure the
    # same as "no run found yet": log it and retry on the next iteration.
    if ! run_json=$(gh api "repos/${REPO}/actions/runs?head_sha=${SHA}&per_page=20" --jq \
        "[.workflow_runs[] | select(.name == \"${WORKFLOW_NAME}\" and .run_started_at >= \"${not_before}\")] | sort_by(.run_started_at) | last // empty" 2>&1); then
        echo "gh api call failed (elapsed ${elapsed}s), will retry: ${run_json}"
        run_json=""
    fi

    if [ -n "$run_json" ]; then
        seen_run=true
        status=$(jq -r '.status' <<<"$run_json")
        if [ "$status" = "completed" ]; then
            conclusion=$(jq -r '.conclusion' <<<"$run_json")
            break
        fi
        echo "\"${WORKFLOW_NAME}\" run status: ${status} (elapsed ${elapsed}s)"
    else
        echo "No \"${WORKFLOW_NAME}\" run found yet for ${SHA} (elapsed ${elapsed}s)"
    fi

    sleep "$POLL_INTERVAL_SECONDS"
    elapsed=$((elapsed + POLL_INTERVAL_SECONDS))
done

if [ "$conclusion" = "not_found" ] && [ "$seen_run" = true ]; then
    conclusion="timeout"
fi

# Live re-check, not the job-start snapshot: a PR marked ready and then
# reverted to draft while this script was polling must not still trigger a
# review just because the earlier CI run it waited for eventually succeeded.
if [ "$conclusion" = "success" ]; then
    if is_draft=$(gh api "repos/${REPO}/pulls/${PR_NUMBER}" --jq '.draft' 2>&1); then
        if [ "$is_draft" = "true" ]; then
            echo "PR #${PR_NUMBER} is a draft as of the final check; downgrading conclusion"
            conclusion="draft"
        fi
    else
        echo "Final draft-state check failed, treating as draft (fail closed): ${is_draft}"
        conclusion="draft"
    fi
fi

echo "Resolved conclusion: ${conclusion}"
echo "conclusion=${conclusion}" >>"${GITHUB_OUTPUT}"
