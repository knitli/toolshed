"""Offline stage-3 spike: classify observations, never certify round completion.

Input is locally curated evidence, NOT an authenticated GitHub adapter. IDs below
are observed provider identities, not a new runtime authority policy.
"""

import json
from pathlib import Path
import re
import sys


ACTORS = {"codex_code": 199175422, "codex_security": 199175422,
          "knitli_agent": 15368}  # Knitli job evidence is from GitHub Actions.


def classify(evidence, candidate):
    result = {"signal": "unknown", "candidate": "unknown", "round_complete": False}
    if not isinstance(evidence, dict) or not isinstance(candidate, dict):
        return result
    provider = evidence.get("provider")
    if provider not in ACTORS or evidence.get("actor_id") != ACTORS[provider]:
        return result
    if evidence.get("sources_complete") is not True:
        return result
    head = candidate.get("head_sha")
    reviewed = evidence.get("reviewed_head")
    if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head):
        return result
    if isinstance(reviewed, str) and re.fullmatch(r"[0-9a-f]{7,40}", reviewed):
        result["candidate"] = ("stale_head" if not head.startswith(reviewed)
                               else "current_head" if reviewed == head else "prefix_only")
    # Base/policy/attempt evidence is separate; equal head does not imply equal round.
    for key in ("base_sha", "policy_revision", "invocation_id", "run_attempt"):
        if key in candidate and evidence.get(key) != candidate[key]:
            result["candidate"] = "stale_or_unbound_round"
    if evidence.get("kind") in ("reaction", "partial_comment"):
        return result
    status = evidence.get("status")
    if evidence.get("kind") == "no_run_observed":
        result["signal"] = "no_run_observed"
    elif status in ("cancelled", "canceled"):
        result["signal"] = "execution_cancelled"
    elif status == "timed_out":
        result["signal"] = "execution_timed_out"
    elif status in ("failed", "failure"):
        result["signal"] = "execution_failed"
    elif status in ("queued", "in_progress", "running"):
        result["signal"] = "running"
    elif provider == "knitli_agent":
        if evidence.get("review_step") == "skipped":
            result["signal"] = "review_not_run"
        elif evidence.get("review_step") in ("failure", "cancelled", "timed_out"):
            result["signal"] = "execution_failed"
        elif status == "success" and evidence.get("review_step") == "success":
            result["signal"] = "execution_succeeded_unproven"
    elif status == "completed":
        result["signal"] = ("reported_completed_with_findings"
                            if evidence.get("findings_present") is True
                            else "reported_completed")
    return result


def replay(path):
    cases = json.loads(path.read_text())["cases"]
    for case in cases:
        actual = classify(case["evidence"], case["candidate"])
        if actual != case["expected"]:
            raise AssertionError((case["name"], actual, case["expected"]))
    print(f"PASS: {len(cases)} reviewer-signal cases; no clean-completion authority")


if __name__ == "__main__":
    replay(Path(sys.argv[1]) if len(sys.argv) > 1 else
           Path(__file__).resolve().parents[1] / "docs/reviewer-signals/replay.json")
