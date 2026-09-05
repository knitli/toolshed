// SPDX-FileCopyrightText: 2026 Knitli Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const script = join(import.meta.dir, "wait-for-ci.sh");
const eventTime = "2026-09-04T12:00:00Z";
const head = "0123456789abcdef0123456789abcdef01234567";

// Replace only GitHub/network access and wall-clock sleeping. The script's
// actual jq expression, polling budget, and GITHUB_OUTPUT write still execute.
const harness = `
gh() {
  if [[ "$1" != api || "$3" != --jq ]]; then
    return 1
  fi
  case "$2" in
    "repos/knitli/toolshed/actions/runs?head_sha=${head}&per_page=20")
      jq "$4" <<< "$RUNS_FIXTURE"
      ;;
    repos/knitli/toolshed/pulls/17)
      if [[ "$DRAFT_CHECK" == fail ]]; then return 1; fi
      jq -r "$4" <<< "$DRAFT_CHECK"
      ;;
    *) return 1 ;;
  esac
}
sleep() { :; }
source "$1"
`;

function runGate(
  options: {
    workflow?: string;
    runName?: string;
    startedAt?: string;
    sha?: string;
    draftCheck?: string;
    status?: string;
    conclusion?: string;
  } = {},
) {
  const directory = mkdtempSync(join(tmpdir(), "wait-for-ci-test-"));
  const output = join(directory, "output");
  try {
    const result = Bun.spawnSync(
      ["bash", "-c", harness, "wait-for-ci-test", script],
      {
        env: {
          ...process.env,
          GH_TOKEN: "test-token-no-network",
          REPO: "knitli/toolshed",
          SHA: options.sha ?? head,
          PR_NUMBER: "17",
          EVENT_TIME: eventTime,
          GITHUB_OUTPUT: output,
          WORKFLOW_NAME: options.workflow ?? "",
          POLL_INTERVAL_SECONDS: "1",
          MAX_WAIT_SECONDS: "2",
          DRAFT_CHECK: options.draftCheck ?? '{"draft":false}',
          RUNS_FIXTURE: JSON.stringify({
            workflow_runs: [
              {
                id: 1,
                name: options.runName ?? "Validate",
                head_sha: head,
                run_started_at: options.startedAt ?? eventTime,
                status: options.status ?? "completed",
                conclusion: options.conclusion ?? "success",
              },
            ],
          }),
        },
        timeout: 5_000,
      },
    );
    expect(result.exitCode).toBe(0);
    return readFileSync(output, "utf8").trim();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("accepts the current head Validate success with the default workflow name", () => {
  expect(runGate()).toBe("conclusion=success");
});

test("honors an explicit workflow name override", () => {
  expect(runGate({ workflow: "Custom checks", runName: "Custom checks" })).toBe(
    "conclusion=success",
  );
});

test("does not accept a success older than the triggering event", () => {
  expect(runGate({ startedAt: "2026-09-04T11:59:59Z" })).toBe(
    "conclusion=not_found",
  );
});

test("does not accept a success for a different head", () => {
  expect(runGate({ sha: "different-head" })).toBe("conclusion=not_found");
});

test("downgrades success when the final live PR check reports a draft", () => {
  expect(runGate({ draftCheck: '{"draft":true}' })).toBe("conclusion=draft");
});

test("fails closed when the final live PR check fails", () => {
  expect(runGate({ draftCheck: "fail" })).toBe("conclusion=draft");
});

test("reports timeout when a matching run never completes", () => {
  expect(runGate({ status: "in_progress" })).toBe("conclusion=timeout");
});

test("preserves a completed run failure conclusion", () => {
  expect(runGate({ conclusion: "failure" })).toBe("conclusion=failure");
});
