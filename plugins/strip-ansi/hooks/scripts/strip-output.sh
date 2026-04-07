#!/usr/bin/env bash
# PostToolUse hook for Bash: strip ANSI escape sequences from tool output
# before it lands in the agent's context.
#
# Reads the hook payload (JSON) on stdin, extracts tool_response.stdout
# and tool_response.stderr, runs each through `strip-ansi --preset dumb`,
# and emits a hookSpecificOutput.additionalContext block ONLY when the
# stripped output differs from the original (i.e., ANSI was actually present).
#
# Requires: jq, strip-ansi (cargo install distill-strip-ansi)
# Fails open: if either tool is missing, the hook exits 0 without modifying
# anything so it never blocks the user's workflow.

set -euo pipefail

command -v jq >/dev/null 2>&1 || exit 0
command -v strip-ansi >/dev/null 2>&1 || exit 0

payload=$(cat)

stdout_raw=$(printf '%s' "$payload" | jq -r '.tool_response.stdout // ""')
stderr_raw=$(printf '%s' "$payload" | jq -r '.tool_response.stderr // ""')

stdout_clean=$(printf '%s' "$stdout_raw" | strip-ansi --preset dumb)
stderr_clean=$(printf '%s' "$stderr_raw" | strip-ansi --preset dumb)

if [[ "$stdout_raw" == "$stdout_clean" && "$stderr_raw" == "$stderr_clean" ]]; then
  exit 0
fi

# ANSI was present. Surface a sanitized view to the agent via additionalContext.
# We can't mutate the tool_response in place from PostToolUse, but additionalContext
# gives the agent a clean version to quote from instead of the polluted original.
jq -n \
  --arg stdout "$stdout_clean" \
  --arg stderr "$stderr_clean" \
  '{
    hookSpecificOutput: {
      hookEventName: "PostToolUse",
      additionalContext: ("[strip-ansi] ANSI escape sequences detected and stripped from Bash output. Use this sanitized version when quoting:\n\n--- stdout (sanitized) ---\n" + $stdout + "\n--- stderr (sanitized) ---\n" + $stderr)
    }
  }'
