#!/usr/bin/env bash
# session-start.sh — Record a baseline for ctx's stale-context reminder.
#
# Runs on SessionStart. Decides whether the Stop hook should fire for this
# session and, if so, records a baseline hash of repo state to diff against.
#
# Sentinel file written to the session state dir:
#   disabled      — no context files found, or non-git repo; Stop hook no-ops
#   <git-hash>\n<status-hash>  — baseline for diffing at Stop time
#
# The session state dir is derived from CLAUDE_SESSION_ID when available and
# falls back to a PID-tagged temp path otherwise.

set -eu

_ctx_state_dir="${TMPDIR:-/tmp}/ctx-hook-${CLAUDE_SESSION_ID:-$$}"
mkdir -p "$_ctx_state_dir"
_ctx_sentinel="$_ctx_state_dir/baseline"

_ctx_disable() {
    printf 'disabled\n' >"$_ctx_sentinel"
    exit 0
}

# Must be a git repo — we rely on git for precise change detection.
if ! git rev-parse --show-toplevel >/dev/null 2>&1; then
    _ctx_disable
fi

# Must have at least one discoverable context file, else nothing can go stale.
_ctx_lib="$(dirname "$0")/lib/scan-context-files.sh"
if [ ! -f "$_ctx_lib" ]; then
    _ctx_disable
fi

_ctx_found="$(bash "$_ctx_lib" 2>/dev/null | head -n1 || true)"
if [ -z "$_ctx_found" ]; then
    _ctx_disable
fi

# Record baseline: HEAD commit + hash of the working tree status.
_ctx_head="$(git rev-parse HEAD 2>/dev/null || printf 'no-head')"
_ctx_status_hash="$(git status --porcelain=v1 2>/dev/null | sha1sum | awk '{print $1}')"
printf '%s\n%s\n' "$_ctx_head" "$_ctx_status_hash" >"$_ctx_sentinel"
