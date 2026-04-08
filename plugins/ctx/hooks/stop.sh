#!/usr/bin/env bash
# stop.sh — Emit a stale-context reminder when the session changed tracked files.
#
# Compares current git state against the baseline recorded by session-start.sh.
# Silent on: missing baseline, "disabled" sentinel, or unchanged state.
# Prints a single reminder line when HEAD or working-tree status changed.

set -eu

_ctx_state_dir="${TMPDIR:-/tmp}/ctx-hook-${CLAUDE_SESSION_ID:-$$}"
_ctx_sentinel="$_ctx_state_dir/baseline"

# No baseline → plugin installed mid-session, or SessionStart didn't fire. No-op.
[ -f "$_ctx_sentinel" ] || exit 0

_ctx_first_line="$(head -n1 "$_ctx_sentinel" 2>/dev/null || printf '')"
if [ "$_ctx_first_line" = "disabled" ]; then
    exit 0
fi

# Must still be in a git repo (paranoid check).
git rev-parse --show-toplevel >/dev/null 2>&1 || exit 0

_ctx_baseline_head="$_ctx_first_line"
_ctx_baseline_status="$(sed -n '2p' "$_ctx_sentinel" 2>/dev/null || printf '')"

_ctx_now_head="$(git rev-parse HEAD 2>/dev/null || printf 'no-head')"
_ctx_now_status="$(git status --porcelain=v1 2>/dev/null | sha1sum | awk '{print $1}')"

if [ "$_ctx_now_head" = "$_ctx_baseline_head" ] && \
   [ "$_ctx_now_status" = "$_ctx_baseline_status" ]; then
    exit 0
fi

printf 'Context files may now be stale — run /ctx:check to validate.\n'
