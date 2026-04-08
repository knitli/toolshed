#!/usr/bin/env bash
# scan-context-files.sh — Discover AI context files in the current project.
#
# Prints one path per line (NUL-safe via -0 flag). Exits 0 even when nothing is
# found; callers should check whether any lines were emitted.
#
# Sourced by ctx hooks and may be invoked directly by /ctx:discover helpers.
# Keep the pattern lists in sync with plugins/ctx/commands/ctx-discover.md.

set -eu

# --- fast finder selection ----------------------------------------------------
# Prefer tools that respect .gitignore and handle large trees well:
#   1. fd / fdfind — fastest, gitignore-aware, sensible defaults
#   2. rg --files  — nearly as fast, same ignore semantics
#   3. find        — POSIX fallback, slow but universal
# On Windows (Git Bash / WSL) the same binaries apply; native PowerShell is
# out of scope — this script assumes a POSIX shell.
_ctx_finder=""
if command -v fd >/dev/null 2>&1; then
    _ctx_finder="fd"
elif command -v fdfind >/dev/null 2>&1; then
    # Debian/Ubuntu ship fd as fdfind to avoid a name collision.
    _ctx_finder="fdfind"
elif command -v rg >/dev/null 2>&1; then
    _ctx_finder="rg"
else
    _ctx_finder="find"
fi

# --- patterns -----------------------------------------------------------------
# Root-level memory files (exact names, repo root only).
_ctx_root_files=(
    CLAUDE.md AGENTS.md GEMINI.md
    .cursorrules .windsurfrules .continuerules .clinerules
    ai-rules.yml .ai-rules.yml
    .aider.conf.yml .aider.model.settings.yml
    .mcp.json
)

# Tool directories — everything inside counts as context.
_ctx_tool_dirs=(
    .claude .gemini .codex .cursor .continue .roo .serena .specify
    .github/agents .github/skills
    .vscode
)

# Nested memory files that can appear at any depth (CLAUDE.md in subpackages,
# AGENTS.md in monorepo workspaces, etc.).
_ctx_nested_names=(CLAUDE.md AGENTS.md GEMINI.md)

# --- emission -----------------------------------------------------------------
_ctx_emit_if_exists() {
    # $1 = path; prints it (with trailing newline) when it exists.
    [ -e "$1" ] && printf '%s\n' "$1"
}

# Root-level exact files.
for f in "${_ctx_root_files[@]}"; do
    _ctx_emit_if_exists "$f"
done

# Tool directories — list every file beneath them.
for d in "${_ctx_tool_dirs[@]}"; do
    [ -d "$d" ] || continue
    case "$_ctx_finder" in
        fd|fdfind)
            "$_ctx_finder" --type f --hidden --no-ignore . "$d"
            ;;
        rg)
            rg --files --hidden --no-ignore "$d"
            ;;
        find)
            find "$d" -type f -print
            ;;
    esac
done

# Nested memory files anywhere in the tree (skip .git, node_modules, venvs).
case "$_ctx_finder" in
    fd|fdfind)
        # fd: -H includes hidden, default excludes .git; exclude common noise.
        "$_ctx_finder" --type f --hidden \
            --exclude .git --exclude node_modules \
            --exclude .venv --exclude venv --exclude target --exclude dist \
            --glob "CLAUDE.md" --glob "AGENTS.md" --glob "GEMINI.md" .
        ;;
    rg)
        rg --files --hidden \
            --glob '!.git' --glob '!node_modules' \
            --glob '!.venv' --glob '!venv' --glob '!target' --glob '!dist' \
            --glob 'CLAUDE.md' --glob 'AGENTS.md' --glob 'GEMINI.md'
        ;;
    find)
        find . \
            \( -name .git -o -name node_modules -o -name .venv -o -name venv \
               -o -name target -o -name dist \) -prune -o \
            -type f \( -name CLAUDE.md -o -name AGENTS.md -o -name GEMINI.md \) \
            -print
        ;;
esac
