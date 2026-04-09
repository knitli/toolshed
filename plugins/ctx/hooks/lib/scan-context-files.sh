#!/usr/bin/env bash
# scan-context-files.sh — Discover AI context files in the current project.
#
# Reads the authoritative ecosystem list from data/context-files.ini and
# emits one matching file path per line. Exits 0 even when nothing is found;
# callers check whether any lines were emitted.
#
# Finder cascade (fastest to slowest):
#   fd → fdfind → rg --files → find
# If none of those are available, writes a "needs-model-scan" sentinel to
# stderr and exits 2 — the caller should surface the work to the model via
# Glob/Grep (which are always available in the LLM tool set).
#
# INI parser: pure awk, POSIX. No jq/yq/python dependency.

set -eu

# --- locate data file ---------------------------------------------------------
_ctx_script_dir="$(cd "$(dirname "$0")" && pwd)"
_ctx_data_file="${_ctx_script_dir}/../../data/context-files.ini"
if [ ! -f "$_ctx_data_file" ]; then
    printf 'scan-context-files: missing data file %s\n' "$_ctx_data_file" >&2
    exit 2
fi

# --- parse INI into TSV (section\tkey\tvalue) ---------------------------------
# Repeated keys are preserved as separate lines.
_ctx_parse_ini() {
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        /^\[.*\]$/ {
            section = substr($0, 2, length($0) - 2)
            next
        }
        /^[[:alnum:]_]+[[:space:]]*=/ {
            key = $0
            sub(/[[:space:]]*=.*/, "", key)
            val = $0
            sub(/^[^=]*=[[:space:]]*/, "", val)
            sub(/[[:space:]]+$/, "", val)
            print section "\t" key "\t" val
        }
    ' "$_ctx_data_file"
}

_ctx_tsv="$(_ctx_parse_ini)"

# Helper: extract values for a given key across all sections.
# Usage: _ctx_values_for root_file
_ctx_values_for() {
    printf '%s\n' "$_ctx_tsv" | awk -F'\t' -v k="$1" '$2 == k { print $3 }'
}

# Collect pattern lists.
_ctx_root_files="$(_ctx_values_for root_file)"
_ctx_nested_files="$(_ctx_values_for nested_file | sort -u)"
_ctx_directories="$(_ctx_values_for directory)"
_ctx_config_files="$(_ctx_values_for config_file)"
_ctx_file_globs="$(_ctx_values_for file_glob)"
_ctx_ignore_dirs="$(_ctx_values_for ignore_dir)"

# --- finder selection ---------------------------------------------------------
if command -v fd >/dev/null 2>&1; then
    _ctx_finder="fd"
elif command -v fdfind >/dev/null 2>&1; then
    _ctx_finder="fdfind"
elif command -v rg >/dev/null 2>&1; then
    _ctx_finder="rg"
elif command -v find >/dev/null 2>&1; then
    _ctx_finder="find"
else
    printf 'needs-model-scan\n' >&2
    exit 2
fi

# --- build ignore args for each finder ----------------------------------------
_ctx_fd_excludes=""
_ctx_rg_globs=""
_ctx_find_prunes=""
while IFS= read -r d; do
    [ -n "$d" ] || continue
    _ctx_fd_excludes="$_ctx_fd_excludes --exclude $d"
    _ctx_rg_globs="$_ctx_rg_globs --glob !$d"
    if [ -z "$_ctx_find_prunes" ]; then
        _ctx_find_prunes="-name $d"
    else
        _ctx_find_prunes="$_ctx_find_prunes -o -name $d"
    fi
done <<EOF
$_ctx_ignore_dirs
EOF

# --- emit matches -------------------------------------------------------------
# All emission goes through _ctx_emit which normalizes leading "./" so that
# the final sort -u can merge duplicates from different code paths.
_ctx_emit() {
    printf '%s\n' "$1" | sed 's|^\./||'
}

_ctx_emit_if_exists() {
    if [ -e "$1" ]; then
        _ctx_emit "$1"
    fi
    return 0
}

_ctx_emit_all() {

# Root-level exact files and config files (repo root only).
while IFS= read -r f; do
    [ -n "$f" ] && _ctx_emit_if_exists "$f"
done <<EOF
$_ctx_root_files
$_ctx_config_files
EOF

# Tool directories — list every file beneath them.
while IFS= read -r d; do
    [ -n "$d" ] || continue
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
done <<EOF
$_ctx_directories
EOF

# File globs (relative to repo root).
while IFS= read -r g; do
    [ -n "$g" ] || continue
    # Let the shell expand the glob; guard against no-match literal output.
    for match in $g; do
        [ -e "$match" ] && printf '%s\n' "$match"
    done
done <<EOF
$_ctx_file_globs
EOF

# Nested memory files anywhere in the tree, honoring the ignore list.
if [ -n "$_ctx_nested_files" ]; then
    case "$_ctx_finder" in
        fd|fdfind)
            # fd takes a single regex pattern. Build an alternation like
            # ^(CLAUDE|AGENTS|GEMINI)\.md$ from the nested_files entries.
            _ctx_alt=""
            while IFS= read -r n; do
                [ -n "$n" ] || continue
                # Escape regex metacharacters in the filename.
                n_esc="$(printf '%s' "$n" | sed 's/[.[\*^$()+?{|]/\\&/g')"
                if [ -z "$_ctx_alt" ]; then
                    _ctx_alt="$n_esc"
                else
                    _ctx_alt="$_ctx_alt|$n_esc"
                fi
            done <<EOF
$_ctx_nested_files
EOF
            # shellcheck disable=SC2086
            "$_ctx_finder" --type f --hidden $_ctx_fd_excludes \
                "^($_ctx_alt)\$" .
            ;;
        rg)
            _ctx_name_globs=""
            while IFS= read -r n; do
                [ -n "$n" ] && _ctx_name_globs="$_ctx_name_globs --glob $n"
            done <<EOF
$_ctx_nested_files
EOF
            # shellcheck disable=SC2086
            rg --files --hidden $_ctx_rg_globs $_ctx_name_globs
            ;;
        find)
            _ctx_find_names=""
            while IFS= read -r n; do
                [ -n "$n" ] || continue
                if [ -z "$_ctx_find_names" ]; then
                    _ctx_find_names="-name $n"
                else
                    _ctx_find_names="$_ctx_find_names -o -name $n"
                fi
            done <<EOF
$_ctx_nested_files
EOF
            # shellcheck disable=SC2086
            find . \( $_ctx_find_prunes \) -prune -o \
                -type f \( $_ctx_find_names \) -print
            ;;
    esac
fi
}

# Run the emission pipeline: normalize leading "./" and dedupe.
_ctx_emit_all | sed 's|^\./||' | sort -u
