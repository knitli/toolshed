---
description: "Scan the repository and inventory all AI context files across tool ecosystems"
---

# /ctx:discover — Context File Inventory

Scan this repository and produce a complete inventory of AI context files across all tool ecosystems.

## Arguments

`$ARGUMENTS`

- **No arguments**: discover all context files across all ecosystems.
- **Ecosystem names** (e.g., `/ctx:discover cursor serena`): restrict scanning to those ecosystems only.
- **Directory paths** (e.g., `/ctx:discover .claude/ .serena/`): scan only those directories.

## Instructions

Search every location listed in the plugin's authoritative ecosystem inventory. If the user provided arguments above, restrict the scan to the specified ecosystems or directories. For each file found, record its path, which tool ecosystem it belongs to, its type (memory, config, planning, or output), file size, and last-modified date.

### Locations to scan

**The authoritative list of known ecosystems, root files, nested memory files, tool directories, config files, and ignore directories lives in `${CLAUDE_PLUGIN_ROOT}/data/context-files.ini`.** Read that file first — it is the single source of truth. Any file, directory, or glob listed there is in scope; anything not listed is not. When adding support for a new ecosystem, add it to the INI, not here.

Briefly, the INI covers ~15 ecosystems including Claude Code, universal `AGENTS.md`, Gemini, OpenAI Codex, Cursor, Windsurf, Continue, Roo/Cline, Crush, Aider, Serena, spec-kit, GitHub agents/skills, VS Code, and planning/output directories (`claudedocs/`, `specs/`, `plans/`, etc.). The `[ignore]` section lists directories the scanner must not descend into (`.git`, `node_modules`, `.venv`, build outputs). The `[heuristics]` section lists standard ALL_CAPS markdown filenames to exclude from heuristic detection.

**Heuristic detection** (not covered by the INI's exact-match entries): after reading the INI and collecting its listed files, also scan for:
- Markdown files in the repo root with ALL_CAPS names that don't match the `allcaps_exclude` list in `[heuristics]`. These are often context files in disguise.
- Symlinks between any context files (e.g., `GEMINI.md → CLAUDE.md`).
- Files in `docs/` that appear AI-agent-targeted (phrases like "project overview", "when working with this repo", "assistant instructions") rather than user-facing.

If a shell helper is available, `${CLAUDE_PLUGIN_ROOT}/hooks/lib/scan-context-files.sh` will emit the deduped list of matching files (one per line) using whichever finder binary is available; the same INI drives it.

### Output format

Produce a table grouped by tool ecosystem showing all discovered files, then a summary with:
- Total count and total size
- Breakdown by ecosystem
- Oldest and newest files
- Any symlinks detected
- Any unusually large directories (10+ files in a planning/output dir)
