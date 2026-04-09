---
description: "Run a full context hygiene audit: discover all AI context files, check for staleness, and detect cross-tool drift"
---

# /ctx — Full Context Audit

Run a complete context hygiene audit: discover all AI context files, check them for staleness against the actual codebase, and detect drift/contradictions across tool boundaries.

## Arguments

`$ARGUMENTS`

- **No arguments**: audit everything — full discovery, check all files, detect all drift.
- **File paths** (e.g., `/ctx CLAUDE.md`): scope all three phases to just those files. Discovery still runs (to build the full inventory for drift comparison), but staleness checking and drift detection focus on the named files.
- **Ecosystem names** (e.g., `/ctx cursor serena`): scope to all context files belonging to those ecosystems (as defined in the INI).

## Instructions

You are running a context hygiene audit on this repository. Complete all three phases in order, then produce a summary report. If the user provided arguments above, scope your work accordingly — but always run discovery first to establish the full context file inventory.

### Phase 1: Discovery

Scan the repository for ALL AI context files using the plugin's authoritative ecosystem inventory at `${CLAUDE_PLUGIN_ROOT}/data/context-files.ini`. Read that file first — it lists every ecosystem, root file, nested memory file, tool directory, config file, and ignore directory the plugin knows about. Any entry there is in scope; entries not there are not (unless caught by heuristics, below).

The INI currently covers ~15 ecosystems: Claude Code, universal `AGENTS.md`, Gemini, OpenAI Codex, Cursor, Windsurf, Continue, Roo/Cline, Crush, Aider, Serena, spec-kit, GitHub agents/skills, VS Code, and planning/output directories. See `/ctx:discover` for the full treatment.

**Heuristic checks** (beyond the INI's exact-match list):
- Any markdown file in repo root with an ALL_CAPS filename not in the `allcaps_exclude` list under `[heuristics]` in the INI.
- Symlinks between context files (e.g., `GEMINI.md → CLAUDE.md`).
- Files containing phrases like "when working with this repo", "you are an AI", "assistant instructions" — these are often context files regardless of extension or location.

For each file found, record: path, tool ecosystem, file type (memory/config/planning/output), size, last modified date.

Produce the discovery inventory as a formatted table.

### Phase 2: Staleness Check

For each **memory and instruction file** found in Phase 1 (skip config-only files and old planning docs), extract factual claims and validate them against the actual codebase.

**Claims to extract and validate**:

1. **Path references** — Any file path or directory path mentioned. Check: does it exist?
2. **Version numbers** — Rust edition, rust-version, dependency versions. Check against: `Cargo.toml`, `package.json`, `pyproject.toml`, `go.mod`, or equivalent.
3. **Dependency names and versions** — Named dependencies with pinned versions. Check against lock files and manifests.
4. **Symbol references** — Type names, function names, module names in backticks. Check: do they exist in the codebase? Search for them.
5. **Structural claims** — "N crates", "N languages", "seven main modules". Check: count the actual items.
6. **Command references** — Build/test/lint commands. Check: do they exist in `mise.toml`, `Makefile`, `package.json` scripts, `justfile`, etc.?
7. **Architecture descriptions** — Technology claims ("uses Recoco", "built with tree-sitter"). Check: is that dependency actually present?

For each claim, assign a status:
- ✅ **Valid** — matches the codebase
- ⚠️ **Stale** — references something that has changed (provide the actual value)
- ❌ **Broken** — references something that doesn't exist at all
- ❓ **Unverifiable** — too vague to check programmatically

Report findings grouped by file, with line numbers where possible.

### Phase 3: Drift Detection

Compare memory/instruction files **against each other** to find contradictions.

For each pair of files that describe the same project:

1. **Identify shared topics** — Both describe the architecture? Both list dependencies? Both mention build commands?
2. **Compare claims on shared topics** — Do they agree? Where do they disagree?
3. **Flag contradictions** — Where file A says X and file B says Y about the same thing.
4. **Flag gaps** — Where file A covers a major topic (like a core dependency or architectural pattern) that file B omits entirely. This often means file B predates a significant change.

Also check for **orphaned planning docs**:
- Files in `claudedocs/` or similar that reference completed/superseded phases
- Planning docs whose proposed changes appear to have been implemented (or abandoned)
- Multiple versions of the same plan without clear resolution

### Summary Report

Produce a final summary with:

1. **Discovery stats**: Total files, breakdown by tool ecosystem, total size
2. **Staleness score**: X of Y verifiable claims are valid. Percentage.
3. **Critical issues**: The most important things to fix (broken paths, wrong versions, major contradictions)
4. **Drift summary**: Which files contradict each other and on what
5. **Recommendations**: Prioritized list of what to fix first
6. **Maintenance suggestions**: Files that should be archived, consolidated, or deleted

Format the report clearly with headers and use emoji status indicators (✅ ⚠️ ❌ ❓) for scannability.
