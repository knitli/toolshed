# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Toolshed is a Claude Code plugin marketplace monorepo (`knitli/toolshed`). It packages multiple plugins for installation from a single source. Users add the marketplace with `/plugin marketplace add knitli/toolshed` and install individual plugins by name.

## Commands

```bash
npm run validate          # Run marketplace validation (structure, JSON, version sync)
```

There is no build step, no test suite, and no linter beyond commitlint on PRs.

## Architecture

All plugin logic is **markdown prompts** interpreted by Claude Code at runtime. There is no compiled code.

### Version sync

Each plugin's version lives in two files that must match:
- `plugins/<name>/package.json` — semantic-release writes this on merge to main
- `plugins/<name>/.claude-plugin/plugin.json` — Claude Code reads this at install time

The release workflow auto-syncs `plugin.json` after semantic-release bumps `package.json`. The validation script (`scripts/validate-marketplace.sh`) catches mismatches.

### Key files

- `.claude-plugin/marketplace.json` — Discovery manifest listing all plugins with source paths
- `plugins/<name>/.claude-plugin/plugin.json` — Per-plugin manifest (name, version, description, mcpServers, userConfig)
- `plugins/<name>/package.json` — npm package with `semantic-release-monorepo` config
- `.commitlintrc.json` — Enforces conventional commits; `scope-enum` must list all plugin names
- `.github/workflows/release.yml` — Per-plugin semantic-release via matrix; `matrix.plugin` must list all plugin names
- `.github/workflows/validate.yml` — PR gate: runs marketplace validation + commitlint

### Plugin component types

Plugins can contain any combination of these, all as markdown files:
- `commands/` — Slash commands (e.g., `/ctx`, `/ctx:check`)
- `agents/` — Subagents with YAML frontmatter (`name`, `description`, optional `tools`)
- `skills/<name>/SKILL.md` — Passive knowledge loaded into context (must be a directory, not a flat file)
- `hooks/hooks.json` — Event-driven automation (JSON format, not markdown)
- `cross-client/` — Equivalent logic for non-Claude tools (Cursor `.mdc`, Codex, generic `AGENTS.md`)

## Runtime environment assumptions

What a plugin can and cannot rely on at execution time. These are the ground rules for writing hooks, commands, and agents in this marketplace.

### Tools available to the LLM (prompts: commands, agents, skills, prompt-type hooks)

**Always available, no user permission required** — safe to assume in any prompt:
`Read`, `Glob`, `Grep`, `Agent`, `AskUserQuestion`, `TodoWrite`, `ToolSearch`, `EnterPlanMode`/`ExitPlanMode`, `EnterWorktree`/`ExitWorktree`, `CronCreate`/`CronDelete`/`CronList`, `TaskCreate`/`TaskGet`/`TaskList`/`TaskUpdate`/`TaskStop`, `ListMcpResourcesTool`, `ReadMcpResourceTool`, LSP tools.

**Permission-gated, may be denied** — never assume; degrade gracefully:
`Bash`, `Edit`, `Write`, `NotebookEdit`, `WebFetch`, `WebSearch`, all MCP server tools.

Practical consequences:
- A command/agent can unconditionally `Read ${CLAUDE_PLUGIN_ROOT}/data/foo.json` to load plugin data files. This is the preferred pattern for shared data across prompts.
- Any prompt that *requires* `Bash`/`Edit`/`Write` to function must state so in its description and fail clearly if denied, rather than silently misbehaving.
- Plugin data files the LLM reads should be formats `Read` handles well (text, JSON, YAML, markdown). No binary formats.

### Tools available to `command`-type hooks (shell environment)

Claude Code does **not** guarantee any particular binary is on `PATH`. The docs show `jq`, `git`, etc. in examples, but nothing is promised. Hook scripts must:
- Check for tools with `command -v <tool>` before use.
- Provide POSIX fallbacks (`awk`, `sed`, `grep`, `find`) — these are the only things reasonably assumed on any Unix-like environment, and Git Bash ships them on Windows.
- Prefer fast tools when present (`fd` → `fdfind` → `rg --files` → `find`; `jq` → pure-shell parsing) via a detection cascade.
- Exit 0 silently on the no-op path; only write to stdout when the hook has something to actually say. **Never** emit reasoning, status chatter, or acknowledgements — Stop-hook stdout becomes feedback and can trigger re-firing loops.
- Assume nothing about `$SHELL`; scripts should use `#!/usr/bin/env bash` and `set -eu`, and avoid bashisms if portability to `sh` is desired.

### The universal fallback: the model itself

LLM tools (`Read`, `Glob`, `Grep`) are **always available** and form the bottom rung of every degradation ladder. When a shell hook can't find any usable finder binary — or when a data file can't be parsed without `jq` — the correct move is not to give up, but to surface the work to the next prompt turn and let the model handle it with its built-in tools. The work moves from invisible/background to visible/foreground, costs some context budget, and is slower, but it always succeeds.

In practice this means a hook can exit 0 with a sentinel (e.g. writing `needs-model-scan` to its state file) and a companion command/agent prompt reads that sentinel and performs the scan with `Glob`/`Grep`. This pattern turns "graceful degradation" from "fail cleanly" into "fail over to a different execution layer." Prefer it over silent no-ops when the hook's job actually matters.

### Prompt-type hooks: avoid for Stop

The Stop event re-fires if the hook's output is treated as new model feedback. LLMs are bad at "say nothing" and tend to narrate their silence, which creates an infinite loop. Prefer `command`-type hooks for Stop. Reserve `prompt`-type hooks for events where LLM judgment is genuinely needed and looping isn't a risk.

## Current plugins

- **ctx** (`plugins/ctx/`) — Context hygiene auditing. Has its own `CLAUDE.md` with detailed architecture.
- **codeweaver** (`plugins/codeweaver/`) — Semantic code search MCP server. Alpha status. Bundles an MCP server config in `plugin.json` using `uvx`.

## Adding a new plugin

Four files must be updated in sync:
1. Create `plugins/<name>/.claude-plugin/plugin.json` and `plugins/<name>/package.json` with matching versions
2. Add entry to `.claude-plugin/marketplace.json` `plugins` array
3. Add plugin name to `scope-enum` in `.commitlintrc.json`
4. Add plugin name to `matrix.plugin` in `.github/workflows/release.yml`

## Commit convention

```
type(scope): message
```

- Scope must be a plugin name (`ctx`, `codeweaver`). Unscoped commits are for repo-level changes only and do not trigger releases.
- `feat` → minor bump, `fix` → patch bump, `feat!` or `BREAKING CHANGE` → major bump.
- `chore`, `docs`, `ci`, `style`, `refactor`, `test` do not trigger releases.
