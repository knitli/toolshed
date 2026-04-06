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
