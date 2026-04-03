# CLAUDE.md

## What this is

Toolshed is a Claude Code plugin marketplace monorepo (`knitli/toolshed`). It packages multiple plugins for installation from a single source.

## Key files

- `.claude-plugin/marketplace.json` — Discovery manifest listing all plugins with source paths
- `plugins/<name>/.claude-plugin/plugin.json` — Per-plugin manifest (authoritative for components)
- `plugins/<name>/package.json` — Per-plugin npm package (semantic-release writes the version)
- `.commitlintrc.json` — Enforces conventional commits with plugin scope
- `scripts/validate-marketplace.sh` — Validates manifest/package consistency
- `docs/plans/2026-04-03-toolshed-marketplace-design.md` — Design doc

## Architecture

All plugin logic is markdown prompts interpreted by Claude Code at runtime. No build step, no compiled code, no tests.

Version lives in two places per plugin: `package.json` (semantic-release writes) and `plugin.json` (Claude Code reads). These must stay in sync.

## Current plugins

- **ctx** (`plugins/ctx/`) — Context hygiene auditing
- **codeweaver** (`plugins/codeweaver/`) — Semantic code search

## Commit convention

```
type(scope): message
```

Scope must be a plugin name (`ctx`, `codeweaver`). Unscoped commits are for repo-level changes and do not trigger releases.

## Validation

```
npm run validate
```
