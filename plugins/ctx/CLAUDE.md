> **Note:** This plugin is part of the [knitli/toolshed](https://github.com/knitli/toolshed) marketplace monorepo.

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**ctx** is a Claude Code plugin that audits AI context files (CLAUDE.md, AGENTS.md, Serena memories, Cursor rules, etc.) for staleness, contradictions, and drift across 10+ tool ecosystems. It uses the LLM itself as the analysis engine — no binary dependencies or external API keys.

Installable via `/plugin install knitli/ctx`. The plugin exposes slash commands, agents, a skill, and a session-stop hook.

## Origin and roadmap

`thread-context-doctor-spec.md` is the original product spec. It describes ctx as a Rust CLI binary inside the [Thread](https://github.com/knitli/thread) workspace with AST-powered claim extraction. This repo is the **Claude Code plugin** — the fast-to-ship Phase 1 from `PLAN.md` that uses the LLM as the analysis engine instead of compiled Rust.

The larger vision is integrating Thread into the ctx pipeline. Thread is a high-performance realtime codebase intelligence tool built on tree-sitter + ast-grep with data ETL integration that builds a codebase-wide AST graph. It is approaching language-agnostic coverage via universal node mapping across any tree-sitter grammar. In the ctx pipeline, Thread would provide deterministic claim extraction, precise symbol/path/version validation, and a structured codebase graph that agents can query — replacing the LLM-as-analysis-engine approach with compiled speed and reproducibility while keeping the LLM for semantic drift detection. Thread also enables the future phases: canonical context store, cross-tool materialization, and continuous state/memory management for agents.

The spec's Rust architecture (two crates: `ctx` CLI + `ctx-core` library, claim data model, three extraction layers) is the planned Phase 3 evolution. Later phases (canonical store, materialization, watch mode, CI integration) are not in scope for this plugin.

## Plugin structure

This is a **prompt-only Claude Code plugin** — all components are markdown files interpreted by Claude Code at runtime. There is no build step, no tests, no compiled code.

- `.claude-plugin/plugin.json` — Plugin metadata (name, version, description)
- `commands/` — Slash commands (`/ctx`, `/ctx:discover`, `/ctx:check`, `/ctx:drift`, `/ctx:fix`)
- `agents/` — Subagents spawned by commands (`context-auditor`, `claim-validator`)
- `skills/context-hygiene/SKILL.md` — Passive knowledge loaded into context about context file patterns
- `hooks/hooks.json` — Hook config: `Stop` event prompt reminds about stale context after code-modifying sessions
- `cross-client/` — Equivalent functionality for non-Claude tools (Cursor `.mdc` rule, Codex `SKILL.md`, generic `AGENTS.md`)

## Architecture

The plugin follows a **three-phase audit pipeline**:

1. **Discovery** — Scan known locations for AI context files across all tool ecosystems
2. **Staleness check** — Extract factual claims (paths, versions, symbols, counts, commands, dependencies) from memory files and validate each against the actual codebase
3. **Drift detection** — Compare memory files against each other to find contradictions and gaps

`/ctx` runs all three phases. `/ctx:discover`, `/ctx:check`, `/ctx:drift` run individual phases. `/ctx:fix` runs the full audit then proposes interactive edits.

The two agents divide labor: `context-auditor` handles discovery and high-level analysis; `claim-validator` handles per-claim verification with a structured output format (CLAIM/FILE/TYPE/STATUS/EVIDENCE/ACTUAL).

## Supported tool ecosystems

The plugin knows how to find and validate context files for: Claude Code, GitHub Copilot/Codex, Gemini, Cursor, Serena, spec-kit, Roo/Cline, Continue, Aider, and Windsurf. The full location list is in `commands/ctx-discover.md`.

## Cross-client packaging

`cross-client/` contains the same core logic adapted to each client's native format:
- `AGENTS.md` — Universal agent instruction file (works with any tool that reads it)
- `.cursor/rules/ctx-audit.mdc` — Cursor rule triggered by context file globs
- `.codex/SKILL.md` — OpenAI Codex skill format

These are lower-fidelity than the Claude Code plugin (no hooks, no agent orchestration) but provide broad reach.

## When editing this plugin

- All logic lives in the markdown prompts. Changes to audit behavior go in the command files.
- The claim type taxonomy (path, version, dependency, symbol, count, command, technology, description) is defined in `commands/ctx-check.md` and mirrored in `agents/claim-validator.md` — keep them in sync.
- The authoritative source hierarchy (code > governance > CLAUDE.md > tool memories > planning docs) appears in multiple files — keep consistent.
- Hooks use the JSON format in `hooks/hooks.json` — not markdown. See the Claude Code plugin API for supported event types and hook types (`command`, `prompt`, `http`, `agent`).
- Agents require YAML frontmatter with at least `name` and `description` (for auto-invocation). `tools` restricts available tools.
- Commands support optional `description` frontmatter for help text display.
- Skills must be directories (`skills/skill-name/SKILL.md`), not flat markdown files.
