# Toolshed Marketplace Design

## Summary

Convert the standalone `ctx-plugin` and `codeweaver-plugin` repositories into a single monorepo plugin marketplace at `knitli/toolshed`. Users add the marketplace with `/plugin marketplace add knitli/toolshed` and install individual plugins by name.

## Repository

- **Name**: `knitli/toolshed`
- **Existing repos**: `knitli/ctx` and `knitli/codeweaver` will be archived with pointers to the new repo

## Structure

```
knitli/toolshed/
├── .claude-plugin/
│   └── marketplace.json
├── plugins/
│   ├── ctx/
│   │   ├── .claude-plugin/
│   │   │   └── plugin.json
│   │   ├── package.json              # version anchor for semantic-release
│   │   ├── CHANGELOG.md
│   │   ├── README.md
│   │   ├── CLAUDE.md
│   │   ├── commands/
│   │   │   ├── ctx.md
│   │   │   ├── ctx-check.md
│   │   │   ├── ctx-discover.md
│   │   │   ├── ctx-drift.md
│   │   │   └── ctx-fix.md
│   │   ├── agents/
│   │   │   ├── claim-validator.md
│   │   │   └── context-auditor.md
│   │   ├── skills/
│   │   │   └── context-hygiene/
│   │   │       └── SKILL.md
│   │   ├── hooks/
│   │   │   └── hooks.json
│   │   └── cross-client/
│   │       ├── AGENTS.md
│   │       ├── .cursor/rules/
│   │       │   └── ctx-audit.mdc
│   │       └── .codex/
│   │           └── SKILL.md
│   └── codeweaver/
│       ├── .claude-plugin/
│       │   └── plugin.json
│       ├── package.json              # version anchor for semantic-release
│       ├── CHANGELOG.md
│       ├── README.md
│       ├── .mcp.json
│       ├── agents/
│       │   └── onboarding/
│       │       ├── README.md
│       │       └── SKILL.md
│       ├── skills/
│       │   ├── README.md
│       │   └── setup/
│       │       └── SKILL.md
│       └── hooks/
│           ├── README.md
│           ├── hooks.json
│           └── scripts/
│               └── check-first-run.sh
├── .github/
│   ├── workflows/
│   │   ├── validate.yml
│   │   └── release.yml
│   └── PULL_REQUEST_TEMPLATE.md
├── scripts/
│   └── validate-marketplace.sh
├── package.json                      # root: workspaces, devDeps, commitlint
├── .commitlintrc.json
├── README.md
├── CONTRIBUTING.md
├── CLAUDE.md
└── LICENSE
```

## Marketplace Manifest

`.claude-plugin/marketplace.json`:

```json
{
  "name": "toolshed",
  "owner": {
    "name": "Knitli Inc.",
    "email": "hello@knitli.com"
  },
  "plugins": [
    {
      "name": "ctx",
      "source": "./plugins/ctx",
      "description": "Context hygiene for AI-assisted codebases. Finds stale, contradictory, and drifting AI context files across 10+ tool ecosystems.",
      "keywords": ["context", "memory", "staleness", "drift", "hygiene"],
      "category": "quality",
      "license": "MIT"
    },
    {
      "name": "codeweaver",
      "source": "./plugins/codeweaver",
      "description": "Semantic code search with hybrid search, AST-level understanding, and intelligent chunking for 166+ languages.",
      "keywords": ["search", "semantic", "AST", "indexing", "code-intelligence"],
      "category": "search",
      "license": "MIT OR Apache-2.0"
    }
  ]
}
```

Version and component details are authoritative in each plugin's own `plugin.json` (`strict: true` default).

## Versioning

### Strategy

Semantic-release with `semantic-release-monorepo`. Each plugin versions independently.

### Version sources

Each plugin has two version files kept in sync:

- **`package.json`** — semantic-release reads and bumps this (source of truth at release time)
- **`.claude-plugin/plugin.json`** — Claude Code reads this at install time

A post-release script syncs the bumped version from `package.json` into `plugin.json` and commits it.

### Git tags

Namespaced by plugin: `ctx@0.2.0`, `codeweaver@0.7.0`.

### Commit convention

Conventional commits with plugin name as scope:

| Commit | Effect |
|--------|--------|
| `fix(ctx): correct claim type matching` | ctx patch release |
| `feat(codeweaver): add reindex command` | codeweaver minor release |
| `feat(ctx)!: redesign audit pipeline` | ctx major release |
| `chore: update CI` | no release |
| `docs: update root README` | no release |

### Per-plugin package.json

Thin version anchors, never published to npm:

```json
{
  "name": "@knitli/ctx",
  "version": "0.1.0",
  "private": true
}
```

### Per-plugin CHANGELOG.md

Generated automatically by `@semantic-release/changelog`. Follows Keep a Changelog format.

## CI/CD

### `validate.yml` — on every PR

1. **Marketplace schema**: `marketplace.json` is valid JSON with required fields (`name`, `owner`, `plugins`)
2. **Plugin schema**: Each plugin's `plugin.json` is valid with required fields
3. **Structural integrity**: Every `source` path in `marketplace.json` resolves to a directory containing `.claude-plugin/plugin.json`
4. **Version sync**: `package.json` version matches `plugin.json` version for each plugin
5. **Commitlint**: Commit messages follow conventional commits with valid plugin scopes

### `release.yml` — on push to main

1. `semantic-release-monorepo` detects which plugin(s) have releasable changes
2. Bumps `version` in affected `package.json`
3. Post-release script syncs version to `plugin.json`
4. Generates/updates `CHANGELOG.md` for affected plugin(s)
5. Creates namespaced git tag (e.g., `ctx@0.2.0`)
6. Creates GitHub Release with changelog excerpt as body

### Validation script

`scripts/validate-marketplace.sh`:

- Every `source` in `marketplace.json` exists as a directory
- Every plugin directory has `.claude-plugin/plugin.json`
- `package.json` version matches `plugin.json` version (drift guard)
- Run locally or in CI

## Root package.json

```json
{
  "name": "toolshed",
  "private": true,
  "workspaces": [
    "plugins/*"
  ],
  "devDependencies": {
    "semantic-release": "^25.0.0",
    "semantic-release-monorepo": "^8.0.0",
    "@semantic-release/changelog": "^6.0.0",
    "@semantic-release/git": "^10.0.0",
    "@semantic-release/github": "^11.0.0",
    "@semantic-release/commit-analyzer": "^13.0.0",
    "@semantic-release/release-notes-generator": "^14.0.0",
    "@commitlint/cli": "^19.0.0",
    "@commitlint/config-conventional": "^19.0.0"
  },
  "scripts": {
    "validate": "./scripts/validate-marketplace.sh"
  }
}
```

## Commitlint config

`.commitlintrc.json`:

```json
{
  "extends": ["@commitlint/config-conventional"],
  "rules": {
    "scope-enum": [2, "always", ["ctx", "codeweaver"]]
  }
}
```

Scopes are limited to plugin names. Unscoped commits (e.g., `chore: update CI`) are allowed for repo-level work and produce no releases.

## Documentation

### README.md (marketplace landing page)

- What toolshed is: curated Claude Code plugins by Knitli
- Quick start: `marketplace add` then `install`
- Plugin catalog table with name, description, version, status
- Links to per-plugin READMEs

### CONTRIBUTING.md

- Adding a new plugin: directory under `plugins/`, wire into `marketplace.json`, add thin `package.json`
- Commit convention and scope rules
- PR checklist
- Plugin structure requirements

### CLAUDE.md (repo-level)

- Monorepo layout description
- `marketplace.json` is source of truth for discovery
- Each plugin's `plugin.json` is source of truth for components
- Version sync between `package.json` and `plugin.json`
- Pointer to this design doc

### Per-plugin docs

Each plugin keeps its own README and CLAUDE.md. Moved as-is from their original repos.

## User flow

### Adding the marketplace

```
/plugin marketplace add knitli/toolshed
```

### Installing a plugin

```
/plugin install ctx@toolshed
/plugin install codeweaver@toolshed
```

### Updating

```
/plugin marketplace update
```

## Migration plan

1. Create `knitli/toolshed` repo on GitHub
2. Set up monorepo structure (root configs, `.claude-plugin/marketplace.json`)
3. Move `ctx-plugin` files into `plugins/ctx/`
4. Move `codeweaver-plugin` files into `plugins/codeweaver/`
5. Add thin `package.json` to each plugin
6. Set up CI workflows
7. Validate everything works with `/plugin marketplace add` locally
8. Archive original repos with README pointers to toolshed
