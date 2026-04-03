# Toolshed Marketplace Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Convert ctx-plugin and codeweaver-plugin into a monorepo plugin marketplace at knitli/toolshed with independent versioning via semantic-release.

**Architecture:** Single git repo with `plugins/` subdirectories for each plugin, a root `marketplace.json` for discovery, and semantic-release-monorepo for per-plugin versioning. CI validates structure on PR and releases on merge to main.

**Tech Stack:** Claude Code plugin system (markdown prompts), semantic-release + semantic-release-monorepo, commitlint, GitHub Actions

**Design doc:** `docs/plans/2026-04-03-toolshed-marketplace-design.md`

---

### Task 1: Initialize repo structure and root configs

**Files:**
- Create: `.claude-plugin/marketplace.json`
- Create: `package.json` (root)
- Create: `.commitlintrc.json`
- Create: `LICENSE`
- Create: `.gitignore`
- Remove: `install.sh` (legacy Thread-era install script, replaced by marketplace)
- Remove: `thread-context-doctor-spec.md` (spec for the Rust binary vision, not the plugin)
- Remove: `PLAN.md` (original planning doc, superseded by this plan)

**Step 1: Create `.claude-plugin/marketplace.json`**

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

**Step 2: Create root `package.json`**

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

**Step 3: Create `.commitlintrc.json`**

```json
{
  "extends": ["@commitlint/config-conventional"],
  "rules": {
    "scope-enum": [2, "always", ["ctx", "codeweaver"]]
  }
}
```

**Step 4: Create `LICENSE`**

MIT license, copyright Knitli Inc.

**Step 5: Create `.gitignore`**

```
node_modules/
.npm
*.log
```

**Step 6: Remove legacy files**

Delete `install.sh`, `thread-context-doctor-spec.md`, `PLAN.md` from root.

**Step 7: Commit**

```bash
git add -A
git commit -m "chore: initialize toolshed monorepo structure

Root package.json with workspaces, marketplace.json manifest,
commitlint config, and license."
```

---

### Task 2: Move ctx plugin into `plugins/ctx/`

**Files:**
- Create: `plugins/ctx/` directory
- Move: all ctx plugin files from repo root into `plugins/ctx/`
- Create: `plugins/ctx/package.json` (version anchor)
- Create: `plugins/ctx/CHANGELOG.md`
- Update: `plugins/ctx/.claude-plugin/plugin.json` (update repository URL)
- Update: `plugins/ctx/CLAUDE.md` (adjust for new location in monorepo)

The ctx plugin files currently at repo root are:
- `.claude-plugin/plugin.json` → `plugins/ctx/.claude-plugin/plugin.json`
- `commands/*.md` → `plugins/ctx/commands/*.md`
- `agents/*.md` → `plugins/ctx/agents/*.md`
- `skills/context-hygiene/SKILL.md` → `plugins/ctx/skills/context-hygiene/SKILL.md`
- `hooks/hooks.json` → `plugins/ctx/hooks/hooks.json`
- `cross-client/**` → `plugins/ctx/cross-client/**`
- `README.md` → `plugins/ctx/README.md`
- `CLAUDE.md` → `plugins/ctx/CLAUDE.md`

**Step 1: Create directory and move files**

```bash
mkdir -p plugins/ctx
# Move plugin component directories
mv .claude-plugin commands agents skills hooks cross-client plugins/ctx/
# Move plugin docs
mv README.md plugins/ctx/
mv CLAUDE.md plugins/ctx/
```

**Step 2: Create `plugins/ctx/package.json`**

```json
{
  "name": "@knitli/ctx",
  "version": "0.1.0",
  "private": true,
  "release": {
    "extends": "semantic-release-monorepo",
    "plugins": [
      "@semantic-release/commit-analyzer",
      "@semantic-release/release-notes-generator",
      "@semantic-release/changelog",
      "@semantic-release/git",
      "@semantic-release/github"
    ]
  }
}
```

**Step 3: Create `plugins/ctx/CHANGELOG.md`**

```markdown
# Changelog

All notable changes to the ctx plugin will be documented in this file.

## [0.1.0] - 2026-04-03

### Added

- Initial release as part of knitli/toolshed marketplace
- Context file discovery across 10+ tool ecosystems
- Staleness checking with claim extraction and validation
- Drift detection between context files
- Interactive fix mode
- Cross-client support (Cursor, Codex, generic AGENTS.md)
```

**Step 4: Update `plugins/ctx/.claude-plugin/plugin.json`**

Change `repository` from `https://github.com/knitli/ctx` to `https://github.com/knitli/toolshed`.

**Step 5: Update `plugins/ctx/CLAUDE.md`**

Add a note at the top that this plugin is part of the knitli/toolshed marketplace monorepo. Remove references to `install.sh` and the Thread workspace. Keep all other content as-is.

**Step 6: Commit**

```bash
git add -A
git commit -m "feat(ctx): move ctx plugin into plugins/ctx/

Relocate all ctx plugin files from repo root into the monorepo
plugins directory. Add version anchor package.json and changelog."
```

---

### Task 3: Copy codeweaver plugin into `plugins/codeweaver/`

**Files:**
- Create: `plugins/codeweaver/` directory with all files from `/home/knitli/codeweaver/codeweaver-plugin/`
- Create: `plugins/codeweaver/package.json` (version anchor)
- Create: `plugins/codeweaver/CHANGELOG.md`
- Update: `plugins/codeweaver/.claude-plugin/plugin.json` (update repository URL)

Source files from `/home/knitli/codeweaver/codeweaver-plugin/`:
- `.claude-plugin/plugin.json` → `plugins/codeweaver/.claude-plugin/plugin.json`
- `.mcp.json` → `plugins/codeweaver/.mcp.json`
- `agents/onboarding/` → `plugins/codeweaver/agents/onboarding/`
- `skills/` → `plugins/codeweaver/skills/`
- `hooks/` → `plugins/codeweaver/hooks/`
- `README.md` → `plugins/codeweaver/README.md`

Do NOT copy `.mcp.json.license`, `.claude-plugin/plugin.json.license`, `hooks/hooks.json.license` — these are REUSE metadata files for the license, not needed in the marketplace (the root LICENSE covers it, and each plugin.json has its own license field).

**Step 1: Copy plugin files**

```bash
mkdir -p plugins/codeweaver/.claude-plugin
mkdir -p plugins/codeweaver/agents/onboarding
mkdir -p plugins/codeweaver/skills/setup
mkdir -p plugins/codeweaver/hooks/scripts

cp /home/knitli/codeweaver/codeweaver-plugin/.claude-plugin/plugin.json plugins/codeweaver/.claude-plugin/
cp /home/knitli/codeweaver/codeweaver-plugin/.mcp.json plugins/codeweaver/
cp /home/knitli/codeweaver/codeweaver-plugin/agents/onboarding/README.md plugins/codeweaver/agents/onboarding/
cp /home/knitli/codeweaver/codeweaver-plugin/agents/onboarding/SKILL.md plugins/codeweaver/agents/onboarding/
cp /home/knitli/codeweaver/codeweaver-plugin/skills/README.md plugins/codeweaver/skills/
cp /home/knitli/codeweaver/codeweaver-plugin/skills/setup/SKILL.md plugins/codeweaver/skills/setup/
cp /home/knitli/codeweaver/codeweaver-plugin/hooks/hooks.json plugins/codeweaver/hooks/
cp /home/knitli/codeweaver/codeweaver-plugin/hooks/README.md plugins/codeweaver/hooks/
cp /home/knitli/codeweaver/codeweaver-plugin/hooks/scripts/check-first-run.sh plugins/codeweaver/hooks/scripts/
cp /home/knitli/codeweaver/codeweaver-plugin/README.md plugins/codeweaver/
```

**Step 2: Create `plugins/codeweaver/package.json`**

```json
{
  "name": "@knitli/codeweaver",
  "version": "0.6.0-alpha",
  "private": true,
  "release": {
    "extends": "semantic-release-monorepo",
    "plugins": [
      "@semantic-release/commit-analyzer",
      "@semantic-release/release-notes-generator",
      "@semantic-release/changelog",
      "@semantic-release/git",
      "@semantic-release/github"
    ]
  }
}
```

**Step 3: Create `plugins/codeweaver/CHANGELOG.md`**

```markdown
# Changelog

All notable changes to the codeweaver plugin will be documented in this file.

## [0.6.0-alpha] - 2026-04-03

### Added

- Initial release as part of knitli/toolshed marketplace
- Semantic code search MCP server with hybrid search
- AST-level understanding for 27 languages, keyword matching for 166+
- Automatic background indexing with file watching
- First-run onboarding agent with embedding provider selection
- Reconfiguration skill (/codeweaver:setup)
```

**Step 4: Update `plugins/codeweaver/.claude-plugin/plugin.json`**

Change `repository` from `https://github.com/knitli/codeweaver` to `https://github.com/knitli/toolshed`.

**Step 5: Commit**

```bash
git add -A
git commit -m "feat(codeweaver): add codeweaver plugin to marketplace

Copy codeweaver plugin files into plugins/codeweaver/.
Add version anchor package.json and changelog."
```

---

### Task 4: Create the validation script

**Files:**
- Create: `scripts/validate-marketplace.sh`

**Step 1: Write the script**

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MARKETPLACE="$ROOT/.claude-plugin/marketplace.json"
ERRORS=0

echo "Validating toolshed marketplace..."

# Check marketplace.json exists and is valid JSON
if ! jq empty "$MARKETPLACE" 2>/dev/null; then
  echo "FAIL: marketplace.json is not valid JSON"
  exit 1
fi

# Check required top-level fields
for field in name owner plugins; do
  if ! jq -e ".$field" "$MARKETPLACE" >/dev/null 2>&1; then
    echo "FAIL: marketplace.json missing required field: $field"
    ERRORS=$((ERRORS + 1))
  fi
done

# Validate each plugin entry
PLUGIN_COUNT=$(jq '.plugins | length' "$MARKETPLACE")
for i in $(seq 0 $((PLUGIN_COUNT - 1))); do
  NAME=$(jq -r ".plugins[$i].name" "$MARKETPLACE")
  SOURCE=$(jq -r ".plugins[$i].source" "$MARKETPLACE")
  PLUGIN_DIR="$ROOT/$SOURCE"

  echo "  Checking plugin: $NAME"

  # Source directory exists
  if [ ! -d "$PLUGIN_DIR" ]; then
    echo "    FAIL: source directory does not exist: $SOURCE"
    ERRORS=$((ERRORS + 1))
    continue
  fi

  # plugin.json exists
  if [ ! -f "$PLUGIN_DIR/.claude-plugin/plugin.json" ]; then
    echo "    FAIL: missing .claude-plugin/plugin.json"
    ERRORS=$((ERRORS + 1))
    continue
  fi

  # plugin.json is valid JSON
  if ! jq empty "$PLUGIN_DIR/.claude-plugin/plugin.json" 2>/dev/null; then
    echo "    FAIL: plugin.json is not valid JSON"
    ERRORS=$((ERRORS + 1))
    continue
  fi

  # Version sync: package.json version == plugin.json version
  if [ -f "$PLUGIN_DIR/package.json" ]; then
    PKG_VERSION=$(jq -r '.version' "$PLUGIN_DIR/package.json")
    PLUGIN_VERSION=$(jq -r '.version' "$PLUGIN_DIR/.claude-plugin/plugin.json")
    if [ "$PKG_VERSION" != "$PLUGIN_VERSION" ]; then
      echo "    FAIL: version mismatch — package.json=$PKG_VERSION, plugin.json=$PLUGIN_VERSION"
      ERRORS=$((ERRORS + 1))
    fi
  fi

  echo "    OK"
done

if [ "$ERRORS" -gt 0 ]; then
  echo ""
  echo "FAILED: $ERRORS error(s) found"
  exit 1
fi

echo ""
echo "All checks passed."
```

**Step 2: Make executable and commit**

```bash
chmod +x scripts/validate-marketplace.sh
git add scripts/validate-marketplace.sh
git commit -m "chore: add marketplace validation script

Checks marketplace.json schema, plugin directory existence,
plugin.json validity, and version sync with package.json."
```

---

### Task 5: Create CI workflows

**Files:**
- Create: `.github/workflows/validate.yml`
- Create: `.github/workflows/release.yml`
- Create: `.github/PULL_REQUEST_TEMPLATE.md`

**Step 1: Create `.github/workflows/validate.yml`**

```yaml
name: Validate

on:
  pull_request:
    branches: [main]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install jq
        run: sudo apt-get install -y jq

      - name: Validate marketplace structure
        run: ./scripts/validate-marketplace.sh

  commitlint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-node@v4
        with:
          node-version: 22

      - run: npm ci

      - name: Lint commits
        run: npx commitlint --from ${{ github.event.pull_request.base.sha }} --to ${{ github.event.pull_request.head.sha }}
```

**Step 2: Create `.github/workflows/release.yml`**

```yaml
name: Release

on:
  push:
    branches: [main]

permissions:
  contents: write
  issues: write
  pull-requests: write

jobs:
  release:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        plugin: [ctx, codeweaver]
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-node@v4
        with:
          node-version: 22

      - run: npm ci

      - name: Release ${{ matrix.plugin }}
        working-directory: plugins/${{ matrix.plugin }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: npx semantic-release

      - name: Sync version to plugin.json
        working-directory: plugins/${{ matrix.plugin }}
        run: |
          PKG_VERSION=$(jq -r '.version' package.json)
          PLUGIN_JSON=".claude-plugin/plugin.json"
          jq --arg v "$PKG_VERSION" '.version = $v' "$PLUGIN_JSON" > tmp.json && mv tmp.json "$PLUGIN_JSON"

      - name: Commit version sync
        uses: stefanzweifel/git-auto-commit-action@v5
        with:
          commit_message: "chore(${{ matrix.plugin }}): sync plugin.json version"
          file_pattern: "plugins/${{ matrix.plugin }}/.claude-plugin/plugin.json"
```

**Step 3: Create `.github/PULL_REQUEST_TEMPLATE.md`**

```markdown
## What

<!-- Brief description of the change -->

## Plugin(s) affected

- [ ] ctx
- [ ] codeweaver
- [ ] None (repo-level change)

## Checklist

- [ ] Commit messages follow conventional commits with plugin scope
- [ ] `npm run validate` passes locally
- [ ] Plugin README updated (if user-facing change)
- [ ] CHANGELOG entry will be auto-generated on release
```

**Step 4: Commit**

```bash
git add -A
git commit -m "chore: add CI workflows for validation and release

validate.yml: marketplace structure + commitlint on PRs
release.yml: per-plugin semantic-release on main"
```

---

### Task 6: Create root documentation

**Files:**
- Create: `README.md` (marketplace landing page)
- Create: `CONTRIBUTING.md`
- Create: `CLAUDE.md` (repo-level instructions)

**Step 1: Create `README.md`**

Content should include:
- Toolshed tagline: "Curated Claude Code plugins by Knitli"
- Quick start block:
  ```
  /plugin marketplace add knitli/toolshed
  /plugin install ctx@toolshed
  /plugin install codeweaver@toolshed
  ```
- Plugin catalog table:

  | Plugin | Description | Version | Status |
  |--------|-------------|---------|--------|
  | [ctx](plugins/ctx/) | Context hygiene — finds stale, contradictory AI context files | 0.1.0 | Stable |
  | [codeweaver](plugins/codeweaver/) | Semantic code search with hybrid search and AST understanding | 0.6.0-alpha | Alpha |

- "What's a marketplace?" brief explainer
- Link to CONTRIBUTING.md
- Knitli branding / license footer

**Step 2: Create `CONTRIBUTING.md`**

Content should include:
- Adding a new plugin:
  1. Create `plugins/<name>/` with `.claude-plugin/plugin.json`
  2. Add thin `package.json` with `@knitli/<name>`, version, `private: true`, semantic-release config
  3. Add entry to `.claude-plugin/marketplace.json`
  4. Add plugin name to `scope-enum` in `.commitlintrc.json`
  5. Add plugin to `matrix.plugin` in `.github/workflows/release.yml`
- Commit convention with scope examples
- PR checklist
- Plugin structure requirements (must have `.claude-plugin/plugin.json`, should have README)

**Step 3: Create `CLAUDE.md`**

Content should include:
- This is a Claude Code plugin marketplace monorepo
- `.claude-plugin/marketplace.json` is the discovery manifest
- Each plugin under `plugins/<name>/` has its own `plugin.json` (authoritative for components)
- Version lives in two places: `package.json` (semantic-release writes) and `plugin.json` (Claude Code reads) — keep in sync
- Commit convention: `type(scope): message` where scope is a plugin name
- To validate: `npm run validate`
- Design doc at `docs/plans/2026-04-03-toolshed-marketplace-design.md`

**Step 4: Commit**

```bash
git add README.md CONTRIBUTING.md CLAUDE.md
git commit -m "docs: add marketplace README, CONTRIBUTING, and CLAUDE.md"
```

---

### Task 7: Install dependencies and validate

**Step 1: Install npm dependencies**

```bash
npm install
```

**Step 2: Run validation**

```bash
npm run validate
```

Expected: "All checks passed."

**Step 3: Verify marketplace structure**

```bash
# Quick visual check
find . -name plugin.json -o -name marketplace.json -o -name package.json | sort
```

Expected output:
```
./.claude-plugin/marketplace.json
./package.json
./plugins/codeweaver/.claude-plugin/plugin.json
./plugins/codeweaver/package.json
./plugins/ctx/.claude-plugin/plugin.json
./plugins/ctx/package.json
```

**Step 4: Commit lockfile**

```bash
git add package-lock.json
git commit -m "chore: add package-lock.json"
```

---

### Task 8: Final cleanup and verification

**Step 1: Verify no stale files remain at repo root**

The repo root should NOT contain any of these (they were moved or deleted):
- `install.sh`
- `thread-context-doctor-spec.md`
- `PLAN.md`
- `commands/`
- `agents/`
- `skills/`
- `hooks/`
- `cross-client/`

Run: `ls` at root and confirm only expected files.

**Step 2: Verify the full tree matches the design**

```bash
find . -type f -not -path './.git/*' -not -path './node_modules/*' | sort
```

Compare against the structure in the design doc.

**Step 3: Move design docs into repo**

```bash
# docs/plans/ already exists with the design docs from brainstorming
git add docs/
git commit -m "docs: add toolshed design and implementation plan"
```

---

## Task dependency graph

```
Task 1 (root configs)
  → Task 2 (move ctx)
  → Task 3 (copy codeweaver)
    → Task 4 (validation script)  [needs plugins in place to test]
      → Task 5 (CI workflows)     [references validation script]
        → Task 6 (documentation)  [needs final structure settled]
          → Task 7 (install + validate) [needs everything in place]
            → Task 8 (cleanup + verify)
```

Tasks 2 and 3 can run in parallel after Task 1.
