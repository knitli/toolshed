# Contributing to Toolshed

## Adding a new plugin

1. Create `plugins/<name>/` with a `.claude-plugin/plugin.json` containing at minimum:
   ```json
   {
     "name": "<name>",
     "version": "0.1.0",
     "description": "What the plugin does"
   }
   ```

2. Add `plugins/<name>/package.json`:
   ```json
   {
     "name": "@knitli/<name>",
     "version": "0.1.0",
     "private": true,
     "release": {
       "extends": "semantic-release-monorepo"
     }
   }
   ```
   The version here must match `plugin.json`.

3. Add an entry to `.claude-plugin/marketplace.json` in the `plugins` array.

4. Add the plugin name to `scope-enum` in `.commitlintrc.json`.

5. Add the plugin name to `matrix.plugin` in `.github/workflows/release.yml`.

## Commit convention

Format: `type(scope): message`

- **Scope** must be a plugin name: `ctx`, `codeweaver`, etc.
- Unscoped commits are for repo-level changes and do not trigger a release.
- Types that trigger releases:
  - `feat` — minor version bump
  - `fix` — patch version bump
  - `feat!` or `BREAKING CHANGE` — major version bump
- Types that do **not** trigger releases: `chore`, `docs`, `ci`, `style`, `refactor`, `test`

Examples:

```
feat(ctx): add YAML frontmatter validation
fix(codeweaver): correct chunk boundary detection
docs: update marketplace README
```

## PR checklist

- [ ] Commits follow conventional format with plugin scope
- [ ] `npm run validate` passes
- [ ] Plugin README updated if changes are user-facing

## Plugin structure requirements

Every plugin must have:

- `.claude-plugin/plugin.json` — name, version, description (authoritative manifest)
- `package.json` — matching `@knitli/<name>`, same version, `private: true`

Recommended:

- `README.md` — what it does, how to use it

Optional components:

- `commands/` — slash commands
- `agents/` — subagents
- `skills/` — passive knowledge loaded into context
- `hooks/` — event-driven automation (uses `hooks.json`)
