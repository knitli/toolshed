#!/usr/bin/env bun
/**
 * Central manifest generator.
 *
 * Reads .claude-plugin/marketplace.json (and the root package.json version)
 * and writes all derived files:
 *   - .commitlintrc.json                            (scope-enum, scope-empty)
 *   - .github/workflows/release.yml                 (matrix.plugin)
 *   - .releaserc.json                               (marketplace release config)
 *   - .claude-plugin/marketplace.json               (metadata.version propagated)
 *   - plugins/<name>/.claude-plugin/plugin.json
 *   - plugins/<name>/package.json                   (scope-gated release config)
 *
 * Release routing is SCOPE-AUTHORITATIVE: each plugin's and the marketplace's
 * semantic-release config uses commit-analyzer releaseRules keyed on commit
 * scope, with a catchall `release: false` to block fallthrough to the preset
 * defaults. Path-based filtering (semantic-release-monorepo) is NOT used.
 *
 * Usage:
 *   bun scripts/generate.mts              # generate all files
 *   bun scripts/generate.mts --check      # exit 1 if any file differs (for CI)
 *   bun scripts/generate.mts --new <name> # scaffold a new plugin directory
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

const args = process.argv.slice(2);
const CHECK_MODE = args.includes('--check');
const newIdx = args.indexOf('--new');

let NEW_PLUGIN = null;
if (newIdx !== -1) {
  const candidate = args[newIdx + 1];
  if (!candidate || candidate.startsWith('--')) {
    console.error('ERROR: --new requires a plugin name.');
    process.exit(1);
  }
  NEW_PLUGIN = candidate;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function readJSON(filePath: string) {
  return JSON.parse(readFileSync(filePath, 'utf8'));
}

/**
 * Build a scope-gated semantic-release config for a single plugin.
 *
 * Routing rule: commit must have `scope: <pluginName>` to trigger a release.
 * Any other scope (or no scope) falls through to the catchall `release: false`
 * entry, which short-circuits commit-analyzer's preset defaults.
 */
function buildPluginReleaseConfig(pluginName: string) {
  return {
    branches: ['main'],
    tagFormat: `${pluginName}@\${version}`,
    plugins: [
      [
        '@semantic-release/commit-analyzer',
        {
          preset: 'conventionalcommits',
          releaseRules: [
            { breaking: true, scope: pluginName, release: 'major' },
            { scope: pluginName, type: 'feat', release: 'minor' },
            { scope: pluginName, type: 'fix', release: 'patch' },
            { scope: pluginName, type: 'perf', release: 'patch' },
            { release: false },
          ],
        },
      ],
      '@semantic-release/release-notes-generator',
      '@semantic-release/changelog',
      ['@semantic-release/npm', { npmPublish: false }],
      '@semantic-release/git',
      '@semantic-release/github',
    ],
  };
}

/**
 * Build the scope-gated semantic-release config for the marketplace (repo root).
 *
 * Routing rule: commit must have `scope: marketplace` to trigger a release.
 * Any other scope falls through to the catchall `release: false`. This is
 * written to .releaserc.json at repo root so it wins over any stale
 * `release` field that might be left in package.json.
 */
function buildMarketplaceReleaseConfig() {
  return {
    branches: ['main'],
    tagFormat: 'marketplace@${version}',
    plugins: [
      [
        '@semantic-release/commit-analyzer',
        {
          preset: 'conventionalcommits',
          releaseRules: [
            { breaking: true, scope: 'marketplace', release: 'major' },
            { scope: 'marketplace', type: 'feat', release: 'minor' },
            { scope: 'marketplace', type: 'fix', release: 'patch' },
            { scope: 'marketplace', type: 'perf', release: 'patch' },
            { release: false },
          ],
        },
      ],
      '@semantic-release/release-notes-generator',
      '@semantic-release/changelog',
      ['@semantic-release/npm', { npmPublish: false }],
      '@semantic-release/git',
      '@semantic-release/github',
    ],
  };
}

let drifted = false;

/**
 * In check mode: compare content to disk and record drift.
 * In write mode: write content to disk.
 */
function writeOrCheck(filePath: string, content: string) {
  if (CHECK_MODE) {
    const existing = existsSync(filePath) ? readFileSync(filePath, 'utf8') : null;
    if (existing !== content) {
      console.error(`  DRIFT: ${filePath.replace(ROOT + '/', '')}`);
      drifted = true;
    }
    return;
  }
  writeFileSync(filePath, content, 'utf8');
  console.log(`  wrote: ${filePath.replace(ROOT + '/', '')}`);
}

// ---------------------------------------------------------------------------
// Load manifest
// ---------------------------------------------------------------------------

const manifest = readJSON(join(ROOT, '.claude-plugin/marketplace.json'));
const { shared, plugins, pluginManifestExtensions = {} } = manifest;

if (!shared) {
  console.error('ERROR: marketplace.json is missing the "shared" block.');
  process.exit(1);
}

const pluginNames = plugins.map((p: typeof plugins[number]) => p.name);

// ---------------------------------------------------------------------------
// 1. .commitlintrc.json
// ---------------------------------------------------------------------------

// Scope is authoritative for release routing, so PR-gate commits must carry
// a valid scope: either a plugin name or `marketplace`. Unscoped commits are
// rejected.
const commitlintrc = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'scope-enum': [2, 'always', [...pluginNames, 'marketplace']],
    'scope-empty': [2, 'never'],
  },
};

writeOrCheck(
  join(ROOT, '.commitlintrc.json'),
  JSON.stringify(commitlintrc, null, 2) + '\n'
);

// ---------------------------------------------------------------------------
// 2. .github/workflows/release.yml  — update matrix.plugin line in-place
// ---------------------------------------------------------------------------

const releaseYmlPath = join(ROOT, '.github/workflows/release.yml');
const releaseYml = readFileSync(releaseYmlPath, 'utf8');

// Match the existing indentation so the replace is idempotent.
const matrixMatch = releaseYml.match(/^(\s*)plugin:\s*\[.*\]$/m);
if (!matrixMatch) {
  console.error('ERROR: Could not find "plugin: [...]" line in release.yml');
  process.exit(1);
}
const indent = matrixMatch[1];
const updatedReleaseYml = releaseYml.replace(
  /^(\s*)plugin:\s*\[.*\]$/m,
  `${indent}plugin: [${pluginNames.join(', ')}]`
);

writeOrCheck(releaseYmlPath, updatedReleaseYml);

// ---------------------------------------------------------------------------
// 3. Per-plugin: .claude-plugin/plugin.json  +  package.json
//
// Version source of truth: package.json (managed by semantic-release).
// The generate script reads the version from the existing package.json
// and propagates it to plugin.json.  New plugins default to "0.0.0".
// ---------------------------------------------------------------------------

for (const plugin of plugins) {
  // plugin.source is a relative path from the repo root, e.g. "./plugins/ctx"
  const pluginRelPath = plugin.source.replace(/^\.\//, '');
  const pluginDir = join(ROOT, pluginRelPath);
  const pkgJsonPath = join(pluginDir, 'package.json');
  const dotClaudePluginDir = join(pluginDir, '.claude-plugin');
  const pluginJsonPath = join(dotClaudePluginDir, 'plugin.json');

  if (!CHECK_MODE) {
    mkdirSync(dotClaudePluginDir, { recursive: true });
  }

  // Read existing package.json — its version is the source of truth.
  // New plugins default to 0.0.0 (pre-release); the first `feat(<name>): …`
  // commit lands the plugin's first release.
  const existingPkg = existsSync(pkgJsonPath) ? readJSON(pkgJsonPath) : {};
  const version = existingPkg.version ?? '0.0.0';

  // --- plugin.json ---
  const extensions = pluginManifestExtensions[plugin.name] ?? {};

  // Spread extensions first so canonical fields always win if there's a conflict.
  const pluginJson = {
    ...extensions,
    name: plugin.name,
    version,
    description: plugin.description,
    author: shared.author,
    homepage: plugin.homepage ?? shared.homepage,
    repository: shared.repository,
    license: plugin.license ?? shared.license,
    keywords: plugin.keywords,
    ...(plugin.mcpServers !== undefined && { mcpServers: plugin.mcpServers }),
  };

  writeOrCheck(pluginJsonPath, JSON.stringify(pluginJson, null, 2) + '\n');

  // --- package.json ---
  const pkgJson = {
    name: existingPkg.name ?? `@${shared.npmScope}/${shared.npmPrefix ?? ''}${plugin.name}`,
    version,
    private: shared.private ?? true,
    description: plugin.description,
    author: shared.author,
    license: plugin.license ?? shared.license,
    homepage: plugin.homepage ?? shared.homepage,
    keywords: plugin.keywords,
    repository: {
      type: 'git',
      url: shared.repository,
      directory: pluginRelPath,
    },
    release: buildPluginReleaseConfig(plugin.name),
    ...Object.fromEntries(Object.entries(extensions).filter(([key]) => !['name', 'version', 'description', 'author', 'license', 'homepage', 'keywords', 'repository'].includes(key)))
  };

  writeOrCheck(pkgJsonPath, JSON.stringify(pkgJson, null, 2) + '\n');
}

// ---------------------------------------------------------------------------
// 4. .releaserc.json — marketplace release config at repo root.
//
// Semantic-release prefers .releaserc.* over package.json.release, so this
// is the sole source of truth for the marketplace release and keeps the
// root package.json hand-managed.
// ---------------------------------------------------------------------------

writeOrCheck(
  join(ROOT, '.releaserc.json'),
  JSON.stringify(buildMarketplaceReleaseConfig(), null, 2) + '\n'
);

// ---------------------------------------------------------------------------
// 5. .claude-plugin/marketplace.json — propagate root package.json version.
//
// Root package.json.version is the source of truth for the marketplace
// version (managed by semantic-release). generate.mts reads it and writes
// it into marketplace.json.metadata.version. All other manifest fields are
// preserved via spread.
// ---------------------------------------------------------------------------

const rootPkg = readJSON(join(ROOT, 'package.json'));
const marketplaceVersion = rootPkg.version ?? '0.0.0';

const updatedManifest = {
  ...manifest,
  metadata: { ...manifest.metadata, version: marketplaceVersion },
};

writeOrCheck(
  join(ROOT, '.claude-plugin/marketplace.json'),
  JSON.stringify(updatedManifest, null, 2) + '\n'
);

// ---------------------------------------------------------------------------
// 6. --new  scaffolding
// ---------------------------------------------------------------------------

if (NEW_PLUGIN) {
  if (CHECK_MODE) {
    console.error('ERROR: --new and --check are incompatible flags.');
    process.exit(1);
  } else {
    const entry = plugins.find((p: typeof plugins[number]) => p.name === NEW_PLUGIN);
    if (!entry) {
      console.error(
        `ERROR: "${NEW_PLUGIN}" not found in marketplace.json plugins array.`
      );
      console.error(
        'Add the plugin entry to marketplace.json first, then re-run with --new.'
      );
      process.exit(1);
    }

    const pluginDir = join(ROOT, entry.source.replace(/^\.\//, ''));
    const dotClaudePluginDir = join(pluginDir, '.claude-plugin');
    const commandsDir = join(pluginDir, 'commands');

    for (const dir of [dotClaudePluginDir, commandsDir]) {
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
        console.log(`  mkdir: ${dir.replace(ROOT + '/', '')}`);
      }
    }

    // Write README.md if missing
    const readmePath = join(pluginDir, 'README.md');
    if (!existsSync(readmePath)) {
      const readme = `# ${entry.name}\n\n${entry.description}\n`;
      writeFileSync(readmePath, readme, 'utf8');
      console.log(`  wrote: ${readmePath.replace(ROOT + '/', '')}`);
    }

    // The plugin.json and package.json will already have been written above
    // by the normal generation pass (since the entry is in the manifest).
    console.log(`\nScaffolded: plugins/${NEW_PLUGIN}/`);
    console.log('Next: add your commands/agents/skills/hooks content, then commit with:');
    console.log(`      git commit -am "feat(marketplace): add ${NEW_PLUGIN} plugin"`);
  }
}

// ---------------------------------------------------------------------------
// Final exit
// ---------------------------------------------------------------------------

if (CHECK_MODE) {
  if (drifted) {
    console.error(
      '\nGenerated files are out of sync. Run: npm run generate'
    );
    process.exit(1);
  } else {
    console.log('All generated files are in sync.');
  }
} else if (!NEW_PLUGIN) {
  console.log('\nDone. Commit the updated files.');
}
