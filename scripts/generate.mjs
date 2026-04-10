#!/usr/bin/env node
/**
 * Central manifest generator.
 *
 * Reads .claude-plugin/marketplace.json and writes all derived files:
 *   - .commitlintrc.json          (scope-enum from plugin names)
 *   - .github/workflows/release.yml  (matrix.plugin from plugin names)
 *   - plugins/<name>/.claude-plugin/plugin.json
 *   - plugins/<name>/package.json
 *
 * Usage:
 *   node scripts/generate.mjs              # generate all files
 *   node scripts/generate.mjs --check      # exit 1 if any file differs (for CI)
 *   node scripts/generate.mjs --new <name> # scaffold a new plugin directory
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

function readJSON(filePath) {
  return JSON.parse(readFileSync(filePath, 'utf8'));
}

let drifted = false;

/**
 * In check mode: compare content to disk and record drift.
 * In write mode: write content to disk.
 */
function writeOrCheck(filePath, content) {
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

const pluginNames = plugins.map((p) => p.name);

// ---------------------------------------------------------------------------
// 1. .commitlintrc.json
// ---------------------------------------------------------------------------

const commitlintrc = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'scope-enum': [2, 'always', pluginNames],
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
// 3. plugins/<name>/.claude-plugin/plugin.json
// ---------------------------------------------------------------------------

for (const plugin of plugins) {
  const pluginDir = join(ROOT, plugin.source.replace(/^\.\//, ''));
  const dotClaudePluginDir = join(pluginDir, '.claude-plugin');
  const pluginJsonPath = join(dotClaudePluginDir, 'plugin.json');

  if (!CHECK_MODE) {
    mkdirSync(dotClaudePluginDir, { recursive: true });
  }

  const extensions = pluginManifestExtensions[plugin.name] ?? {};

  // Spread extensions first so canonical fields always win if there's a conflict.
  const pluginJson = {
    ...extensions,
    name: plugin.name,
    version: plugin.version,
    description: plugin.description,
    author: shared.author,
    homepage: plugin.homepage ?? shared.homepage,
    repository: shared.repository,
    license: plugin.license ?? shared.license,
    keywords: plugin.keywords,
    ...(plugin.mcpServers !== undefined && { mcpServers: plugin.mcpServers }),
  };

  writeOrCheck(pluginJsonPath, JSON.stringify(pluginJson, null, 2) + '\n');
}

// ---------------------------------------------------------------------------
// 4. plugins/<name>/package.json
// ---------------------------------------------------------------------------

for (const plugin of plugins) {
  const pluginDir = join(ROOT, plugin.source.replace(/^\.\//, ''));
  const pkgJsonPath = join(pluginDir, 'package.json');

  if (!CHECK_MODE) {
    mkdirSync(pluginDir, { recursive: true });
  }

  // Preserve the release config block from the existing file if present.
  const existing = existsSync(pkgJsonPath) ? readJSON(pkgJsonPath) : {};

  const pkgJson = {
    name: existing.name ?? `@${shared.npmScope}/${plugin.name}`,
    version: plugin.version,
    private: shared.private ?? true,
    description: plugin.description,
    author: shared.author,
    license: plugin.license ?? shared.license,
    homepage: plugin.homepage ?? shared.homepage,
    keywords: plugin.keywords,
    repository: {
      type: 'git',
      url: shared.repository,
    },
    ...(existing.release !== undefined && { release: existing.release }),
  };

  writeOrCheck(pkgJsonPath, JSON.stringify(pkgJson, null, 2) + '\n');
}

// ---------------------------------------------------------------------------
// 5. --new  scaffolding
// ---------------------------------------------------------------------------

if (NEW_PLUGIN) {
  if (CHECK_MODE) {
    console.error('ERROR: --new and --check are incompatible flags.');
    process.exit(1);
  } else {
    const entry = plugins.find((p) => p.name === NEW_PLUGIN);
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
    console.log('Next: add your commands/agents/skills/hooks content.');
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
