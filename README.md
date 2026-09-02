# Toolshed

Curated Claude Code plugins by Knitli.

## Quick start

Add the marketplace:

```
/plugin marketplace add knitli/toolshed
```

Then install a plugin:

```
/plugin install strip-ansi@toolshed
```

## Plugin catalog

| Plugin | Description | Version | Status |
|--------|-------------|---------|--------|
| [strip-ansi](plugins/strip-ansi/) | Strips ANSI escape sequences from tool output and flags terminal-based prompt injection — cuts context bloat and keeps PRs, issues, and files uncorrupted, using [distill-strip-ansi](https://github.com/belt/distill-strip-ansi) | 1.1.0 | Stable |
| [ctx](plugins/ctx/) | Context hygiene — finds stale, contradictory AI context files across 10+ tool ecosystems | 1.2.1 | [Deprecated](plugins/ctx/DEPRECATED.md) |
| [codeweaver](plugins/codeweaver/) | Semantic code search with hybrid search, AST understanding, and intelligent chunking for 166+ languages | 1.1.0 | [Deprecated](plugins/codeweaver/DEPRECATED.md) |

Deprecated plugins still install and still work, but are unmaintained and will be removed from the
marketplace in a future release. See each plugin's `DEPRECATED.md` for migration notes.

More plugins are in the works — the catalog above is a floor, not a ceiling.

## What's a marketplace?

A Claude Code marketplace is a curated collection of plugins installable from a single source. Instead of installing plugins one repo at a time, you add a marketplace once and then pick the plugins you want from it. The marketplace manifest (`.claude-plugin/marketplace.json`) tells Claude Code what's available and where to find it.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a plugin, commit conventions, and PR guidelines.

## License

[MIT](LICENSE) — Knitli Inc.
