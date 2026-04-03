# Toolshed

Curated Claude Code plugins by Knitli.

## Quick start

Add the marketplace:

```
/plugin marketplace add knitli/toolshed
```

Then install individual plugins:

```
/plugin install ctx@toolshed
/plugin install codeweaver@toolshed
```

## Plugin catalog

| Plugin | Description | Version | Status |
|--------|-------------|---------|--------|
| [ctx](plugins/ctx/) | Context hygiene — finds stale, contradictory AI context files across 10+ tool ecosystems | 0.1.0 | Stable |
| [codeweaver](plugins/codeweaver/) | Semantic code search with hybrid search, AST understanding, and intelligent chunking for 166+ languages | 0.6.0-alpha | Alpha |

## What's a marketplace?

A Claude Code marketplace is a curated collection of plugins installable from a single source. Instead of installing plugins one repo at a time, you add a marketplace once and then pick the plugins you want from it. The marketplace manifest (`.claude-plugin/marketplace.json`) tells Claude Code what's available and where to find it.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a plugin, commit conventions, and PR guidelines.

## License

[MIT](LICENSE) — Knitli Inc.
