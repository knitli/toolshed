# [@knitli/ctx-v1.1.0](https://github.com/knitli/toolshed/compare/@knitli/ctx-v1.0.1...@knitli/ctx-v1.1.0) (2026-04-09)


### Bug Fixes

* **ctx:** Fix an issue where in certain situations an LLMs meta-thinking can cause an infinite loop ([38c9422](https://github.com/knitli/toolshed/commit/38c9422c1d90f800768db89e62434aa8b83cbf87))


### Features

* **ctx:** Add ability to pass arguments to ctx commands to direct behavior ([7689926](https://github.com/knitli/toolshed/commit/76899260e2ed5eae501fc9278e88934fa6ac6765))

# [@knitli/ctx-v1.0.1](https://github.com/knitli/toolshed/compare/@knitli/ctx-v1.0.0...@knitli/ctx-v1.0.1) (2026-04-06)


### Bug Fixes

* **codeweaver,ctx:** Corrected issue with malformed plugin manifests ([07714f5](https://github.com/knitli/toolshed/commit/07714f514bbf9739160dfc3eae48b39234be260f))

# @knitli/ctx-v1.0.0 (2026-04-03)


### Features

* **ctx:** move ctx plugin into plugins/ctx/ ([62a4194](https://github.com/knitli/toolshed/commit/62a41945863fdf5dd67e8427bc8f050d8ddf129b))

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
