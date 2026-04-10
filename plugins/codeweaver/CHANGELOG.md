# [@knitli/codeweaver-v1.1.0](https://github.com/knitli/toolshed/compare/@knitli/codeweaver-v1.0.1...@knitli/codeweaver-v1.1.0) (2026-04-10)


### Bug Fixes

* apply code review fixes to generate.mjs, validate.yml, and release.yml ([894b7ea](https://github.com/knitli/toolshed/commit/894b7ea631f41c3f63e49eb0c691abbe07323925))
* comply with marketplace.json schema (additionalProperties: false on PluginEntry) ([d9cd49b](https://github.com/knitli/toolshed/commit/d9cd49bfc340f0c5ab02b1f5eb77b3584949f5b6))


### Features

* central manifest generator — marketplace.json as source of truth ([65d23a5](https://github.com/knitli/toolshed/commit/65d23a5001184312ea47c286a86f29bc0b14d2f0))

# [@knitli/codeweaver-v1.0.1](https://github.com/knitli/toolshed/compare/@knitli/codeweaver-v1.0.0...@knitli/codeweaver-v1.0.1) (2026-04-07)


### Bug Fixes

* **codeweaver:** Corrected flawed env variable configuration ([1a50d42](https://github.com/knitli/toolshed/commit/1a50d427674941199d6da806f613b2330ef68685))

# @knitli/codeweaver-v1.0.0 (2026-04-06)


### Bug Fixes

* **codeweaver,ctx:** Corrected issue with malformed plugin manifests ([07714f5](https://github.com/knitli/toolshed/commit/07714f514bbf9739160dfc3eae48b39234be260f))
* **codeweaver:** corrected invalid manifest variable ([6b89e5f](https://github.com/knitli/toolshed/commit/6b89e5f019cb519496b7b6405b3bc9a9cf72e6d1))

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
