# codeweaver is deprecated

`codeweaver` is no longer maintained. Its last release was `@knitli/codeweaver-v1.1.0` (2026-04-10).

**What this means:**

- The plugin still installs from the toolshed marketplace, and the bundled MCP server config still
  points at the `code-weaver` package on PyPI via `uvx`.
- No new features, no bug fixes, no compatibility updates.
- Issues and PRs against `codeweaver` will not be actioned.

**If you depend on it:** run the MCP server directly rather than through this plugin — add the
`uvx --from "code-weaver['recommended']" cw server --transport stdio` command to your own
`.mcp.json`. The plugin was only ever a thin wrapper around that.

The directory is kept here so existing installs keep resolving. It will be removed in a future
marketplace release.
