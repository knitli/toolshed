# ctx is deprecated

`ctx` is no longer maintained. Its last release was `@knitli/ctx-v1.2.1` (2026-04-10).

**What this means:**

- The plugin still installs from the toolshed marketplace and still works as of its last release.
- No new features, no bug fixes, no compatibility updates for future Claude Code versions.
- Issues and PRs against `ctx` will not be actioned.

**If you depend on it:** pin to `@knitli/ctx-v1.2.1` or vendor the `plugins/ctx/` directory into
your own repo. It's all markdown prompts and a couple of shell hooks — nothing to build.

The directory is kept here so existing installs keep resolving. It will be removed in a future
marketplace release.
