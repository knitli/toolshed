# strip-ansi

Prevents ANSI escape sequences from polluting agent context, commits, PRs, and file edits.

## The problem

LLM coding agents routinely run dev tools (`cargo`, `git`, `gh`, `npm`, `bat`) whose output contains ANSI color codes, OSC 8 hyperlinks, and other terminal escapes. The agent ingests that output, then quotes it into commit messages, PR bodies, and file edits — and the escape codes survive the round-trip, ending up committed to git or posted to GitHub as garbage.

Worse: by the time corrupted content reaches a `Write` call or a chat paste, the actual ESC bytes (0x1B) may have been stripped somewhere upstream, leaving *literal* `[38;5;238m` text that no ANSI parser can recognize. The only reliable place to intervene is **at the moment Bash output enters agent context** — which is what this plugin does.

## What it does

Installs a single `PostToolUse` hook on the `Bash` tool. After every Bash invocation:

1. Reads the tool output (stdout + stderr).
2. Pipes it through [`distill-strip-ansi`](https://crates.io/crates/distill-strip-ansi) (an ECMA-48 state-machine parser, not a regex hack).
3. If ANSI was present, emits a sanitized version as `additionalContext` so the agent quotes the clean version instead of the polluted original.
4. If no ANSI was present, does nothing (zero overhead — the parser's `Cow::Borrowed` fast path).

## Requirements

- [`distill-strip-ansi`](https://crates.io/crates/distill-strip-ansi) on PATH:
  ```sh
  cargo install distill-strip-ansi
  ```
- `jq` (almost always already installed)

The hook **fails open**: if either tool is missing, it exits silently without blocking your workflow.

## What this plugin does NOT do (yet)

- **`NO_COLOR=1` injection into Bash environment.** This would prevent colors from being emitted in the first place, but PreToolUse hooks can't reliably mutate the Bash tool's environment from a subprocess. Tracked for v2.
- **`Write`/`Edit` sanitization.** By the time ANSI residue reaches a file write, the ESC bytes are usually already gone — leaving literal text that a parser-based stripper can't safely distinguish from legitimate content. A heuristic regex cleaner would have unacceptable false-positive rates.
- **Git commit-msg hooks, `gh` wrappers, threat scanning.** Out of scope for the agent-context-hygiene v1.

## Status

Alpha. The hook is a thin shim around an external tool; the interesting logic lives in `distill-strip-ansi`.
