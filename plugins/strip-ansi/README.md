# strip-ansi

Sanitizes ANSI escape sequences from tool output and detects terminal-based prompt injection attacks. Uses [`distill-strip-ansi`](https://crates.io/crates/distill-strip-ansi) for ECMA-48 state-machine parsing and CVE-tagged threat classification.

## The problem

LLM coding agents ingest tool output containing ANSI escape sequences. This creates two distinct threats:

**Hygiene** — Color codes, OSC 8 hyperlinks, and other terminal escapes survive round-trips into commits, PRs, and file edits as garbage characters. The only reliable intervention point is at the moment output enters agent context.

**Security** — [ANSI escape codes can hide malicious instructions from users while the model still processes them](https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/). Techniques include invisible text (foreground/background color matching), cursor movement overwriting, screen clearing, and deceptive hyperlinks. This enables supply chain attacks via prompt injection that the user cannot see.

## Architecture: two-tier protection

The plugin installs `PostToolUse` hooks on Bash, Read, and all MCP tools. Protection differs by tool type because of what the hook API allows:

| | MCP tools | Built-in tools (Bash, Read) |
|---|---|---|
| **Mechanism** | `updatedMCPToolOutput` | `additionalContext` |
| **Effect** | Output replaced — Claude never sees the attack | Warning injected — Claude sees both original and counter-signal |
| **Protection level** | Full | Partial (best available until [#36843](https://github.com/anthropics/claude-code/issues/36843) ships) |

### MCP tools (full protection)

When a PostToolUse hook fires for an `mcp__*` tool, the hook can return `updatedMCPToolOutput` to replace what the model sees. The original payload is discarded from context. If threats are detected, the hook also injects an `additionalContext` warning with the threat classification (not the payload).

### Built-in tools (partial protection)

For Bash and Read, `PostToolUse` cannot replace the tool response — Claude already has it. The hook injects a loud `additionalContext` block: threat classification, sanitized output, and an explicit instruction not to follow any directives from the original output. This is a strong counter-signal but not a hard boundary.

## What gets detected

The `sanitize` preset in distill-strip-ansi preserves legitimate display sequences (colors, basic cursor, safe OSC) and strips known attack vectors:

- **Echoback vectors**: DECRQSS, OSC 50, CSI 21t, CSI 6n — sequences that cause the terminal to echo data back, enabling data exfiltration
- **Dangerous OSC**: OSC 52 (clipboard manipulation)
- **Screen/cursor manipulation**: sequences used to overwrite visible content with benign-looking text

With `--check-threats`, the library classifies detected sequences with CVE IDs, type, line, byte offset, and NVD references. Only the classification is forwarded to Claude and the user — never the payload text itself.

### Optional: homograph detection

Install distill-strip-ansi with the `unicode-normalize` feature to additionally detect Unicode homograph attacks (fullwidth ASCII, math bold Latin, circled letters, superscript/subscript digits — ~247 visually-similar character mappings):

```sh
cargo install distill-strip-ansi --features unicode-normalize
```

This feature is off by default to avoid false positives in legitimate multilingual content.

## What never gets forwarded

The actual attack payload is never sent to Claude, the user's terminal, or any downstream agent. The hook forwards:

- Threat classification and location (CVE, type, line, offset)
- Sanitized output (attack sequences stripped)
- An explicit counter-instruction when threats are detected

Raw payloads from threat events are logged to `${TMPDIR}/strip-ansi-threats/` for forensic review only.

## Requirements

- [`distill-strip-ansi`](https://crates.io/crates/distill-strip-ansi) on PATH:
  ```sh
  cargo install distill-strip-ansi
  ```
- `jq` (almost always already installed)

The hook **fails open**: if either tool is missing, it exits silently without blocking your workflow.

## What this plugin does NOT do (yet)

- **`NO_COLOR=1` injection into Bash environment.** Would prevent colors from being emitted in the first place, but PreToolUse hooks can't reliably mutate the Bash tool's environment from a subprocess. Tracked for v2.
- **Built-in tool output replacement.** The hook API does not yet support `updatedBuiltinToolOutput` ([#36843](https://github.com/anthropics/claude-code/issues/36843)). When it ships, built-in tools get the same full protection as MCP tools.
- **MCP tool description scanning.** Descriptions are loaded at connection time, before any hook fires. This requires a platform-level fix — see [anthropics/claude-code#15718](https://github.com/anthropics/claude-code/issues/15718).
- **Write/Edit sanitization.** By the time ANSI residue reaches a file write, ESC bytes are usually already gone — leaving literal text that a parser can't safely distinguish from legitimate content.

## Background

- [Trail of Bits: Deceiving users with ANSI terminal codes in MCP](https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/) — the vulnerability this plugin's security tier addresses
- [Trail of Bits: mcp-context-protector](https://github.com/trailofbits/mcp-context-protector) — a complementary MCP proxy approach that replaces ESC bytes with literal "ESC" strings
- [anthropics/claude-code#36843](https://github.com/anthropics/claude-code/issues/36843) — request for `updatedBuiltinToolOutput` to close the built-in tool gap
- [anthropics/claude-code#15718](https://github.com/anthropics/claude-code/issues/15718) — request for MCP display/context separation

## Status

Alpha. The hook delegates to distill-strip-ansi for parsing, threat detection, and sanitization. The plugin's role is hook integration and two-tier response routing.
