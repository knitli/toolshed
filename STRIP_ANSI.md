# ANSI Stripping for LLM Workflows — Context Handoff

> Handoff doc for continuing this work in the `knitli/toolshed` repo. Self-contained: read this and you have everything from the prior conversation.

## The Problem

LLM-generated content (commit messages, PR bodies, code comments, documentation, issue replies) regularly arrives polluted with ANSI escape sequences. The pattern:

1. An agent runs a dev tool (`cargo build`, `git status`, `npm install`, `gh pr view`, etc.) with color enabled.
2. The tool's output — colors, OSC 8 hyperlinks, cursor moves, progress bars — lands in the agent's context as raw bytes.
3. The agent paraphrases/quotes that output into a commit message, PR description, or file edit.
4. The escape codes survive the round-trip and end up committed to git, posted to GitHub, or written into source files.

The result: corrupted commits, unreadable PR descriptions, files with embedded `\e[` garbage, occasional terminal-injection vectors. Increasingly common as agentic coding tools proliferate. The OSC 8 hyperlink case (`ESC ] 8 ; ; URL ST text ESC ] 8 ; ; ST`) is particularly nasty because modern dev tools (cargo, gh, rustc) emit them constantly and naive `sed` patterns miss them entirely.

## Investigation Summary

Goal: determine whether to build a new tool or whether existing tooling is good enough.

### Tools Evaluated (against a hand-built fixture covering SGR, truecolor, OSC 8 BEL+ST, OSC title, cursor moves, DEC private modes, charset designators, clear screen)

| Tool | Install | Verdict |
|---|---|---|
| `sed`/`perl` one-liners | builtin | **Wrong.** Only matches `\e[...m`. Misses OSC 8, OSC title, DEC private, charset designators. The status quo and the source of most corrupted commits. |
| `ansi2txt` (colorized-logs) | `apt install colorized-logs` | **Nearly perfect.** Handles OSC 8, DEC private, cursor moves. **Bug:** charset designator `ESC ( B` leaves stray `B` in output. Linux-only, no brew, no static binary, ~2008-era C. |
| `ansifilter` | apt/brew | Feature-rich (HTML/LaTeX/RTF output) but heavyweight. Slow startup. Overkill for plain stripping. |
| `cli-denoiser` (Rust, 2025) | `cargo install` | **Disqualified.** (a) Pollutes stdout with `[cli-denoiser] saved ~34 tokens (37%)` banner — corrupts any pipe. (b) Misses DEC private modes (`\e[?25l`). (c) Uses regex, not a real parser. (d) "Zero false positives" guarantee is a motte-and-bailey: defined narrowly as "didn't drop required signal in benchmark"; doesn't mean correct ANSI handling. Vibe-coded; the dev pattern-matched "strip ANSI → regex" instead of using `vte`. README is impressive (charts, tables, architecture diagrams) but architecturally wrong for a stdin filter. |
| **`distill-strip-ansi`** (Rust, v0.4.0) | `cargo install distill-strip-ansi` | **Winner.** Passes every fixture test. See below. |

### distill-strip-ansi: Why It Wins

**Correctness:** Custom 1-byte ECMA-48 state machine (15 states), not regex. Handles CSI / OSC (BEL+ST) / Fe / DCS / SS2 / SS3 / APC / PM / SOS / EscIntermediate / CAN+SUB abort (ECMA-48 §5.6 — almost everyone forgets this). Beats both `ansi2txt` (charset bug) and `cli-denoiser` (DEC private bug) on the fixture, with no regressions vs either.

**Architecture:**
- `memchr` SIMD scanning for ESC bytes
- `Cow::Borrowed` zero-alloc fast path on clean input (the common case for commit messages — usually no ANSI at all)
- Streaming with 1 byte of cross-chunk state
- `no_std` compatible, zero `unsafe`
- ~100KB binary vs `strip-ansi-escapes` 225KB / `console` 500KB

**Security model nobody else has:** Preset gradient instead of binary strip/keep:

| Preset | Preserves | `--unsafe` |
|---|---|---|
| `dumb` | nothing | |
| `color` | SGR | |
| `vt100` | + cursor, erase | |
| `tmux` | + all CSI, Fe | |
| **`sanitize`** | **+ safe OSC (titles, links)** — auto-detect ceiling | |
| `xterm` | + all OSC | required |
| `full` | everything | required |

Auto-detect picks `dumb` when piped to a file/process and `sanitize` for terminals. `sanitize` is the ceiling for auto — known echoback vectors (CSI 6n cursor query, CSI 21t window title query, OSC 50, OSC 52 clipboard, DECRQSS) are always stripped because they enable terminal injection attacks.

**Threat scanner:** `--check-threats` scans for echoback vectors and reports machine-parseable output to stderr with byte offsets, line numbers, and CVE references:
```
[strip-ansi:threat] type=csi_6n line=2 pos=9 offset=20 len=4
[strip-ansi:threat] type=osc_clipboard line=3 pos=19 offset=53 len=16
```
Exits 77 on threat detection (CI gate-friendly). `--on-threat=strip` mode strips threats from stdout while reporting to stderr — clean channel separation. External threat database via `--threat-db custom.toml` extends patterns without recompiling.

**Library API:** Drop-in replacements for `strip-ansi-escapes` and `fast-strip-ansi`. Full `Cow`-returning `strip()` for new code.

**Author signal:** README and `doc/ECOSYSTEM.md` use specific terminology (ECMA-48 section numbers, SS2/SS3/Fe/DCS distinctions, CVE references). Names competitors honestly with download counts. Concedes when not to use the crate ("Good choice when you already depend on `vte`"). Marks unknown competitor capabilities as `unknown` rather than `no`. Hedges benchmarks with "likely" and "on author's hardware." Engineer-with-AI mode, not walk-away-for-8-hours mode.

## The Decision

**Don't build a new ANSI stripper. Use `distill-strip-ansi`.**

The original instinct was right — the niche existed, the existing tools were inadequate. But `distill-strip-ansi` (v0.4.0, recent) has already filled it well, with a security model that's more sophisticated than what we'd have shipped. The author clearly knew the problem domain. Prior art wins.

**The remaining gaps are not parsers — they're integration and distribution.**

## Recommended Work (Toolshed Scope)

The unfilled niches, in rough priority order:

### 1. Agent integration layer (the original itch)

This is the actual problem. ANSI shows up in commits/PRs because agents don't strip it before writing. Options:

- **Claude Code hook** (`PostToolUse` on `Write`/`Edit`/`Bash`?) — pipe the content through `strip-ansi --preset dumb` before it reaches disk or before it lands in agent context. Probably the highest-leverage intervention.
- **Git hook** (`prepare-commit-msg`, `commit-msg`) — sanitize commit messages at the git layer regardless of which agent generated them. Universal but reactive (only catches commits, not PR bodies or file edits).
- **`gh` extension** (`gh pr create` / `gh issue create` wrapper) — sanitize PR/issue bodies before they hit the GitHub API.
- **A `toolshed`-native plugin** that bundles all of the above with sensible defaults.

Open question: do we want a *passive* sanitizer (strip silently) or an *active* one (warn the agent that its output had ANSI, so the agent learns)? The active version is more interesting for agent training feedback loops; the passive version is more reliable.

### 2. Distribution / packaging contribution

`distill-strip-ansi` is currently `cargo install` only. Contributing distribution would help non-Rust users and broaden adoption:

- **Homebrew tap** — `brew tap knitli/tap && brew install strip-ansi`. ~30 min of work pointing at the upstream GitHub releases. Could later be promoted to `homebrew-core` if upstream wants.
- **`curl | sh` installer** — single shell script that detects OS/arch and downloads from GitHub releases.
- **Debian packaging** — meaningfully harder; probably not worth it short-term.

**Coordinate with upstream first.** Open an issue on the distill-strip-ansi repo asking whether the author wants help with distribution before forking effort. The README/ECOSYSTEM voice suggests they'd welcome it.

### 3. Threat-database contributions

`distill-strip-ansi` supports external threat databases via TOML. The built-in set covers the well-known echoback CVEs. There's room to contribute additional patterns as new terminal-injection vectors are documented (especially as agentic tools start reading untrusted command output). Possibly a `toolshed` repo of curated threat DBs.

### 4. Benchmarking against real LLM output

The existing benchmarks compare token counts on synthetic dev-tool output. The actually-interesting benchmark is: collect a corpus of real LLM-generated commits/PRs/file edits with embedded ANSI, run all the tools against them, measure (a) correctness of stripping, (b) any signal loss, (c) latency on commit-message-sized inputs (the `Cow::Borrowed` fast path should dominate). Useful for the README, useful for the integration plugin's defaults.

## Considerations / Open Questions

- **Where in the agent pipeline to intervene.** Hook on tool *output* (clean before it enters context) vs hook on *write* (clean before it hits disk) vs both. Cleaning early prevents the agent from quoting garbage; cleaning late is the safety net. Both is probably right; both is also more code.
- **Preset selection per integration.** Commit messages: `dumb`. PR bodies: probably `dumb` (GitHub renders some ANSI but not reliably). Code/markdown files: `dumb`. Terminal pass-through (if we add a wrapper command): `sanitize`. Logs being captured for later display: `color`. Should be configurable but defaults matter.
- **Whether to wrap or shell out.** Toolshed plugins can either shell out to `strip-ansi` (simple, requires it on PATH) or depend on `distill-strip-ansi` as a Rust crate (faster, no PATH dep, requires the plugin be Rust). Likely shell out for the v1 hooks, link as a library for any Rust components.
- **Detection mode.** Even when not stripping, `strip-ansi --check` (exit 1 if ANSI found) is useful as a CI lint to flag PRs/commits that contain escapes — maybe we offer a "report only" mode for repos that want to surface the problem without auto-fixing.
- **Multi-agent landscape.** The plugin should work for Claude Code, Codex, Gemini CLI, Aider, and whatever comes next. Hook APIs vary. cli-denoiser does this with `cli-denoiser install` auto-detection — the approach is right even if the tool is wrong; we can borrow the pattern.

## Quick Reference

**Install:**
```sh
cargo install distill-strip-ansi
# binary lands at ~/.cargo/bin/strip-ansi
```

**Use:**
```sh
# Default: auto-detect, strips everything when piped
some-tool 2>&1 | strip-ansi

# Explicit preset
strip-ansi --preset dumb < input.txt
strip-ansi --preset sanitize < input.txt   # safe default for terminal

# Lint mode (CI)
strip-ansi --check < commit-msg.txt        # exit 1 if ANSI found

# Threat scan
strip-ansi --check-threats < untrusted.log # exit 77 on echoback vector
strip-ansi --check-threats --on-threat=strip < input.log  # strip + report
```

**Library:**
```toml
[dependencies]
distill-strip-ansi = "0.4"
```

**Upstream:**
- crates.io: <https://crates.io/crates/distill-strip-ansi>
- (Find the repo via crates.io — wasn't captured in this conversation.)

## TL;DR for the next conversation

1. The ANSI-in-LLM-output problem is real and growing.
2. We investigated. `distill-strip-ansi` is the right parser; it has a security model the others lack and beats every alternative on a real test fixture.
3. **Don't write a parser.** Build the integration layer in `toolshed`: agent hooks (Claude Code first), commit/PR sanitization, optional CI lint mode. Use `distill-strip-ansi` as the engine, either via shell-out or as a crate dep.
4. Consider contributing a Homebrew tap to upstream while we're at it — coordinate via issue first.
