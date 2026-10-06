# Stock Codex TUI bridge observation

2026-10-05: **Reject a launcher/proxy as selected-client authority. Production
Codex delivery and wake remain disabled.** Live menu cancellation has no wire
transition; connection and thread RPCs therefore cannot supply the required UI
selection generation. No native client fork or production adapter was changed.

## Bounded experiment

Used the installed Homebrew executable
`/opt/homebrew/Caskroom/codex/0.160.0/bin/codex`, reporting `codex-cli 0.160.0`;
SHA-256 `112fae7a5a1223e673c8a1791d32338f37df8b527ff1159bb8adac6c4dbf1b4b`.
The existing locked package environment supplied `websockets` 16.1.1. A dedicated
app-server and Unix WebSocket proxy ran under a mode-0700 scratch directory, with
an allowlisted environment (`PATH`, private `HOME`/`CODEX_HOME`, `TERM`). Dedicated
PTY child processes ran the stock TUI. No credentials, active sessions, shared
daemon controls, model turns, native queues, or tool approvals were used.

Invocation overrides, on both backend and TUI:

```text
-c check_for_update_on_startup=false
-c model_provider="bridge"
-c model_providers.bridge.name="Bridge observation"
-c model_providers.bridge.base_url="http://127.0.0.1:9"
-c model_providers.bridge.wire_api="responses"
-c model_providers.bridge.requires_openai_auth=false
```

A disposable `CODEX_HOME/config.toml` contained only
`[projects."<scratch>"] trust_level = "trusted"` (on separate TOML lines).
Invocation-only trust did not satisfy the TUI's remote `config/read` lookup.
This fixture was explicitly authorized; real configuration was untouched.
Initial reconnaissance hit sign-in and folder-trust onboarding without accepting
either. Update notices were dismissed, never installed.

The exploratory proxy blocked all `turn/*` and `thread/queue/*` calls. The retained
harness tightens this to the observed no-turn method allowlist and rejects server
requests and client response messages, so it cannot broker approvals. It records
only direction/case marker, monotonically increasing order, connection incarnation,
method, RPC ID, and relevant thread ID. Terminal state was inspected transiently;
no transcript or complete RPC body is retained. This is test instrumentation,
not authenticated client enrollment or production transport.

## Observed cases

Order references identify the 249-row exploratory run; selected rows and its
SHA-256 are in [codex-bridge-spike-evidence.json](codex-bridge-spike-evidence.json).
Case markers (connection 0) are observer annotations, not native protocol signals.

| Case | Actual observation | Meaning / limitation |
| --- | --- | --- |
| New TUI conversation | `thread/start` returned a thread ID, composer rendered | Initial lifecycle correlation only |
| Model menu open | UI showed Select Model and Effort; `model/list` at 66–67 | Catalog request is not selection revocation |
| Model menu cancel / return | Escape restored composer; **no RPC between markers 68 and 69** | Concrete counterexample to authoritative proxy-only UI observation |
| Resume picker open | Separate connection 3 initialized and listed threads, 71–77; conversation connection 2 stayed open | One TUI can have several connections; open conversation connection does not imply selected conversation |
| Resume picker cancel | Picker connection closed at 79; composer returned | No selected-client generation on the conversation channel |
| Same-process new-thread switch | `/new` sent `thread/start` at 84, new ID at 86; no old-thread unsubscribe | Lifecycle traffic is not a complete selection transition |
| Return to old thread | `/resume <old UUID>` sent read/resume at 95–100; UI reported no rollout found | **Return was attempted but not completed**: untouched empty threads have no persisted rollout |
| Two clients | Two separate PTY TUIs concurrently opened new conversations, connections 2 and 4 | Different-client transport observed; simultaneous selection of the same saved thread **not proven** |
| Ordinary exit | `/quit` closed connection 2 at 161 | Transport disconnect observed; no instantaneous loss/lease bound measured |
| Forced crash | Killing only second TUI closed connection 4 at 163 | Crash detection observed, not queue fencing |
| Relaunch | New TUI got connection 5 at 165 | New incarnation observable, no automatic authority inheritance justified |
| Dedicated backend restart | Connections 1 and 5 closed at 227–228; reconnect attempt 6 closed; connection 7 initialized | Transport reconnection is observable |
| Automatic reconnect | Same TUI tried `thread/resume` at 244; UI then displayed conversation unavailable/input paused | Empty-thread restoration failed; no successful saved-thread restoration claim |

Zero `turn/*` or `thread/queue/*` messages occurred in the exploratory run.
`thread/start` alone initiated no model turn. Empty threads were intentionally
not populated with synthetic turns or fabricated history to make resume pass.
Thus full saved-thread switch/return and same-thread multi-client coverage remain
unproven. The menu counterexample is already enough to reject proxy-only authority.

## Pinned source corroboration

Read-only official tag `rust-v0.160.0` resolves to commit
`a956835d020762cb2b570053af06f643a11c0ecc`. This is version-matched source, **not a
reproducible-build attestation** that the installed binary has identical build
inputs/features. Live wire/UI evidence above remains the primary observation.

- [Session picker](https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/tui/src/app/session_picker.rs#L10): opens its own app-server handle; cancel selections refresh local config and redraw (lines 130–143), without a selection-generation message.
- [Picker Escape](https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/tui/src/resume_picker.rs#L1245): empty-query cancellation returns `StartFresh`; the existing-session caller treats this as returning to its prior view.
- [Model menu](https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/tui/src/chatwidget/model_popups.rs#L16): renders cached choices and asynchronously requests model data. The selection-view construction supplies no cancellation callback (lines 190–199).
- [Selection cancellation](https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/tui/src/bottom_pane/list_selection_view.rs#L1249): marks local completion as cancelled. No native selection event is sent when the optional callback is absent.
- [Resume path](https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/tui/src/app/session_lifecycle.rs#L1269): has same-thread early return, async configuration/resume, and read-only failure branches. An attempted resume does not prove a successfully selected writable conversation.

## Reproduce and stop

Use the existing locked event-gateway environment; no added dependencies:

```sh
python scripts/observe_codex_bridge.py --self-check
python scripts/observe_codex_bridge.py --binary /absolute/path/to/codex
```

The harness prints its private evidence directory. Interactive commands:
`launch a new`, `send a /model`, then a **separate** `send a \r` after typing settles;
`read a` verifies the menu; `mark menu-cancel`, `send a \x1b`, `read a`,
`mark returned`. Repeat with `/resume`, `/new`, and `/quit`.
`launch b new`, `kill b`, and `restart` exercise only owned children. `quit` closes
the harness. Explicit UUID resumes must name only threads created in this fixture.
Do not submit text prompts or select model/permission changes. The no-turn guard
closes any connection that attempts a method outside its allowlist.

The retained harness was separately smoke-tested with stock TUI startup and the
menu open/cancel path. Its self-check covers metadata scrubbing and the no-turn /
no-approval guard; `tests/test_codex_bridge_spike.py` invokes that check in normal
unittest discovery. Locked `ruff check src tests scripts` passed; all 72 Python
unittests passed (1.097 seconds) with local socket binding enabled. It removes its child processes, private home/config and sockets;
only metadata evidence remains in private scratch. Runtime logs/DBs are not PR
artifacts. This is not an ingress-versus-queue-consumption integration test.

Next implementation needs an actual client-side selection witness plus native
acceptance/dispatch fencing, or a deliberately constrained custom client with
explicitly different semantics. This spike authorizes neither production delivery
nor a production fork; retain the disabled adapter until that contract is proven.
