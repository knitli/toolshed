# Muse ingress assessment — 2026-10-17

Muse automatic delivery remains unqualified. No production adapter or refusal-only
placeholder is added. Available evidence does not support exact-session gateway
submission with safe busy handling, restart fencing, and no blind replay.

## Evidence

The inspected binary SHA-256 is
`87ff5a31b63e30b6ac04d3e8298285517e753c126fb6f3aee80accf28c4562f1`.

- Knitli `origin/main:apps/os/spikes/event-runtime/README.md` explicitly excludes
  Muse from its tested clients. Its adapter is Codex-only. The plan separately
  requires exact-session peer messaging and MSP attachment qualification.
- Installed native binary `muse-bin-1.4.7-R6101.1` advertises
  `session-message send --target <session-uuid-or-name> [--in-reply-to <reply-token>]
  [--display-context <json>] [--json] < body`. The help exposes neither a
  caller-supplied message identity nor a durable receipt-query command.
- A read-only native-binary `session-message list --json` probe returned exit 1,
  `external_agent_ingress_closed`. No peer identities or transcript were logged.
- Installed first-party bundled `host-manager/scripts/lane_runtime.py`,
  `compose_message` (line 5440), states shell sends are refused with
  `unverified_target_receipt`; it instead composes input for the model's native
  `send_session_message` tool. This is actual peer ingress, distinct from its
  terminal-multiplexer adapters. No sender token was accessed or forged.
- [Official session messaging documentation](https://dev.meta.ai/docs/muse-code/session-messaging)
  documents exact session UUID targeting, recipient sender approval, idle wake,
  active-turn steering, and session-scoped trust that ends on restart. Eligible
  interactive sessions participate; headless sessions do not. These documented
  capabilities do not prove that the gateway has sender authority.
- [Official MSP concepts](https://meta-models.github.io/muse-code-sdk/next/guides/msp-concepts/)
  describe a spawned `muse serve` host over stdio. Starting that host is not
  attachment to an already running TUI.

## Missing prerequisite

Qualification requires an authorized external sender binding accepted by Muse
for the exact existing interactive session, with a supported ingress gate and
recipient approval lifecycle. It also needs atomic busy handling, generation
fencing across restart, caller-stable delivery identity, and a durable receipt
lookup (or an explicit supported no-retry policy for ambiguous sends). Installed
CLI help and bundled source do not establish that interface. Simply enabling a
setting would not establish these guarantees.

## Plugin and native monitor alternatives

[Official extension documentation](https://dev.meta.ai/docs/muse-code/extending)
describes lifecycle hooks and model-invoked MCP tools; it does not establish an
external idle-session ingress. Hooks load at startup and react to existing
lifecycle events. A plugin that polls only during those events is a next-turn
fallback, not an independently proven idle wake.

The [official changelog](https://dev.meta.ai/docs/muse-code/changelog) says the
native `monitor` tool is available by default and monitor event batches can wake
a session. A monitor started by the target session could therefore be a useful
pull-based integration candidate, without an external peer sender. This is an
inference, not runtime proof. Required evidence is the target session's advertised
monitor tool schema, a permitted monitor started inside that session, and
idle/busy/restart/acknowledgement tests tied to its exact identity. No public
external monitor-start method was found in the installed binary's experimental
MSP method export. The export contains `subagent/sendMessage`, not an existing
independent TUI attachment or peer-send method. The export's own help notes a
separate deferral register, so absence is not proof of no internal capability.

The concrete next prerequisite is access to a disposable eligible Muse TUI
session's native tool interface (especially `monitor` or `send_session_message`),
or a documented authenticated external ingress with durable receipts. Generic
permission to run another CLI command does not supply either interface.

## Concrete next action

In a disposable eligible Muse TUI, ask:

> Inspect your available native monitor tool schema and report its exact
> input/output contract; do not start any monitor or send any messages.

That read-only schema determines whether a session-owned pull monitor can support
the gateway. An actual monitor must then prove exact-session idle wake, busy
behavior, restart fencing and ambiguous-outcome handling before activation.

## Checks and artifacts

Read-only CLI help, native peer-list refusal, and offline experimental MSP schema
export were exercised against the installed binary. Sanitized proof and schema
are under `.local-artifacts/event-all-stages-20261017/muse/` (directories 0700,
files 0600). No owner configuration, authentication, installation, or live session
was changed; no peer message was sent. No replacement MSP session or terminal
input was used. Live idle/busy/restart/lost-ack qualification remains unperformed.
