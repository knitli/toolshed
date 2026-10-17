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

## Push ingress qualification

Push qualification requires an authorized external sender binding accepted by Muse
for the exact existing interactive session, with a supported ingress gate and
recipient approval lifecycle. It also needs atomic busy handling, generation
fencing across restart, caller-stable delivery identity, and a durable receipt
lookup (or an explicit supported no-retry policy for ambiguous sends). Installed
CLI help and bundled source do not establish that interface. Simply enabling a
setting would not establish these guarantees.

## Pull monitor qualification

A session-owned pull monitor needs its actual advertised tool contract, an
owner-started monitor bound to the exact session, an authenticated gateway read
with a durable cursor, and an explicit acknowledgement before advancing that
cursor. Prove idle wake, busy queuing, restart generation fencing and lost-read/ACK
recovery. It does not need an external peer sender or push-ingress approval; those
requirements apply only to the push path above. Monitor output cannot itself
authorize tools or source access.

### Plugin and native monitor evidence

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
MSP method export. The export contains `subagent/sendMessage`, whose exact description is:

> Queue a user note into a running child; admission-only ack, the note settles on the child session's view stream (SS3.16).

Its `SubagentInputParams` requires `sessionId`, a durable child `subagentId`,
`commandId`, and `body`. Its `CommandAcceptedResult` echoes the command identity
and reports admission only, never the outcome. This contract targets a running
child within the MSP subagent interface; it does not establish attachment or
authorized peer delivery to an independent existing TUI session. Observing an
`accepted` response would not prove that the child processed the note or woke.
The export's own help notes a
separate deferral register, so absence is not proof of no internal capability.

## Owner-reported monitor contract and offline invocation

The owner subsequently supplied native tool introspection, transcribed in
[owner-monitor-contract.json](muse-ingress/owner-monitor-contract.json). This is
a structured transcription of owner-reported evidence, not an independently
exported native schema; no monitor was started and no synchronous return schema
was supplied. `event_gateway.muse.normalize_monitor` validates that input, while
`command_monitor` quotes trusted argv into the tool's shell-source `command`.
Its executable must be an explicit path containing `/` (absolute or relative),
so shell builtins cannot replace it. It does not resolve names using the
constructor process's `PATH`; raw `command` input remains shell source.
Neither function executes anything, locates a session, or grants read authority.

The input requires `description` and exactly one of `command` or `ws`. Defaults
are `persistent=false`, `timeout_ms=300000`, `wake_delay_ms=120000`, and
`show_lines=false`. Explicit timeout is forbidden with persistence; the normalized
persistent input therefore omits timeout. Timeout is 1000–1800000 ms. Wake delay
is zero or 1000–1800000 ms. WebSocket subprotocols must be unique RFC6455 tokens
and may appear only with `ws`. Each stdout line or UTF-8 WebSocket text frame is
an asynchronous machine notification; source closure ends the watch. Persistent
watches have no deadline until the source, session, or `muse.work_stop` stops them.
`show_lines=true` also renders FEED cells. None of this constitutes a receipt.

WebSocket preflight percent-decodes domain hosts as strict UTF-8, rejects forbidden
host characters, and checks numeric IPv4 bounds while retaining valid shorthand,
octal, and hexadecimal forms. Compatibility-character and Unicode-dot checks
prevent those forms from hiding forbidden characters or numeric overflow. These
are bounded guards informed by the [URL Standard](https://url.spec.whatwg.org/#host-parsing),
not a complete WHATWG parser: native UTS46/IDNA validation remains authoritative.
The original URL is preserved, and acceptance makes no connectivity claim.

Once a separately implemented and authorized session polling command exists, the
target session can prepare native tool input without shell interpolation:

```python
from event_gateway.muse import command_monitor

# Illustrative argv only: no polling command is implemented by this slice.
monitor_input = command_monitor(
    "Read pending event references for this disposable session",
    ["/absolute/path/to/authorized-poller", "--binding", "/private/session-binding.json"],
    wake_delay_ms=0,
)
# The owning Muse session would pass monitor_input to its native monitor tool.
```

Quoting protects argument boundaries, not executable provenance. The caller must
supply trusted executable/arguments and independently establish session ownership.
Do not place credentials in command strings or confuse a supplied session UUID
with an authenticated session binding. No CLI registration, native/provider call,
configuration change, pull endpoint, cursor, or acknowledgment is added here.

## Concrete next action

Push ingress remains a separate, unqualified path; see [Push ingress qualification](#push-ingress-qualification).

Design the session-owned pull service against an independently trusted Muse
session/generation binding. Existing `control.sock` authenticates the filesystem
owner, not a Muse session. The HTTP listener accepts signed delivery intake only.
`Store.list_pending` is scheduler state, not a durable consumer cursor, and Codex
attachments do not establish Muse ownership. A real service needs bounded reads,
a durable pending notification, explicit idempotent ACK, lost-read/ACK recovery,
and generation fencing. It must also isolate Muse work from the existing native
push dispatcher. Native receipt-v3 ACK/settlement methods cannot acknowledge a
monitor line. Only after those boundaries exist can an owner-started disposable
monitor establish idle/busy/restart behavior. Monitor output never authorizes
source access or tools.

`test_muse_monitor.py` covers the reported contract and shell quoting offline;
these are contract-derived checks, not Muse wake or delivery qualification.

## Checks and artifacts

Read-only CLI help, native peer-list refusal, and offline experimental MSP schema
export were exercised against the installed binary. The [sanitized proof](muse-ingress/qualification.json),
[experimental schema manifest](muse-ingress/schema-manifest.json) and
[complete offline MSP schema](muse-ingress/msp.schema.json) are committed here.
The schema is plain JSON with the original export bytes preserved; its exact SHA-256 is
`0eb3ef3ec63341b6b1f6f52ab61116e37cc59aaa6d69e9b6c265e2011e3e5931`.
The manifest's `fingerprint` is preserved exactly as observed, but its derivation
and source semantics have not been established. It is nonauthoritative evidence,
not the raw schema digest or a verified identity claim. The proof's separate
`schemaManifestSha256` pins the complete manifest file bytes, and the evidence
test verifies that digest independently of the raw schema digest.
The schema is static protocol data, not a session export or credential file. No owner configuration, authentication, installation, or live session
was changed; no peer message was sent. No replacement MSP session or terminal
input was used. Live idle/busy/restart/lost-ack qualification remains unperformed.
