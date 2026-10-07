# Private native witness transport

This companion patch replaces the feasibility spike's FIFO with a private inherited Unix stream endpoint. It is a launcher-to-TUI observation capability. It does **not** authenticate the app-server incarnation or authorize ingress/execution. Hostile processes running as the same OS user are outside this channel's threat boundary. Production native and automatic dispatch remain disabled.

## Wire contract

The launcher creates `socketpair(AF_UNIX, SOCK_STREAM)`, transfers only the child endpoint through `pass_fds`, and sets `CODEX_SELECTION_WITNESS_FD` to that decimal descriptor. After spawning, the launcher closes its copy of the child endpoint. The TUI validates a connected Unix stream, same-user peer ownership (Linux/macOS), and sets close-on-exec before using it. The descriptor is a private capability; no pathname or bearer token is published.

Parent challenge: NDJSON `{"nonce":1}`. Nonces are positive strictly increasing u64 values. Each challenge is at most 128 bytes including newline; no unknown fields or pipelining. Only one challenge may be outstanding. Replies are at most 2048 bytes including newline and contain `version: 1`, the matching `nonce`, and the prior witness fields: `clientId`, `backendPid`, `connectionId`, `threadId`, `generation`, `eligible`, `sequence`, `cause`. `backendPid` and the local connection nonce remain observations, not server-attested identity.

The parent issues challenges approximately every 100 ms and accepts a reply only before its own 750 ms monotonic deadline. Expiry makes the lease unavailable. An expired outstanding request remains outstanding until its correctly matched reply arrives; that late reply grants no lease, but permits a fresh challenge. This supports initial startup and UI pause recovery without pipelining old requests. Unknown/replayed nonce, malformed record, oversize, or EOF fails closed. A new challenge does not extend the previous lease.

Only the actual UI loop services the private endpoint, every 25 ms while enabled and when state transitions occur. There is no background heartbeat emitter. State changes do not create unsolicited output, so keyboard bursts cannot fill an output queue. One immutable pending reply retains its partial-write offset across `WouldBlock`/`Interrupted`. It expires after 750 ms; an incomplete expired stream frame closes the channel rather than corrupting subsequent framing. Native loop gaps of at least 750 ms revoke eligibility and advance generation before replying.

Permanent failures emit sanitized tracing fields under target `codex_selection_witness`: stage, `ErrorKind`, exact OS errno when supplied by the OS, sequence and generation. No input body, prompt, authentication token, or model output is logged. Receiver observation remains asynchronous and cannot provide an atomic execution fence.

## Source and verification

Source base: `openai/codex` `rust-v0.160.0`, commit `a956835d020762cb2b570053af06f643a11c0ecc`. Build uses pinned Rust 1.95.0, profile `dev-small`; the archived release's workspace-only lockfile normalization is retained, with no new dependencies. The source companion test file is included in the patch.

Focused native tests exercise fragmented challenge input after 10,000 native state transitions, replay rejection, partial writes with temporary backpressure, exact errno retention, and pending-response deadline closure. Each new causal is checked independently by production sabotage in a private source copy, then restored and rerun. Existing generation/reconnect and UI-gap tests remain in the focused set. Exact results and final binary hash are retained with the completed checkpoint.

This transport checkpoint does not establish saved-thread resume, same-thread writable/read-only behavior, or live model execution. Those need separate source binding and controlled qualification evidence.

Checkpoint result: seven focused native tests passed; all five new causals independently failed by assertion under isolated production sabotage and passed after restoration. Scoped `just fix -p codex-tui --profile dev-small`, source build, and pinned Rust formatting check passed. The full upstream `just fmt` was also attempted in the isolated copy; it could not complete because `dotslash` was unavailable and unrelated Python formatter downloads failed DNS resolution. This does not change the scoped Rust formatting result. See [machine-readable checkpoint](transport-checkpoint.json) and [red/green proof](transport-red-green.log.excerpt).
