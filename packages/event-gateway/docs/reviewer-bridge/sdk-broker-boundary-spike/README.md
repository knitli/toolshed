# SDK / Docker broker boundary: derived local proof summary

On 2026-10-17, the pinned real SDK completed four expected lifecycle cases through a separately sandboxed broker: success, incomplete early terminal, EOF without terminal, and timeout with owned cancellation. Each passed ten containment observations. All four exact container IDs and names were independently absent afterward; the daemon identity was unchanged and no observed owned processes remained.

[result.json](result.json) contains the four measured outcomes, all forty containment observations, and hashes identifying the privately retained original manifest, root receipt and audit ledger. This is a derived public summary, not a byte-identical archive, executable fixture, or independent reproduction. Absolute local paths, source copies, raw logs and raw receipts are omitted. Original executed inputs and receipts remain preserved privately. Private evidence hashes do not describe these derived public files.

| Case | Reviewer outcome | Container exit | Host / SDK exit |
| --- | --- | ---: | --- |
| success | completed | 0 | 0 / 0 |
| early-terminal | refused: incomplete | 0 | 0 / 0 |
| eof | refused: missing_terminal | 0 | 0 / 0 |
| abort | refused: timeout | 137 | 0 / 0 |

First cancellation followed stdin EOF by 2,001.273417 ms. Total raw capture was 9,018 bytes under the shared 1 MiB cap. The trusted broker settlement matched each SDK report; SDK reports alone were not authority. Broker observations recorded owner-file preservation and zero delivered SDK signals.

The ten observations were denied daemon-socket connection, Docker execution, IPv4, IPv6, another live Unix socket, owner-canary read, fixture write, fixture-alias write and owner signal, plus successful scratch write. These observations cover this fixed local macOS fixture only. The SDK used a synthetic protocol child, with no native Claude execution or provider/model call.

All four stderr captures reported `CLAUDE_SDK_CAN_USE_TOOL_SHADOWED` for the bare-allowlisted tool; callback-based tool authorization was not established. Process ancestry and second-resolution birth observations do not eliminate PID-reuse or check-to-signal races. No hosted equivalence, arbitrary hostile-code containment, portable execution or production integration is claimed.

Packaging this summary did not rerun the SDK, Docker or sandbox workloads.
