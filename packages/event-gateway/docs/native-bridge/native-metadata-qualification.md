# Native background metadata qualification

The proposed macOS ARM64 release pins binary SHA-256
`362074bba4d43bbcc7e1e4162f67f8439106ef388670899309effd75cca65f27`.
It preserves eligible selection across display-only periodic rate-limit updates.
Recovery, stale hard-stop generations, Reserve/model transitions, blocked usage,
banners, prompts, input, resize and semantic server events remain fenced. The
periodic-response branch rechecks the app-event queue after the acknowledgment
await, preserving FIFO order and revoking authority when another event is queued.

The [cumulative patch](native-metadata-v1-implementation.patch) and
[source manifest](native-metadata-v1-source-manifest.json) cover 52 source files
against pinned upstream `a956835d020762cb2b570053af06f643a11c0ecc`.
V3 adds diagnostics containing static cause categories and numeric generations;
these diagnostics do not change selection authority or establish the cause of an
earlier failure. Historical patches, manifests and proofs are preserved.

The [release proof](native-metadata-release-proof.json) records the clean full-tree
Rust 1.95.0 build. Original V3 builder JSON remains unchanged (SHA prefix `c05d`):
it recorded `launcherQualified: false` against the then-current `9888…ae78` pin.
Subsequent launcher qualification is separate evidence, not a rewritten build result.

## Foreground proof

The frozen [qualifier](native-metadata-launcher-smoke.py), SHA prefix `ea6ba6fc`,
uses a fresh private home and a copied ChatGPT auth file. Its `finally` cleanup
removes that copy after foreground teardown, on success or failure; the original
source remains untouched. On macOS use `TMPDIR=/private/tmp` for short socket paths.

The startup gate requires 60 seconds elapsed and ten continuously stable seconds
within 120 seconds. This is measured warmup, not proof that all asynchronous
plugin/MCP startup has finished. V3 then passed **125.06128 seconds and 209 fresh
binding samples**, without input or resize. Two measured rate-limit requests were
**62.18143 seconds apart**. Resize and composer refusal/restoration checks passed;
graceful exit returned zero, removed the control socket and stopped the backend.
The copied auth file was removed. The earlier V3 foreground pass (125.09796
seconds, requests 60.45235 seconds apart) is preserved separately.

The harness submits no prompts or turn-start requests. Actual model-network calls
and account-read/turn-start RPC counts remain unknown. The 22 self-checks cover
strict observation, terminal replies, private pinned helpers, auth cleanup,
failure phases and sanitized diagnostics. On failure, an additional bounded
11-second capture preserves the original failure time/result and excludes capture
time from passive RPC counts. Positive authority transitions are not labeled
revocations.

The matching `d820…c02` baseline failed the same frozen `ea6ba6fc` qualifier after
60.010 seconds of warmup: both generations changed at passive +1.730 seconds
(three samples). One measured rate-limit request preceded the failure at
+1.647 seconds; this timing does not establish causation. The old binary lacks
the new cause producer, so its empty 11-second capture does not prove no events
occurred. Its copied auth was removed.
V2 passed synthetic recovery/admission
but failed real-auth stability after 24.465 seconds;
the exact cause was not retained. V3's successful run and new diagnostics do not
retroactively explain or prove a fix for that failure.

## Other validation and limits

All **278 focused native tests** passed. The full TUI aggregate had **5,598 passed,
45 failed and 8 skipped**: a paired baseline reproduced 44 failure signatures;
the remaining isolated binary fixture passed, as did all four isolated NO_COLOR
cases on both candidates. The aggregate is not green.

Fresh V3 two-TUI recovery passed: two exact expired-receipt recoveries, all 15
identity mutations rejected, and stale Start refused. Controlled workerd admission
passed with two actual native sessions, 16 requests and nine outcomes. The daemon
was the local writer; no native-runtime rows were inserted directly. These runs
used a synthetic provider with zero real model calls and fixture authority;
production admission was not proven.

All 389 gateway tests passed in 17.843 seconds, along with Ruff, the Node
source-boundary test and contract synchronization. The post-await queue regression
tests exercise the production predicate, not actual scheduler interleaving across
the acknowledgment await.

The seven contract blobs remain unchanged. No owner installation, configuration,
history or original authentication was changed. This artifact update activates
no automatic, manual or GitHub delivery. Production attachment/renewal, Mesh
transport, live wake, observed ACK and settlement remain separate gates; the
existing unknown production pending attempt remains untouched.
