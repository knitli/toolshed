# Native background metadata qualification

The proposed release pins binary SHA-256
`9e99dd87bf932bc6960fd2ff9c60fc9af73f19667323562483e10f86b17042f5`.
The earlier Draw fix preserved idle animation, but background metadata still
revoked selection and prevented a later live canary renewal. This release
preserves a selection only across an eligible periodic metadata update.

The TUI classifies the actual snapshots before handling a successful periodic
rate-limit result. Recovery, stale hard-stop generations, Reserve transitions,
model/settings changes, blocked usage, new or removed banners, and high-usage
prompts remain fenced. Benign meter changes may preserve selection. The FIFO
prefetch slot preserves event ordering and select fairness; heartbeat readiness
checks refresh pending-event state after the synchronization await. Input,
resize, focus, other UI events, and semantic server events still revoke selection.
Title and rate-limit timers no longer revoke merely for requesting metadata.

The separate [cumulative patch](native-metadata-v1-implementation.patch) and
[source manifest](native-metadata-v1-source-manifest.json) apply to pinned upstream
`a956835d020762cb2b570053af06f643a11c0ecc`. All 52 source hashes are checked;
six source files changed from the Draw candidate. Historical Draw and v3
patches, manifests and proofs are preserved.

The [release proof](native-metadata-release-proof.json) records a clean full-tree
macOS ARM64 build with Rust 1.95.0, installed-wheel inventories and runtime checks.
Original builder evidence remains unchanged: it recorded `launcherQualified: false`
against the prior `d820…c02` pin. The launcher and builder now propose the same
new digest; a different rebuild needs separate qualification and review.

## Foreground stability

The frozen [qualifier](native-metadata-launcher-smoke.py) copies only the existing
canary's private ChatGPT authentication into a new private home, using a minimal
configuration. It submits no prompts. It answers terminal queries and requires
at least 60 seconds of measured warmup plus ten continuously stable seconds,
within a 120-second startup deadline. Plugin/MCP initialization can intentionally
revoke selection; this warmup does not prove all asynchronous startup is complete.

After warmup, the same full binding remained current across 209 fresh samples
for 125.035 seconds without input or resize. Two distinct source-defined
`account-rate-limits-UUID` requests occurred during that interval, 60.426 seconds
apart. These are measured requests, not inferred timer ticks. Real model-network
calls and account-read/turn-start counts are uninstrumented and reported unknown;
the harness itself submits zero prompts or turn-start requests.

The previous `d820…c02` binary fails the identical frozen qualifier, changing
selection generations 1.732 seconds after warmup. Its retained log flush did not
prove a passive metadata request before failure; this is a regression baseline,
not an exact attribution of that event. Earlier short-warmup runs and an incorrect
RPC-log extractor are retained privately and are not counted as passing proofs.

A resize revokes the previous binding, composer input refuses readiness, and
clearing it restores selection. Graceful exit returns zero, removes the control
socket and stops the backend. The eight qualifier self-checks cover bounded
warmup/observation, unavailable or changed bindings, exact request-ID parsing,
deduplication and terminal replies.

## Recovery and admission

Fresh two-TUI recovery restores the exact expired receipt twice, rejects all
15 identity mutations, and refuses stale Start. Controlled workerd admission
uses two actual native sessions, 16 requests and nine outcomes, including lost
attach replies, renewal, denial and transfer. The daemon remains the local writer;
no native-runtime rows are inserted directly. These synthetic-provider runs make
zero real model calls and use fixture authority, not production admission.

All 389 gateway tests, Ruff, the Node source-boundary test and repository validation
pass. Scoped native tests cover periodic metadata, selection, banners and recovery.
The full Rust workspace/TUI aggregate was not rerun; historical aggregate fixture
failures remain separately recorded, without accepting snapshots.

The seven cross-repository contract blobs are unchanged. This artifact update
activates neither cloud admission nor automatic, manual or GitHub delivery.
Production attachment and renewal must be retried after review and merge. Mesh
transport, live wake, observed ACK and cloud settlement remain separate gates.
The earlier unknown production pending attempt remains untouched. No owner
Codex installation, configuration, history or authentication was changed.
