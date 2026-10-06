# Foundation validation

Base: freshly fetched Toolshed `origin/main`,
`4157bab84934e0e4fa0170d4a7415855c065d786` (2026-10-05).
The owner authorized a disabled foundation plus separate Codex bridge research.
This evidence does not qualify automatic wake or complete PR2's release gates.

## Tested boundaries

- Canonical PR1 schema and fixture blobs exported at the manifest's full commit;
  local hashes and a fetch of those exact Git blobs match. Runtime parsing rejects
  malformed/duplicate keys, unknown fields, bad freshness and wrong delivery IDs.
- Real disposable Unix WebSocket fixtures exercise framing, deadlines, bounded
  history, server-action refusal and exact native user-message correlation.
- Real disposable TCP fixtures exercise absolute header/body deadlines despite
  trickled bytes, duplicate framing and bounded concurrency.
- SQLite tests cover private files, one writer, receipt conflicts, restart
  quarantine, generation tombstones, capacity and persistent ACK recovery.
- Dispatcher fixtures test authority expiry/detach across awaits, busy accepted
  deliveries outliving transport expiry, cancellation and lost native response,
  and lost cloud ACK. Recovery never calls the native submit method a second time.
- Production CLI refuses attachment, reports automatic wake disabled, preserves
  local private keys without claiming enrollment, and runs/stops a private control
  daemon. An installed wheel outside the source tree loads its embedded schema.
- Existing Bun suite: 1,101 pass, one preexisting skip, zero failures; marketplace
  and generated scope checks pass. CI separately exercises Linux and macOS.

## Causal red/green checks

Scratch copies or in-memory module mutations left production source intact:

| Defect introduced | Evidence of detection |
| --- | --- |
| Remove duplicate-key guard | Parser test fails on wrong error code; restored green |
| Remove native client-message correlation | Unrelated completed turn becomes observed; test fails; restored green |
| Remove dedup conflict, restart quarantine, detach fence, capacity or writer lock | Five narrow store mutations each produce a targeted failure; restored green |
| Bypass signature verification | Bad-signature gateway assertion fails; restored green |
| Bypass dispatch permit check | Expired-permit gateway assertion fails; restored green |
| Treat lost native response as submitted | Ambiguity assertion fails; restored green |
| Relax absolute header deadline | Trickled-header test times out waiting for rejection; restored green |
| Lose observed ACK recovery | Real implementation initially drops the row from recovery; regression red, durable ACK fix green |
| Cancel native RPC without quarantine | Real implementation initially retains `submitting`; regression red, cancellation fix green |
| Drop durable ACK marking/fence/capacity | Three narrow store mutations fail; restored green |
| Remove boolean RPC-ID exclusion or native-version guard | Each focused transport test fails; unchanged source passes all 12 |
| Accept a different or missing consumer-generation fence | Two store regressions initially accept stale work; fixed equality/transfer/tombstone checks pass |

Final local suite: 47 Python tests pass. Review upgraded cryptography to 50.0.2;
the installed signature/consumer checks and both native read-only probes were
repeated with that lock. Module summaries use one line to satisfy the conflicting
multiline documentation rules, retaining the explanations in comments.

Exact disposable native, locked dependency evidence is in
[transport-evidence.json](transport-evidence.json), reproducible with
`scripts/probe_codex_transport.py --binary /absolute/path/to/codex`.
Both 0.160.0 and 0.160.1 read-only canaries matched the launched server PID,
with zero loaded threads and zero model turns. These canaries prove transport;
they do not prove selected-client presence.

## Remaining qualification gates

Native client selection/consumption fencing; production owner enrollment and
current cloud admission; private Mesh delivery; three-session routing; user-service
install/upgrade lifecycle; source-aware coalescing; and shared semantic boundary
vectors executed by both OS TypeScript and Toolshed Python validators remain open.
The proposed local signature and permit seams require a reviewed PR3 contract.
