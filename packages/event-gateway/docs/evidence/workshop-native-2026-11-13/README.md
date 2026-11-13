# Workshop native bounded evidence — 2026-11-13

These are exact copies of the reviewed local receipts and one-read snippet source. The receipts are synthetic observer outputs: their `chainLength` and `receiptDigest` fields are reported values, not independently verified cryptographic receipt chains. Request and order IDs are opaque identifiers; the signed requests were revoked after each run. No authorization secrets are included.

The idle and busy trials each observed one canonical read and a bounded callback, then verified the hook remained off and the order was revoked. The busy receipt also records that the original operation completed unchanged before its deferred callback. Running the snippet normally emits a self-contained idle fixture; adapt its note and ACK literals inline for a busy fixture. `--self-check` parses and validates both receipts and exercises the emitted snippet; that check does not establish live production qualification.

These results do not establish Event Runtime v2 lifecycle ACK, task completion, full E5 qualification, or broad rollout/load qualification.
