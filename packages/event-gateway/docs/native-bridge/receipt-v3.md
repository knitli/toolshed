# Explicit receipt v3 consumer

The private bridge reader accepts v3 only when explicitly constructed with
`receipt_version=3`. The qualifier pairs this reader with the disposable native
client using `--receipt-version 3`, which sets
`CODEX_NATIVE_BRIDGE_RECEIPT_VERSION=3` for that child. The default stays v2;
there is no negotiation or downgrade. Witness frames remain v2.

V3 start and receipt frames must echo the original full identity and the exact
integer local bridge generation. Missing, extra, mistyped or mismatched identity
fields, generation or frame version close the channel and yield `Unknown`.
The adapter includes generation only after the configured v3 reader validates
the native echo. A historical positive does not authorize a new Start or make
an attachment current.

Existing schema-4 v2 receipts and pending ACKs retain their original JSON bytes.
This change adds no database migration and does not add generation to old
stored receipts. Recovery retries the original ACK without another native
submission.

## Evidence and replay

[The proof manifest](receipt-v3-proof.json) records 197 passing package tests,
ten individual intended-assertion-red/restored-green pairs, and an independent
source/evidence audit with no P1/P2 findings. The qualifier incorporates the
input-recorded and independent-deadline fixes from native checkpoint #45; its
exact baseline commit and hash are recorded separately.

The installed wheel matches all eleven production modules and five canonical
event-contract files. Six focused installed checks pass, including strict v3
generation, default v2 and legacy receipt/ACK recovery. The private reader is
source-loaded from `scripts/qualify_native_bridge.py`; it is not bundled in the
wheel. Automatic wake remains disabled.

From `packages/event-gateway`, run the package checks with the existing Python
environment and `PYTHONPATH=src:tests python -m unittest discover -s tests`.
The ten mutation pairs and their exact test names, source substitutions and
log hashes are recorded in the manifest; mutations belong in a scratch copy.

The paired disposable native run also passes with the installed adapter. It
stops the first TUI and backend, then starts an ordinary embedded TUI with the
same private home and a different selected thread. The adapter recovers the
exact expired Core item while the original mapping remains unavailable. Fifteen
structurally valid changed-identity probes yield Unknown, with exact positive
recovery between probes and no repeated model submission. FD stale Start is a
local `selectionChanged` refusal, not proof that the earlier attempt never ran.

The first busy-witness assumption and daemon-dependent agents startup failed;
their logs remain separate from the passing run. Witness selection availability
does not prove Core is idle. Core's final atomic idle fence remains authoritative.
InputRecorded proves Core item completion plus a durable receipt anchor; it
does not establish model success or transcript materialization. Real cloud
admission remains unproved. No installed owner client, production database or
deployment changed.
