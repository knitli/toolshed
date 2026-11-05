# Active Messaging v2 contract profile

`event_gateway.messaging_protocol_v2` implements the decoded DTO and raw-wire
contracts from Cloud's `src/messaging/protocol-v2.ts`. The trusted contract
workflow now adopts the exact four-blob assigned-stock V2 profile at merged
source commit `e954904603b3467e30bbeaf7446977b61fbcb9ef`. This is active contract
policy adoption, not a production rollout. On the explicit stock-only path,
the listener routes V2 envelopes through V2 admission and the store validates
the assigned-stock profile and conversation before the configured Codex CLI
queues the opaque event reference. A successful CLI exit is recorded as
`command_accepted`; it means the command accepted the queue request, not that a
native turn started or completed. Unknown CLI outcomes remain ambiguous and
are not automatically reissued by the Gateway. Version 1 validation, contract
pins, trusted families and packaging configuration remain unchanged. This path
does not enable V2 native execution or claim production activation.

The exact upstream fixture is stored separately under `contracts/messaging-v2`.
The two source receipts record the Cloud source revision and SHA-256 values,
including its lockfile and the relevant installed Zod files. They are provenance
evidence, not self-authorizing manifests: authorization comes from the trusted
workflow's exact SHA-256 mapping for all four profile blobs. No release or
runtime code consumes the receipts. The fixtures are for source-tree tests; the
existing wheel's v1 contract-data packaging is unchanged.

| Function | Meaning |
| --- | --- |
| `parse_envelope(body, now_ms=None)` | Parse bounded raw JSON and validate envelope shape/freshness |
| `parse_acknowledgment(body, now_ms=None)` | Parse bounded raw JSON and validate ACK shape/freshness |
| `validate_envelope(value, now_ms=None)` | Strict decoded envelope shape, compact JSON byte limit, canonical timestamps and freshness |
| `validate_acknowledgment(value, now_ms=None)` | Strict decoded submitted/observed or assigned-stock `command_accepted` ACK and timestamp/skew checks |
| `derive_delivery_id(identity)` | Version-2 SHA-256 digest over the eight Cloud destination/identity selectors |
| `matches_delivery_id(envelope)` | Compare the supplied delivery ID with that digest |
| `acknowledgment_matches_delivery(envelope, acknowledgment)` | Match every attempt, owner, destination, generation and source-version field |

Digest derivation accepts a full envelope and projects the same eight fields as
Cloud. Attempts and timestamps do not change delivery identity. ACK mapping
accepts both native stages and the assigned-stock `command_accepted` stage; it
does not advance a watermark or settle work.
Mapping requires valid shapes but does not refresh their freshness or establish
current authority. Publisher authenticity, registered keys, route consent,
consumer qualification and native evidence remain external requirements.

## Exact value semantics

Decoded validators accept only plain decoded dictionaries and JSON scalar types.
Their behavior is unchanged; passing raw JSON to them still returns false. There
is no `toJSON` hook or authentication wrapper.
Integers must be safe JavaScript integers; booleans, nonintegral numbers,
nonfinite numbers and values above `2**53 - 1` are refused. Integral floats such
as `1.0` are valid JavaScript integer numbers and serialize as `1`. The optional
`now_ms` follows Cloud's finite numeric clock semantics.

The locked Zod 4.6.5 string bound counts **Unicode code points**, not UTF-16
code units or graphemes. Namespace lengths of 128, 129 or 256 emoji are valid;
257 are not. A valid surrogate pair counts once, an unpaired surrogate counts
once, and ASCII control characters are refused. Principal, agent and UUID
patterns remain canonical ASCII. Compact byte counting preserves Unicode,
combines surrogate pairs and escapes lone surrogates as `JSON.stringify` does.
Canonical timestamps require exactly three fractional digits and `Z`, including
ECMAScript year `0000`; invalid calendar dates are refused.

## Raw-wire boundary

`parse_envelope` and `parse_acknowledgment` accept only exact built-in `str` or
`bytes`. They return a validated DTO or raise `MessagingProtocolError` containing
only a safe reason code. They lazily reuse `event_gateway.protocol._decode`:
4096 raw UTF-8 bytes maximum, strict UTF-8, duplicate decoded keys rejected at
any nesting level, and maximum depth 32 (root depth zero, scalar leaves counted).
The v1 decoder remains unchanged. The stock-only listener path explicitly
routes V2 envelopes to this parser; importing the decoded v2 module does not
load the v1 schema or `jsonschema`, while an explicit wire call does.

Whitespace counts toward the raw byte cap. BOM-prefixed JSON and malformed UTF-8
are rejected. Escaped lone surrogates retain the decoded DTO semantics above;
a literal surrogate in a Python string is not UTF-8 and is rejected. JSON
`NaN`/`Infinity` tokens are invalid JSON; exponent overflow such as `1e400` is
rejected by the DTO shape. Unsafe integer fields are rejected by that same shape.

Wire errors are `invalid_json`, `duplicate_json_key`, `message_too_large`,
`invalid_envelope`, `invalid_acknowledgment`, or `stale_message`. Structural wire
checks precede shape validation, and shape validation precedes freshness checks.
For inputs violating multiple wire rules, rejection is shared but the specific
reason may differ: Cloud validates JSON syntax before its duplicate scan, while
Python detects duplicates during decoding. These inherited decoder priorities
are preserved; consumers must not depend on identical reasons for such input.
Successful parsing establishes no publisher identity, route consent, current
consumer authority, native execution, acknowledgment settlement, or activation.

`messaging-v2-wire.json` mirrors the Cloud-owned raw fixture exactly. Its cases
encode raw bytes as `utf8Hex`, including malformed UTF-8, and record verdicts and
safe reason codes for both implementations. The wire source receipt records the
upstream source and fixture hashes used by the active contract profile. It does
not authorize itself or activate a runtime path; the receipt alone grants no
runtime authority, and this documentation does not claim production rollout.

## Local verification

From the repository root, using existing installed Python dependencies:

```sh
PYTHONPATH=packages/event-gateway/src python3 -m unittest discover -s packages/event-gateway/tests -p 'test_messaging_protocol_v2*.py' -v
PYTHONPATH=packages/event-gateway/src python3 -m unittest discover -s packages/event-gateway/tests -p test_protocol.py -v
PYTHONPATH=packages/event-gateway/src python3 -m unittest discover -s packages/event-gateway/tests -p test_semantic_vectors.py -v
```

The new test module exposes `decoded_cases()` for an independent Cloud-source
comparison. Its cases cover both ACK stages, closed fields, canonical identity,
integer limits, Unicode, timestamps and freshness. Existing v1 tests continue to
execute all 45 vendored semantic verdicts unchanged. These are local contract
checks, not native-client qualification or production activation evidence.
