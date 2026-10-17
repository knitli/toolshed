# Dormant Messaging v2 source conformance

`event_gateway.messaging_protocol_v2` implements only the decoded DTO contract
from Cloud's `src/messaging/protocol-v2.ts`. It is not imported by the gateway,
listener, store, native adapters, claim path or producer. Version 1 validation,
contract pins, trusted families, packaging configuration and workflows are
unchanged. This module does not enable Messaging delivery or native execution.

The exact upstream fixture is stored separately under `contracts/messaging-v2`.
`source-receipt.json` records the Cloud source revision and SHA-256 values,
including its lockfile and the relevant installed Zod files. This is evidence of
source conformance, **not a trusted-policy adoption manifest**. No release or
runtime code consumes that receipt. The fixture is for source-tree tests; the
existing wheel's v1 contract-data packaging is unchanged.

| Function | Meaning |
| --- | --- |
| `validate_envelope(value, now_ms=None)` | Strict decoded envelope shape, compact JSON byte limit, canonical timestamps and freshness |
| `validate_acknowledgment(value, now_ms=None)` | Strict decoded submitted/observed ACK and timestamp/skew checks |
| `derive_delivery_id(identity)` | Version-2 SHA-256 digest over the eight Cloud destination/identity selectors |
| `matches_delivery_id(envelope)` | Compare the supplied delivery ID with that digest |
| `acknowledgment_matches_delivery(envelope, acknowledgment)` | Match every attempt, owner, destination, generation and source-version field |

Digest derivation accepts a full envelope and projects the same eight fields as
Cloud. Attempts and timestamps do not change delivery identity. ACK mapping
accepts both native stages; it neither advances a watermark nor settles work.
Mapping requires valid shapes but does not refresh their freshness or establish
current authority. Publisher authenticity, registered keys, route consent,
consumer qualification and native evidence remain external requirements.

## Exact value semantics

Only plain decoded dictionaries and JSON scalar types are accepted. There is no
wire parser, duplicate-key claim, `toJSON` hook, or authentication wrapper.
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

## Local verification

From the repository root, using existing installed Python dependencies:

```sh
PYTHONPATH=packages/event-gateway/src python3 -m unittest discover -s packages/event-gateway/tests -p test_messaging_protocol_v2.py -v
PYTHONPATH=packages/event-gateway/src python3 -m unittest discover -s packages/event-gateway/tests -p test_protocol.py -v
PYTHONPATH=packages/event-gateway/src python3 -m unittest discover -s packages/event-gateway/tests -p test_semantic_vectors.py -v
```

The new test module exposes `decoded_cases()` for an independent Cloud-source
comparison. Its cases cover both ACK stages, closed fields, canonical identity,
integer limits, Unicode, timestamps and freshness. Existing v1 tests continue to
execute all 45 vendored semantic verdicts unchanged. These are local contract
checks, not native-client qualification or production activation evidence.
