"""Dormant native Messaging V2 checks using local data and socketpair fixtures."""
import copy
import json
from pathlib import Path
import unittest
from event_gateway.native import NativeError, validate_request, _copy
from event_gateway.native_reader import BridgeError, validate_start
from event_gateway.native_messaging import FIELDS, INTEGERS, canonical_metadata
from test_native import request, ADMISSION

ENVELOPE = json.loads((Path(__file__).resolve().parents[1] /
    "contracts/messaging-v2/messaging-protocol-semantics-v2.json").read_text())["envelope"]


def sample():
    admission = copy.deepcopy(ADMISSION)
    admission["envelope"] = copy.deepcopy(ENVELOPE)
    start = request()
    start.update(receiptVersion=3, attemptId=ENVELOPE["attemptId"], deliveryId=ENVELOPE["deliveryId"],
                 event={key: copy.deepcopy(ENVELOPE[key]) for key in FIELDS})
    return start, admission


def wire(start):
    return {key: value for key, value in start.items() if key != "receiptVersion"}


class NativeMessagingMetadataTests(unittest.TestCase):
    def test_valid_metadata_changes_do_not_match_admission(self):
        start, admission = sample()
        changes = {
            "eventId": "01234567-89ab-4def-8123-456789abcdef",
            "principal": "other@example.com", "agent": "other-agent",
            "nodeId": "01234567-89ab-4def-8123-456789abcdef",
            "runtimeId": "01234567-89ab-4def-8123-456789abcdef",
            "nodeGeneration": start["event"]["nodeGeneration"] + 1,
            "runtimeGeneration": start["event"]["runtimeGeneration"] + 1,
            "routingGeneration": start["event"]["routingGeneration"] + 1,
            "policyRevision": start["event"]["policyRevision"] + 1,
            "sourceStateVersion": "msg:" + "f" * 64,
            "eventReference": "ref_01234567-89ab-4def-8123-456789abcdef",
            "observedAt": "2026-10-17T11:59:44.000Z",
        }
        for field, value in changes.items():
            changed = copy.deepcopy(start)
            self.assertNotEqual(changed["event"][field], value)
            changed["event"][field] = value
            validate_start(wire(changed), receipt_version=3)
            with self.subTest(field=field), self.assertRaises(NativeError):
                validate_request(changed, admission)

    def test_oversized_valid_metadata_is_rejected_before_wire(self):
        from event_gateway.native_reader import NativeBridge
        from unittest.mock import Mock
        from test_native_bridge import peer

        start, _ = sample()
        event = start["event"]
        event["canonicalSubject"]["namespace"] = "\U0001f600" * 256
        event["principal"] = "a" * 64 + "@" + "b" * 63 + "." + "c" * 63 + "." + "d" * 61
        event["agent"] = "a" * 32
        canonical_metadata(event, start["attemptId"], start["deliveryId"])
        self.assertGreater(len(json.dumps(wire(start), separators=(",", ":")).encode()), 4096)
        with self.assertRaises(NativeError):
            _copy(start)
        with peer(lambda channel: self.assertEqual(channel.recv(1), b""), receipt_version=3) as bridge:
            bridge._receipt_exchange = Mock(side_effect=AssertionError("oversized request reached wire"))
            bridge.witness = {**wire(start), "eligible": True}
            bridge.valid_until = float("inf")
            with self.assertRaises(BridgeError):
                NativeBridge.start(bridge, wire(start))
            bridge._receipt_exchange.assert_not_called()
            self.assertEqual(bridge.attempts, {})

    def test_explicit_v3_and_legacy_defaults(self):
        start, admission = sample()
        self.assertEqual(validate_request(start, admission), start)
        validate_start(wire(start), receipt_version=3)
        for version in (None, 2, True, 3.0, "3"):
            bad = dict(start)
            if version is None:
                bad.pop("receiptVersion")
            else:
                bad["receiptVersion"] = version
            with self.assertRaises(NativeError):
                validate_request(bad, admission)
            with self.assertRaises(BridgeError):
                validate_start(wire(start), receipt_version=version)
        validate_start(request())
        legacy = request()
        self.assertEqual(validate_request(legacy, ADMISSION), legacy)

    def test_every_field_missing_or_invalid_and_unknown(self):
        start, admission = sample()
        for field in FIELDS:
            for missing in (True, False):
                bad = copy.deepcopy(start)
                if missing:
                    del bad["event"][field]
                else:
                    bad["event"][field] = None
                with self.subTest(field=field, missing=missing), self.assertRaises(NativeError):
                    validate_request(bad, admission)
        for field in ("issuedAt", "expiresAt", "extra"):
            bad = copy.deepcopy(start)
            bad["event"][field] = "unexpected"
            with self.assertRaises(NativeError):
                validate_request(bad, admission)
        for field in start["event"]["canonicalSubject"]:
            bad = copy.deepcopy(start)
            del bad["event"]["canonicalSubject"][field]
            with self.assertRaises(NativeError):
                validate_request(bad, admission)

    def test_bool_float_and_safe_integer_bounds(self):
        start, _ = sample()
        event = start["event"]
        for field in INTEGERS:
            for invalid in (True, False, 1.5, 2**53, -1):
                bad = dict(event, **{field: invalid})
                with self.assertRaises(ValueError):
                    canonical_metadata(bad, start["attemptId"], start["deliveryId"])
        for value in (True, 0.5, -1, 2**53):
            bad = copy.deepcopy(event)
            bad["canonicalSubject"]["agentIncarnation"] = value
            with self.assertRaises(ValueError):
                canonical_metadata(bad, start["attemptId"], start["deliveryId"])

    def test_canonical_order_and_immutable_observed_time(self):
        start, admission = sample()
        reordered = copy.deepcopy(start)
        reordered["event"] = dict(reversed(list(start["event"].items())))
        reordered["event"]["canonicalSubject"] = dict(reversed(list(start["event"]["canonicalSubject"].items())))
        self.assertEqual(json.dumps(validate_request(start, admission)["event"]),
                         json.dumps(validate_request(reordered, admission)["event"]))
        changed = copy.deepcopy(start)
        changed["event"]["observedAt"] = "2026-10-17T11:59:44.000Z"
        with self.assertRaises(NativeError):
            validate_request(changed, admission)
        refreshed = copy.deepcopy(admission)
        refreshed["envelope"].update(issuedAt="2026-10-17T12:00:01.000Z", expiresAt="2026-10-17T12:01:01.000Z")
        self.assertEqual(validate_request(start, admission), validate_request(start, refreshed))

    def test_namespace_and_request_budget(self):
        start, _ = sample()
        for namespace, valid in (("", False), ("x"*257, False), ("x\x00", False),
                                  ("界"*256, True), ("😀"*256, True)):
            event = copy.deepcopy(start["event"])
            event["canonicalSubject"]["namespace"] = namespace
            if valid:
                canonical_metadata(event, start["attemptId"], start["deliveryId"])
            else:
                with self.assertRaises(ValueError):
                    canonical_metadata(event, start["attemptId"], start["deliveryId"])
        self.assertEqual(len(json.dumps("x"*4094).encode()), 4096)
        _copy("x"*4094)
        with self.assertRaises(NativeError):
            _copy("x"*4095)

    def test_restore_exact_identity_and_changed_tuple(self):
        from event_gateway.native_reader import NativeBridge

        start, _ = sample()
        bridge = NativeBridge.__new__(NativeBridge)
        bridge.receipt_version, bridge.closed = 3, False
        bridge.attempts, bridge.deliveries = {}, {}
        bridge.messages, bridge.terminal_attempts = set(), set()
        bridge.restore_attempt(wire(start))
        bridge.restore_attempt(wire(start))
        for field in FIELDS:
            changed = wire(copy.deepcopy(start))
            changed["event"][field] = None
            with self.subTest(field=field), self.assertRaises((BridgeError, ValueError)):
                bridge.restore_attempt(changed)
        changed = wire(copy.deepcopy(start))
        changed["event"]["observedAt"] = "2026-10-17T11:59:44.000Z"
        with self.assertRaises(BridgeError):
            bridge.restore_attempt(changed)

    def test_safe_max_and_zero_incarnation(self):
        start, _ = sample()
        for value in (0, 2**53-1):
            event = copy.deepcopy(start["event"])
            event["canonicalSubject"]["agentIncarnation"] = value
            for field in INTEGERS:
                if field != "schemaVersion":
                    event[field] = 2**53-1
            canonical_metadata(event, start["attemptId"], start["deliveryId"])

    def test_integral_float_projection_and_strict_wire(self):
        start, admission = sample()
        floats = copy.deepcopy(start)
        for field in INTEGERS:
            floats["event"][field] = float(start["event"][field])
        floats["event"]["canonicalSubject"]["agentIncarnation"] = float(start["event"]["canonicalSubject"]["agentIncarnation"])
        projected = validate_request(floats, admission)
        self.assertEqual(json.dumps(projected["event"]), json.dumps(validate_request(start, admission)["event"]))
        validate_start(wire(projected), receipt_version=3)
        with self.assertRaises(BridgeError):
            validate_start(wire(floats), receipt_version=3)

    def test_native_unicode_scalar_subset(self):
        start, admission = sample()
        scalar, paired = copy.deepcopy(start), copy.deepcopy(start)
        scalar["event"]["canonicalSubject"]["namespace"] = "\U0001f600"
        paired["event"]["canonicalSubject"]["namespace"] = "\ud83d\ude00"
        scalar_admission = copy.deepcopy(admission)
        scalar_admission["envelope"]["canonicalSubject"]["namespace"] = "\U0001f600"
        projected = validate_request(paired, scalar_admission)
        self.assertEqual(json.dumps(projected["event"]),
                         json.dumps(validate_request(scalar, scalar_admission)["event"]))
        self.assertEqual(canonical_metadata(paired["event"], paired["attemptId"], paired["deliveryId"]),
                         canonical_metadata(scalar["event"], scalar["attemptId"], scalar["deliveryId"]))
        validate_start(wire(projected), receipt_version=3)
        for namespace in ("\ud800", "\udfff", "a\ud800b", "\ud83d\ude00\udfff"):
            invalid = copy.deepcopy(start)
            invalid["event"]["canonicalSubject"]["namespace"] = namespace
            matching_admission = copy.deepcopy(admission)
            matching_admission["envelope"]["canonicalSubject"]["namespace"] = namespace
            with self.subTest(namespace=repr(namespace)):
                with self.assertRaises(ValueError):
                    canonical_metadata(invalid["event"], invalid["attemptId"], invalid["deliveryId"])
                with self.assertRaises(NativeError):
                    validate_request(invalid, matching_admission)
                with self.assertRaises(BridgeError):
                    validate_start(wire(invalid), receipt_version=3)
