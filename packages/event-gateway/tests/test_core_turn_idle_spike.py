"""Offline checks for the disposable Core-active-turn witness DTO."""

import time
import unittest
from unittest.mock import patch
from uuid import uuid4

from event_gateway.launcher import BINDING_FIELDS, LaunchError, NativeClient, session_challenge


def witness(state="idle"):
    return {
        "version": 2,
        "nonce": 1,
        "clientId": str(uuid4()),
        "backendPid": 123,
        "connectionId": str(uuid4()),
        "threadId": str(uuid4()),
        "generation": 2,
        "eligible": True,
        "sequence": 1,
        "cause": "heartbeat",
        "serverInstanceId": str(uuid4()),
        "serverGeneration": 3,
        "leaseMs": 750,
        "nativeCoreTurnState": state,
    }


class Bridge:
    def __init__(self, row):
        self.row = row
        self.valid_until = time.monotonic() + 0.5

    def challenge(self):
        return dict(self.row)


class CoreTurnIdleChallengeTests(unittest.TestCase):
    def test_launcher_challenge_preserves_state_and_exact_seven_field_binding(self):
        row = witness("busy")
        bridge = Bridge(row)
        client = NativeClient(bridge, expected_thread=row["threadId"])
        client.ready = True
        binding = {key: row[key] for key in BINDING_FIELDS}
        challenge_id = str(uuid4())

        with patch("event_gateway.launcher._session_request",
                   side_effect=lambda _state, _session, request: client.challenge(
                       request["challengeId"], request["expectedBinding"])):
            observed = session_challenge("unused", str(uuid4()), challenge_id, binding)

        self.assertEqual(observed["witness"], row)
        self.assertEqual(set(binding), set(BINDING_FIELDS))
        self.assertEqual(observed["witness"]["nativeCoreTurnState"], "busy")

    def test_launcher_rejects_missing_state_or_changed_binding(self):
        row = witness()
        self.assertTrue(NativeClient.__module__ == "event_gateway.launcher")
        client = NativeClient(Bridge(row), expected_thread=row["threadId"])
        client.ready = True
        binding = {key: row[key] for key in BINDING_FIELDS}
        missing = dict(row)
        del missing["nativeCoreTurnState"]
        from event_gateway.launcher import _valid_native_witness
        self.assertFalse(_valid_native_witness(missing))
        for malformed_state in ("running", None, True, []):
            malformed = dict(row, nativeCoreTurnState=malformed_state)
            self.assertFalse(_valid_native_witness(malformed))
        with self.assertRaisesRegex(LaunchError, "^native_binding_changed$"):
            changed = dict(binding, generation=binding["generation"] + 1)
            client.challenge(str(uuid4()), changed)

    def test_expired_lease_and_wrong_thread_fail_closed(self):
        row = witness("idle")
        bridge = Bridge(row)
        client = NativeClient(bridge, expected_thread=str(uuid4()))
        client.ready = True
        binding = {key: row[key] for key in BINDING_FIELDS}

        with self.assertRaisesRegex(LaunchError, "^native_binding_changed$"):
            client.challenge(str(uuid4()), binding)

        client = NativeClient(bridge, expected_thread=row["threadId"])
        client.ready = True
        bridge.valid_until = time.monotonic() - 0.001
        with self.assertRaisesRegex(LaunchError, "^native_binding_changed$"):
            client.challenge(str(uuid4()), binding)
