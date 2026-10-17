"""Dormant terminal query checks using private socket fixtures only."""

import asyncio
from copy import deepcopy
import importlib
import socket
import unittest
from unittest.mock import Mock
from uuid import uuid4

from event_gateway.native import IDENTITY, NativeError, validate_receipt
from event_gateway.native_reader import NativeBridge
from test_native import request
from test_native_bridge import peer, receive, send


def full_receipt(item, outcome):
    return {**{key: item[key] for key in (*IDENTITY, "generation")}, "outcome": outcome}


class TerminalEvidenceTests(unittest.TestCase):
    def api(self):
        self.assertTrue(
            callable(getattr(NativeBridge, "terminal_evidence", None)),
            "reader must expose the dormant terminal_evidence query",
        )
        return importlib.import_module("event_gateway.native_terminal_evidence")

    def setUp(self):
        self.item = {**request(), "receiptVersion": 3}
        self.wire = {
            key: value for key, value in self.item.items() if key != "receiptVersion"
        }
        self.observed = {
            "status": "inputRecorded",
            "turnId": self.item["clientUserMessageId"],
            "itemId": str(uuid4()),
            "replayed": True,
        }
        self.anchor = full_receipt(self.item, self.observed)
        self.terminal = {
            **self.observed,
            "status": "terminal",
            "receiptId": str(uuid4()),
            "terminalStatus": "completed",
        }

    def test_restart_saved_anchor_queries_only_terminal_operation(self):
        api = self.api()
        for status in ("completed", "failed", "canceled"):
            outcome = {**self.terminal, "terminalStatus": status}

            def handler(channel):
                row = receive(channel)
                self.assertEqual(row, {"nonce": 1, "terminalEvidence": self.wire})
                send(
                    channel,
                    {
                        "version": 3,
                        "nonce": row["nonce"],
                        "receipt": full_receipt(self.item, outcome),
                    },
                )
                self.assertIsNone(receive(channel))

            with (
                self.subTest(status=status),
                peer(handler, receipt_version=3) as bridge,
            ):
                adapter = api.NativeTerminalEvidenceAdapter(
                    {"nativeThreadId": self.item["threadId"]}, bridge
                )
                result = asyncio.run(
                    adapter.terminal_evidence(self.item, deepcopy(self.anchor))
                )
                self.assertEqual(result, full_receipt(self.item, outcome))
                self.assertEqual(bridge.attempts, {self.item["attemptId"]: self.wire})
                self.assertEqual(bridge.terminal_attempts, set())
                self.assertIsNone(bridge.witness)
                self.assertEqual(bridge.valid_until, 0)
                self.assertIsNone(adapter.witness)

    def test_terminal_receipt_rejects_identity_and_outcome_mutants(self):
        api = self.api()
        good = full_receipt(self.item, self.terminal)
        self.assertEqual(api.validate_terminal_receipt(self.item, good), self.terminal)
        self.assertEqual(
            api.validate_terminal_receipt(
                self.item, full_receipt(self.item, {"status": "unknown"})
            ),
            {"status": "unknown"},
        )
        cases = []
        for key in (*IDENTITY, "generation"):
            bad = deepcopy(good)
            bad[key] = True if isinstance(bad[key], int) else "wrong"
            cases.append(bad)
        for changes in (
            {"turnId": str(uuid4())},
            {"itemId": "bad"},
            {"itemId": self.item["clientUserMessageId"]},
            {"receiptId": "bad"},
            {"replayed": False},
            {"replayed": 1},
            {"terminalStatus": "unknown"},
            {"status": "started"},
            {"extra": True},
        ):
            cases.append(full_receipt(self.item, {**self.terminal, **changes}))
        for key in self.terminal:
            cases.append(
                full_receipt(
                    self.item, {k: v for k, v in self.terminal.items() if k != key}
                )
            )
        cases.append(full_receipt(self.item, {"status": "unknown", "replayed": True}))
        for bad in cases:
            with self.subTest(receipt=bad), self.assertRaises(NativeError):
                api.validate_terminal_receipt(self.item, bad)
        with self.assertRaises(NativeError):
            api.validate_terminal_receipt({**self.item, "receiptVersion": 2}, good)

    def test_invalid_saved_anchor_prevents_any_bridge_operation(self):
        api = self.api()
        for changes in ({"status": "started"}, {"itemId": "bad"}, {"replayed": False}):
            bridge = Mock(receipt_version=3)
            adapter = api.NativeTerminalEvidenceAdapter(
                {"nativeThreadId": self.item["threadId"]}, bridge
            )
            anchor = full_receipt(self.item, {**self.observed, **changes})
            with self.subTest(changes=changes), self.assertRaises(NativeError):
                asyncio.run(adapter.terminal_evidence(self.item, anchor))
            self.assertEqual(bridge.mock_calls, [])

    def test_anchor_item_mismatch_never_returns_terminal(self):
        api = self.api()
        bridge = Mock(receipt_version=3)
        bridge.terminal_evidence.return_value = {
            **self.terminal,
            "itemId": str(uuid4()),
        }
        adapter = api.NativeTerminalEvidenceAdapter(
            {"nativeThreadId": self.item["threadId"]}, bridge
        )
        try:
            result = asyncio.run(adapter.terminal_evidence(self.item, self.anchor))
        except NativeError:
            pass
        else:
            self.assertEqual(result["outcome"], {"status": "unknown"})
        self.assertEqual(
            [call[0] for call in bridge.mock_calls],
            ["restore_attempt", "terminal_evidence"],
        )

    def test_reader_requires_exact_restored_v3_request(self):
        self.api()
        for mode, restored, mutate in (
            (3, False, False),
            (3, True, True),
            (2, True, False),
        ):
            parent, child = socket.socketpair()
            bridge = NativeBridge(parent, receipt_version=mode)
            try:
                if restored:
                    bridge.restore_attempt(self.wire)
                query = deepcopy(self.wire)
                if mutate:
                    query["event"]["sourceStateVersion"] += "-changed"
                try:
                    outcome = bridge.terminal_evidence(query)
                except ValueError:
                    pass
                else:
                    self.assertEqual(outcome, {"status": "unknown"})
                child.setblocking(False)
                try:
                    sent = child.recv(4096)
                except BlockingIOError:
                    sent = b""
                self.assertEqual(sent, b"")
                self.assertEqual(bridge.terminal_attempts, set())
            finally:
                bridge.close()
                child.close()

    def test_terminal_evidence_cannot_enter_existing_ack_receipt_validator(self):
        self.api()
        with self.assertRaises(NativeError):
            validate_receipt(
                self.item,
                full_receipt(self.item, self.terminal),
                allow_input_recorded=True,
            )

    def test_unknown_and_malformed_wire_responses_fail_closed_without_retry(self):
        self.api()
        for mutation in (
            "unknown",
            "version",
            "nonce",
            "identity",
            "outcome",
            "unsupported",
        ):

            def handler(channel):
                row = receive(channel)
                self.assertEqual(row, {"nonce": 1, "terminalEvidence": self.wire})
                reply = {
                    "version": 3,
                    "nonce": row["nonce"],
                    "receipt": full_receipt(self.item, self.terminal),
                }
                if mutation == "unknown":
                    reply["receipt"]["outcome"] = {"status": "unknown"}
                elif mutation == "version":
                    reply["version"] = 2
                elif mutation == "nonce":
                    reply["nonce"] += 1
                elif mutation == "identity":
                    reply["receipt"]["generation"] += 1
                elif mutation == "outcome":
                    reply["receipt"]["outcome"]["replayed"] = False
                if mutation != "unsupported":
                    send(channel, reply)
                    self.assertIsNone(receive(channel))

            with (
                self.subTest(mutation=mutation),
                peer(handler, receipt_version=3) as bridge,
            ):
                bridge.restore_attempt(self.wire)
                self.assertEqual(
                    bridge.terminal_evidence(self.wire), {"status": "unknown"}
                )
                self.assertEqual(bridge.closed, mutation != "unknown")
                self.assertEqual(bridge.nonce, 1)
                self.assertEqual(bridge.terminal_attempts, set())
