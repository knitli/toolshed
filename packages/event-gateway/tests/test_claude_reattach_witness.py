"""Three-turn witness checks using inert records only; no sockets or providers."""

import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from uuid import uuid4
from event_gateway.claude import event_frame

SPEC = importlib.util.spec_from_file_location(
    "reattach_witness_canary",
    Path(__file__).parents[1] / "scripts/qualify_claude_socket.py",
)
CANARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CANARY)


class ReattachWitnessTests(unittest.TestCase):
    def setUp(self):
        self.session = str(uuid4())
        self.ready, self.old, self.fresh = (
            "READY_" + "a" * 32,
            "BUSY_" + "b" * 32,
            "FRESH_" + "c" * 32,
        )
        self.prefix, self.suffix = "fixture λ\n", "\nend 🧪"
        for part, value in [("PREFIX", self.prefix), ("SUFFIX", self.suffix)]:
            for field, expected in [
                ("BYTES", len(value.encode())),
                ("SHA256", hashlib.sha256(value.encode()).hexdigest()),
            ]:
                p = patch.object(CANARY, f"PEER_REPLAY_{part}_{field}", expected)
                p.start()
                self.addCleanup(p.stop)
        self.initial = {
            "type": "user",
            "session_id": self.session,
            "uuid": str(uuid4()),
            "message": {"role": "user", "content": "synthetic initial input"},
        }
        self.old_frame, self.fresh_frame = (
            self.frame(marker) for marker in (self.old, self.fresh)
        )

    def frame(self, marker):
        return event_frame(
            self.session,
            {
                "eventId": str(uuid4()),
                "deliveryId": "dly_" + hashlib.sha256(marker.encode()).hexdigest(),
                "source": "manual",
                "sourceStateVersion": "canary-1",
                "canonicalSubject": {"kind": "manual", "subjectId": marker},
                "eventReference": "ref_" + str(uuid4()),
            },
        )

    def state(self, state):
        return {
            "type": "system",
            "subtype": "session_state_changed",
            "session_id": self.session,
            "uuid": str(uuid4()),
            "state": state,
        }

    def replay(self, frame):
        return frame | {
            "isReplay": True,
            "message": {
                "role": "user",
                "content": self.prefix + frame["message"]["content"] + self.suffix,
            },
        }

    def assistant(self, marker):
        return {
            "type": "assistant",
            "session_id": self.session,
            "message": {"content": [{"type": "text", "text": marker}]},
        }

    def result(self, marker):
        return {
            "type": "result",
            "session_id": self.session,
            "uuid": str(uuid4()),
            "subtype": "success",
            "is_error": False,
            "result": marker,
        }

    def pair(self):
        p = CANARY.ReattachProbe(self.session, self.initial, self.ready)
        p.observe(
            {
                "type": "system",
                "subtype": "init",
                "session_id": self.session,
                "tools": [],
            }
        )
        p.observe(self.state("running"))
        p.provider_request(self.ready)
        p.hold_response()
        p.prepare(self.old_frame)
        p.sent()
        p.release_response()
        p.observe(self.assistant(self.ready))
        p.observe(self.result(self.ready))
        p.observe(self.state("idle"))
        p.observe(self.state("running"))
        p.provider_request(self.old)
        p.observe(self.replay(self.old_frame))
        p.observe(self.assistant(self.old))
        p.observe(self.result(self.old))
        p.observe(self.state("idle"))
        self.assertTrue(p.first_pair_complete.is_set())
        self.assertFalse(p.complete.is_set())
        return p

    def stages(self, p):
        return [
            ("running", lambda: p.observe(self.state("running"))),
            ("request", lambda: p.provider_request(self.fresh)),
            ("replay", lambda: p.observe(self.replay(self.fresh_frame))),
            ("assistant", lambda: p.observe(self.assistant(self.fresh))),
            ("result", lambda: p.observe(self.result(self.fresh))),
            ("idle", lambda: p.observe(self.state("idle"))),
            ("write", p.fresh_sent),
        ]

    def test_three_turn_success_and_original_snapshot(self):
        for early_write in (False, True):
            p = self.pair()
            snapshot = repr(p.initial_busy_proof)
            p.prepare_fresh(self.fresh_frame)
            if early_write:
                p.fresh_sent()
            for name, action in self.stages(p):
                if name != "write" or not early_write:
                    action()
            proof = p.proof()
            self.assertEqual(repr(p.initial_busy_proof), snapshot)
            self.assertEqual(
                [
                    x["turn"]
                    for x in p.initial_busy_proof["observations"]
                    if x["kind"] == "native_result"
                ],
                [1, 2],
            )
            self.assertEqual(
                [
                    x["turn"]
                    for x in proof["observations"]
                    if x["kind"] == "native_result"
                ],
                [1, 2, 3],
            )
            self.assertEqual(
                (proof["admission"], proof["delivery"]), ("unknown", "unknown")
            )
            self.assertFalse(proof["nativeRestartQualified"])
            self.assertNotEqual(proof["oldInputUuid"], proof["freshInputUuid"])

    def test_each_independent_witness_is_required(self):
        for missing in (
            "running",
            "request",
            "replay",
            "assistant",
            "result",
            "idle",
            "write",
        ):
            with self.subTest(missing=missing):
                p = self.pair()
                p.prepare_fresh(self.fresh_frame)
                try:
                    for name, action in self.stages(p):
                        if name != missing:
                            action()
                except CANARY.CanaryError:
                    pass
                self.assertFalse(p.complete.is_set())
                with self.assertRaises(CANARY.CanaryError):
                    p.proof()

    def test_prepare_before_completion_or_old_uuid_refused(self):
        p = CANARY.ReattachProbe(self.session, self.initial, self.ready)
        with self.assertRaises(CANARY.CanaryError):
            p.prepare_fresh(self.fresh_frame)
        p = self.pair()
        with self.assertRaises(CANARY.CanaryError):
            p.prepare_fresh(self.fresh_frame | {"uuid": self.old_frame["uuid"]})

    def test_wrong_session_wrapper_old_and_duplicate_replays_refused(self):
        good = self.replay(self.fresh_frame)
        cases = [
            good | {"session_id": str(uuid4())},
            self.replay(self.old_frame),
            good | {"isReplay": False},
            good | {"parent_tool_use_id": "tool"},
            good
            | {
                "message": {
                    "role": "user",
                    "content": self.fresh_frame["message"]["content"],
                }
            },
            good
            | {
                "message": {
                    "role": "user",
                    "content": self.prefix + "wrong" + self.suffix,
                }
            },
        ]
        for value in cases:
            p = self.pair()
            p.prepare_fresh(self.fresh_frame)
            with self.subTest(value=value), self.assertRaises(CANARY.CanaryError):
                p.observe(value)
        p = self.pair()
        p.prepare_fresh(self.fresh_frame)
        p.observe(good)
        with self.assertRaises(CANARY.CanaryError):
            p.observe(good)

    def test_wrong_marker_order_and_terminal_lifecycle_refused(self):
        for action in (
            lambda p: p.provider_request(self.old),
            lambda p: p.observe(self.result(self.fresh)),
            lambda p: p.observe(self.assistant(self.fresh)),
            lambda p: p.observe(self.state("idle")),
        ):
            p = self.pair()
            p.prepare_fresh(self.fresh_frame)
            with self.assertRaises(CANARY.CanaryError):
                action(p)
        for state in ("cancelled", "discarded", "refused", "completed"):
            p = self.pair()
            p.prepare_fresh(self.fresh_frame)
            with self.subTest(state=state), self.assertRaises(CANARY.CanaryError):
                p.observe(
                    {
                        "type": "command_lifecycle",
                        "command_uuid": self.fresh_frame["uuid"],
                        "uuid": str(uuid4()),
                        "session_id": self.session,
                        "state": state,
                    }
                )

    def test_provider_first_two_requests_keep_existing_busy_contract(self):
        p = CANARY.ReattachProbe(self.session, self.initial, self.ready)
        provider = CANARY.ReattachProvider("dummy", "fixture-model", p)
        first = {
            "stream": True,
            "model": "fixture-model",
            "tools": [],
            "system": self.ready,
            "messages": [{"role": "user", "content": "synthetic initial input"}],
        }
        self.assertIn(self.ready.encode(), provider.respond(first))
        p.observe(
            {
                "type": "system",
                "subtype": "init",
                "session_id": self.session,
                "tools": [],
            }
        )
        p.observe(self.state("running"))
        p.hold_response()
        p.prepare(self.old_frame)
        second = first | {"messages": [{"role": "user", "content": self.old}]}
        with self.assertRaises(CANARY.CanaryError):
            provider.respond(second)
        self.assertEqual(provider.turns, 1)
        p.sent()
        p.release_response()
        self.assertIn(self.old.encode(), provider.respond(second))
        self.assertEqual(provider.turns, 2)
        self.assertEqual(p.busy.requests, 2)
        with self.assertRaises(CANARY.CanaryError):
            provider.respond(
                first | {"messages": [{"role": "user", "content": self.fresh}]}
            )
        self.assertEqual(provider.turns, 2)

    def test_provider_exact_third_request_and_fourth_refusal(self):
        p = self.pair()
        p.prepare_fresh(self.fresh_frame)
        provider = CANARY.ReattachProvider("dummy", "fixture-model", p)
        provider.turns = 2
        request = {
            "stream": True,
            "model": "fixture-model",
            "tools": [],
            "messages": [{"role": "user", "content": self.fresh}],
        }
        for change in (
            {"model": "wrong"},
            {"tools": [{}]},
            {"stream": False},
            {"messages": [{"role": "user", "content": self.old}]},
        ):
            with self.assertRaises(CANARY.CanaryError):
                provider.respond(request | change)
            self.assertEqual(provider.turns, 2)
        self.assertIn(self.fresh.encode(), provider.respond(request))
        self.assertEqual(provider.turns, 3)
        with self.assertRaises(CANARY.CanaryError):
            provider.respond(request)


if __name__ == "__main__":
    unittest.main()
