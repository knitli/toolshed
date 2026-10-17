"""Exercise the fixture's held C2 restart proof without native or provider processes."""
from contextlib import ExitStack
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

from event_gateway import launcher


SCRIPT = Path(__file__).resolve().parents[1] / "docs/native-bridge/three-session-workerd.py"
SPEC = importlib.util.spec_from_file_location("busy_restart_fixture", SCRIPT)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
F.launcher = launcher


class BusyRestartTests(unittest.IsolatedAsyncioTestCase):
    async def scenario(self, violation=None):
        binding = {"clientId": str(uuid4()), "connectionId": str(uuid4()), "backendPid": 42,
                   "threadId": str(uuid4()), "serverInstanceId": str(uuid4()),
                   "generation": 4, "serverGeneration": 5}
        mapping = {"runtimeId": "C", "nodeGeneration": 1, "runtimeGeneration": 2,
                   "attachmentGeneration": 2}
        envelope = {**mapping, "deliveryId": "c2", "attemptId": "c2-attempt"}
        transport = {"attempt_id": "c2-attempt", "state": "created", "reservation_state": "none",
                     "transport_status": "sending", "permit_id": None, "submission_id": None, "turn_id": None}
        cloud = {"cloud": {"attempts": [transport], "native_claims": []}}
        held = SimpleNamespace(hold_lock=threading.Lock(), hold_started=threading.Event(),
                               release_hold=threading.Event(), hold_state="held", hold_deadline=time.monotonic() + 60)
        held.hold_started.set()
        ctx = SimpleNamespace(state=Path("/fixture"), runtime_ids={"C": "C"}, node_id="node",
                              transport_key=Mock(), c_busy_mapping=mapping, c_busy_binding=binding,
                              sessions={"C": {"provider": held, "binding": {**binding, "generation": 1}}},
                              start_calls={"C": [{"attemptId": "c1-attempt"}]}, dispatch_labels={},
                              dispatch_calls=[], dispatch_results=[], dispatch_errors=[], c_challenges=[],
                              c_busy_nonces=set(), daemon_task=object(), listen_port=1)
        ctx.transport_key.private_bytes.return_value = b"fixture-key"
        ctx.fixture = Mock(side_effect=lambda path, body=None: (
            {"envelope": envelope, "signedDelivery": {}} if path == "/fixture/setup" else cloud))
        restarted = False

        async def restart():
            nonlocal restarted
            restarted = True
            if violation == "claim":
                cloud["cloud"]["native_claims"].append({"attempt_id": "c2-attempt"})
            if violation == "start":
                ctx.start_calls["C"].append({"attemptId": "c2-attempt"})
            return object()

        ctx.start_daemon = AsyncMock(side_effect=restart)
        ctx.stop_daemon = AsyncMock()
        ctx.c_second_busy_dispositions = lambda: F.c_second_busy_dispositions(ctx)

        async def dispatch(*args):
            nonce = 1 if not restarted or violation == "replayed" else 2
            challenge_id = str(uuid4())
            ctx.c_challenges.append({
                "request": {"command": "challenge", "challengeId": challenge_id, "expectedBinding": binding},
                "receivedAt": time.monotonic(),
                "response": {"challengeId": challenge_id,
                             "observedAt": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                             "validUntilMonotonic": time.monotonic() + 0.5,
                             "witness": {**binding, "version": 2, "nonce": nonce, "sequence": nonce,
                                         "cause": "heartbeat", "leaseMs": 750, "eligible": True,
                                         "nativeCoreTurnState": "busy"}},
            })
            return {"status": "queued", "reason": "client_unavailable_or_busy"}

        ctx.original_dispatch = dispatch

        async def wait(predicate, message, **kwargs):
            if message in ("production dispatch did not return C's busy disposition",
                           "restarted daemon did not observe C still busy"):
                await F.observe_dispatch(None, ctx, "c2")
            self.assertTrue(predicate(), message)

        with ExitStack() as stack:
            stack.enter_context(patch.object(F, "serialization", Mock()))
            stack.enter_context(patch.object(F, "attach_busy_session", new=AsyncMock()))
            stack.enter_context(patch.object(F, "listener_delivery", return_value=(202, None)))
            stack.enter_context(patch.object(F, "db_delivery", return_value={"state": "queued", "attemptState": None}))
            stack.enter_context(patch.object(F, "db_delivery_envelope_sha256", return_value="unchanged"))
            stack.enter_context(patch.object(F, "wait_until", side_effect=wait))
            stack.enter_context(patch.object(F.asyncio, "sleep", new=AsyncMock()))
            stack.enter_context(patch.object(F, "record_evidence"))
            await F.run_held_busy_stage(ctx, time.time())
        return ctx, cloud

    async def test_restarted_c2_needs_fresh_busy_proof_and_zero_claims_or_starts(self):
        ctx, cloud = await self.scenario()
        self.assertEqual(ctx.c_busy_nonces, {1, 2})
        self.assertEqual(len(ctx.c_second_busy_dispositions()), 2)
        self.assertEqual(ctx.start_daemon.await_count, 1)
        self.assertEqual(ctx.stop_daemon.await_count, 2)
        self.assertEqual(cloud["cloud"]["native_claims"], [])
        self.assertEqual(ctx.start_calls["C"], [{"attemptId": "c1-attempt"}])
        for violation, message in (("claim", "restarted busy delivery did not remain queued"),
                                   ("start", "restarted busy delivery did not remain queued"),
                                   ("replayed", "fresh authoritative Core-busy")):
            with self.subTest(violation=violation), self.assertRaisesRegex(AssertionError, message):
                await self.scenario(violation)
