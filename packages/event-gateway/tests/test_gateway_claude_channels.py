"""Assigned Claude Channel receipt and no-replay behavior over the shared ledger."""

import asyncio
import copy
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_gateway import daemon, messaging_protocol_v2
from event_gateway.cloud import _iso
from event_gateway.gateway import Gateway
from event_gateway.store import IDENTITY, Store, StoreError


ROOT = Path(__file__).resolve().parents[1]
V1 = json.loads((ROOT / "contracts/event-v1/protocol-v1.json").read_text())
V2 = json.loads((ROOT / "contracts/messaging-v2/messaging-protocol-semantics-v2.json").read_text())


class Authority:
    def __init__(self, now):
        """Fake the cloud authority for isolated gateway tests."""
        self.now = now
        self.acks = []
        self.fail_ack = False

    async def claim(self, envelope):
        return {
            "status": "admitted", "permitId": "52345678-1234-4234-8234-123456789abc",
            "nodeId": envelope.get("nodeId", "32345678-1234-4234-8234-123456789abc"),
            "permitIssuedAt": _iso(self.now), "permitExpiresAt": _iso(self.now + 5),
            "envelope": copy.deepcopy(envelope),
        }

    async def acknowledge(self, envelope, acknowledgment):
        self.acks.append((copy.deepcopy(envelope), copy.deepcopy(acknowledgment)))
        if self.fail_ack:
            self.fail_ack = False
            raise TimeoutError("lost ACK")
        return {"status": acknowledgment["status"], "current": False}


class ClaudeChannelGatewayTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve() / "state"
        self.event = copy.deepcopy(next(e for e in V1["validEnvelopes"] if "runtimeProfile" in e))
        self.event["runtimeProfile"]["client"] = "claude"
        self.event["runtimeProfile"]["conversationId"] = str(uuid.uuid4())
        self.now = 1791201630
        self.mapping = {key: self.event[key] for key in IDENTITY}
        self.mapping.update(
            nodeId="32345678-1234-4234-8234-123456789abc",
            consumerGeneration=self.event["consumerGeneration"],
            runtimeProfile=copy.deepcopy(self.event["runtimeProfile"]),
            leaseExpiresAt=self.now + 3600,
        )
        self.store = Store(self.path, clock=lambda: self.now)
        self.addCleanup(self.store.close)
        self.store.put_attachment(self.mapping)
        self.authority = Authority(self.now)
        self.gateway = Gateway(
            self.store, self.authority, lambda _mapping: None,
            audience="test", keys={"test": Ed25519PrivateKey.generate().public_key()},
            clock=lambda: self.now,
        )

    def install_v2(self):
        self.now = V2["nowMs"] / 1000
        self.authority.now = self.now
        event = copy.deepcopy(V2["envelope"])
        event["runtimeProfile"] = {
            "profile": "assigned_stock_client", "client": "claude",
            "conversationId": str(uuid.uuid4()),
        }
        event["deliveryId"] = messaging_protocol_v2.derive_delivery_id(event)
        self.store.detach(self.event["runtimeId"])
        self.event = event
        self.mapping = {key: event[key] for key in (
            "principal", "agent", "nodeId", "runtimeId", "nodeGeneration", "runtimeGeneration",
            "attachmentGeneration", "consumerGeneration", "routingGeneration",
        )}
        self.mapping.update(
            namespace=event["canonicalSubject"]["namespace"],
            agentIncarnation=event["canonicalSubject"]["agentIncarnation"],
            runtimeProfile=copy.deepcopy(event["runtimeProfile"]),
            leaseExpiresAt=self.now + 3600,
        )
        self.store.put_messaging_attachment(self.mapping)

    async def admit_and_claim(self):
        delivery_id = self.store.accept(copy.deepcopy(self.event))["deliveryId"]
        self.gateway.authority.now = self.now
        await self.gateway.dispatch(delivery_id)
        return delivery_id

    async def test_v1_claude_callback_is_explicit_and_acknowledged(self):
        delivery_id = await self.admit_and_claim()
        claimed = self.store.claim_claude_handoff(self.event["runtimeId"],
                                                   self.event["runtimeProfile"]["conversationId"])
        payload = claimed["delivery"]
        self.assertEqual(payload["eventReference"], self.event["eventReference"])
        self.assertNotIn("receiptToken", self.store.current_attempt(delivery_id)["claude_handoff"])
        self.assertIsNone(self.store.claim_claude_handoff(
            self.event["runtimeId"], self.event["runtimeProfile"]["conversationId"],
        )["delivery"])
        self.store.record_claude_client_reported(
            self.event["runtimeId"], self.event["runtimeProfile"]["conversationId"],
            delivery_id, self.event["attemptId"], payload["receiptToken"],
        )
        result = await self.gateway.reconcile(delivery_id)
        self.assertEqual(result["status"], "client_reported")
        ack = self.authority.acks[-1][1]
        self.assertEqual(ack["status"], "client_reported")
        self.assertNotIn("permitId", ack)
        self.assertEqual(self.store.current_attempt(delivery_id)["ack_state"], "client_reported")

    async def test_claude_poll_skips_other_runtime_handoff_before_decoding(self):
        delivery_id = await self.admit_and_claim()
        other_delivery_id, other_attempt_id = str(uuid.uuid4()), str(uuid.uuid4())
        with self.store.db:
            self.store.db.execute(
                "INSERT INTO deliveries(id,dedup,semantic,envelope,runtime,agent,state,created,updated,retain_until) "
                "VALUES(?,?,?,?,?,?,'admitted',?,?,?)",
                (other_delivery_id, str(uuid.uuid4()), "{}", "{}", "other-runtime", "other-agent",
                 self.now, self.now - 1, self.now + 3600),
            )
            self.store.db.execute(
                "INSERT INTO attempts(delivery_id,attempt_id,state,envelope,reserved_bytes,updated,claude_handoff) "
                "VALUES(?,?,'admitted','{}',0,?,'{')",
                (other_delivery_id, other_attempt_id, self.now - 1),
            )

        claimed = self.store.claim_claude_handoff(
            self.event["runtimeId"], self.event["runtimeProfile"]["conversationId"],
        )["delivery"]
        self.assertEqual(claimed["deliveryId"], delivery_id)
        other_state = self.store.db.execute(
            "SELECT state FROM attempts WHERE delivery_id=? AND attempt_id=?",
            (other_delivery_id, other_attempt_id),
        ).fetchone()["state"]
        self.assertEqual(other_state, "admitted")

    async def test_v2_claude_receipt_keeps_permit_and_retries_cloud_ack(self):
        self.install_v2()
        self.gateway.stock_only = True
        delivery_id = await self.admit_and_claim()
        payload = self.store.claim_claude_handoff(
            self.event["runtimeId"], self.event["runtimeProfile"]["conversationId"],
        )["delivery"]
        self.authority.fail_ack = True
        self.store.record_claude_client_reported(
            self.event["runtimeId"], self.event["runtimeProfile"]["conversationId"],
            delivery_id, self.event["attemptId"], payload["receiptToken"],
        )
        pending = await self.gateway.reconcile(delivery_id)
        self.assertEqual(pending["reason"], "client_reported_ack_pending")
        ack = self.store.current_attempt(delivery_id)["native_ack"]
        self.assertEqual(ack["status"], "client_reported")
        self.assertEqual(ack["permitId"], self.store.current_attempt(delivery_id)["admission"]["permitId"])
        self.assertNotIn("nativeCorrelation", ack)
        with self.assertRaises(messaging_protocol_v2.MessagingProtocolError):
            messaging_protocol_v2.parse_acknowledgment(
                json.dumps({**ack, "status": "command_accepted"}), now_ms=self.now * 1000,
            )
        result = await self.gateway.reconcile(delivery_id)
        self.assertEqual(result["status"], "client_reported")
        self.assertEqual(self.store.current_attempt(delivery_id)["ack_state"], "client_reported")
        self.store.detach(self.event["runtimeId"])
        self.assertEqual(self.store.record_claude_client_reported(
            self.event["runtimeId"], self.event["runtimeProfile"]["conversationId"],
            delivery_id, self.event["attemptId"], payload["receiptToken"],
        ), {"status": "client_reported"})

    async def test_lost_poll_reply_and_bad_callback_never_replay_or_settle(self):
        self.install_v2()
        delivery_id = await self.admit_and_claim()
        first = self.store.claim_claude_handoff(
            self.event["runtimeId"], self.event["runtimeProfile"]["conversationId"],
        )["delivery"]
        self.assertIsNotNone(first)
        self.assertIsNone(self.store.claim_claude_handoff(
            self.event["runtimeId"], self.event["runtimeProfile"]["conversationId"],
        )["delivery"])
        with self.assertRaises(StoreError):
            self.store.record_claude_client_reported(
                self.event["runtimeId"], self.event["runtimeProfile"]["conversationId"],
                delivery_id, self.event["attemptId"], "A" * 43,
            )
        self.store.close()
        self.store = Store(self.path, clock=lambda: self.now)
        self.addCleanup(self.store.close)
        self.gateway.store = self.store
        self.assertIsNone(self.store.claim_claude_handoff(
            self.event["runtimeId"], self.event["runtimeProfile"]["conversationId"],
        )["delivery"])
        self.assertEqual(self.store.current_attempt(delivery_id)["state"], "claude_claimed")
        self.assertEqual(self.authority.acks, [])

    async def test_callback_rejects_routed_message_id_drift(self):
        self.install_v2()
        delivery_id = await self.admit_and_claim()
        payload = self.store.claim_claude_handoff(
            self.event["runtimeId"], self.event["runtimeProfile"]["conversationId"],
        )["delivery"]
        handoff = self.store.current_attempt(delivery_id)["claude_handoff"]
        self.assertEqual(handoff["messageId"], self.event["canonicalSubject"]["messageId"])
        handoff["messageId"] = str(uuid.uuid4())
        with self.store.db:
            self.store.db.execute(
                "UPDATE attempts SET claude_handoff=? WHERE delivery_id=? AND attempt_id=?",
                (json.dumps(handoff, sort_keys=True, separators=(",", ":")),
                 delivery_id, self.event["attemptId"]),
            )
        with self.assertRaisesRegex(StoreError, "^stale_claude_receipt$"):
            self.store.record_claude_client_reported(
                self.event["runtimeId"], self.event["runtimeProfile"]["conversationId"],
                delivery_id, self.event["attemptId"], payload["receiptToken"],
            )
        self.assertEqual(self.store.current_attempt(delivery_id)["state"], "claude_claimed")
        self.assertEqual(self.authority.acks, [])

    async def test_callback_after_assignment_rotation_is_rejected(self):
        self.install_v2()
        delivery_id = await self.admit_and_claim()
        payload = self.store.claim_claude_handoff(
            self.event["runtimeId"], self.event["runtimeProfile"]["conversationId"],
        )["delivery"]
        self.store.detach(self.event["runtimeId"])
        with self.assertRaises(StoreError):
            self.store.record_claude_client_reported(
                self.event["runtimeId"], self.event["runtimeProfile"]["conversationId"],
                delivery_id, self.event["attemptId"], payload["receiptToken"],
            )
        self.assertEqual(self.authority.acks, [])

    async def test_control_rpc_uses_exact_assignment_and_rejects_extra_fields(self):
        self.install_v2()
        registered = daemon._execute_control_command(self.store, {
            "command": "claude-register", "runtimeId": self.event["runtimeId"],
            "conversationId": self.event["runtimeProfile"]["conversationId"],
        })
        self.assertTrue(registered["registered"])
        rejected = daemon._execute_control_command(self.store, {
            "command": "claude-register", "runtimeId": self.event["runtimeId"],
            "conversationId": self.event["runtimeProfile"]["conversationId"], "extra": True,
        })
        self.assertEqual(rejected["reason"], "unsupported_command")
        delivery_id = await self.admit_and_claim()
        claimed = daemon._execute_control_command(self.store, {
            "command": "claude-poll", "runtimeId": self.event["runtimeId"],
            "conversationId": self.event["runtimeProfile"]["conversationId"],
        })["delivery"]
        self.assertEqual(claimed["messageId"], self.event["canonicalSubject"]["messageId"])
        callback = daemon._execute_control_command(self.store, {
            "command": "claude-client-reported", "runtimeId": self.event["runtimeId"],
            "conversationId": self.event["runtimeProfile"]["conversationId"],
            "deliveryId": delivery_id, "attemptId": self.event["attemptId"],
            "receiptToken": claimed["receiptToken"],
        })
        self.assertEqual(callback, {"recorded": True})

    async def test_mcp_channel_and_daemon_complete_one_claude_receipt_end_to_end(self):
        self.install_v2()
        delivery_id = self.store.accept(copy.deepcopy(self.event))["deliveryId"]
        now = self.now
        self.store.close()

        class FakeCloud(Authority):
            def __init__(cloud_self):
                super().__init__(now)
                cloud_self.node_id = self.event["nodeId"]
                cloud_self.node_generation = self.event["nodeGeneration"]
                cloud_self.principal = self.event["principal"]
                cloud_self.agent = self.event["agent"]
                cloud_self.acknowledged = asyncio.Event()

            async def claim(cloud_self, envelope):
                return {
                    "status": "admitted", "permitId": "62345678-1234-4234-8234-123456789abc",
                    "nodeId": envelope["nodeId"], "permitIssuedAt": _iso(now),
                    "permitExpiresAt": _iso(now + 5), "envelope": copy.deepcopy(envelope),
                }

            async def acknowledge(cloud_self, envelope, acknowledgment):
                cloud_self.acks.append((copy.deepcopy(envelope), copy.deepcopy(acknowledgment)))
                cloud_self.acknowledged.set()
                return {"status": acknowledgment["status"], "current": True}

            async def assigned_stock(cloud_self, _request):
                raise daemon.CloudError("assigned_stock_disabled", definitive_refusal=True)

        cloud = FakeCloud()
        key = Ed25519PrivateKey.generate().public_key()
        config = {"version": 1, "listenHost": "127.0.0.1", "listenPort": 0,
                  "transportKeys": {"test": key}}
        state_dir = self.path
        dispatch_config = state_dir / "dispatch.json"
        daemon_task = None
        channel_process = None

        async def read_frame():
            line = await asyncio.wait_for(channel_process.stdout.readline(), 5)
            self.assertTrue(line, "Claude channel process exited before replying")
            return json.loads(line)

        async def send_frame(value):
            channel_process.stdin.write(json.dumps(value).encode() + b"\n")
            await channel_process.stdin.drain()

        try:
            with patch.object(daemon, "load_dispatch_config", return_value=(config, cloud)), \
                    patch.object(daemon, "Store", side_effect=lambda path: Store(
                        path, clock=lambda: now)), \
                    patch.object(daemon, "Gateway", side_effect=lambda *args, **kwargs: Gateway(
                        *args, **kwargs, clock=lambda: now)):
                daemon_task = asyncio.create_task(daemon.serve(
                    state_dir, dispatch_config=dispatch_config, stock_only=True,
                ))
                socket_path = state_dir / "control.sock"
                deadline = asyncio.get_running_loop().time() + 4
                while (not socket_path.exists()
                       or not stat.S_ISSOCK(socket_path.stat().st_mode)
                       or stat.S_IMODE(socket_path.stat().st_mode) != 0o600):
                    if daemon_task.done():
                        await daemon_task
                    if asyncio.get_running_loop().time() >= deadline:
                        self.fail("Gateway daemon did not open its private control socket")
                    await asyncio.sleep(0.01)

                channel_process = await asyncio.create_subprocess_exec(
                    sys.executable, "-m", "event_gateway.claude_channel",
                    "--state-dir", str(state_dir), "--runtime-id", self.event["runtimeId"],
                    "--conversation-id", self.event["runtimeProfile"]["conversationId"],
                    cwd=ROOT / "../..", env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
                    stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await send_frame({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                               "clientInfo": {"name": "gateway-integration", "version": "1"}},
                })
                initialized = await read_frame()
                self.assertEqual(initialized["result"]["capabilities"]["experimental"]["claude/channel"], {})
                await send_frame({"jsonrpc": "2.0", "method": "notifications/initialized"})
                await send_frame({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
                frames = []
                while (not any(frame.get("id") == 2 for frame in frames)
                       or not any(frame.get("method") == "notifications/claude/channel" for frame in frames)):
                    frames.append(await read_frame())
                notification = next(frame for frame in frames
                                    if frame.get("method") == "notifications/claude/channel")
                body = json.loads(notification["params"]["content"])
                self.assertEqual(body["event"], self.event["eventReference"])
                self.assertEqual(body["deliveryId"], delivery_id)
                self.assertEqual(body["messageId"], self.event["canonicalSubject"]["messageId"])
                await send_frame({
                    "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {"name": "client_reported", "arguments": {
                        "deliveryId": body["deliveryId"], "attemptId": body["attemptId"],
                        "receiptToken": body["receiptToken"],
                    }},
                })
                callback = await read_frame()
                self.assertTrue(json.loads(callback["result"]["content"][0]["text"])["recorded"])
                await asyncio.wait_for(cloud.acknowledged.wait(), 4)
                acknowledgment = cloud.acks[-1][1]
                self.assertEqual(acknowledgment["status"], "client_reported")
                self.assertEqual(acknowledgment["permitId"], "62345678-1234-4234-8234-123456789abc")
                self.assertNotIn(body["receiptToken"], json.dumps(acknowledgment))
        finally:
            if channel_process is not None:
                if channel_process.stdin and not channel_process.stdin.is_closing():
                    channel_process.stdin.close()
                if channel_process.returncode is None:
                    channel_process.kill()
                await channel_process.wait()
            if daemon_task is not None:
                daemon_task.cancel()
                await asyncio.gather(daemon_task, return_exceptions=True)
            self.store = Store(self.path, clock=lambda: now)
            self.addCleanup(self.store.close)


if __name__ == "__main__":
    unittest.main()
